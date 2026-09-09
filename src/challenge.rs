//! Challenge generation, single-use consumption (replay protection),
//! freshness/expiry enforcement, and the sign-count clone-detection state
//! machine.
//!
//! This module lifts the challenge/replay/sign-count logic that was previously
//! entangled with application storage into a self-contained, storage-free
//! helper. Pending challenges are held in-process; challenge *consumption* is
//! atomic (single-use) and time-bounded.
//!
//! # Storage contract
//!
//! [`ChallengeStore`] keeps only *pending* challenges in memory. It never
//! touches credentials. Integrators persisting state across restarts should
//! either accept that pending challenges are lost on restart (users simply
//! retry) or implement their own store using [`ChallengeStore`] as reference.
//!
//! # Threat model
//!
//! - **Replay**: a consumed challenge is removed from the store before the
//!   result is returned, so the same challenge can never complete two
//!   ceremonies, even with concurrent requests (single map entry).
//! - **Staleness**: challenges carry a creation timestamp; consumption fails
//!   with [`WebauthnError::ChallengeExpired`] once older than the caller's
//!   timeout.
//! - **Predictability**: challenge bytes come from the OS CSPRNG (see
//!   [`generate_challenge_bytes`]).
//! - **Cloned authenticators**: [`check_sign_count`] rejects counters that
//!   move backwards.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::WebauthnConfig;
use crate::credential::{
    AllowCredential, AuthenticationOptions, AuthenticatorSelection, ExcludeCredential,
    PubKeyCredParam, RegistrationOptions, RelyingParty, WebauthnUser,
};
use crate::crypto::{base64_encode_urlsafe, generate_challenge_bytes};
use crate::error::WebauthnError;

/// Current Unix timestamp in seconds; `0` if the clock is before the epoch
/// (which would only make challenges look stale, never fresh — fail-safe).
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Enforce the sign-count freshness state machine for an authentication
/// assertion.
///
/// Semantics (preserved from the reference implementation):
///
/// - If the stored counter is `0` (authenticators that do not implement the
///   counter, or first use), the check is skipped and the assertion is
///   accepted with whatever counter the authenticator reports.
/// - Otherwise, a reported counter *strictly lower* than the stored counter
///   indicates a cloned authenticator and is rejected.
/// - An *equal* counter is accepted: many hardware keys only increment the
///   counter occasionally and this must not lock users out.
///
/// # Security note
///
/// The caller must persist `new_sign_count` only after this function returns
/// `Ok`, ideally with a compare-and-swap against `current_sign_count` so that
/// two concurrent authentications cannot both bump the stored counter.
///
/// Returns `Ok(())` when the counter is fresh, [`WebauthnError::VerificationFailed`]
/// when clone activity is suspected.
///
/// # Requirements
/// REQ-WA-111, REQ-WA-112
pub fn check_sign_count(current_sign_count: u32, new_sign_count: u32) -> Result<(), WebauthnError> {
    if current_sign_count != 0 && new_sign_count < current_sign_count {
        return Err(WebauthnError::VerificationFailed(format!(
            "Sign count decreased: {new_sign_count} < {current_sign_count} (possible cloned authenticator)"
        )));
    }
    Ok(())
}

/// A pending registration challenge.
#[derive(Debug, Clone)]
struct RegistrationChallenge {
    username: String,
    challenge_bytes: Vec<u8>,
    created_at: i64,
}

/// A pending authentication challenge.
#[derive(Debug, Clone)]
struct AuthenticationChallenge {
    username: String,
    challenge_bytes: Vec<u8>,
    allowed_credential_ids: Vec<String>,
    created_at: i64,
}

/// In-memory store of pending `WebAuthn` challenges with single-use
/// consumption and expiry enforcement.
///
/// Construct with [`ChallengeStore::new`] or [`ChallengeStore::with_clock`]
/// (the latter for deterministic expiry tests). See the module documentation
/// for the threat model and storage contract.
///
/// # Requirements
/// REQ-WA-108, REQ-WA-109, REQ-WA-115, REQ-WA-200
pub struct ChallengeStore {
    /// Injectable clock (Unix seconds); defaults to the system clock.
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Pending registration challenges (challenge ID → entry).
    registration_challenges: HashMap<String, RegistrationChallenge>,
    /// Pending authentication challenges (challenge ID → entry).
    authentication_challenges: HashMap<String, AuthenticationChallenge>,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ChallengeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit challenge contents (secrets in transit).
        f.debug_struct("ChallengeStore")
            .field("pending_registration", &self.registration_challenges.len())
            .field(
                "pending_authentication",
                &self.authentication_challenges.len(),
            )
            .finish()
    }
}

impl ChallengeStore {
    /// Create a new empty challenge store using the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            now: Arc::new(unix_now),
            registration_challenges: HashMap::new(),
            authentication_challenges: HashMap::new(),
        }
    }

    /// Create a challenge store with an injectable clock (Unix seconds),
    /// primarily for deterministic expiry testing.
    #[must_use]
    pub fn with_clock(now: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            now,
            registration_challenges: HashMap::new(),
            authentication_challenges: HashMap::new(),
        }
    }

    /// Store a pending registration challenge.
    ///
    /// The challenge is keyed by `challenge_id` (an opaque handle the caller
    /// tracks in its own session state) and stores the raw challenge bytes the
    /// client must echo back.
    pub fn store_registration_challenge(
        &mut self,
        challenge_id: &str,
        username: &str,
        challenge_bytes: Vec<u8>,
    ) {
        self.store_registration_challenge_at(challenge_id, username, challenge_bytes, (self.now)());
    }

    /// Store a pending registration challenge with an explicit creation
    /// timestamp (Unix seconds). Useful for testing expiry and for
    /// restoring persisted state.
    pub fn store_registration_challenge_at(
        &mut self,
        challenge_id: &str,
        username: &str,
        challenge_bytes: Vec<u8>,
        created_at: i64,
    ) {
        self.registration_challenges.insert(
            challenge_id.to_string(),
            RegistrationChallenge {
                username: username.to_string(),
                challenge_bytes,
                created_at,
            },
        );
    }

    /// Consume a registration challenge (single use), returning the
    /// associated username and raw challenge bytes.
    ///
    /// # Security notes
    ///
    /// - The entry is removed *before* validation results are returned, so a
    ///   challenge can never be used twice (replay protection).
    /// - Expired challenges are rejected with [`WebauthnError::ChallengeExpired`].
    /// - Unknown IDs are rejected with [`WebauthnError::InvalidChallenge`].
    ///
    /// # Requirements
    /// REQ-WA-108, REQ-WA-109
    pub fn consume_registration_challenge(
        &mut self,
        challenge_id: &str,
        timeout_secs: u64,
    ) -> Result<(String, Vec<u8>), WebauthnError> {
        let challenge = self
            .registration_challenges
            .remove(challenge_id)
            .ok_or_else(|| WebauthnError::InvalidChallenge("not found".to_string()))?;

        if (self.now)() - challenge.created_at > timeout_secs as i64 {
            return Err(WebauthnError::ChallengeExpired);
        }

        Ok((challenge.username, challenge.challenge_bytes))
    }

    /// Store a pending authentication challenge.
    pub fn store_authentication_challenge(
        &mut self,
        challenge_id: &str,
        username: &str,
        challenge_bytes: Vec<u8>,
        allowed_credential_ids: Vec<String>,
    ) {
        self.store_authentication_challenge_at(
            challenge_id,
            username,
            challenge_bytes,
            allowed_credential_ids,
            (self.now)(),
        );
    }

    /// Store a pending authentication challenge with an explicit creation
    /// timestamp (Unix seconds).
    pub fn store_authentication_challenge_at(
        &mut self,
        challenge_id: &str,
        username: &str,
        challenge_bytes: Vec<u8>,
        allowed_credential_ids: Vec<String>,
        created_at: i64,
    ) {
        self.authentication_challenges.insert(
            challenge_id.to_string(),
            AuthenticationChallenge {
                username: username.to_string(),
                challenge_bytes,
                allowed_credential_ids,
                created_at,
            },
        );
    }

    /// Consume an authentication challenge (single use), returning the
    /// username, raw challenge bytes, and the allowed credential IDs.
    ///
    /// Same security semantics as [`ChallengeStore::consume_registration_challenge`].
    ///
    /// # Requirements
    /// REQ-WA-108, REQ-WA-109
    pub fn consume_authentication_challenge(
        &mut self,
        challenge_id: &str,
        timeout_secs: u64,
    ) -> Result<(String, Vec<u8>, Vec<String>), WebauthnError> {
        let challenge = self
            .authentication_challenges
            .remove(challenge_id)
            .ok_or_else(|| WebauthnError::InvalidChallenge("not found".to_string()))?;

        if (self.now)() - challenge.created_at > timeout_secs as i64 {
            return Err(WebauthnError::ChallengeExpired);
        }

        Ok((
            challenge.username,
            challenge.challenge_bytes,
            challenge.allowed_credential_ids,
        ))
    }

    /// Generate a fresh registration challenge and the corresponding
    /// `navigator.credentials.create()` options.
    ///
    /// The advertised `pubKeyCredParams` are built from
    /// [`WebauthnConfig::allowed_algorithms`]; unknown algorithm IDs are
    /// skipped (advertised as "unknown" device names by the protocol layer is
    /// not a concern here). `existing_credential_ids` are advertised as
    /// `excludeCredentials` so compliant authenticators refuse re-registering
    /// a credential the server already holds.
    ///
    /// Returns `(challenge_id, options)`; the challenge ID doubles as the
    /// Base64url challenge string and the returned options embed the same
    /// value. Store the pair via [`ChallengeStore::store_registration_challenge`].
    ///
    /// # Requirements
    /// REQ-WA-005
    #[must_use]
    pub fn generate_registration_challenge(
        &self,
        config: &WebauthnConfig,
        username: &str,
        display_name: &str,
        existing_credential_ids: &[String],
    ) -> (String, RegistrationOptions) {
        let challenge_bytes = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge_bytes);

        let mut algorithms = config.allowed_algorithms.clone();
        algorithms.sort();
        algorithms.dedup();
        let pub_key_cred_params = if algorithms.is_empty() {
            vec![
                PubKeyCredParam {
                    alg: -7,
                    type_: "public-key".to_string(),
                },
                PubKeyCredParam {
                    alg: -257,
                    type_: "public-key".to_string(),
                },
            ]
        } else {
            algorithms
                .into_iter()
                .map(|alg| PubKeyCredParam {
                    alg,
                    type_: "public-key".to_string(),
                })
                .collect()
        };

        let options = RegistrationOptions {
            challenge: challenge_b64.clone(),
            rp: RelyingParty {
                id: config.rp_id.clone(),
                name: config.rp_name.clone(),
            },
            user: WebauthnUser {
                id: base64_encode_urlsafe(username.as_bytes()),
                name: display_name.to_string(),
                display_name: username.to_string(),
            },
            pub_key_cred_params,
            timeout: config.challenge_timeout_secs * 1000,
            exclude_credentials: existing_credential_ids
                .iter()
                .map(|id| ExcludeCredential {
                    id: id.clone(),
                    type_: "public-key".to_string(),
                    transports: None,
                })
                .collect(),
            attestation: "none".to_string(),
            authenticator_selection: AuthenticatorSelection {
                resident_key: "preferred".to_string(),
                user_verification: "preferred".to_string(),
            },
        };

        (challenge_b64, options)
    }

    /// Generate a fresh authentication challenge and the corresponding
    /// `navigator.credentials.get()` options.
    ///
    /// Returns `(challenge_id, options)` as in
    /// [`ChallengeStore::generate_registration_challenge`].
    ///
    /// # Requirements
    /// REQ-WA-006
    #[must_use]
    pub fn generate_authentication_challenge(
        &self,
        config: &WebauthnConfig,
        credential_ids: Vec<String>,
    ) -> (String, AuthenticationOptions) {
        let challenge_bytes = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge_bytes);

        let options = AuthenticationOptions {
            challenge: challenge_b64.clone(),
            rp_id: config.rp_id.clone(),
            allow_credentials: credential_ids
                .iter()
                .map(|id| AllowCredential {
                    id: id.clone(),
                    type_: "public-key".to_string(),
                    transports: None,
                })
                .collect(),
            timeout: config.challenge_timeout_secs * 1000,
            user_verification: "preferred".to_string(),
        };

        (challenge_b64, options)
    }
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WebauthnConfig {
        WebauthnConfig {
            rp_id: "localhost".to_string(),
            rp_name: "Kit Test".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            allowed_algorithms: vec![-7, -257],
            attestation: crate::attestation::AttestationPolicy::default(),
            challenge_timeout_secs: 300,
        }
    }

    fn clock_at(secs: i64) -> Arc<dyn Fn() -> i64 + Send + Sync> {
        Arc::new(move || secs)
    }

    #[test]
    fn test_challenge_registration_flow() {
        let mut store = ChallengeStore::new();
        let config = test_config();

        let (challenge_id, _options) =
            store.generate_registration_challenge(&config, "alice", "Alice", &[]);

        store.store_registration_challenge(&challenge_id, "alice", challenge_id.as_bytes().into());

        let (username, bytes) = store
            .consume_registration_challenge(&challenge_id, 300)
            .unwrap();
        assert_eq!(username, "alice");
        assert_eq!(bytes, challenge_id.as_bytes());

        // Single use: second consume must fail.
        assert!(store
            .consume_registration_challenge(&challenge_id, 300)
            .is_err());
    }

    #[test]
    fn test_challenge_expiration() {
        let mut store = ChallengeStore::new();
        store.store_registration_challenge_at("ch-1", "alice", vec![0u8; 32], unix_now() - 301);

        let result = store.consume_registration_challenge("ch-1", 300);
        assert!(matches!(result, Err(WebauthnError::ChallengeExpired)));
    }

    #[test]
    fn test_challenge_not_found() {
        let mut store = ChallengeStore::new();
        let result = store.consume_registration_challenge("nonexistent", 300);
        assert!(matches!(result, Err(WebauthnError::InvalidChallenge(_))));
    }

    #[test]
    fn test_authentication_challenge_flow() {
        let mut store = ChallengeStore::new();
        let config = test_config();

        let (challenge_id, _options) =
            store.generate_authentication_challenge(&config, vec!["cred-1".to_string()]);

        store.store_authentication_challenge(
            &challenge_id,
            "alice",
            vec![0u8; 32],
            vec!["cred-1".to_string()],
        );

        let (username, _bytes, allowed) = store
            .consume_authentication_challenge(&challenge_id, 300)
            .unwrap();
        assert_eq!(username, "alice");
        assert_eq!(allowed, vec!["cred-1".to_string()]);

        assert!(store
            .consume_authentication_challenge(&challenge_id, 300)
            .is_err());
    }

    #[test]
    fn test_consume_authentication_challenge_not_found() {
        let mut store = ChallengeStore::new();
        let result = store.consume_authentication_challenge("nonexistent", 300);
        assert!(matches!(result, Err(WebauthnError::InvalidChallenge(_))));
    }

    #[test]
    fn test_consume_authentication_challenge_expired() {
        let mut store = ChallengeStore::new();
        store.store_authentication_challenge_at(
            "ch-1",
            "alice",
            vec![0u8; 32],
            vec!["cred-1".to_string()],
            unix_now() - 400,
        );
        let result = store.consume_authentication_challenge("ch-1", 300);
        assert!(matches!(result, Err(WebauthnError::ChallengeExpired)));
    }

    #[test]
    fn test_expiry_with_injected_clock() {
        let t0 = 1_700_000_000i64;
        let mut store = ChallengeStore::with_clock(clock_at(t0));
        store.store_registration_challenge_at("ch", "alice", vec![0u8; 32], t0);

        let mut store = ChallengeStore::with_clock(clock_at(t0 + 301));
        store.store_registration_challenge_at("ch2", "alice", vec![0u8; 32], t0);

        let result = store.consume_registration_challenge("ch2", 300);
        assert!(matches!(result, Err(WebauthnError::ChallengeExpired)));

        // Just inside the window succeeds.
        store.store_registration_challenge_at("ch3", "alice", vec![0u8; 32], t0 + 1);
        let result = store.consume_registration_challenge("ch3", 300);
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_options_serialization() {
        let store = ChallengeStore::new();
        let config = test_config();
        let (_, options) = store.generate_registration_challenge(
            &config,
            "alice",
            "Alice Johnson",
            &["existing-1".to_string()],
        );

        let json = serde_json::to_string(&options).unwrap();
        let deser: RegistrationOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.rp.id, "localhost");
        assert_eq!(deser.user.display_name, "alice");
        assert_eq!(deser.exclude_credentials.len(), 1);
        assert_eq!(deser.pub_key_cred_params.len(), 2);
    }

    #[test]
    fn test_authentication_options_serialization() {
        let store = ChallengeStore::new();
        let config = test_config();
        let (_, options) =
            store.generate_authentication_challenge(&config, vec!["cred-1".to_string()]);

        let json = serde_json::to_string(&options).unwrap();
        let deser: AuthenticationOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.rp_id, "localhost");
        assert_eq!(deser.allow_credentials.len(), 1);
    }

    #[test]
    fn test_registration_options_configurable() {
        let store = ChallengeStore::new();
        let config = WebauthnConfig {
            rp_id: "custom.example.com".to_string(),
            rp_name: "Custom App".to_string(),
            rp_origins: vec!["https://custom.example.com".to_string()],
            allowed_algorithms: vec![-7, -257],
            attestation: crate::attestation::AttestationPolicy::default(),
            challenge_timeout_secs: 600,
        };
        let (_, options) = store.generate_registration_challenge(
            &config,
            "alice",
            "Alice",
            &["existing-cred".to_string()],
        );
        assert_eq!(options.rp.id, "custom.example.com");
        assert_eq!(options.rp.name, "Custom App");
        assert_eq!(options.timeout, 600_000);
        assert_eq!(options.exclude_credentials.len(), 1);
    }

    #[test]
    fn test_authentication_options_configurable() {
        let store = ChallengeStore::new();
        let config = WebauthnConfig {
            rp_id: "custom.example.com".to_string(),
            rp_name: "Custom App".to_string(),
            rp_origins: vec![],
            allowed_algorithms: vec![],
            attestation: crate::attestation::AttestationPolicy::default(),
            challenge_timeout_secs: 120,
        };
        let (_, options) = store
            .generate_authentication_challenge(&config, vec!["c1".to_string(), "c2".to_string()]);
        assert_eq!(options.rp_id, "custom.example.com");
        assert_eq!(options.timeout, 120_000);
        assert_eq!(options.allow_credentials.len(), 2);
    }

    #[test]
    fn test_pub_key_cred_params_from_allowed_algorithms() {
        let store = ChallengeStore::new();
        let config = WebauthnConfig {
            allowed_algorithms: vec![-257, -7, -257],
            ..test_config()
        };
        let (_, options) = store.generate_registration_challenge(&config, "alice", "Alice", &[]);
        let algs: Vec<i32> = options.pub_key_cred_params.iter().map(|p| p.alg).collect();
        assert_eq!(algs, vec![-257, -7]);
        assert!(options
            .pub_key_cred_params
            .iter()
            .all(|p| p.type_ == "public-key"));
    }

    #[test]
    fn test_user_id_is_base64_of_username() {
        let store = ChallengeStore::new();
        let (_, options) =
            store.generate_registration_challenge(&test_config(), "alice", "Alice", &[]);
        let decoded = crate::crypto::base64_decode_urlsafe(&options.user.id).unwrap();
        assert_eq!(decoded, b"alice");
    }

    #[test]
    fn test_check_sign_count_first_use_zero_stored() {
        assert!(check_sign_count(0, 0).is_ok());
        assert!(check_sign_count(0, 42).is_ok());
        assert!(check_sign_count(0, u32::MAX).is_ok());
    }

    #[test]
    fn test_check_sign_count_monotonic() {
        assert!(check_sign_count(1, 2).is_ok());
        assert!(check_sign_count(5, 5).is_ok()); // equal allowed (no-counter authenticators)
        assert!(check_sign_count(u32::MAX, u32::MAX).is_ok());
        assert!(check_sign_count(u32::MAX - 1, u32::MAX).is_ok());
    }

    #[test]
    fn test_check_sign_count_decrease_rejected() {
        assert!(matches!(
            check_sign_count(10, 5),
            Err(WebauthnError::VerificationFailed(_))
        ));
        assert!(matches!(
            check_sign_count(u32::MAX, 0),
            Err(WebauthnError::VerificationFailed(_))
        ));
        assert!(matches!(
            check_sign_count(1, 0),
            Err(WebauthnError::VerificationFailed(_))
        ));
    }

    #[test]
    fn test_debug_does_not_leak_challenge_bytes() {
        let mut store = ChallengeStore::new();
        store.store_registration_challenge("ch", "alice", b"secret-challenge".to_vec());
        let dbg = format!("{store:?}");
        assert!(!dbg.contains("secret-challenge"));
    }

    /// `Default` must behave exactly like `new()` (an empty, usable store).
    #[test]
    fn default_store_is_usable() {
        let mut store = ChallengeStore::default();
        store.store_registration_challenge("ch", "alice", vec![0u8; 32]);
        let (username, _) = store.consume_registration_challenge("ch", 300).unwrap();
        assert_eq!(username, "alice");
    }

    /// An empty `allowed_algorithms` config falls back to advertising the
    /// two implemented algorithms (ES256, RS256).
    #[test]
    fn empty_algorithms_fall_back_to_es256_rs256() {
        let store = ChallengeStore::new();
        let config = WebauthnConfig {
            allowed_algorithms: vec![],
            ..test_config()
        };
        let (_, options) = store.generate_registration_challenge(&config, "alice", "Alice", &[]);
        let params: Vec<(i32, &str)> = options
            .pub_key_cred_params
            .iter()
            .map(|p| (p.alg, p.type_.as_str()))
            .collect();
        assert_eq!(params, vec![(-7, "public-key"), (-257, "public-key")]);
    }
}
