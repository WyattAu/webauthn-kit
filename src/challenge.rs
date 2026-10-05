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
//! - **Cloned authenticators**: [`check_sign_count`] rejects counters that do
//!   not strictly increase, per WebAuthn §7.2.

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
use crate::policy::ResidentKeyPolicy;

/// Current Unix timestamp in seconds; `0` if the clock is before the epoch
/// (which would only make challenges look stale, never fresh — fail-safe).
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What a sign-count comparison says, independent of any policy.
///
/// WebAuthn L3 §7.2 step 18 is explicit that a counter which does not increase
/// is *"a signal, but not proof"*, and it names one benign cause: *"a race
/// condition where the Relying Party is processing assertion responses in an
/// order other than the order they were generated."* So the comparison itself
/// yields a fact; what the relying party does about it is a separate decision,
/// and this enum is the first half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignCountVerdict {
    /// The stored counter was zero, so there is no baseline: first use, or an
    /// authenticator that has never signed.
    NoBaseline,
    /// The reported counter was zero, so the authenticator implements no
    /// counter and the assertion carries no freshness signal either way.
    NoCounter,
    /// The counter strictly increased. Fresh.
    Increased,
    /// The counter is unchanged — which is exactly what a *replayed* assertion
    /// looks like, since it carries the value the authenticator last wrote.
    Equal,
    /// The counter went backwards.
    Decreased,
}

impl SignCountVerdict {
    /// Whether this verdict is a counter regression — L3's "signal".
    pub fn is_regression(self) -> bool {
        matches!(self, Self::Equal | Self::Decreased)
    }

    /// Whether the assertion may proceed under a policy that treats regressions
    /// as signals.
    pub fn is_fresh(self) -> bool {
        !self.is_regression()
    }
}

/// Classify a sign-count comparison. Never fails; see [`SignCountVerdict`].
pub fn classify_sign_count(current: u32, new: u32) -> SignCountVerdict {
    if current == 0 {
        SignCountVerdict::NoBaseline
    } else if new == 0 {
        SignCountVerdict::NoCounter
    } else if new > current {
        SignCountVerdict::Increased
    } else if new == current {
        SignCountVerdict::Equal
    } else {
        SignCountVerdict::Decreased
    }
}

/// What a relying party does when the counter does not increase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnRegression {
    /// Refuse the assertion. Correct for a relying party that processes
    /// assertions one at a time, and the safe default.
    Reject,
    /// Accept the assertion and report the regression, so the caller can score
    /// it. Required for a relying party that verifies assertions
    /// concurrently: L3 §7.2 names out-of-order processing as a benign cause of
    /// an apparently regressed counter, and a party that hard-fails there
    /// locks out legitimate users.
    Signal,
}

/// The relying party's sign-count policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignCountPolicy {
    /// What to do on a counter regression.
    pub on_regression: OnRegression,
}

impl Default for SignCountPolicy {
    /// Fail closed: refuse on regression. A party that has not thought about
    /// out-of-order processing gets the safe behaviour.
    fn default() -> Self {
        Self {
            on_regression: OnRegression::Reject,
        }
    }
}

impl SignCountPolicy {
    /// A policy for a relying party that verifies assertions concurrently and
    /// would otherwise lock out users on an out-of-order race.
    pub fn signal_on_regression() -> Self {
        Self {
            on_regression: OnRegression::Signal,
        }
    }

    /// Apply this policy to a verdict.
    pub fn evaluate(
        &self,
        current: u32,
        new: u32,
    ) -> (SignCountVerdict, Result<(), WebauthnError>) {
        let verdict = classify_sign_count(current, new);
        if verdict.is_regression() && self.on_regression == OnRegression::Reject {
            let relation = if verdict == SignCountVerdict::Equal {
                "unchanged"
            } else {
                "decreased"
            };
            return (
                verdict,
                Err(WebauthnError::VerificationFailed(format!(
                    "Sign count {relation}: {new} <= {current} (possible cloned authenticator)"
                ))),
            );
        }
        (verdict, Ok(()))
    }
}

/// Enforce the sign-count freshness state machine under the default policy.
///
/// Equivalent to [`SignCountPolicy::default`] plus [`SignCountPolicy::evaluate`]:
/// a counter that does not strictly increase is refused. The zero exemptions
/// are load-bearing in both directions — a stored zero means no baseline, a
/// reported zero means no counter.
///
/// # Security note
///
/// L3 §7.2 treats a non-increasing counter as a signal, not proof, and names
/// out-of-order processing as a benign cause. This function is therefore
/// deliberately strict; a relying party that verifies assertions concurrently
/// should call [`classify_sign_count`] (or
/// [`SignCountPolicy::signal_on_regression`]) and score the result rather than
/// lock the user out.
///
/// The caller must persist `new_sign_count` only after this function returns
/// `Ok`, ideally with a compare-and-swap against `current_sign_count` so two
/// concurrent authentications cannot both bump the stored counter. L3 §7.2 goes
/// further: state updates (`signCount`, `backupState`, `uvInitialized`) SHOULD be
/// **deferred until after** any additional security checks the relying party
/// performs have succeeded, which [`DeferredSignCountUpdate`] makes explicit.
///
/// # Requirements
/// REQ-WA-111, REQ-WA-112
pub fn check_sign_count(current_sign_count: u32, new_sign_count: u32) -> Result<(), WebauthnError> {
    SignCountPolicy::default()
        .evaluate(current_sign_count, new_sign_count)
        .1
}

/// A sign-count advance held back until the host's own checks have passed.
///
/// L3 §7.2: *"If the Relying Party performs additional security checks beyond
/// these WebAuthn authentication ceremony steps, the above state updates SHOULD
/// be deferred to after those additional checks are completed successfully."*
/// Applying the counter early means a later check that fails has already
/// advanced the stored value — the credential now looks stale to every
/// subsequent assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredSignCountUpdate {
    /// The counter the credential is believed to hold now.
    pub current: u32,
    /// The counter the assertion reported.
    pub proposed: u32,
}

impl DeferredSignCountUpdate {
    /// Stage an update. Takes no effect until [`Self::commit`].
    pub fn stage(current: u32, new: u32) -> Self {
        Self {
            current,
            proposed: new,
        }
    }

    /// The value to store, if this update should be applied at all.
    ///
    /// A proposed counter of zero is never stored: it means the authenticator
    /// has no counter, and persisting it would erase a real baseline.
    pub fn value(&self) -> Option<u32> {
        if self.proposed == 0 {
            None
        } else {
            Some(self.proposed)
        }
    }

    /// Commit the staged update. Call only after the host's own checks passed.
    ///
    /// Returns the new counter, or the unchanged current one when there was
    /// nothing to store.
    pub fn commit(self) -> u32 {
        self.value().unwrap_or(self.current)
    }
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
    /// The `residentKey` / `userVerification` / `attestation` preferences in
    /// the options reflect the corresponding [`WebauthnConfig`] settings;
    /// when [`ResidentKeyPolicy::Required`] is configured, the L2
    /// `requireResidentKey = true` flag is emitted as well. These are
    /// *preferences*: server-side enforcement lives in
    /// [`crate::policy::CredentialPolicy`].
    ///
    /// Returns `(challenge_id, options)`; the challenge ID doubles as the
    /// Base64url challenge string and the returned options embed the same
    /// value. Store the pair via [`ChallengeStore::store_registration_challenge`].
    ///
    /// # Requirements
    /// REQ-WA-005, REQ-WA-145
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
                    alg: -35,
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

        let resident_key_required = config.resident_key == ResidentKeyPolicy::Required;
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
            attestation: config.attestation_conveyance.as_str().to_string(),
            authenticator_selection: AuthenticatorSelection {
                resident_key: config.resident_key.as_str().to_string(),
                user_verification: config
                    .credential_policy
                    .user_verification
                    .as_str()
                    .to_string(),
                require_resident_key: resident_key_required,
            },
        };

        (challenge_b64, options)
    }

    /// Generate a fresh authentication challenge and the corresponding
    /// `navigator.credentials.get()` options.
    ///
    /// The `userVerification` preference reflects the config's credential
    /// policy; enforcement of that policy happens in
    /// [`crate::verify_authentication`].
    ///
    /// Returns `(challenge_id, options)` as in
    /// [`ChallengeStore::generate_registration_challenge`].
    ///
    /// # Requirements
    /// REQ-WA-006, REQ-WA-145
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
            user_verification: config
                .credential_policy
                .user_verification
                .as_str()
                .to_string(),
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
            credential_policy: crate::policy::CredentialPolicy::default(),
            resident_key: crate::policy::ResidentKeyPolicy::Preferred,
            attestation_conveyance: crate::policy::AttestationConveyance::None,
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
            credential_policy: crate::policy::CredentialPolicy::default(),
            resident_key: crate::policy::ResidentKeyPolicy::Preferred,
            attestation_conveyance: crate::policy::AttestationConveyance::None,
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
            credential_policy: crate::policy::CredentialPolicy::default(),
            resident_key: crate::policy::ResidentKeyPolicy::Preferred,
            attestation_conveyance: crate::policy::AttestationConveyance::None,
            challenge_timeout_secs: 120,
        };
        let (_, options) = store
            .generate_authentication_challenge(&config, vec!["c1".to_string(), "c2".to_string()]);
        assert_eq!(options.rp_id, "custom.example.com");
        assert_eq!(options.timeout, 120_000);
        assert_eq!(options.allow_credentials.len(), 2);
    }

    /// REQ-WA-145: the config's resident-key, user-verification, and
    /// attestation-conveyance preferences are reflected in the emitted
    /// options, including the L2 `requireResidentKey` flag when resident
    /// keys are required.
    #[test]
    fn test_policy_preferences_plumbed_into_options() {
        let store = ChallengeStore::new();
        let config = WebauthnConfig {
            resident_key: crate::policy::ResidentKeyPolicy::Required,
            attestation_conveyance: crate::policy::AttestationConveyance::Direct,
            credential_policy: crate::policy::CredentialPolicy {
                user_verification: crate::policy::UserVerificationPolicy::Required,
                ..crate::policy::CredentialPolicy::default()
            },
            ..test_config()
        };

        let (_, reg) = store.generate_registration_challenge(&config, "alice", "Alice", &[]);
        assert_eq!(reg.attestation, "direct");
        assert_eq!(reg.authenticator_selection.resident_key, "required");
        assert!(reg.authenticator_selection.require_resident_key);
        assert_eq!(reg.authenticator_selection.user_verification, "required");

        let (_, auth) = store.generate_authentication_challenge(&config, vec![]);
        assert_eq!(auth.user_verification, "required");
    }

    /// REQ-WA-145: discouraging resident keys never sets the L2
    /// `requireResidentKey` flag.
    #[test]
    fn test_discouraged_resident_key_leaves_require_flag_false() {
        let store = ChallengeStore::new();
        let config = WebauthnConfig {
            resident_key: crate::policy::ResidentKeyPolicy::Discouraged,
            ..test_config()
        };
        let (_, reg) = store.generate_registration_challenge(&config, "alice", "Alice", &[]);
        assert_eq!(reg.authenticator_selection.resident_key, "discouraged");
        assert!(!reg.authenticator_selection.require_resident_key);
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
    fn test_check_sign_count_increases() {
        assert!(check_sign_count(1, 2).is_ok());
        assert!(check_sign_count(5, 6).is_ok());
        assert!(check_sign_count(u32::MAX - 1, u32::MAX).is_ok());
    }

    /// §7.2: "not greater than" is the clone signal, so an equal counter is
    /// refused. A replayed assertion reports the counter the authenticator last
    /// wrote, which is exactly this case.
    #[test]
    fn test_check_sign_count_equal_is_refused() {
        let err = check_sign_count(5, 5).expect_err("an equal counter is a replay");
        assert!(
            err.to_string().contains("unchanged"),
            "the error names the relation: {err}"
        );
        assert!(check_sign_count(u32::MAX, u32::MAX).is_err());
    }

    /// A stored zero means there is no baseline to compare against — first use
    /// — and a reported zero means the authenticator implements no counter.
    #[test]
    fn test_check_sign_count_zero_exemptions() {
        assert!(check_sign_count(0, 0).is_ok());
        assert!(check_sign_count(0, 42).is_ok());
        assert!(check_sign_count(0, u32::MAX).is_ok());
        assert!(check_sign_count(42, 0).is_ok(), "no counter, no signal");
        assert!(
            check_sign_count(u32::MAX, 0).is_ok(),
            "no counter, no signal"
        );
    }

    /// L3 §7.2 step 18: a counter that does not increase is "a signal, but not
    /// proof", and it names a benign cause — the RP processing assertions out
    /// of order. The classification must therefore be available separately from
    /// the decision, so a concurrent verifier can score rather than lock out.
    #[test]
    fn verdicts_separate_the_fact_from_the_decision() {
        assert_eq!(classify_sign_count(0, 0), SignCountVerdict::NoBaseline);
        assert_eq!(classify_sign_count(0, 7), SignCountVerdict::NoBaseline);
        assert_eq!(classify_sign_count(7, 0), SignCountVerdict::NoCounter);
        assert_eq!(classify_sign_count(7, 8), SignCountVerdict::Increased);
        assert_eq!(classify_sign_count(7, 7), SignCountVerdict::Equal);
        assert_eq!(classify_sign_count(7, 3), SignCountVerdict::Decreased);

        assert!(classify_sign_count(7, 8).is_fresh());
        assert!(!classify_sign_count(7, 8).is_regression());
        // Both regressions are signals...
        assert!(classify_sign_count(7, 7).is_regression());
        assert!(classify_sign_count(7, 3).is_regression());
    }

    /// The scenario the split exists for: two assertions generated in order,
    /// verified out of order. The second one to *arrive* carries the lower
    /// counter, and refusing it would lock out a legitimate user.
    #[test]
    fn out_of_order_assertions_are_signals_under_a_concurrent_policy() {
        let stored = 10;
        // Assertion B (counter 11) is verified first and succeeds.
        assert!(check_sign_count(stored, 11).is_ok());
        let deferred = DeferredSignCountUpdate::stage(stored, 11);
        // ...and only then does assertion A (counter 10) arrive. Against a
        // single-threaded verifier this looks exactly like a replay.
        let (verdict, result) = SignCountPolicy::signal_on_regression().evaluate(stored, 10);
        assert_eq!(
            verdict,
            SignCountVerdict::Equal,
            "the counter appears not to increase"
        );
        assert!(
            result.is_ok(),
            "but a concurrent verifier scores it, not fails it"
        );
        assert_eq!(
            deferred.commit(),
            11,
            "and the stored counter advances exactly once"
        );

        // The default policy is still fail-closed: same input, refused.
        assert!(
            check_sign_count(stored, 10).is_err(),
            "a verifier that has not opted into out-of-order handling must fail closed"
        );
    }

    /// L3 §7.2: state updates SHOULD be deferred until additional security
    /// checks succeed, and a zero must never overwrite a real baseline.
    #[test]
    fn deferred_update_does_not_erase_a_baseline() {
        let update = DeferredSignCountUpdate::stage(41, 0);
        assert_eq!(
            update.value(),
            None,
            "a counter-less authenticator stores nothing"
        );
        assert_eq!(update.commit(), 41, "and the existing baseline survives");

        let real = DeferredSignCountUpdate::stage(41, 42);
        assert_eq!(real.value(), Some(42));
        assert_eq!(real.commit(), 42);

        // A regression must not be committed as if it were progress.
        let regression = DeferredSignCountUpdate::stage(41, 7);
        assert_eq!(
            regression.value(),
            Some(7),
            "the host decides; the helper does not"
        );
    }

    #[test]
    fn test_check_sign_count_decrease_reports_verification_failed() {
        assert!(check_sign_count(10, 3).is_err());
        assert!(check_sign_count(u32::MAX, 0).is_ok());
    }

    #[test]
    fn test_check_sign_count_decrease_refused() {
        assert!(matches!(
            check_sign_count(10, 5),
            Err(WebauthnError::VerificationFailed(_))
        ));
        assert!(matches!(
            check_sign_count(10, 9),
            Err(WebauthnError::VerificationFailed(_))
        ));
        // A *reported* zero used to be treated as a decrease here. It is not:
        // §7.2 skips the check when either side is zero, because a zero is how
        // an authenticator says "I have no counter", which is no freshness
        // signal rather than a backwards one. The zero cases are covered by
        // test_check_sign_count_zero_exemptions.
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
    /// implemented algorithms (ES256, ES384, RS256).
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
        assert_eq!(
            params,
            vec![
                (-7, "public-key"),
                (-35, "public-key"),
                (-257, "public-key")
            ]
        );
    }

    /// The default (real) clock path must record creation times the
    /// expiry math treats as fresh: a challenge consumed immediately with
    /// a generous timeout succeeds. Mutants of `unix_now` (returning 0,
    /// 1, or -1) make every challenge look centuries old and fail here.
    #[test]
    fn default_clock_store_consumes_fresh_challenges() {
        let mut store = ChallengeStore::new();
        let config = test_config();

        store.store_registration_challenge("reg-ch", "alice", vec![1u8; 32]);
        store
            .consume_registration_challenge("reg-ch", 300)
            .expect("fresh registration challenge must consume on the real clock");

        let (auth_id, _options) = store.generate_authentication_challenge(&config, Vec::new());
        store.store_authentication_challenge(&auth_id, "alice", vec![0u8; 32], vec![]);
        store
            .consume_authentication_challenge(&auth_id, 300)
            .expect("fresh authentication challenge must consume on the real clock");
    }

    /// The default clock must be the real system clock: recorded creation
    /// times land in a ±5 s window around wall-clock now. (Store and
    /// consume read the same injected closure, so expiry math alone cannot
    /// distinguish a constant-time mutant — the recorded value can.)
    #[test]
    fn default_clock_records_current_unix_time() {
        let mut store = ChallengeStore::new();
        store.store_registration_challenge("c", "alice", vec![0u8; 32]);
        let created = store.registration_challenges["c"].created_at;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        assert!(
            (now - 5..=now + 5).contains(&created),
            "created_at {created} must be wall-clock now (~{now})"
        );
    }

    /// Expiry is *strictly* greater: a challenge consumed at exactly
    /// `timeout_secs` seconds of age is still valid; one second later it
    /// is expired.
    #[test]
    fn expiry_boundary_is_strictly_greater_than_timeout() {
        let config = test_config();

        let mut store = ChallengeStore::with_clock(clock_at(1_000));
        store.store_registration_challenge("reg-ch", "alice", vec![1u8; 32]);
        // Rebind the clock to exactly timeout age: elapsed == timeout.
        store.now = Arc::new(|| 1_300);
        store
            .consume_registration_challenge("reg-ch", 300)
            .expect("challenge aged exactly timeout_secs must still consume");

        let mut store = ChallengeStore::with_clock(clock_at(1_000));
        let (auth_id, _options) = store.generate_authentication_challenge(&config, Vec::new());
        store.store_authentication_challenge(&auth_id, "alice", vec![0u8; 32], vec![]);
        // Exactly timeout age: still valid (strict >).
        store.now = Arc::new(|| 1_300);
        store
            .consume_authentication_challenge(&auth_id, 300)
            .expect("authentication challenge aged exactly timeout_secs must still consume");

        // One second past: expired.
        let mut store = ChallengeStore::with_clock(clock_at(1_000));
        let (auth_id, _options) = store.generate_authentication_challenge(&config, Vec::new());
        store.store_authentication_challenge(&auth_id, "alice", vec![0u8; 32], vec![]);
        store.now = Arc::new(|| 1_301);
        assert!(
            matches!(
                store.consume_authentication_challenge(&auth_id, 300),
                Err(WebauthnError::ChallengeExpired)
            ),
            "challenge aged timeout_secs + 1 must be expired"
        );
    }

    /// The Debug impl deliberately omits challenge contents (secrets in
    /// transit): rendered output shows only counters, never the pending
    /// challenge ids or bytes.
    #[test]
    fn debug_rendering_omits_challenge_secrets() {
        let mut store = ChallengeStore::with_clock(clock_at(1_000));
        let config = test_config();
        let (reg_id, reg_options) =
            store.generate_registration_challenge(&config, "alice", "Alice", &[]);
        let reg_bytes = crate::crypto::base64_decode_urlsafe(&reg_options.challenge)
            .expect("options challenge must be base64url");
        store.store_registration_challenge(&reg_id, "alice", reg_bytes);
        let (auth_id, auth_options) = store.generate_authentication_challenge(&config, Vec::new());
        store.store_authentication_challenge(&auth_id, "alice", vec![0xAB; 32], vec![]);

        let rendered = format!("{store:?}");
        assert!(rendered.contains("ChallengeStore"), "{rendered}");
        assert!(
            !rendered.contains(&reg_id) && !rendered.contains(&auth_id),
            "challenge ids must not appear in Debug: {rendered}"
        );
        assert!(
            !rendered.contains(&reg_options.challenge)
                && !rendered.contains(&auth_options.challenge),
            "challenge values must not appear in Debug: {rendered}"
        );
    }
}
