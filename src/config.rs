//! Relying-party configuration.

use crate::attestation::AttestationPolicy;
use crate::policy::{AttestationConveyance, CredentialPolicy, ResidentKeyPolicy};

/// `WebAuthn` relying party configuration.
///
/// This is the kit-local replacement for any application-specific auth config
/// struct: it carries everything the protocol layer needs and nothing else.
/// Application concerns (feature flags, storage, session handling) are
/// deliberately excluded.
///
/// # Security notes
///
/// - `rp_id` must be the registrable domain suffix shared by all origins that
///   may perform `WebAuthn` ceremonies. It is hashed (SHA-256) and compared
///   against the `rpIdHash` embedded in authenticator data; a wrong value
///   fails every verification.
/// - Every entry in `rp_origins` is an exact-match allow-list entry. Origins
///   are compared byte-for-byte against `clientDataJSON.origin`; scheme,
///   host, and port must all match. List only origins you fully trust.
/// - `allowed_algorithms` controls which COSE algorithms are *advertised* to
///   authenticators in registration options. Runtime verification implements
///   ES256 (-7), ES384 (-35), EdDSA (-8), and RS256 (-257); anything else is
///   rejected with [`crate::WebauthnError::UnsupportedAlgorithm`] regardless
///   of this setting. For server-side *enforcement* of the advertised set
///   (rejecting credentials with other algorithms), set
///   `credential_policy.allowed_algorithms` — advertising alone is not
///   enforcement.
/// - `attestation` governs attestation statement verification during
///   registration; see [`AttestationPolicy`] for the trust implications of
///   empty `trust_anchors` and `allow_unknown_formats`.
/// - `credential_policy` is enforced server-side by
///   [`crate::verify_registration`] / [`crate::verify_authentication`]; the
///   `resident_key` / `attestation_conveyance` / advertised-algorithm
///   settings are *preferences conveyed to the client* and cannot be relied
///   on for enforcement.
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    /// Relying party ID (effective domain, e.g. `"example.com"`).
    ///
    /// Must NOT include scheme or port. See struct-level security notes.
    pub rp_id: String,
    /// Human-readable relying party name (advertised in registration options).
    pub rp_name: String,
    /// Allowed origins for `WebAuthn` ceremonies (exact match, e.g.
    /// `"https://example.com"`).
    pub rp_origins: Vec<String>,
    /// COSE algorithm identifiers advertised for registration.
    ///
    /// Defaults to `[-7 (ES256), -35 (ES384), -257 (RS256)]`.
    pub allowed_algorithms: Vec<i32>,
    /// Challenge freshness window in seconds (default 300 = 5 minutes).
    ///
    /// Challenges older than this are rejected on consumption.
    pub challenge_timeout_secs: u64,
    /// Attestation verification policy applied by
    /// [`crate::verify_registration`] (default: strict — unknown formats
    /// rejected, no trust anchors configured).
    pub attestation: AttestationPolicy,
    /// Server-side credential policy enforced during both ceremonies
    /// (default: permissive — UV reported, syncable credentials allowed, no
    /// algorithm allowlist). See [`CredentialPolicy`].
    pub credential_policy: CredentialPolicy,
    /// Discoverable-credential preference conveyed in registration options
    /// (default: [`ResidentKeyPolicy::Preferred`]).
    pub resident_key: ResidentKeyPolicy,
    /// Attestation conveyance preference conveyed in registration options
    /// (default: [`AttestationConveyance::None`]).
    pub attestation_conveyance: AttestationConveyance,
}

impl Default for WebauthnConfig {
    /// Sensible development defaults (`localhost` RP).
    ///
    /// Do not use `Default::default()` in production; set `rp_id` and
    /// `rp_origins` to your real domain and HTTPS origin.
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "webauthn-kit".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            allowed_algorithms: vec![-7, -35, -257],
            challenge_timeout_secs: 300,
            attestation: AttestationPolicy::default(),
            credential_policy: CredentialPolicy::default(),
            resident_key: ResidentKeyPolicy::default(),
            attestation_conveyance: AttestationConveyance::default(),
        }
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
    use crate::policy::UserVerificationPolicy;

    #[test]
    fn test_config_default() {
        let config = WebauthnConfig::default();
        assert_eq!(config.rp_id, "localhost");
        assert_eq!(config.rp_name, "webauthn-kit");
        assert_eq!(config.rp_origins, vec!["http://localhost:8080"]);
        assert_eq!(config.allowed_algorithms, vec![-7, -35, -257]);
        assert_eq!(config.challenge_timeout_secs, 300);
        assert_eq!(config.credential_policy, CredentialPolicy::default());
        assert_eq!(
            config.credential_policy.user_verification,
            UserVerificationPolicy::Preferred
        );
        assert_eq!(config.resident_key, ResidentKeyPolicy::Preferred);
        assert_eq!(config.attestation_conveyance, AttestationConveyance::None);
    }

    #[test]
    fn test_config_custom_algorithms() {
        let config = WebauthnConfig {
            allowed_algorithms: vec![-7],
            ..WebauthnConfig::default()
        };
        assert_eq!(config.allowed_algorithms.len(), 1);
        assert_eq!(config.allowed_algorithms[0], -7);
    }
}
