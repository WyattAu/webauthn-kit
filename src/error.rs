//! Error type for all `webauthn-kit` operations.

/// Error type for `WebAuthn` operations.
///
/// The type is `#[non_exhaustive]`: matching on it requires a wildcard arm.
///
/// # Security note
///
/// Error strings may echo attacker-controlled fragments of the request being
/// verified (e.g. a base64 payload or an origin string). They are intended for
/// server-side logs and debugging. Do **not** forward raw error messages to
/// untrusted clients; surface only a generic verification-failed response.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    /// A caller-supplied configuration value is invalid or inconsistent.
    #[error("Configuration error: {0}")]
    Config(String),
    /// The presented challenge is unknown, malformed, or was already consumed
    /// (single-use replay protection triggered).
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
    /// The referenced credential does not exist for the given user/scope.
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    /// Generic verification failure (challenge mismatch, bad origin, wrong
    /// `type` field, truncated authenticator data, RP ID hash mismatch, ...).
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    /// The registration presented a credential ID that is already registered.
    #[error("Duplicate credential: {0}")]
    DuplicateCredential(String),
    /// The referenced user does not exist.
    #[error("User not found: {0}")]
    UserNotFound(String),
    /// The challenge was consumed after its freshness window elapsed.
    #[error("Challenge expired")]
    ChallengeExpired,
    /// The COSE algorithm is not one of the supported/allowed algorithms.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(i32),
    /// `ring` rejected the cryptographic signature.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    /// The attestation object or statement could not be parsed, or
    /// attestation verification failed for a non-signature reason
    /// (unsupported/unknown format, untrusted chain, expired certificate,
    /// AAGUID extension mismatch, ...).
    ///
    /// Signature failures surface as [`WebauthnError::SignatureVerificationFailed`].
    #[error("Attestation error: {0}")]
    AttestationError(String),
    /// A ceremony required user verification
    /// ([`crate::policy::UserVerificationPolicy::Required`]) but the
    /// authenticator's UV flag was clear.
    #[error("User verification required but not performed")]
    UserVerificationRequired,
    /// The presented credential violates the caller's
    /// [`crate::policy::CredentialPolicy`] (backup-eligibility policy, ...).
    #[error("Credential policy violation: {0}")]
    PolicyViolation(String),
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

    #[test]
    fn test_error_display_variants() {
        let errors = vec![
            WebauthnError::Config("test".to_string()),
            WebauthnError::InvalidChallenge("test".to_string()),
            WebauthnError::CredentialNotFound("test".to_string()),
            WebauthnError::VerificationFailed("test".to_string()),
            WebauthnError::DuplicateCredential("test".to_string()),
            WebauthnError::UserNotFound("test".to_string()),
            WebauthnError::ChallengeExpired,
            WebauthnError::UnsupportedAlgorithm(-7),
            WebauthnError::SignatureVerificationFailed,
            WebauthnError::AttestationError("test".to_string()),
            WebauthnError::UserVerificationRequired,
            WebauthnError::PolicyViolation("test".to_string()),
        ];
        for err in errors {
            assert!(!format!("{err}").is_empty());
            assert!(!format!("{err:?}").is_empty());
        }
    }
}
