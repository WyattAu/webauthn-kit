//! Caller-enforceable credential policies for the registration and
//! authentication ceremonies.
//!
//! A [`CredentialPolicy`] bundles the per-ceremony decisions that turn
//! reported authenticator state into *enforced* requirements:
//!
//! - **User verification** ([`UserVerificationPolicy`]): whether the UV flag
//!   is required, preferred, or discouraged. `Required` makes the kit reject
//!   assertions/registrations whose UV flag is clear — before, the flag was
//!   only *reported* and every caller had to hand-roll this check.
//! - **Backup policy** ([`BackupPolicy`]): the WebAuthn L3 multi-device
//!   (syncable passkey) story. BE (backup eligibility) is set at creation and
//!   immutable; BS (backup state) reflects whether the credential is
//!   currently backed up. A [`BackupPolicy::RequireDeviceBound`] policy
//!   rejects BE=1 credentials, i.e. credentials that may exist in a cloud
//!   account rather than only inside one hardware authenticator.
//! - **Algorithm allowlist** ([`CredentialPolicy::allowed_algorithms`]):
//!   registration-time server-side enforcement — a credential whose COSE
//!   algorithm is not on the list is rejected even if the kit can verify it.
//!
//! # Security notes
//!
//! - Defaults are deliberately permissive (`Preferred` / `Allow` / empty
//!   allowlist) so 0.2.x behavior is preserved; permissive UV never accepts
//!   *less* than before, it only declines to reject.
//! - Enforcement is server-side and unconditional: a hostile authenticator
//!   cannot satisfy `UserVerificationPolicy::Required` without the UV flag
//!   being genuinely set in the signed authenticator data.
//! - BE/BS come from the signed authenticator data flags, so policy decisions
//!   on them are authenticated (they cannot be flipped without breaking the
//!   assertion signature).
//!
//! # Requirements
//! REQ-WA-142, REQ-WA-143, REQ-WA-144, REQ-WA-145

/// User-verification requirement for a ceremony (WebAuthn L2/L3
/// `userVerification`).
///
/// `Required` is *enforced*: the ceremony fails with
/// [`crate::WebauthnError::UserVerificationRequired`] when the authenticator
/// flags lack the UV bit. `Preferred`/`Discouraged` never reject; the flag is
/// reported via the result's `user_verified` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserVerificationPolicy {
    /// Reject the ceremony unless the UV flag is set.
    Required,
    /// Ask the authenticator for UV but accept either outcome (default).
    #[default]
    Preferred,
    /// Do not ask for UV; accept either outcome.
    Discouraged,
}

impl UserVerificationPolicy {
    /// The `userVerification` wire string for ceremony options.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            UserVerificationPolicy::Required => "required",
            UserVerificationPolicy::Preferred => "preferred",
            UserVerificationPolicy::Discouraged => "discouraged",
        }
    }
}

/// Resident-key (discoverable credential) preference for registration
/// (WebAuthn L2/L3 `residentKey`).
///
/// This is a *preference conveyed to the authenticator* via ceremony options;
/// the server cannot cryptographically verify discoverability from the
/// response alone (see THREAT-MODEL.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResidentKeyPolicy {
    /// The authenticator must create a discoverable credential.
    Required,
    /// Ask for a discoverable credential, fall back to server-side ones
    /// (default).
    #[default]
    Preferred,
    /// Prefer server-side credentials.
    Discouraged,
}

impl ResidentKeyPolicy {
    /// The `residentKey` wire string for registration options.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResidentKeyPolicy::Required => "required",
            ResidentKeyPolicy::Preferred => "preferred",
            ResidentKeyPolicy::Discouraged => "discouraged",
        }
    }
}

/// Attestation conveyance preference for registration (WebAuthn L2/L3
/// `attestation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttestationConveyance {
    /// Do not request attestation (default; privacy-preserving).
    #[default]
    None,
    /// Ask the client to indicate to attestation CA keys may be shared.
    Indirect,
    /// Obtain attestation statements directly from the authenticator.
    Direct,
    /// Convey platform-enterprise attestation (may identify the device).
    Enterprise,
}

impl AttestationConveyance {
    /// The `attestation` wire string for registration options.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttestationConveyance::None => "none",
            AttestationConveyance::Indirect => "indirect",
            AttestationConveyance::Direct => "direct",
            AttestationConveyance::Enterprise => "enterprise",
        }
    }
}

/// Policy for multi-device (syncable) credentials — the WebAuthn L3 BE/BS
/// story.
///
/// BE (backup eligibility) is an immutable creation-time property: "this
/// credential *may* be backed up / synced". BS (backup state) says whether it
/// *currently is*. Both arrive in the signed authenticator data flags and are
/// reported on both ceremony results.
///
/// # Account-recovery implications
///
/// - A **synced** (BE=1) credential lives in a cloud account (iCloud
///   Keychain, Google Password Manager, ...). Account recovery therefore
///   follows the *platform's* rules — a phone number or recovery email can
///   resurrect the credential. Treat these like a possession factor that
///   inherits the recovery strength of the user's cloud account.
/// - A **device-bound** (BE=0) credential is confined to one hardware
///   authenticator; losing the device means losing the credential (stronger
///   possession semantics, worse recovery story).
/// - RPs that want to exclude synced credentials from sensitive flows use
///   [`BackupPolicy::RequireDeviceBound`], which rejects BE=1 credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupPolicy {
    /// Accept device-bound and synced credentials; report the flags
    /// (default).
    #[default]
    Allow,
    /// Reject BE=1 (syncable) credentials at both ceremonies.
    RequireDeviceBound,
}

/// Per-ceremony credential policy: user verification, multi-device (backup)
/// handling, and the registration algorithm allowlist.
///
/// Attach to [`crate::WebauthnConfig`] (`credential_policy`) and/or pass
/// directly to [`crate::verify_registration`] /
/// [`crate::protocol::AuthenticationParams::policy`].
///
/// # Requirements
/// REQ-WA-142, REQ-WA-143, REQ-WA-144
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPolicy {
    /// User-verification requirement, enforced server-side
    /// (default: [`UserVerificationPolicy::Preferred`] — report only).
    pub user_verification: UserVerificationPolicy,
    /// Multi-device credential policy (default: [`BackupPolicy::Allow`]).
    pub backup: BackupPolicy,
    /// Registration-time COSE algorithm allowlist. An empty list accepts
    /// every algorithm the kit can verify (default). A non-empty list
    /// rejects registration of any credential whose algorithm is absent
    /// with [`crate::WebauthnError::UnsupportedAlgorithm`].
    pub allowed_algorithms: Vec<i32>,
}

impl Default for CredentialPolicy {
    /// Permissive-by-default policy preserving 0.2.x behavior: UV reported
    /// but never required, any backup eligibility accepted, no algorithm
    /// restriction beyond what the crypto layer supports.
    fn default() -> Self {
        Self {
            user_verification: UserVerificationPolicy::Preferred,
            backup: BackupPolicy::Allow,
            allowed_algorithms: Vec::new(),
        }
    }
}

impl CredentialPolicy {
    /// Strict policy: UV required, device-bound credentials only, ES256
    /// only.
    ///
    /// Suitable for high-assurance flows (step-up, admin actions). Note that
    /// `RequireDeviceBound` rejects synced passkeys outright — combined with
    /// per-user registration, this limits credentials to hardware keys.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            user_verification: UserVerificationPolicy::Required,
            backup: BackupPolicy::RequireDeviceBound,
            allowed_algorithms: vec![crate::crypto::COSE_ALG_ES256],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_roundtrip() {
        assert_eq!(UserVerificationPolicy::Required.as_str(), "required");
        assert_eq!(UserVerificationPolicy::Preferred.as_str(), "preferred");
        assert_eq!(UserVerificationPolicy::Discouraged.as_str(), "discouraged");
        assert_eq!(ResidentKeyPolicy::Required.as_str(), "required");
        assert_eq!(ResidentKeyPolicy::Preferred.as_str(), "preferred");
        assert_eq!(ResidentKeyPolicy::Discouraged.as_str(), "discouraged");
        assert_eq!(AttestationConveyance::None.as_str(), "none");
        assert_eq!(AttestationConveyance::Indirect.as_str(), "indirect");
        assert_eq!(AttestationConveyance::Direct.as_str(), "direct");
        assert_eq!(AttestationConveyance::Enterprise.as_str(), "enterprise");
    }

    /// Defaults must preserve 0.2.x ceremony behavior (permissive).
    #[test]
    fn default_policy_is_permissive() {
        let policy = CredentialPolicy::default();
        assert_eq!(policy.user_verification, UserVerificationPolicy::Preferred);
        assert_eq!(policy.backup, BackupPolicy::Allow);
        assert!(policy.allowed_algorithms.is_empty());
    }

    #[test]
    fn strict_policy_tightens_everything() {
        let policy = CredentialPolicy::strict();
        assert_eq!(policy.user_verification, UserVerificationPolicy::Required);
        assert_eq!(policy.backup, BackupPolicy::RequireDeviceBound);
        assert_eq!(
            policy.allowed_algorithms,
            vec![crate::crypto::COSE_ALG_ES256]
        );
    }
}
