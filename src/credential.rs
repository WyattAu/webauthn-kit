//! `WebAuthn` credential descriptor and protocol DTOs (options, responses,
//! results).
//!
//! This module is **storage-free**. It defines the [`WebauthnCredential`]
//! record (including the sign-count state that callers must persist) and the
//! JSON wire structures exchanged with the browser. Persisting, looking up,
//! and updating credentials is the integrator's job; see the crate-level
//! documentation for the recommended storage contract.

/// A registered `WebAuthn` credential.
///
/// The integrator persists one record per credential. [`WebauthnCredential::sign_count`]
/// is security-relevant state: after every successful
/// [`crate::verify_authentication`], the caller must atomically persist
/// [`AuthenticationResult::new_sign_count`] (monotonic counter used for
/// authenticator-clone detection).
///
/// # Security note
///
/// `public_key_cose` is parsed and signature-checked on every authentication,
/// but the bytes stored at registration time should be treated as trusted
/// only because they were validated by [`crate::verify_registration`] before
/// persisting. Never accept a credential record whose provenance you cannot
/// establish.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WebauthnCredential {
    /// Base64url-encoded credential ID.
    pub credential_id: String,
    /// COSE public key bytes (CBOR-encoded).
    pub public_key_cose: Vec<u8>,
    /// Counter to prevent replay/clone attacks. Persist the updated value
    /// returned by [`crate::verify_authentication`] after each login.
    pub sign_count: u32,
    /// Human-readable device name (e.g. "`YubiKey` 5 NFC").
    pub device_name: String,
    /// Registration timestamp (Unix seconds).
    pub registered_at: i64,
    /// Last authentication timestamp (Unix seconds).
    pub last_used_at: i64,
    /// Attestation format (e.g. "none", "packed", "fido-u2f", "android-key").
    ///
    /// Informational only: this kit does not verify attestation statements.
    pub attestation_format: String,
    /// Whether user verification (biometrics/PIN) was performed at registration.
    pub user_verified: bool,
}

/// Options sent to the client for credential registration
/// (`navigator.credentials.create()`).
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RegistrationOptions {
    /// Server-generated challenge (Base64url-encoded).
    pub challenge: String,
    /// Relying party information.
    pub rp: RelyingParty,
    /// User information for the new credential.
    pub user: WebauthnUser,
    /// Required public key parameters.
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// Timeout hint in milliseconds.
    pub timeout: u64,
    /// Exclude already-registered credentials.
    pub exclude_credentials: Vec<ExcludeCredential>,
    /// Attestation conveyance preference.
    pub attestation: String,
    /// Authenticator selection criteria.
    pub authenticator_selection: AuthenticatorSelection,
}

/// Relying party descriptor.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RelyingParty {
    /// Relying party ID (effective domain).
    pub id: String,
    /// Human-readable relying party name.
    pub name: String,
}

/// User descriptor for registration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WebauthnUser {
    /// Unique user ID (Base64url-encoded).
    pub id: String,
    /// Display name (e.g. "Alice Johnson").
    pub name: String,
    /// Username (e.g. "alice").
    pub display_name: String,
}

/// Public key credential parameter (algorithm + type).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PubKeyCredParam {
    /// Algorithm identifier (COSE algorithm).
    pub alg: i32,
    /// Credential type (always "public-key").
    pub type_: String,
}

/// Credential to exclude from registration (prevent re-registration).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExcludeCredential {
    /// Base64url-encoded credential ID.
    pub id: String,
    /// Credential type.
    pub type_: String,
    /// Optional transports hint.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticatorSelection {
    /// Require resident key (discoverable credential).
    pub resident_key: String,
    /// User verification requirement.
    pub user_verification: String,
}

/// Response from the client during registration
/// (`navigator.credentials.create()` response).
///
/// The integrator deserializes this from the browser payload and passes the
/// fields to [`crate::verify_registration`].
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct RegistrationResponse {
    /// Client data JSON (Base64url-encoded).
    pub client_data_json: String,
    /// Attestation object (Base64url-encoded).
    pub attestation_object: String,
    /// Transports used (e.g. "usb", "nfc", "internal").
    #[cfg_attr(feature = "serde", serde(default))]
    pub transports: Vec<String>,
}

/// Options sent to the client for authentication
/// (`navigator.credentials.get()`).
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticationOptions {
    /// Server-generated challenge (Base64url-encoded).
    pub challenge: String,
    /// Relying party ID.
    pub rp_id: String,
    /// Allowed credential IDs for this authentication.
    pub allow_credentials: Vec<AllowCredential>,
    /// Timeout hint in milliseconds.
    pub timeout: u64,
    /// User verification requirement.
    pub user_verification: String,
}

/// Credential allowed for authentication.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AllowCredential {
    /// Base64url-encoded credential ID.
    pub id: String,
    /// Credential type.
    pub type_: String,
    /// Optional transports hint.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub transports: Option<Vec<String>>,
}

/// Response from the client during authentication
/// (`navigator.credentials.get()` response).
///
/// The integrator deserializes this from the browser payload and passes the
/// fields to [`crate::verify_authentication`].
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct AuthenticationResponse {
    /// Base64url-encoded credential ID.
    pub id: String,
    /// Client data JSON (Base64url-encoded).
    pub client_data_json: String,
    /// Authenticator data (Base64url-encoded).
    pub authenticator_data: String,
    /// Signature (Base64url-encoded).
    pub signature: String,
    /// User handle (Base64url-encoded, for resident keys).
    pub user_handle: Option<String>,
}

/// Result of a successful registration.
///
/// The caller is responsible for persisting a [`WebauthnCredential`] built
/// from the verified credential ID and COSE public key extracted from the
/// authenticator data.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RegistrationResult {
    /// The credential ID that was registered (Base64url-encoded).
    pub credential_id: String,
    /// Device name (from client or auto-generated).
    pub device_name: String,
    /// Attestation format used (informational; not verified).
    pub attestation_format: String,
    /// Whether user verification was performed.
    pub user_verified: bool,
}

/// Result of a successful authentication.
///
/// # Security note
///
/// [`AuthenticationResult::new_sign_count`] MUST be persisted by the caller
/// (compare-and-swap against the stored value) — see [`WebauthnCredential::sign_count`].
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AuthenticationResult {
    /// The credential ID that authenticated.
    pub credential_id: String,
    /// Updated sign count; persist this after verification succeeds.
    pub new_sign_count: u32,
    /// Whether user verification was performed.
    pub user_verified: bool,
}
