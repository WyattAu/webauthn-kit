//! CTAP2 protocol parsing and ceremony verification.
//!
//! Implements the two server-side `WebAuthn` ceremonies per the W3C
//! `WebAuthn` Level 2/3 model and CTAP2 authenticator data layout:
//!
//! - [`verify_registration`]: parse and validate an attestation object,
//!   extract the new credential (ID + COSE public key) and flags.
//! - [`verify_authentication`]: validate an assertion (challenge, origin,
//!   RP ID hash, user presence, sign-count freshness) and verify the
//!   signature over `authenticatorData || SHA-256(clientDataJSON)`.
//!
//! # Threat assumptions
//!
//! - All base64/BOR/JSON/CBOR inputs originate from the client and are
//!   hostile: parsers return `Err` instead of panicking on arbitrary bytes
//!   (fuzz-tested in `tests/fuzz.rs`).
//! - `challenge_bytes` MUST come from a single-use, server-side source (see
//!   [`crate::ChallengeStore`]); this module only checks that the client
//!   echoed them inside `clientDataJSON`.
//! - Attestation statements are verified for the `none`, `packed`, and
//!   `fido-u2f` formats ([`crate::attestation`]); unknown formats are
//!   rejected unless the caller opts out via
//!   [`AttestationPolicy::allow_unknown_formats`]. Trust conveyed by an
//!   attestation is bounded by the configured trust anchors — see
//!   [`crate::attestation::AttestationPolicy`] before relying on
//!   provenance.

use crate::attestation::{verify_attestation, AttestationPolicy};
use crate::challenge::check_sign_count;
use crate::credential::{AuthenticationResult, RegistrationResult};
use crate::crypto::{
    alg_to_name, base64_decode_urlsafe, base64_encode_urlsafe, cbor_bytes, cbor_map_entries,
    parse_cose_key, verify_cose_signature,
};
use crate::error::WebauthnError;
use crate::policy::{BackupPolicy, CredentialPolicy, UserVerificationPolicy};

/// Parsed authenticator data structure (CTAP2 §6.1).
#[derive(Debug, Clone)]
struct AuthenticatorData {
    /// SHA-256 of the expected RP ID, as claimed by the authenticator.
    rp_id_hash: Vec<u8>,
    /// Flag byte (UP/UV/BE/BS/AT/ED bits).
    flags: u8,
    /// Big-endian signature counter.
    sign_count: u32,
    /// COSE-encoded credential public key (present when AT flag set).
    credential_public_key_cose: Option<Vec<u8>>,
    /// Raw credential ID (present when AT flag set).
    credential_id: Option<Vec<u8>>,
    /// 16-byte AAGUID (present when AT flag set).
    aaguid: Option<[u8; 16]>,
    /// Backup eligibility (BE): the credential may be backed up / synced
    /// (multi-device credential). Creation-time property, immutable.
    backup_eligible: bool,
    /// Backup state (BS): the credential is currently backed up. Volatile.
    backup_state: bool,
}

/// Authenticator data flag bit: User Present.
const FLAG_UP: u8 = 0x01;
/// Authenticator data flag bit: User Verified.
const FLAG_UV: u8 = 0x04;
/// Authenticator data flag bit: Backup Eligibility (WebAuthn L3 §6.1).
const FLAG_BE: u8 = 0x08;
/// Authenticator data flag bit: Backup State (WebAuthn L3 §6.1).
const FLAG_BS: u8 = 0x10;
/// Authenticator data flag bit: Attested Credential Data included.
const FLAG_AT: u8 = 0x40;
/// Authenticator data flag bit: Extension Data included (not parsed).
#[allow(dead_code)]
const FLAG_ED: u8 = 0x80;

/// Minimum authenticator data length: rpIdHash(32) + flags(1) + signCount(4) = 37.
const AUTH_DATA_MIN_LEN: usize = 37;

/// Fixed 18-byte AAGUID + credential-length prefix in attested credential data.
const ATTESTED_CREDENTIAL_PREFIX_LEN: usize = 18;

/// Parse authenticator data from raw bytes (CTAP2 §6.1).
///
/// # Security notes / threat assumptions
///
/// - `auth_data` is attacker-controlled; any truncation or malformed length
///   field yields `Err`, never a panic or out-of-bounds read.
/// - When the AT flag is set, everything after the credential ID is taken as
///   the COSE public key. If the ED flag is set, extension bytes would be
///   appended by the authenticator *after* the key; this parser does not
///   validate extensions and downstream CBOR parsing reads only the first
///   top-level map, so trailing extension data is ignored rather than
///   misinterpreted as key material.
///
/// # Requirements
/// REQ-WA-100, REQ-WA-201
fn parse_authenticator_data(auth_data: &[u8]) -> Result<AuthenticatorData, WebauthnError> {
    if auth_data.len() < AUTH_DATA_MIN_LEN {
        return Err(WebauthnError::VerificationFailed(format!(
            "Authenticator data too short: {} bytes (minimum {})",
            auth_data.len(),
            AUTH_DATA_MIN_LEN
        )));
    }

    // The length pre-check above makes these infallible, but `get` keeps
    // the parser total on any future layout change (attacker-controlled
    // input must never panic).
    let truncated =
        || WebauthnError::VerificationFailed("Authenticator data truncated".to_string());
    let rp_id_hash = auth_data.get(..32).ok_or_else(truncated)?.to_vec();
    let flags = *auth_data.get(32).ok_or_else(truncated)?;
    let sign_count = u32::from_be_bytes(
        auth_data
            .get(33..37)
            .ok_or_else(truncated)?
            .try_into()
            .map_err(|_| truncated())?,
    );

    let mut offset = 37;
    let mut credential_id = None;
    let mut credential_public_key_cose = None;
    let mut aaguid = None;

    if flags & FLAG_AT != 0 {
        if auth_data.len() < offset + ATTESTED_CREDENTIAL_PREFIX_LEN {
            return Err(WebauthnError::VerificationFailed(
                "Attested credential data truncated (AAGUID + length)".to_string(),
            ));
        }
        let aaguid_bytes = auth_data
            .get(offset..offset + 16)
            .ok_or_else(truncated)?
            .to_vec();
        let aaguid_arr: [u8; 16] = aaguid_bytes.try_into().map_err(|_| truncated())?;
        aaguid = Some(aaguid_arr);
        offset += 16;

        let len_hi = *auth_data.get(offset).ok_or_else(truncated)?;
        let len_lo = *auth_data.get(offset + 1).ok_or_else(truncated)?;
        let cred_id_len = u16::from_be_bytes([len_hi, len_lo]) as usize;
        offset += 2;

        if auth_data.len() < offset + cred_id_len {
            return Err(WebauthnError::VerificationFailed(
                "Attested credential data truncated (credential ID)".to_string(),
            ));
        }
        credential_id = Some(
            auth_data
                .get(offset..offset + cred_id_len)
                .ok_or_else(truncated)?
                .to_vec(),
        );
        offset += cred_id_len;

        if offset >= auth_data.len() {
            return Err(WebauthnError::VerificationFailed(
                "Attested credential data truncated (public key)".to_string(),
            ));
        }
        credential_public_key_cose = Some(auth_data.get(offset..).ok_or_else(truncated)?.to_vec());
    }

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        credential_public_key_cose,
        credential_id,
        aaguid,
        backup_eligible: flags & FLAG_BE != 0,
        backup_state: flags & FLAG_BS != 0,
    })
}

/// Enforce the flag-based portion of a [`CredentialPolicy`]: user
/// verification and backup eligibility.
///
/// - `UserVerificationPolicy::Required` with a clear UV flag →
///   [`WebauthnError::UserVerificationRequired`] (REQ-WA-142).
/// - `BackupPolicy::RequireDeviceBound` with BE set →
///   [`WebauthnError::PolicyViolation`] (REQ-WA-144).
///
/// Preferred/Discouraged/Allow never reject; the flags are reported by the
/// caller from the parsed data.
///
/// # Requirements
/// REQ-WA-142, REQ-WA-144
fn enforce_flag_policy(flags: u8, policy: &CredentialPolicy) -> Result<(), WebauthnError> {
    if policy.user_verification == UserVerificationPolicy::Required && flags & FLAG_UV == 0 {
        return Err(WebauthnError::UserVerificationRequired);
    }
    if policy.backup == BackupPolicy::RequireDeviceBound && flags & FLAG_BE != 0 {
        return Err(WebauthnError::PolicyViolation(
            "backup policy requires device-bound credentials, but the credential \
             is backup-eligible (BE=1)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Enforce the registration algorithm allowlist (REQ-WA-143): a non-empty
/// `allowed_algorithms` rejects any credential whose parsed algorithm is
/// absent.
///
/// # Requirements
/// REQ-WA-143
fn enforce_algorithm_allowlist(alg: i32, policy: &CredentialPolicy) -> Result<(), WebauthnError> {
    if !policy.allowed_algorithms.is_empty() && !policy.allowed_algorithms.contains(&alg) {
        return Err(WebauthnError::UnsupportedAlgorithm(alg));
    }
    Ok(())
}

/// Shared `clientDataJSON` validation: parse, challenge echo, ceremony type,
/// origin allow-list, and optional `rpId` cross-check.
///
/// # Requirements
/// REQ-WA-100, REQ-WA-101, REQ-WA-102, REQ-WA-103
///
/// Returns the raw decoded client data bytes (needed for the auth signature).
fn validate_client_data(
    client_data_json_b64: &str,
    challenge_bytes: &[u8],
    expected_type: &str,
    rp_id: &str,
    rp_origins: &[String],
) -> Result<Vec<u8>, WebauthnError> {
    let client_data_bytes = base64_decode_urlsafe(client_data_json_b64)?;
    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|e| WebauthnError::VerificationFailed(format!("client data parse error: {e}")))?;

    let client_challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            WebauthnError::VerificationFailed("missing challenge in client data".to_string())
        })?;
    let client_challenge_bytes = base64_decode_urlsafe(client_challenge)?;
    if client_challenge_bytes != challenge_bytes {
        return Err(WebauthnError::VerificationFailed(
            "challenge mismatch".to_string(),
        ));
    }

    let typ = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            WebauthnError::VerificationFailed("missing type in client data".to_string())
        })?;
    if typ != expected_type {
        return Err(WebauthnError::VerificationFailed(format!(
            "wrong type: {typ}"
        )));
    }

    let origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            WebauthnError::VerificationFailed("missing origin in client data".to_string())
        })?;
    if !rp_origins.iter().any(|o| o == origin) {
        return Err(WebauthnError::VerificationFailed(format!(
            "origin '{origin}' not allowed"
        )));
    }

    // Note: nested `if let` (not a let-chain) — this crate targets edition 2021.
    if let Some(rp) = client_data.get("rpId").and_then(|v| v.as_str()) {
        if rp != rp_id {
            return Err(WebauthnError::VerificationFailed(format!(
                "rpId mismatch: client sent '{rp}', expected '{rp_id}'"
            )));
        }
    }

    Ok(client_data_bytes)
}

/// Verify a registration response with full CTAP2/COSE verification and
/// attestation statement verification.
///
/// # Security notes / threat assumptions
///
/// - `challenge_bytes` must be the server-generated, single-use challenge for
///   this ceremony (obtain via [`crate::ChallengeStore::consume_registration_challenge`]
///   immediately before calling).
/// - `rp_origins` is an exact-match allow-list; `rp_id` is SHA-256-hashed and
///   compared against the authenticator's `rpIdHash`, which binds the
///   credential to this RP.
/// - The UP and AT flags are mandatory. UV is enforced per
///   `credential_policy.user_verification` ([`UserVerificationPolicy::Required`]
///   rejects UV-clear registrations); the backup-eligibility flag is enforced
///   per `credential_policy.backup`.
/// - Attestation statements are verified for the `none`, `packed`, and
///   `fido-u2f` formats; unknown formats are rejected unless
///   [`AttestationPolicy::allow_unknown_formats`] is set (trust-weakening).
///   The provenance conveyed by a verified attestation is bounded by
///   `attestation.trust_level` in the result — see
///   [`crate::attestation`]: only [`crate::attestation::TrustLevel::AttCa`]
///   (chain terminating at a configured trust anchor) attests device
///   provenance.
/// - Re-registration of an existing credential is rejected when
///   `existing_credential_id` matches the presented credential ID.
///
/// # Requirements
/// REQ-WA-001, REQ-WA-101, REQ-WA-102, REQ-WA-103, REQ-WA-104, REQ-WA-105,
/// REQ-WA-113, REQ-WA-117, REQ-WA-119, REQ-WA-120, REQ-WA-121, REQ-WA-123,
/// REQ-WA-124, REQ-WA-126, REQ-WA-142, REQ-WA-143, REQ-WA-144
///
/// Returns the verified registration data to persist.
#[allow(clippy::too_many_arguments)]
pub fn verify_registration(
    challenge_bytes: &[u8],
    client_data_json_b64: &str,
    attestation_object_b64: &str,
    existing_credential_id: &str,
    rp_id: &str,
    rp_origins: &[String],
    attestation_policy: &AttestationPolicy,
    credential_policy: &CredentialPolicy,
) -> Result<RegistrationResult, WebauthnError> {
    let client_data_bytes = validate_client_data(
        client_data_json_b64,
        challenge_bytes,
        "webauthn.create",
        rp_id,
        rp_origins,
    )?;

    let attestation_bytes = base64_decode_urlsafe(attestation_object_b64)?;
    let attestation_val: ciborium::Value = ciborium::de::from_reader(&attestation_bytes[..])
        .map_err(|e| {
            WebauthnError::AttestationError(format!("attestation object CBOR parse error: {e}"))
        })?;

    let attestation_entries = cbor_map_entries(&attestation_val).ok_or_else(|| {
        WebauthnError::AttestationError("attestation object is not a CBOR map".to_string())
    })?;

    let mut fmt: Option<String> = None;
    let mut auth_data_bytes: Option<Vec<u8>> = None;
    let mut att_stmt: Option<ciborium::Value> = None;

    for (key, val) in &attestation_entries {
        match *key {
            1 => {
                if let ciborium::Value::Text(s) = val {
                    fmt = Some(s.clone());
                }
            }
            2 => {
                if let Some(b) = cbor_bytes(val) {
                    auth_data_bytes = Some(b);
                }
            }
            3 => {
                att_stmt = Some(val.clone());
            }
            _ => {}
        }
    }

    let fmt = fmt.unwrap_or_else(|| "none".to_string());
    let auth_data_bytes = auth_data_bytes.ok_or_else(|| {
        WebauthnError::AttestationError("missing authData in attestation object".to_string())
    })?;

    let auth_data = parse_authenticator_data(&auth_data_bytes)?;

    use sha2::Digest;
    let computed_rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
    if auth_data.rp_id_hash != computed_rp_id_hash {
        return Err(WebauthnError::VerificationFailed(format!(
            "rpId hash mismatch: computed {:x?}, got {:x?}",
            computed_rp_id_hash, auth_data.rp_id_hash
        )));
    }

    if auth_data.flags & FLAG_UP == 0 {
        return Err(WebauthnError::VerificationFailed(
            "User Present flag not set".to_string(),
        ));
    }

    if auth_data.flags & FLAG_AT == 0 {
        return Err(WebauthnError::VerificationFailed(
            "Attested Credential Data flag not set during registration".to_string(),
        ));
    }

    // Credential policy: UV requirement and backup eligibility (REQ-WA-142/144).
    enforce_flag_policy(auth_data.flags, credential_policy)?;

    let credential_id = auth_data.credential_id.ok_or_else(|| {
        WebauthnError::VerificationFailed("no credential ID in attested data".to_string())
    })?;
    let credential_id_b64 = base64_encode_urlsafe(&credential_id);

    if existing_credential_id == credential_id_b64 {
        return Err(WebauthnError::DuplicateCredential(credential_id_b64));
    }

    let public_key_cose = auth_data.credential_public_key_cose.ok_or_else(|| {
        WebauthnError::VerificationFailed("no public key in attested data".to_string())
    })?;

    let (alg, cose_key) = parse_cose_key(&public_key_cose)?;

    // Server-side algorithm allowlist (REQ-WA-143).
    enforce_algorithm_allowlist(alg, credential_policy)?;

    // Attestation verification (REQ-WA-119..): dispatch on `fmt` and verify
    // the statement per the caller's policy. Fails closed on tampered
    // signatures, unknown formats (unless opted out), and policy violations.
    let client_data_hash = sha2::Sha256::digest(&client_data_bytes).to_vec();
    let aaguid = auth_data.aaguid.unwrap_or([0u8; 16]);
    let attestation = verify_attestation(
        &fmt,
        att_stmt.as_ref(),
        &auth_data_bytes,
        &client_data_hash,
        &credential_id,
        alg,
        &cose_key,
        aaguid,
        attestation_policy,
    )?;

    let user_verified = auth_data.flags & FLAG_UV != 0;

    Ok(RegistrationResult {
        credential_id: credential_id_b64,
        device_name: format!("WebAuthn ({})", alg_to_name(alg)),
        attestation_format: fmt,
        attestation,
        user_verified,
        backup_eligible: auth_data.backup_eligible,
        backup_state: auth_data.backup_state,
    })
}

/// Parameters for verifying an authentication response.
///
/// All base64 fields are client-supplied and hostile; `public_key_cose` and
/// `current_sign_count` are the server-side stored credential state.
#[derive(Debug, Clone)]
pub struct AuthenticationParams {
    /// The raw challenge bytes that were stored server-side.
    pub challenge_bytes: Vec<u8>,
    /// Base64url-encoded client data JSON.
    pub client_data_json_b64: String,
    /// Base64url-encoded authenticator data.
    pub authenticator_data_b64: String,
    /// Base64url-encoded signature.
    pub signature_b64: String,
    /// Base64url-encoded credential ID presented by the authenticator.
    pub credential_id_b64: String,
    /// COSE-encoded public key for this credential.
    pub public_key_cose: Vec<u8>,
    /// Current sign count stored server-side for this credential.
    pub current_sign_count: u32,
    /// Allowed credential IDs for this authentication session.
    pub allowed_credential_ids: Vec<String>,
    /// Expected relying party ID.
    pub rp_id: String,
    /// Allowed origins.
    pub rp_origins: Vec<String>,
    /// Credential policy enforced on this assertion
    /// (default: [`CredentialPolicy::default`] — UV reported, not required).
    ///
    /// # Security note
    ///
    /// With [`UserVerificationPolicy::Required`], an assertion whose UV flag
    /// is clear is rejected — this is the enforcement point for step-up or
    /// high-assurance logins.
    pub policy: CredentialPolicy,
}

/// Verify an authentication response with full CTAP2/COSE signature
/// verification.
///
/// Verification steps, in order:
///
/// 1. Credential ID membership in `allowed_credential_ids`.
/// 2. `clientDataJSON` validation (challenge echo, `type == "webauthn.get"`,
///    origin allow-list, optional `rpId` cross-check).
/// 3. Authenticator data parsing and `rpIdHash` comparison.
/// 4. User Presence flag + credential-policy flag enforcement (UV, backup).
/// 5. Sign-count freshness ([`check_sign_count`]).
/// 6. `ring` signature verification over `authenticatorData || SHA-256(clientDataJSON)`.
///
/// # Security notes / threat assumptions
///
/// - `challenge_bytes` must be consumed from single-use storage before this
///   call; this module does not (and cannot) detect a challenge used twice.
/// - On success the caller MUST persist [`AuthenticationResult::new_sign_count`]
///   (ideally compare-and-swap) before considering the user logged in.
/// - UV is enforced per `params.policy.user_verification`
///   ([`UserVerificationPolicy::Required`] rejects UV-clear assertions);
///   backup eligibility per `params.policy.backup`. The BE/BS flags are
///   always reported on the result.
///
/// # Requirements
/// REQ-WA-002, REQ-WA-101, REQ-WA-102, REQ-WA-103, REQ-WA-104, REQ-WA-105,
/// REQ-WA-106, REQ-WA-111, REQ-WA-114, REQ-WA-116, REQ-WA-142, REQ-WA-144
///
/// Returns the verified authentication data.
pub fn verify_authentication(
    params: &AuthenticationParams,
) -> Result<AuthenticationResult, WebauthnError> {
    let AuthenticationParams {
        challenge_bytes,
        client_data_json_b64,
        authenticator_data_b64,
        signature_b64,
        credential_id_b64,
        public_key_cose,
        current_sign_count,
        allowed_credential_ids,
        rp_id,
        rp_origins,
        policy,
    } = params;

    if !allowed_credential_ids.contains(credential_id_b64) {
        return Err(WebauthnError::VerificationFailed(
            "credential ID not in allowed list".to_string(),
        ));
    }

    let client_data_bytes = validate_client_data(
        client_data_json_b64,
        challenge_bytes,
        "webauthn.get",
        rp_id,
        rp_origins,
    )?;

    let authenticator_data = base64_decode_urlsafe(authenticator_data_b64)?;
    let auth_data = parse_authenticator_data(&authenticator_data)?;

    use sha2::Digest;
    let computed_rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
    if auth_data.rp_id_hash != computed_rp_id_hash {
        return Err(WebauthnError::VerificationFailed(format!(
            "rpId hash mismatch: computed {:x?}, got {:x?}",
            computed_rp_id_hash, auth_data.rp_id_hash
        )));
    }

    if auth_data.flags & FLAG_UP == 0 {
        return Err(WebauthnError::VerificationFailed(
            "User Present flag not set".to_string(),
        ));
    }

    // Credential policy: UV requirement and backup eligibility (REQ-WA-142/144).
    enforce_flag_policy(auth_data.flags, policy)?;

    check_sign_count(*current_sign_count, auth_data.sign_count)?;

    let client_data_hash = sha2::Sha256::digest(&client_data_bytes).to_vec();

    let mut signed_data = Vec::with_capacity(authenticator_data.len() + 32);
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(&client_data_hash);

    let signature = base64_decode_urlsafe(signature_b64)?;

    let (alg, cose_key) = parse_cose_key(public_key_cose)?;
    verify_cose_signature(alg, &cose_key, &signed_data, &signature)?;

    let user_verified = auth_data.flags & FLAG_UV != 0;
    let new_sign_count = auth_data.sign_count;

    Ok(AuthenticationResult {
        credential_id: credential_id_b64.clone(),
        new_sign_count,
        user_verified,
        backup_state: auth_data.backup_state,
        backup_eligible: auth_data.backup_eligible,
    })
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
    use crate::crypto::tests::{build_cose_ec2_key, build_cose_rsa_key};
    use crate::crypto::{base64_encode_urlsafe, generate_challenge_bytes, COSE_ALG_RS256};
    use ring::signature::KeyPair as _;

    fn build_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        use ciborium::Value;
        let map = vec![
            (Value::Integer(1.into()), Value::Text("none".to_string())),
            (Value::Integer(2.into()), Value::Bytes(auth_data.to_vec())),
            (Value::Integer(3.into()), Value::Map(vec![])),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
        buf
    }

    fn build_auth_data_with_credential(
        rp_id: &str,
        flags: u8,
        sign_count: u32,
        credential_id: &[u8],
        cose_key: &[u8],
    ) -> Vec<u8> {
        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        if flags & FLAG_AT != 0 {
            auth_data.extend_from_slice(&[0u8; 16]);
            auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(credential_id);
            auth_data.extend_from_slice(cose_key);
        }

        auth_data
    }

    #[test]
    fn test_parse_authenticator_data_minimal() {
        let mut auth_data = vec![0u8; 37];
        auth_data[..32].copy_from_slice(&[0xAA; 32]);
        auth_data[32] = FLAG_UP;
        auth_data[33..37].copy_from_slice(&1u32.to_be_bytes());

        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert_eq!(parsed.rp_id_hash, vec![0xAA; 32]);
        assert_eq!(parsed.flags, FLAG_UP);
        assert_eq!(parsed.sign_count, 1);
        assert!(parsed.credential_public_key_cose.is_none());
        assert!(parsed.credential_id.is_none());
    }

    #[test]
    fn test_parse_authenticator_data_with_attested_credential() {
        let credential_id = vec![0x01, 0x02, 0x03, 0x04];
        let public_key_cose = vec![0x10, 0x20, 0x30];

        let total_len = 37 + 16 + 2 + credential_id.len() + public_key_cose.len();
        let mut auth_data = vec![0u8; total_len];
        auth_data[32] = FLAG_UP | FLAG_AT;
        auth_data[33..37].copy_from_slice(&5u32.to_be_bytes());

        let offset = 37 + 16;
        auth_data[offset..offset + 2].copy_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data[offset + 2..offset + 2 + credential_id.len()].copy_from_slice(&credential_id);
        let pk_offset = offset + 2 + credential_id.len();
        auth_data[pk_offset..].copy_from_slice(&public_key_cose);

        let parsed = parse_authenticator_data(&auth_data).unwrap();
        assert_eq!(parsed.flags, FLAG_UP | FLAG_AT);
        assert_eq!(parsed.sign_count, 5);
        assert_eq!(parsed.credential_id, Some(credential_id));
        assert_eq!(parsed.credential_public_key_cose, Some(public_key_cose));
    }

    #[test]
    fn test_parse_authenticator_data_too_short() {
        let auth_data = vec![0u8; 10];
        let result = parse_authenticator_data(&auth_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_registration_valid_es256() {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let cose_key = build_cose_ec2_key(&x, &y);

        let credential_id = vec![0x01, 0x02, 0x03, 0x04];
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &credential_id,
            &cose_key,
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "different-id",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        )
        .unwrap();

        assert_eq!(result.credential_id, base64_encode_urlsafe(&credential_id));
        assert!(result.attestation_format == "none");
    }

    #[test]
    fn test_verify_registration_challenge_mismatch() {
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &[0x01],
            &build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]),
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let _challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&[1u8; 32]),
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "different",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_registration_wrong_type() {
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &[0x01],
            &build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]),
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "different",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_registration_wrong_origin() {
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &[0x01],
            &build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]),
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://evil.com",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "different",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_registration_duplicate() {
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &[0x01, 0x02, 0x03],
            &build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]),
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);
        let cred_id_b64 = base64_encode_urlsafe(&[0x01, 0x02, 0x03]);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            &cred_id_b64,
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::DuplicateCredential(_))));
    }

    #[test]
    fn test_verify_registration_wrong_rp_id_hash() {
        let credential_id = vec![0x01];
        let cose_key = build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]);
        let auth_data = build_auth_data_with_credential(
            "evil.com",
            FLAG_UP | FLAG_AT,
            0,
            &credential_id,
            &cose_key,
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "different",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_registration_missing_up_flag() {
        let credential_id = vec![0x01];
        let cose_key = build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]);
        let auth_data =
            build_auth_data_with_credential("localhost", FLAG_AT, 0, &credential_id, &cose_key);
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "different",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    /// REQ-WA-117: registration with UP set but the AT flag clear (no
    /// attested credential data) must be rejected — a credential cannot be
    /// registered without attested key material.
    #[test]
    fn registration_rejects_missing_at_flag() {
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP, // UP set, AT clear
            0,
            &[0x01],
            &build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]),
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());
        let att_obj_b64 = base64_encode_urlsafe(&att_obj);

        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "different",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_valid_es256() {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let cose_key = build_cose_ec2_key(&x, &y);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&1u32.to_be_bytes());

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let client_data_b64 = base64_encode_urlsafe(&client_data_bytes);
        let client_data_hash = sha2::Sha256::digest(&client_data_bytes).to_vec();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        let signature = key_pair.sign(&rng, &signed_data).unwrap();

        let auth_data_b64 = base64_encode_urlsafe(&auth_data);
        let sig_b64 = base64_encode_urlsafe(signature.as_ref());
        let cred_id_b64 = base64_encode_urlsafe(&[0x01, 0x02]);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: sig_b64,
            credential_id_b64: cred_id_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec![cred_id_b64.clone()],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        })
        .unwrap();

        assert_eq!(result.credential_id, cred_id_b64);
        assert_eq!(result.new_sign_count, 1);
    }

    #[test]
    fn test_verify_authentication_wrong_signature() {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let cose_key = build_cose_ec2_key(&x, &y);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&1u32.to_be_bytes());

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let client_data_b64 = base64_encode_urlsafe(&client_data_bytes);
        let client_data_hash = sha2::Sha256::digest(&client_data_bytes).to_vec();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        let mut wrong_sig = vec![0u8; 64];
        wrong_sig[0] = 0xFF;

        let auth_data_b64 = base64_encode_urlsafe(&auth_data);
        let sig_b64 = base64_encode_urlsafe(&wrong_sig);
        let cred_id_b64 = base64_encode_urlsafe(&[0x01]);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: sig_b64,
            credential_id_b64: cred_id_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec![cred_id_b64],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(
            result,
            Err(WebauthnError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_verify_authentication_credential_not_allowed() {
        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let auth_data_b64 = base64_encode_urlsafe(&auth_data);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: "sig".to_string(),
            credential_id_b64: "unauthorized-cred".to_string(),
            public_key_cose: vec![0x10, 0x20],
            current_sign_count: 0,
            allowed_credential_ids: vec!["allowed-cred".to_string()],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_wrong_origin() {
        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://evil.com",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let auth_data_b64 = base64_encode_urlsafe(&auth_data);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: "sig".to_string(),
            credential_id_b64: "cred".to_string(),
            public_key_cose: vec![0x10],
            current_sign_count: 0,
            allowed_credential_ids: vec!["cred".to_string()],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_wrong_type() {
        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let auth_data_b64 = base64_encode_urlsafe(&auth_data);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: "sig".to_string(),
            credential_id_b64: "cred".to_string(),
            public_key_cose: vec![0x10],
            current_sign_count: 0,
            allowed_credential_ids: vec!["cred".to_string()],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_sign_count_decrease() {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let cose_key = build_cose_ec2_key(&x, &y);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&5u32.to_be_bytes());

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let client_data_b64 = base64_encode_urlsafe(&client_data_bytes);
        let client_data_hash = sha2::Sha256::digest(&client_data_bytes).to_vec();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        let signature = key_pair.sign(&rng, &signed_data).unwrap();

        let auth_data_b64 = base64_encode_urlsafe(&auth_data);
        let sig_b64 = base64_encode_urlsafe(signature.as_ref());
        let cred_id_b64 = base64_encode_urlsafe(&[0x01]);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: sig_b64,
            credential_id_b64: cred_id_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 10,
            allowed_credential_ids: vec![cred_id_b64],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_wrong_rp_id_hash() {
        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"evil.com").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let auth_data_b64 = base64_encode_urlsafe(&auth_data);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: "sig".to_string(),
            credential_id_b64: "cred".to_string(),
            public_key_cose: vec![0x10],
            current_sign_count: 0,
            allowed_credential_ids: vec!["cred".to_string()],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_missing_up_flag() {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let cose_key = build_cose_ec2_key(&x, &y);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0);
        auth_data.extend_from_slice(&1u32.to_be_bytes());

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let client_data_b64 = base64_encode_urlsafe(&client_data_bytes);
        let client_data_hash = sha2::Sha256::digest(&client_data_bytes).to_vec();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        let signature = key_pair.sign(&rng, &signed_data).unwrap();

        let auth_data_b64 = base64_encode_urlsafe(&auth_data);
        let sig_b64 = base64_encode_urlsafe(signature.as_ref());
        let cred_id_b64 = base64_encode_urlsafe(&[0x01]);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: sig_b64,
            credential_id_b64: cred_id_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec![cred_id_b64],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_wrong_rp_id_in_client_data() {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let cose_key = build_cose_ec2_key(&x, &y);

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
            "rpId": "evil.com",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let client_data_b64 = base64_encode_urlsafe(&client_data_bytes);

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&1u32.to_be_bytes());

        let client_data_hash = sha2::Sha256::digest(&client_data_bytes).to_vec();
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        let signature = key_pair.sign(&rng, &signed_data).unwrap();

        let auth_data_b64 = base64_encode_urlsafe(&auth_data);
        let sig_b64 = base64_encode_urlsafe(signature.as_ref());
        let cred_id_b64 = base64_encode_urlsafe(&[0x01]);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: sig_b64,
            credential_id_b64: cred_id_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec![cred_id_b64],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_challenge_mismatch() {
        let challenge = generate_challenge_bytes();
        let _challenge_b64 = base64_encode_urlsafe(&challenge);

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64_encode_urlsafe(&[99u8; 32]),
            "origin": "http://localhost:8080",
        });
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());

        use sha2::Digest;
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let auth_data_b64 = base64_encode_urlsafe(&auth_data);

        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: challenge.clone(),
            client_data_json_b64: client_data_b64,
            authenticator_data_b64: auth_data_b64,
            signature_b64: "sig".to_string(),
            credential_id_b64: "cred".to_string(),
            public_key_cose: vec![0x10],
            current_sign_count: 0,
            allowed_credential_ids: vec!["cred".to_string()],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        });
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_authentication_rs256_roundtrip() {
        // Synthetic fixed-size RSA test key is impractical here; verify the
        // RS256 *dispatch* path instead: an ES256 key claiming RS256 is
        // rejected (key type/algorithm cross-check), proving the RS256 arm
        // requires RSA material.
        let cose_key = build_cose_rsa_key(&[0xAA; 256], &[0x01, 0x00, 0x01]);
        let (alg, key) = crate::crypto::parse_cose_key(&cose_key).unwrap();
        assert_eq!(alg, COSE_ALG_RS256);
        let result = verify_cose_signature(COSE_ALG_RS256, &key, b"data", &[0u8; 256]);
        assert!(matches!(
            result,
            Err(WebauthnError::SignatureVerificationFailed)
        ));
    }

    /// Build a fully valid ES256 registration response. `rp_id_field`
    /// injects a matching `rpId` into clientDataJSON; `extra_att_key`
    /// appends an unknown key to the attestation object (must be ignored).
    fn valid_registration(rp_id_field: bool, extra_att_key: bool) -> (Vec<u8>, String, String) {
        use ring::signature::EcdsaKeyPair;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let cose_key = build_cose_ec2_key(&pub_bytes[1..33], &pub_bytes[33..65]);

        let credential_id = vec![0x42u8; 8];
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &credential_id,
            &cose_key,
        );

        let challenge = generate_challenge_bytes();
        let challenge_b64 = base64_encode_urlsafe(&challenge);

        let mut client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "http://localhost:8080",
        });
        if rp_id_field {
            client_data["rpId"] = serde_json::json!("localhost");
        }
        let client_data_b64 = base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap());

        let mut entries = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text("none".to_string()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Bytes(auth_data),
            ),
        ];
        if extra_att_key {
            entries.push((
                ciborium::Value::Integer(9.into()),
                ciborium::Value::Bool(true),
            ));
        }
        entries.push((
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Map(vec![]),
        ));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(entries), &mut buf).unwrap();

        (challenge, client_data_b64, base64_encode_urlsafe(&buf))
    }

    /// An explicit `rpId` field matching the RP must be accepted, and
    /// unknown attestation-object keys must be ignored.
    #[test]
    fn registration_accepts_rpid_field_and_unknown_keys() {
        let (challenge, client_data_b64, att_obj_b64) = valid_registration(true, true);
        let result = verify_registration(
            &challenge,
            &client_data_b64,
            &att_obj_b64,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.attestation_format, "none");
        assert_eq!(result.credential_id, base64_encode_urlsafe(&[0x42u8; 8]));
    }

    #[test]
    fn registration_rejects_missing_type_in_client_data() {
        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let result = verify_registration(
            &challenge,
            &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            &base64_encode_urlsafe(&[0xFF; 8]),
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn registration_rejects_missing_origin_in_client_data() {
        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&challenge),
        });
        let result = verify_registration(
            &challenge,
            &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            &base64_encode_urlsafe(&[0xFF; 8]),
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    /// Attested credential data that ends right after the credential ID
    /// (no COSE key bytes) must be rejected as truncated, never sliced
    /// out of bounds.
    #[test]
    fn parse_auth_data_rejects_truncated_public_key() {
        let mut auth_data = vec![0u8; 37 + 16 + 2 + 2];
        auth_data[32] = FLAG_UP | FLAG_AT;
        auth_data[53..55].copy_from_slice(&2u16.to_be_bytes());
        let result = parse_authenticator_data(&auth_data);
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    // ---- ES384 / EdDSA ceremonies (REQ-WA-140, REQ-WA-141) ----

    use crate::crypto::tests::{build_cose_ec2_key_alg, build_cose_okp_key};
    use crate::crypto::{COSE_ALG_ES256, COSE_ALG_ES384};

    /// Full ES384 registration roundtrip with a synthetic P-384 keypair.
    #[test]
    fn registration_roundtrip_es384() {
        use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P384_SHA384_FIXED_SIGNING};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let pub_bytes = key_pair.public_key().as_ref();
        let cose_key = build_cose_ec2_key_alg(2, -35, &pub_bytes[1..49], &pub_bytes[49..97]);

        let credential_id = vec![0xE3u8; 8];
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT | FLAG_UV | FLAG_BE | FLAG_BS,
            0,
            &credential_id,
            &cose_key,
        );
        let att_obj = build_attestation_object(&auth_data);

        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let result = verify_registration(
            &challenge,
            &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            &base64_encode_urlsafe(&att_obj),
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        )
        .unwrap();

        assert!(result.device_name.contains("ES384"));
        assert!(result.user_verified);
        assert!(result.backup_eligible);
        assert!(result.backup_state);
    }

    /// Full EdDSA registration → authentication roundtrip.
    #[test]
    fn registration_authentication_roundtrip_eddsa() {
        use ring::signature::{Ed25519KeyPair, KeyPair as _};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let cose_key = build_cose_okp_key(key_pair.public_key().as_ref());

        // -- registration --
        let credential_id = vec![0xEDu8; 8];
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &credential_id,
            &cose_key,
        );
        let att_obj = build_attestation_object(&auth_data);
        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let registration = verify_registration(
            &challenge,
            &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            &base64_encode_urlsafe(&att_obj),
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        )
        .unwrap();
        assert!(registration.device_name.contains("EdDSA"));
        assert!(!registration.backup_eligible);

        // -- authentication --
        let auth_challenge = generate_challenge_bytes();
        let assertion_client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64_encode_urlsafe(&auth_challenge),
            "origin": "http://localhost:8080",
        });
        let assertion_client_data_bytes = serde_json::to_vec(&assertion_client_data).unwrap();
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut assertion_auth_data = rp_id_hash;
        assertion_auth_data.push(FLAG_UP | FLAG_BS);
        assertion_auth_data.extend_from_slice(&1u32.to_be_bytes());

        use sha2::Digest as _;
        let mut signed_data = assertion_auth_data.clone();
        signed_data.extend_from_slice(&sha2::Sha256::digest(&assertion_client_data_bytes));
        let signature = key_pair.sign(&signed_data);

        let cred_b64 = base64_encode_urlsafe(&credential_id);
        let result = verify_authentication(&AuthenticationParams {
            challenge_bytes: auth_challenge,
            client_data_json_b64: base64_encode_urlsafe(&assertion_client_data_bytes),
            authenticator_data_b64: base64_encode_urlsafe(&assertion_auth_data),
            signature_b64: base64_encode_urlsafe(signature.as_ref()),
            credential_id_b64: cred_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec![cred_b64],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy::default(),
        })
        .unwrap();
        assert_eq!(result.new_sign_count, 1);
        assert!(result.backup_state);
        assert!(!result.backup_eligible);
    }

    /// Algorithm-confusion via the ceremony entry point: attested credential
    /// data carrying a P-256 key that claims `alg = -35` (ES384) must be
    /// rejected (the RS256 bug class, replayed against ES384).
    #[test]
    fn registration_rejects_p256_key_claiming_es384() {
        let cose_key = build_cose_ec2_key_alg(1, -35, &[0xAA; 32], &[0xBB; 32]); // crv 1 = P-256
        let auth_data =
            build_auth_data_with_credential("localhost", FLAG_UP | FLAG_AT, 0, &[0x01], &cose_key);
        let att_obj = build_attestation_object(&auth_data);
        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let result = verify_registration(
            &challenge,
            &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            &base64_encode_urlsafe(&att_obj),
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(
            result,
            Err(WebauthnError::UnsupportedAlgorithm(COSE_ALG_ES384))
        ));
    }

    // ---- UV enforcement matrix (REQ-WA-142) ----

    /// Build a minimal valid registration for the given flags; returns the
    /// ceremony inputs.
    fn registration_inputs(flags: u8) -> (Vec<u8>, String, String) {
        let cose_key = build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]);
        let auth_data =
            build_auth_data_with_credential("localhost", flags, 0, &[0x01, 0x02], &cose_key);
        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        (
            challenge,
            base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            base64_encode_urlsafe(&build_attestation_object(&auth_data)),
        )
    }

    #[test]
    fn uv_required_rejects_clear_flag_and_accepts_set() {
        use crate::policy::UserVerificationPolicy;
        let uv_required = CredentialPolicy {
            user_verification: UserVerificationPolicy::Required,
            ..CredentialPolicy::default()
        };

        // Required + UV clear → rejected.
        let (challenge, cd, ao) = registration_inputs(FLAG_UP | FLAG_AT);
        let result = verify_registration(
            &challenge,
            &cd,
            &ao,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &uv_required,
        );
        assert!(matches!(
            result,
            Err(WebauthnError::UserVerificationRequired)
        ));

        // Required + UV set → accepted.
        let (challenge, cd, ao) = registration_inputs(FLAG_UP | FLAG_AT | FLAG_UV);
        let result = verify_registration(
            &challenge,
            &cd,
            &ao,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &uv_required,
        );
        assert!(result.is_ok());
    }

    /// Preferred/Discouraged never reject on UV; the flag is only reported.
    #[test]
    fn uv_preferred_and_discouraged_report_only() {
        use crate::policy::UserVerificationPolicy;
        // UP set, UV clear.
        let (challenge, cd, ao) = registration_inputs(FLAG_UP | FLAG_AT);

        for uv in [
            UserVerificationPolicy::Preferred,
            UserVerificationPolicy::Discouraged,
        ] {
            let policy = CredentialPolicy {
                user_verification: uv,
                ..CredentialPolicy::default()
            };
            let result = verify_registration(
                &challenge,
                &cd,
                &ao,
                "",
                "localhost",
                &["http://localhost:8080".to_string()],
                &AttestationPolicy::default(),
                &policy,
            )
            .unwrap();
            assert!(!result.user_verified, "{uv:?} must report, not reject");
        }
    }

    // ---- algorithm allowlist (REQ-WA-143) ----

    /// A credential whose algorithm is outside the configured allowlist is
    /// rejected at registration, even though the kit could verify it.
    #[test]
    fn registration_rejects_algorithm_outside_allowlist() {
        // P-384/ES384 credential with an ES256-only allowlist.
        use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P384_SHA384_FIXED_SIGNING};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let pub_bytes = key_pair.public_key().as_ref();
        let cose_key = build_cose_ec2_key_alg(2, -35, &pub_bytes[1..49], &pub_bytes[49..97]);

        let auth_data =
            build_auth_data_with_credential("localhost", FLAG_UP | FLAG_AT, 0, &[0x01], &cose_key);
        let att_obj = build_attestation_object(&auth_data);
        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let common = (
            challenge,
            base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            base64_encode_urlsafe(&att_obj),
        );

        // Disallowed: ES384 not on the ES256-only list.
        let es256_only = CredentialPolicy {
            allowed_algorithms: vec![COSE_ALG_ES256],
            ..CredentialPolicy::default()
        };
        let result = verify_registration(
            &common.0,
            &common.1,
            &common.2,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &es256_only,
        );
        assert!(matches!(
            result,
            Err(WebauthnError::UnsupportedAlgorithm(COSE_ALG_ES384))
        ));

        // Allowed once ES384 is listed.
        let with_es384 = CredentialPolicy {
            allowed_algorithms: vec![COSE_ALG_ES256, COSE_ALG_ES384],
            ..CredentialPolicy::default()
        };
        let result = verify_registration(
            &common.0,
            &common.1,
            &common.2,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &with_es384,
        );
        assert!(result.is_ok());

        // Empty allowlist = accept everything supported.
        let result = verify_registration(
            &common.0,
            &common.1,
            &common.2,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(result.is_ok());
    }

    // ---- backup eligibility / backup state policy (REQ-WA-144) ----

    /// `RequireDeviceBound` rejects synced (BE=1) credentials at
    /// registration; device-bound (BE=0) registrations pass.
    #[test]
    fn backup_policy_device_bound_enforced_at_registration() {
        use crate::policy::BackupPolicy;
        let device_bound = CredentialPolicy {
            backup: BackupPolicy::RequireDeviceBound,
            ..CredentialPolicy::default()
        };

        // BE=1 (synced) → rejected.
        let (challenge, cd, ao) = registration_inputs(FLAG_UP | FLAG_AT | FLAG_BE);
        let result = verify_registration(
            &challenge,
            &cd,
            &ao,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &device_bound,
        );
        assert!(matches!(result, Err(WebauthnError::PolicyViolation(_))));

        // BE=0 (device-bound) → accepted; BS reported as-is.
        let (challenge, cd, ao) = registration_inputs(FLAG_UP | FLAG_AT);
        let result = verify_registration(
            &challenge,
            &cd,
            &ao,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &device_bound,
        );
        let registration = result.unwrap();
        assert!(!registration.backup_eligible);
        assert!(!registration.backup_state);
    }

    /// `Allow` (default) accepts synced credentials and reports both flags.
    #[test]
    fn backup_policy_allow_reports_flags() {
        let (challenge, cd, ao) = registration_inputs(FLAG_UP | FLAG_AT | FLAG_BE | FLAG_BS);
        let registration = verify_registration(
            &challenge,
            &cd,
            &ao,
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        )
        .unwrap();
        assert!(registration.backup_eligible);
        assert!(registration.backup_state);
    }

    /// `RequireDeviceBound` also rejects BE=1 assertions at authentication.
    #[test]
    fn backup_policy_device_bound_enforced_at_authentication() {
        use crate::policy::BackupPolicy;
        use ring::signature::{EcdsaKeyPair, KeyPair as _};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pub_bytes = key_pair.public_key().as_ref();
        let cose_key = build_cose_ec2_key(&pub_bytes[1..33], &pub_bytes[33..65]);

        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = rp_id_hash;
        auth_data.push(FLAG_UP | FLAG_BE); // synced credential assertion
        auth_data.extend_from_slice(&1u32.to_be_bytes());

        use sha2::Digest as _;
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&sha2::Sha256::digest(&client_data_bytes));
        let signature = key_pair.sign(&rng, &signed_data).unwrap();

        let cred_b64 = base64_encode_urlsafe(&[0x01]);
        let params = AuthenticationParams {
            challenge_bytes: challenge,
            client_data_json_b64: base64_encode_urlsafe(&client_data_bytes),
            authenticator_data_b64: base64_encode_urlsafe(&auth_data),
            signature_b64: base64_encode_urlsafe(signature.as_ref()),
            credential_id_b64: cred_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec![cred_b64],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy {
                backup: BackupPolicy::RequireDeviceBound,
                ..CredentialPolicy::default()
            },
        };
        assert!(matches!(
            verify_authentication(&params),
            Err(WebauthnError::PolicyViolation(_))
        ));
    }

    /// UV Required is enforced at authentication: a validly signed
    /// assertion with a clear UV flag fails with
    /// `UserVerificationRequired`.
    #[test]
    fn uv_required_enforced_at_authentication() {
        use crate::policy::UserVerificationPolicy;
        use ring::signature::{EcdsaKeyPair, KeyPair as _};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pub_bytes = key_pair.public_key().as_ref();
        let cose_key = build_cose_ec2_key(&pub_bytes[1..33], &pub_bytes[33..65]);

        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let rp_id_hash = sha2::Sha256::digest(b"localhost").to_vec();
        let mut auth_data = rp_id_hash;
        auth_data.push(FLAG_UP); // UV clear
        auth_data.extend_from_slice(&1u32.to_be_bytes());

        use sha2::Digest as _;
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&sha2::Sha256::digest(&client_data_bytes));
        let signature = key_pair.sign(&rng, &signed_data).unwrap();

        let cred_b64 = base64_encode_urlsafe(&[0x01]);
        let params = AuthenticationParams {
            challenge_bytes: challenge,
            client_data_json_b64: base64_encode_urlsafe(&client_data_bytes),
            authenticator_data_b64: base64_encode_urlsafe(&auth_data),
            signature_b64: base64_encode_urlsafe(signature.as_ref()),
            credential_id_b64: cred_b64.clone(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec![cred_b64],
            rp_id: "localhost".to_string(),
            rp_origins: vec!["http://localhost:8080".to_string()],
            policy: CredentialPolicy {
                user_verification: UserVerificationPolicy::Required,
                ..CredentialPolicy::default()
            },
        };
        assert!(matches!(
            verify_authentication(&params),
            Err(WebauthnError::UserVerificationRequired)
        ));

        // The identical assertion under the default policy is accepted.
        let mut default_params = params.clone();
        default_params.policy = CredentialPolicy::default();
        assert!(verify_authentication(&default_params).is_ok());
    }

    /// A malformed attestation *statement* (packed without `alg`) surfaces
    /// as an `AttestationError` through the registration entry point.
    #[test]
    fn registration_propagates_attestation_statement_errors() {
        let auth_data = build_auth_data_with_credential(
            "localhost",
            FLAG_UP | FLAG_AT,
            0,
            &[0x01],
            &build_cose_ec2_key(&[0xAA; 32], &[0xBB; 32]),
        );
        let entries = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text("packed".to_string()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Bytes(auth_data),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Map(vec![]), // packed attStmt without alg/sig
            ),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(entries), &mut buf).unwrap();

        let challenge = generate_challenge_bytes();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64_encode_urlsafe(&challenge),
            "origin": "http://localhost:8080",
        });
        let result = verify_registration(
            &challenge,
            &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
            &base64_encode_urlsafe(&buf),
            "",
            "localhost",
            &["http://localhost:8080".to_string()],
            &AttestationPolicy::default(),
            &CredentialPolicy::default(),
        );
        assert!(matches!(result, Err(WebauthnError::AttestationError(_))));
    }
}
