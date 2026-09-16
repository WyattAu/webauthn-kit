#![no_main]

use libfuzzer_sys::fuzz_target;
use webauthn_kit::{verify_authentication, AuthenticationParams, CredentialPolicy};

/// Split `data` into up to `n` length-prefixed records (u16 LE length +
/// payload). Missing records come back empty; trailing bytes are ignored.
fn split_records(mut data: &[u8], n: usize) -> Vec<&[u8]> {
    let mut parts = Vec::with_capacity(n);
    while parts.len() < n && data.len() >= 2 {
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let rest = &data[2..];
        let take = len.min(rest.len());
        parts.push(&rest[..take]);
        data = &rest[take..];
    }
    while parts.len() < n {
        parts.push(b"");
    }
    parts
}

fuzz_target!(|data: &[u8]| {
    // Bound input so CBOR/authenticator-data parsing stays fast.
    let data = &data[..data.len().min(16_384)];
    let parts = split_records(data, 8);
    let challenge = parts[0];
    let client_data_json_b64 = String::from_utf8_lossy(parts[1]);
    let authenticator_data_b64 = String::from_utf8_lossy(parts[2]);
    let signature_b64 = String::from_utf8_lossy(parts[3]);
    let credential_id_b64 = String::from_utf8_lossy(parts[4]);
    let public_key_cose = parts[5];
    let rp_id = String::from_utf8_lossy(parts[6]);
    let origin = String::from_utf8_lossy(parts[7]);

    let uv_required = challenge.first().is_some_and(|b| b & 1 == 1);

    // The presented credential ID is allow-listed so adversarial
    // authenticator data, client JSON, and COSE keys reach the deep parse
    // and verification paths instead of the allowlist reject.
    let params = AuthenticationParams {
        challenge_bytes: challenge.to_vec(),
        client_data_json_b64: client_data_json_b64.to_string(),
        authenticator_data_b64: authenticator_data_b64.to_string(),
        signature_b64: signature_b64.to_string(),
        credential_id_b64: credential_id_b64.to_string(),
        public_key_cose: public_key_cose.to_vec(),
        current_sign_count: 0,
        allowed_credential_ids: vec![credential_id_b64.to_string()],
        rp_id: rp_id.to_string(),
        rp_origins: vec![origin.to_string()],
        policy: CredentialPolicy {
            user_verification: if uv_required {
                webauthn_kit::UserVerificationPolicy::Required
            } else {
                webauthn_kit::UserVerificationPolicy::Preferred
            },
            ..CredentialPolicy::default()
        },
    };

    // Arbitrary assertion payloads must yield Ok/Err, never panic.
    let _ = verify_authentication(&params);
});
