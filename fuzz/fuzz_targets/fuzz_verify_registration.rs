#![no_main]

use libfuzzer_sys::fuzz_target;
use webauthn_kit::{verify_registration, AttestationPolicy, CredentialPolicy};

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
    // Bound input so CBOR/x509 parsing stays fast.
    let data = &data[..data.len().min(16_384)];
    let parts = split_records(data, 5);
    let challenge = parts[0];
    let client_data_json_b64 = String::from_utf8_lossy(parts[1]);
    let attestation_object_b64 = String::from_utf8_lossy(parts[2]);
    let rp_id = String::from_utf8_lossy(parts[3]);
    let origin = String::from_utf8_lossy(parts[4]);

    // Arbitrary ceremony payloads must yield Ok/Err, never panic — this is
    // the CTAP2 attestation-object parse path (CBOR, authenticator data,
    // attestation statements, COSE keys, x509 chains).
    let strict = challenge.first().is_some_and(|b| b & 1 == 1);
    let attestation_policy = if strict {
        AttestationPolicy::strict()
    } else {
        AttestationPolicy::default()
    };
    let _ = verify_registration(
        challenge,
        &client_data_json_b64,
        &attestation_object_b64,
        "", // no existing credential: allow registration
        &rp_id,
        &[origin.to_string()],
        &attestation_policy,
        &CredentialPolicy::default(),
    );
});
