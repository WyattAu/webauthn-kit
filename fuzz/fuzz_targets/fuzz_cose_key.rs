#![no_main]

use libfuzzer_sys::fuzz_target;
use webauthn_kit::{
    base64_decode_urlsafe, parse_cose_key, verify_cose_signature, AttestationFormat,
};

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
    // Bound input so CBOR parsing stays fast.
    let data = &data[..data.len().min(8192)];
    let parts = split_records(data, 3);
    let cose_bytes = parts[0];
    let signature = parts[1];
    let misc = String::from_utf8_lossy(parts[2]);

    // COSE key parse: arbitrary CBOR must decode-or-Err, never panic.
    if let Ok((alg, key)) = parse_cose_key(cose_bytes) {
        // Signature verification over the parsed key: reject-or-Ok, no panic
        // (covers ring wiring for every key shape the parser can produce).
        let _ = verify_cose_signature(alg, &key, cose_bytes, signature);
    }

    // Base64url decode: arbitrary strings must decode-or-Err, never panic
    // (padding, whitespace, non-canonical trailing bits, control chars).
    let _ = base64_decode_urlsafe(&misc);

    // Attestation format mapping: arbitrary strings map, never panic.
    let _ = AttestationFormat::from_fmt(&misc);
});
