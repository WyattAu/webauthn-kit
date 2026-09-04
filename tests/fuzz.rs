//! Security test pass: property/fuzz-style tests.
//!
//! Invariants under test:
//! - Arbitrary bytes fed into every parse/verify entry point NEVER panic;
//!   they always return `Ok` or `Err` (never panic, never abort).
//! - Truncated authenticator data and malformed CBOR are rejected.
//! - Sign-count edge cases (zero, equal, huge, decreasing).
//! - Expired and stale challenges are rejected; challenges are single-use.
//! - Origin mismatch and RP ID hash mismatch are rejected.

use proptest::prelude::*;

use webauthn_kit::{
    base64_encode_urlsafe, check_sign_count, verify_authentication, verify_registration,
    AuthenticationParams, ChallengeStore, WebauthnConfig, WebauthnError,
};

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8080";

fn origins() -> Vec<String> {
    vec![ORIGIN.to_string()]
}

fn b64(bytes: &[u8]) -> String {
    base64_encode_urlsafe(bytes)
}

/// A verification error, never a panic — helper assertion.
fn assert_err_is_verificationish(result: Result<impl std::fmt::Debug, WebauthnError>) {
    match result {
        Err(_) => { /* any error variant is acceptable */ }
        Ok(value) => panic!("expected Err, got {value:?}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes as the attestation object must never panic.
    #[test]
    fn fuzz_registration_arbitrary_attestation(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let challenge = [0x42u8; 32];
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": b64(&challenge),
            "origin": ORIGIN,
        });
        let result = verify_registration(
            &challenge,
            &b64(&serde_json::to_vec(&client_data).unwrap()),
            &b64(&bytes),
            "",
            RP_ID,
            &origins(),
        );
        assert_err_is_verificationish(result);
    }

    /// Arbitrary bytes as clientDataJSON must never panic.
    #[test]
    fn fuzz_registration_arbitrary_client_data(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let challenge = [0x42u8; 32];
        let attestation = {
            // Minimal well-formed attestation object; client data is the hostile part.
            let auth_data = {
                let mut a = vec![0u8; 37];
                a[32] = 0x41; // UP | AT without attested data is invalid, but parse first
                a
            };
            let map = vec![
                (ciborium::Value::Integer(1.into()), ciborium::Value::Text("none".into())),
                (ciborium::Value::Integer(2.into()), ciborium::Value::Bytes(auth_data)),
                (ciborium::Value::Integer(3.into()), ciborium::Value::Map(vec![])),
            ];
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&ciborium::Value::Map(map), &mut buf).unwrap();
            buf
        };
        let result = verify_registration(
            &challenge,
            &b64(&bytes),
            &b64(&attestation),
            "",
            RP_ID,
            &origins(),
        );
        assert_err_is_verificationish(result);
    }

    /// Arbitrary bytes as every authentication field must never panic.
    #[test]
    fn fuzz_authentication_arbitrary(
        auth_data in proptest::collection::vec(any::<u8>(), 0..256),
        signature in proptest::collection::vec(any::<u8>(), 0..256),
        client_data in proptest::collection::vec(any::<u8>(), 0..256),
        cose_key in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let params = AuthenticationParams {
            challenge_bytes: vec![0x11u8; 32],
            client_data_json_b64: b64(&client_data),
            authenticator_data_b64: b64(&auth_data),
            signature_b64: b64(&signature),
            credential_id_b64: "cred".to_string(),
            public_key_cose: cose_key,
            current_sign_count: 0,
            allowed_credential_ids: vec!["cred".to_string()],
            rp_id: RP_ID.to_string(),
            rp_origins: origins(),
        };
        assert_err_is_verificationish(verify_authentication(&params));
    }

    /// Truncated authenticator data (every truncation length of a valid
    /// 37-byte header) must be rejected, never panic.
    #[test]
    fn fuzz_authentication_truncated_auth_data(
        full in proptest::collection::vec(any::<u8>(), 37..200),
        cut in 0usize..37,
    ) {
        let truncated = &full[..cut.min(full.len())];
        let params = AuthenticationParams {
            challenge_bytes: vec![0x11u8; 32],
            client_data_json_b64: b64(br#"{"type":"webauthn.get","challenge":"AQ","origin":"http://localhost:8080"}"#),
            authenticator_data_b64: b64(truncated),
            signature_b64: b64(&[0u8; 64]),
            credential_id_b64: "cred".to_string(),
            public_key_cose: vec![0xA0],
            current_sign_count: 0,
            allowed_credential_ids: vec!["cred".to_string()],
            rp_id: RP_ID.to_string(),
            rp_origins: origins(),
        };
        assert_err_is_verificationish(verify_authentication(&params));
    }

    /// Valid-length authenticator data with a hostile attestation object:
    /// arbitrary CBOR under the AT flag must never panic the parser.
    #[test]
    fn fuzz_registration_attested_data(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        // auth_data header valid (37 bytes), then arbitrary "attested" bytes.
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // UP only; no AT → attested data ignored
        let attestation = {
            let map = vec![
                (ciborium::Value::Integer(1.into()), ciborium::Value::Text("packed".into())),
                (ciborium::Value::Integer(2.into()), ciborium::Value::Bytes({
                    let mut a = auth_data.clone();
                    a[32] = 0x41; // UP | AT so the arbitrary bytes become attested data
                    a.extend_from_slice(&bytes);
                    a
                })),
                (ciborium::Value::Integer(3.into()), ciborium::Value::Map(vec![])),
            ];
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&ciborium::Value::Map(map), &mut buf).unwrap();
            buf
        };
        let challenge = [0x24u8; 32];
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": b64(&challenge),
            "origin": ORIGIN,
        });
        let result = verify_registration(
            &challenge,
            &b64(&serde_json::to_vec(&client_data).unwrap()),
            &b64(&attestation),
            "",
            RP_ID,
            &origins(),
        );
        assert_err_is_verificationish(result);
    }

    /// Malformed CBOR of random structure sizes must never panic.
    #[test]
    fn fuzz_malformed_cbor(small in proptest::collection::vec(any::<u8>(), 0..16)) {
        let challenge = [0x42u8; 32];
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": b64(&challenge),
            "origin": ORIGIN,
        });
        // Length-prefixed CBOR with a bogus declared length (common DoS shape).
        let mut hostile = small.clone();
        hostile.insert(0, 0x5B); // byte string with 8-byte length
        hostile.extend_from_slice(&[0xFFu8; 8]);
        let result = verify_registration(
            &challenge,
            &b64(&serde_json::to_vec(&client_data).unwrap()),
            &b64(&hostile),
            "",
            RP_ID,
            &origins(),
        );
        assert_err_is_verificationish(result);
    }
}

#[test]
fn sign_count_zero_stored_accepts_any_new() {
    assert!(check_sign_count(0, 0).is_ok());
    assert!(check_sign_count(0, 1).is_ok());
    assert!(check_sign_count(0, u32::MAX).is_ok());
}

#[test]
fn sign_count_equal_accepted() {
    // Authenticators without counters may report the same value forever.
    assert!(check_sign_count(7, 7).is_ok());
    assert!(check_sign_count(u32::MAX, u32::MAX).is_ok());
}

#[test]
fn sign_count_huge_monotonic_accepted() {
    assert!(check_sign_count(u32::MAX - 1, u32::MAX).is_ok());
}

#[test]
fn sign_count_decreasing_rejected() {
    assert!(matches!(
        check_sign_count(10, 9),
        Err(WebauthnError::VerificationFailed(_))
    ));
    assert!(matches!(
        check_sign_count(u32::MAX, 0),
        Err(WebauthnError::VerificationFailed(_))
    ));
}

#[test]
fn expired_challenge_rejected() {
    let now = 1_700_000_000i64;
    let mut store = ChallengeStore::with_clock(std::sync::Arc::new(move || now + 301));
    store.store_registration_challenge_at("ch", "alice", vec![0u8; 32], now);
    let result = store.consume_registration_challenge("ch", 300);
    assert!(matches!(result, Err(WebauthnError::ChallengeExpired)));
}

#[test]
fn stale_challenge_same_second_ok_then_single_use() {
    let now = 1_700_000_000i64;
    let mut store = ChallengeStore::with_clock(std::sync::Arc::new(move || now));
    store.store_registration_challenge("ch", "alice", vec![1u8; 32]);
    let first = store.consume_registration_challenge("ch", 300);
    assert!(first.is_ok());
    // Replay: same challenge ID consumed twice must fail.
    let second = store.consume_registration_challenge("ch", 300);
    assert!(matches!(second, Err(WebauthnError::InvalidChallenge(_))));
}

#[test]
fn authentication_challenge_single_use_replay_rejected() {
    let config = WebauthnConfig::default();
    let mut store = ChallengeStore::new();
    let (challenge_b64, _options) =
        store.generate_authentication_challenge(&config, vec!["cred-1".to_string()]);
    store.store_authentication_challenge(
        &challenge_b64,
        "alice",
        vec![0u8; 32],
        vec!["cred-1".to_string()],
    );

    let first = store.consume_authentication_challenge(&challenge_b64, 300);
    assert!(first.is_ok());
    let replay = store.consume_authentication_challenge(&challenge_b64, 300);
    assert!(matches!(replay, Err(WebauthnError::InvalidChallenge(_))));
}

#[test]
fn origin_mismatch_rejected_and_rp_hash_mismatch_rejected() {
    // origin mismatch: hostile client data with evil origin against a valid
    // minimal registration payload — must fail during client data validation.
    let challenge = [0x0Au8; 32];
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": b64(&challenge),
        "origin": "https://evil.example",
    });
    let result = verify_registration(
        &challenge,
        &b64(&serde_json::to_vec(&client_data).unwrap()),
        &b64(&[]), // garbage attestation; must not matter, origin fails first
        "",
        RP_ID,
        &origins(),
    );
    assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));

    // RP ID hash mismatch: auth data hashed for a different RP.
    use sha2::Digest;
    let rp_id_hash = sha2::Sha256::digest(b"evil.com").to_vec();
    let mut auth_data = rp_id_hash;
    auth_data.push(0x01);
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    let params = AuthenticationParams {
        challenge_bytes: challenge.to_vec(),
        client_data_json_b64: b64(
            br#"{"type":"webauthn.get","challenge":"Cg","origin":"http://localhost:8080"}"#,
        ),
        authenticator_data_b64: b64(&auth_data),
        signature_b64: b64(&[0u8; 64]),
        credential_id_b64: "cred".to_string(),
        public_key_cose: vec![0xA0],
        current_sign_count: 0,
        allowed_credential_ids: vec!["cred".to_string()],
        rp_id: RP_ID.to_string(),
        rp_origins: origins(),
    };
    assert!(matches!(
        verify_authentication(&params),
        Err(WebauthnError::VerificationFailed(_))
    ));
}
