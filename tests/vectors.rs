//! Known-answer and roundtrip vector tests.
//!
//! The source test suite had no hardcoded byte vectors (all fixtures were
//! generated from live keypairs); those are preserved in the unit tests. This
//! file adds full happy-path **registration → authentication** roundtrips
//! with synthetic ES256 (and RS256-parse) keypairs via `ring`, plus a
//! fixed-vector challenge/origin negative case.

use sha2::Digest;
use webauthn_kit::crypto::{parse_cose_key, verify_cose_signature, COSE_ALG_RS256};
use webauthn_kit::{
    base64_decode_urlsafe, base64_encode_urlsafe, check_sign_count, verify_authentication,
    verify_registration, AuthenticationParams, ChallengeStore, WebauthnConfig, WebauthnError,
};

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8080";

fn origins() -> Vec<String> {
    vec![ORIGIN.to_string()]
}

fn build_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let map = vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("none".into()),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Bytes(auth_data.to_vec()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Map(vec![]),
        ),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(map), &mut buf).unwrap();
    buf
}

fn build_cose_ec2_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let map = vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(2.into()),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Integer((-7).into()),
        ),
        (
            ciborium::Value::Integer((-1).into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer((-2).into()),
            ciborium::Value::Bytes(x.to_vec()),
        ),
        (
            ciborium::Value::Integer((-3).into()),
            ciborium::Value::Bytes(y.to_vec()),
        ),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(map), &mut buf).unwrap();
    buf
}

fn build_auth_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    credential_id: &[u8],
    cose_key: &[u8],
) -> Vec<u8> {
    let mut auth_data = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    if flags & 0x40 != 0 {
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
    }
    auth_data
}

/// Full happy path: generate challenge → synthesize registration response
/// with a fresh ES256 keypair → verify registration → synthesize assertion →
/// verify authentication → sign-count advances monotonically.
#[test]
fn registration_authentication_roundtrip_es256() {
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

    let config = WebauthnConfig {
        rp_id: RP_ID.to_string(),
        rp_name: "Kit".to_string(),
        rp_origins: origins(),
        allowed_algorithms: vec![-7, -257],
        challenge_timeout_secs: 300,
    };

    let mut store = ChallengeStore::new();

    // ---------- Registration ceremony ----------
    let (challenge_id, options) =
        store.generate_registration_challenge(&config, "alice", "Alice", &[]);
    let raw_challenge = base64_decode_urlsafe(&challenge_id).unwrap();
    store.store_registration_challenge(&challenge_id, "alice", raw_challenge.clone());
    let (_, challenge_bytes) = store
        .consume_registration_challenge(&challenge_id, 300)
        .unwrap();
    assert_eq!(base64_encode_urlsafe(&challenge_bytes), options.challenge);

    let credential_id = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let auth_data = build_auth_data(RP_ID, 0x45, 0, &credential_id, &cose_key); // UP|UV|AT
    let att_obj = build_attestation_object(&auth_data);

    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": options.challenge,
        "origin": ORIGIN,
    });
    let registration = verify_registration(
        &challenge_bytes,
        &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
        &base64_encode_urlsafe(&att_obj),
        "", // no existing credential
        RP_ID,
        &origins(),
    )
    .expect("registration must verify");

    assert_eq!(
        registration.credential_id,
        base64_encode_urlsafe(&credential_id)
    );
    assert_eq!(registration.attestation_format, "none");
    assert!(registration.user_verified);
    assert!(registration.device_name.contains("ES256"));

    // Duplicate registration must be rejected.
    let (challenge_id2, options2) =
        store.generate_registration_challenge(&config, "alice", "Alice", &[]);
    let raw_challenge2 = base64_decode_urlsafe(&challenge_id2).unwrap();
    store.store_registration_challenge(&challenge_id2, "alice", raw_challenge2);
    let (_, challenge_bytes2) = store
        .consume_registration_challenge(&challenge_id2, 300)
        .unwrap();
    let client_data2 = serde_json::json!({
        "type": "webauthn.create",
        "challenge": options2.challenge,
        "origin": ORIGIN,
    });
    let duplicate = verify_registration(
        &challenge_bytes2,
        &base64_encode_urlsafe(&serde_json::to_vec(&client_data2).unwrap()),
        &base64_encode_urlsafe(&build_attestation_object(&build_auth_data(
            RP_ID,
            0x45,
            0,
            &credential_id,
            &cose_key,
        ))),
        &registration.credential_id,
        RP_ID,
        &origins(),
    );
    assert!(matches!(
        duplicate,
        Err(WebauthnError::DuplicateCredential(_))
    ));

    // ---------- Authentication ceremony ----------
    let credential_id_b64 = registration.credential_id.clone();

    let (auth_challenge_id, auth_options) =
        store.generate_authentication_challenge(&config, vec![credential_id_b64.clone()]);
    let raw_auth_challenge = base64_decode_urlsafe(&auth_challenge_id).unwrap();
    store.store_authentication_challenge(
        &auth_challenge_id,
        "alice",
        raw_auth_challenge,
        vec![credential_id_b64.clone()],
    );
    let (_, auth_challenge, allowed) = store
        .consume_authentication_challenge(&auth_challenge_id, 300)
        .unwrap();
    assert_eq!(allowed, vec![credential_id_b64.clone()]);

    let assertion_auth_data = build_auth_data(RP_ID, 0x01, 1, &[], &[]); // UP, counter 1
    let assertion_client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": auth_options.challenge,
        "origin": ORIGIN,
    });
    let client_data_bytes = serde_json::to_vec(&assertion_client_data).unwrap();
    let mut signed_data = assertion_auth_data.clone();
    signed_data.extend_from_slice(&sha2::Sha256::digest(&client_data_bytes));

    let signature = key_pair.sign(&rng, &signed_data).unwrap();

    let result = verify_authentication(&AuthenticationParams {
        challenge_bytes: auth_challenge,
        client_data_json_b64: base64_encode_urlsafe(&client_data_bytes),
        authenticator_data_b64: base64_encode_urlsafe(&assertion_auth_data),
        signature_b64: base64_encode_urlsafe(signature.as_ref()),
        credential_id_b64: registration.credential_id.clone(),
        public_key_cose: cose_key.clone(),
        current_sign_count: 0, // first authentication
        allowed_credential_ids: vec![registration.credential_id.clone()],
        rp_id: RP_ID.to_string(),
        rp_origins: origins(),
    })
    .expect("authentication must verify");

    assert_eq!(result.credential_id, registration.credential_id);
    assert_eq!(result.new_sign_count, 1);
    assert!(!result.user_verified); // UV flag not set on assertion

    // ---------- Second authentication: sign-count state machine ----------
    check_sign_count(result.new_sign_count, 2).expect("counter must advance");

    // Replay of the SAME assertion against a fresh challenge still verifies
    // cryptographically (stateless), which is why challenge consumption must
    // be single-use — demonstrated in tests/fuzz.rs.
    check_sign_count(result.new_sign_count + 1, result.new_sign_count)
        .expect_err("decreasing counter must be rejected");
}

/// RS256 dispatch: an RSA COSE key parses with alg -257 and the signature
/// verifier cross-checks key type (mismatched dispatch is rejected).
#[test]
fn rs256_key_parse_and_dispatch() {
    let n = vec![0xABu8; 256];
    let e = vec![0x01, 0x00, 0x01];
    let map = vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(3.into()),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Integer((-257).into()),
        ),
        (
            ciborium::Value::Integer((-1).into()),
            ciborium::Value::Bytes(n.clone()),
        ),
        (
            ciborium::Value::Integer((-2).into()),
            ciborium::Value::Bytes(e.clone()),
        ),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(map), &mut buf).unwrap();

    let (alg, key) = parse_cose_key(&buf).unwrap();
    assert_eq!(alg, COSE_ALG_RS256);

    // Well-formed-but-bogus signature over any message → clean failure.
    let result = verify_cose_signature(COSE_ALG_RS256, &key, b"message", &[0x30u8; 256]);
    assert!(matches!(
        result,
        Err(WebauthnError::SignatureVerificationFailed)
    ));

    // Wrong dispatch: RSA key under ES256 → key-type mismatch, not a crash.
    let result = verify_cose_signature(-7, &key, b"message", &[0x30u8; 256]);
    assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
}

/// Fixed-vector negative case: a stored challenge of known bytes must echo
/// exactly; any other client challenge is rejected.
#[test]
fn fixed_vector_challenge_echo() {
    let challenge = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": base64_encode_urlsafe(&challenge),
        "origin": ORIGIN,
    });
    // Attestation deliberately garbage: proves client-data validation runs first.
    let result = verify_registration(
        &challenge,
        &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
        &base64_encode_urlsafe(&[0xFF; 8]),
        "",
        RP_ID,
        &origins(),
    );
    // Must fail on attestation (challenge/origin/type all OK), i.e. AttestationError.
    assert!(matches!(result, Err(WebauthnError::AttestationError(_))));

    // One flipped challenge byte → challenge mismatch, never accepted.
    let mut wrong = challenge;
    wrong[0] ^= 0x01;
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": base64_encode_urlsafe(&wrong),
        "origin": ORIGIN,
    });
    let result = verify_registration(
        &challenge,
        &base64_encode_urlsafe(&serde_json::to_vec(&client_data).unwrap()),
        &base64_encode_urlsafe(&[0xFF; 8]),
        "",
        RP_ID,
        &origins(),
    );
    assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
}

/// DTO serde roundtrip behind the `serde` feature (enabled for tests via the
/// self dev-dependency).
#[test]
fn options_serde_roundtrip() {
    let config = WebauthnConfig {
        rp_id: "example.com".to_string(),
        rp_name: "Example".to_string(),
        rp_origins: vec!["https://example.com".to_string()],
        allowed_algorithms: vec![-7, -257],
        challenge_timeout_secs: 300,
    };
    let store = ChallengeStore::new();
    let (_, reg) =
        store.generate_registration_challenge(&config, "alice", "Alice", &["cred-9".to_string()]);
    let json = serde_json::to_string(&reg).unwrap();
    let back: webauthn_kit::RegistrationOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rp.id, "example.com");
    assert_eq!(back.exclude_credentials.len(), 1);

    let (_, auth) = store.generate_authentication_challenge(&config, vec!["cred-9".to_string()]);
    let json = serde_json::to_string(&auth).unwrap();
    let back: webauthn_kit::AuthenticationOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rp_id, "example.com");

    let credential = webauthn_kit::WebauthnCredential {
        credential_id: "abc".to_string(),
        public_key_cose: vec![1, 2, 3],
        sign_count: 7,
        device_name: "YubiKey 5".to_string(),
        registered_at: 1700000000,
        last_used_at: 1700000001,
        attestation_format: "none".to_string(),
        user_verified: true,
    };
    let json = serde_json::to_string(&credential).unwrap();
    let back: webauthn_kit::WebauthnCredential = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sign_count, 7);
}

/// base64url helper contract check (padding-less, URL-safe alphabet).
#[test]
fn base64url_no_pad_alphabet() {
    for len in 0..40usize {
        let data: Vec<u8> = (0..len as u8).collect();
        let enc = base64_encode_urlsafe(&data);
        assert!(!enc.contains('='), "no padding expected");
        assert!(!enc.contains('+'), "URL-safe alphabet expected");
        assert!(!enc.contains('/'), "URL-safe alphabet expected");
        let dec = base64_decode_urlsafe(&enc).unwrap();
        assert_eq!(dec, data);
    }
}
