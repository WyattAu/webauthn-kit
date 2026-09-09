//! COSE key parsing and signature verification (ES256 / RS256) via `ring`,
//! plus base64url helpers and CSPRNG challenge generation.
//!
//! # Security
//!
//! - All cryptographic primitives come from `ring` (constant-time ECDSA/RSA
//!   verification). This crate contains no hand-rolled cryptography; the only
//!   custom encoding is RFC 5280 DER *wrapping* of already-validated RSA
//!   modulus/exponent byte strings, which never touches secret material.
//! - Signature verification is constant-result: on failure the payload and
//!   signature are discarded and only an error variant is returned.

use crate::error::WebauthnError;

/// Parsed COSE public key (EC2 or RSA).
#[derive(Debug, Clone)]
pub enum CosePublicKey {
    /// Elliptic-curve (P-256) key with affine coordinates `x` and `y`.
    Ec2 {
        /// X coordinate, big-endian, 32 bytes for P-256.
        x: Vec<u8>,
        /// Y coordinate, big-endian, 32 bytes for P-256.
        y: Vec<u8>,
    },
    /// RSA key with modulus `n` and public exponent `e`.
    Rsa {
        /// RSA modulus, big-endian.
        n: Vec<u8>,
        /// RSA public exponent, big-endian (typically 0x010001).
        e: Vec<u8>,
    },
}

/// COSE key type: Octet Key Pair (Ed25519 et al.). Not supported.
pub const COSE_KTY_OKP: i64 = 1;
/// COSE key type: Elliptic-Curve key pair with x/y coordinates.
pub const COSE_KTY_EC2: i64 = 2;
/// COSE key type: RSA key.
pub const COSE_KTY_RSA: i64 = 3;

/// COSE algorithm: ECDSA w/ SHA-256 on P-256.
pub const COSE_ALG_ES256: i32 = -7;
/// COSE algorithm: RSASSA-PKCS1-v1_5 w/ SHA-256.
pub const COSE_ALG_RS256: i32 = -257;

/// COSE key map parameter label: key type (`kty`).
const COSE_KEY_KTY: i64 = 1;
/// COSE key map parameter label: algorithm (`alg`).
const COSE_KEY_ALG: i64 = 2;
/// COSE key map parameter label: curve (EC2) or modulus `n` (RSA).
const COSE_KEY_CRV_N: i64 = -1;
/// COSE key map parameter label: x coordinate (EC2) or exponent `e` (RSA).
const COSE_KEY_X_E: i64 = -2;
/// COSE key map parameter label: y coordinate (EC2).
const COSE_KEY_Y: i64 = -3;

/// COSE curve identifier: NIST P-256 (secp256r1).
const COSE_CRV_P256: i64 = 1;

/// Parse a CBOR integer from a value, handling both positive and negative.
fn cbor_i64(val: &ciborium::Value) -> Option<i64> {
    use ciborium::Value;
    match val {
        Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    }
}

/// Extract a CBOR byte string from a value.
///
/// # Security note
///
/// Deliberately lenient: a CBOR text string is accepted and re-interpreted as
/// its UTF-8 byte representation. This tolerates non-conformant authenticators
/// that encode binary fields as text. Length/format validation of the extracted
/// bytes happens downstream (`ring` rejects malformed keys at verify time).
pub fn cbor_bytes(val: &ciborium::Value) -> Option<Vec<u8>> {
    use ciborium::Value;
    match val {
        Value::Bytes(b) => Some(b.clone()),
        Value::Text(t) => Some(t.as_bytes().to_vec()),
        _ => None,
    }
}

/// Parse a CBOR map into ordered `(i64, Value)` entries.
///
/// Returns `None` if the value is not a map or any key is not an integer.
/// Duplicate keys are preserved in order; last occurrence wins when consumers
/// iterate and assign, matching CBOR common practice.
pub fn cbor_map_entries(val: &ciborium::Value) -> Option<Vec<(i64, ciborium::Value)>> {
    use ciborium::Value;
    match val {
        Value::Map(entries) => {
            let mut result = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let key = cbor_i64(k)?;
                result.push((key, v.clone()));
            }
            Some(result)
        }
        _ => None,
    }
}

/// Parse a COSE key from its CBOR encoding (RFC 9052).
///
/// Supports EC2/P-256 (`kty = 2`, `crv = 1`) and RSA (`kty = 3`). OKP keys
/// return [`WebauthnError::UnsupportedAlgorithm`]; unknown key types return
/// [`WebauthnError::VerificationFailed`].
///
/// # Security notes / threat assumptions
///
/// - `cose_bytes` is attacker-controlled input (it arrives inside authenticator
///   data). Parsing must never panic on arbitrary bytes; malformed input always
///   yields `Err`.
/// - The returned `alg` is whatever the key declares. Callers must check it is
///   one of [`COSE_ALG_ES256`] / [`COSE_ALG_RS256`] *and* pass it to
///   [`verify_cose_signature`], which cross-checks key type against algorithm
///   (e.g. an RSA key claiming `alg = -7` is rejected).
/// - Coordinate/modulus lengths are not pre-validated here; `ring` rejects
///   invalid lengths during signature verification.
///
/// # Requirements
/// REQ-WA-003, REQ-WA-100, REQ-WA-107
///
/// Returns the COSE algorithm identifier and the parsed key components.
pub fn parse_cose_key(cose_bytes: &[u8]) -> Result<(i32, CosePublicKey), WebauthnError> {
    use ciborium::Value;

    let key_val: Value = ciborium::de::from_reader(cose_bytes).map_err(|e| {
        WebauthnError::VerificationFailed(format!("COSE key CBOR parse error: {e}"))
    })?;

    let entries = cbor_map_entries(&key_val).ok_or_else(|| {
        WebauthnError::VerificationFailed("COSE key is not a CBOR map".to_string())
    })?;

    let mut kty: Option<i64> = None;
    let mut alg: Option<i32> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    let mut n: Option<Vec<u8>> = None;
    let mut e: Option<Vec<u8>> = None;

    for (label, val) in &entries {
        match *label {
            COSE_KEY_KTY => kty = cbor_i64(val),
            COSE_KEY_ALG => alg = cbor_i64(val).map(|v| v as i32),
            COSE_KEY_CRV_N => match kty {
                Some(COSE_KTY_RSA) => n = cbor_bytes(val),
                _ => crv = cbor_i64(val),
            },
            COSE_KEY_X_E => match kty {
                Some(COSE_KTY_RSA) => e = cbor_bytes(val),
                _ => x = cbor_bytes(val),
            },
            COSE_KEY_Y => y = cbor_bytes(val),
            _ => {}
        }
    }

    let kty =
        kty.ok_or_else(|| WebauthnError::VerificationFailed("COSE key missing 'kty'".to_string()))?;
    let alg =
        alg.ok_or_else(|| WebauthnError::VerificationFailed("COSE key missing 'alg'".to_string()))?;

    match kty {
        COSE_KTY_EC2 => {
            let crv = crv.ok_or_else(|| {
                WebauthnError::VerificationFailed("EC2 key missing 'crv'".to_string())
            })?;
            if crv != COSE_CRV_P256 {
                return Err(WebauthnError::UnsupportedAlgorithm(alg));
            }
            let x = x.ok_or_else(|| {
                WebauthnError::VerificationFailed("EC2 key missing 'x'".to_string())
            })?;
            let y = y.ok_or_else(|| {
                WebauthnError::VerificationFailed("EC2 key missing 'y'".to_string())
            })?;
            Ok((alg, CosePublicKey::Ec2 { x, y }))
        }
        COSE_KTY_RSA => {
            let n = n.ok_or_else(|| {
                WebauthnError::VerificationFailed("RSA key missing 'n'".to_string())
            })?;
            let e = e.ok_or_else(|| {
                WebauthnError::VerificationFailed("RSA key missing 'e'".to_string())
            })?;
            Ok((alg, CosePublicKey::Rsa { n, e }))
        }
        COSE_KTY_OKP => Err(WebauthnError::UnsupportedAlgorithm(alg)),
        other => Err(WebauthnError::VerificationFailed(format!(
            "Unsupported COSE key type: {other}"
        ))),
    }
}

/// Verify a COSE signature using the parsed public key.
///
/// # Security notes / threat assumptions
///
/// - `alg` is matched strictly: `ES256` requires an [`CosePublicKey::Ec2`]
///   key, `RS256` requires [`CosePublicKey::Rsa`]; any mismatch is an error,
///   never a fallback.
/// - `signed_data` and `signature` are attacker-controlled. Verification uses
///   `ring`'s constant-time implementations
///   (`ECDSA_P256_SHA256_FIXED`, `RSA_PKCS1_2048_8192_SHA256`).
/// - RSA keys smaller than 2048 bits are rejected by `ring`'s
///   `RSA_PKCS1_2048_8192_SHA256` parameters.
///
/// # Requirements
/// REQ-WA-106, REQ-WA-107
///
/// Returns `Ok(())` if and only if the signature verifies over `signed_data`.
pub fn verify_cose_signature(
    alg: i32,
    public_key: &CosePublicKey,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), WebauthnError> {
    use ring::signature;

    match alg {
        COSE_ALG_ES256 => {
            let CosePublicKey::Ec2 { x, y } = public_key else {
                return Err(WebauthnError::VerificationFailed(
                    "EC2 key expected for ES256".to_string(),
                ));
            };

            let mut public_key_bytes = Vec::with_capacity(1 + x.len() + y.len());
            public_key_bytes.push(0x04);
            public_key_bytes.extend_from_slice(x);
            public_key_bytes.extend_from_slice(y);

            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_FIXED,
                &public_key_bytes,
            );
            public_key
                .verify(signed_data, signature)
                .map_err(|_| WebauthnError::SignatureVerificationFailed)?;
            Ok(())
        }
        COSE_ALG_RS256 => {
            let CosePublicKey::Rsa { n, e } = public_key else {
                return Err(WebauthnError::VerificationFailed(
                    "RSA key expected for RS256".to_string(),
                ));
            };

            let rsa_public_key = RsaPublicKeyDer { n, e };
            let der_bytes = rsa_public_key.to_der()?;

            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                &der_bytes,
            );
            public_key
                .verify(signed_data, signature)
                .map_err(|_| WebauthnError::SignatureVerificationFailed)?;
            Ok(())
        }
        other => Err(WebauthnError::UnsupportedAlgorithm(other)),
    }
}

/// ASN.1 DER (PKCS#1 RFC 8017 `RSAPublicKey`) encoding helper for RSA
/// public keys.
struct RsaPublicKeyDer<'a> {
    n: &'a [u8],
    e: &'a [u8],
}

impl RsaPublicKeyDer<'_> {
    /// Encode modulus/exponent into a DER `RSAPublicKey` structure:
    /// `SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    ///
    /// This is the encoding `ring`'s RSA signature verifiers parse
    /// (`ring::rsa::parse_public_key`) — NOT an RFC 5280
    /// `SubjectPublicKeyInfo`.
    fn to_der(&self) -> Result<Vec<u8>, WebauthnError> {
        let mut der = Vec::new();
        Self::encode_integer(&mut der, self.n);
        Self::encode_integer(&mut der, self.e);
        Self::encode_sequence_in_place(&mut der);
        Ok(der)
    }

    /// DER-encode an INTEGER from a big-endian byte string.
    ///
    /// Strips leading zero octets and prepends a single `0x00` when the
    /// high bit is set, per DER INTEGER positivity rules (a form ring's
    /// DER parser accepts).
    fn encode_integer(buf: &mut Vec<u8>, value: &[u8]) {
        let start = value
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(value.len().saturating_sub(1));
        let v = value.get(start..).unwrap_or(&[]);
        if v.first().is_some_and(|&b| b & 0x80 != 0) {
            buf.push(0x02);
            Self::encode_length(buf, v.len() + 1);
            buf.push(0x00);
            buf.extend_from_slice(v);
        } else {
            buf.push(0x02);
            Self::encode_length(buf, v.len());
            buf.extend_from_slice(v);
        }
    }

    /// Wrap the existing buffer content in a SEQUENCE by shifting right.
    fn encode_sequence_in_place(buf: &mut Vec<u8>) {
        let content_len = buf.len();
        let header_len = if content_len < 0x80 {
            2
        } else if content_len < 0x100 {
            3
        } else {
            4
        };
        buf.resize(content_len + header_len, 0);
        buf.copy_within(..content_len, header_len);
        if let Some(tag) = buf.first_mut() {
            *tag = 0x30;
        }
        Self::encode_length_at(buf, 1, content_len);
    }

    /// DER-encode a length octet string at the end of `buf`.
    fn encode_length(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push((len & 0xFF) as u8);
        }
    }

    /// DER-encode a length octet string at `offset` in `buf`.
    ///
    /// INVARIANT: the caller guarantees `buf.len() >= offset + needed`,
    /// where `needed` is 1, 2, or 3 depending on `len` (callers size the
    /// buffer via the matching `header_len` computation before calling).
    /// The direct indexing below is therefore in-bounds by construction.
    #[allow(clippy::indexing_slicing)]
    fn encode_length_at(buf: &mut [u8], offset: usize, len: usize) {
        if len < 0x80 {
            buf[offset] = len as u8;
        } else if len < 0x100 {
            buf[offset] = 0x81;
            buf[offset + 1] = len as u8;
        } else {
            buf[offset] = 0x82;
            buf[offset + 1] = (len >> 8) as u8;
            buf[offset + 2] = (len & 0xFF) as u8;
        }
    }
}

/// Convert a COSE algorithm ID to a human-readable name.
pub fn alg_to_name(alg: i32) -> &'static str {
    match alg {
        COSE_ALG_ES256 => "ES256",
        COSE_ALG_RS256 => "RS256",
        _ => "unknown",
    }
}

/// Generate 32 random bytes (256 bits of entropy) for a `WebAuthn` challenge.
///
/// Uses the operating system CSPRNG via `ring::rand::SystemRandom`.
///
/// # Security notes
///
/// Challenges MUST come from a cryptographically secure source. If the OS
/// entropy source fails, this function panics rather than emit predictable
/// challenges (a failed CSPRNG is unrecoverable for security purposes).
///
/// # Requirements
/// REQ-WA-110
pub fn generate_challenge_bytes() -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    // INVARIANT: a failed OS CSPRNG is unrecoverable for security purposes
    // (documented above) — panicking is the deliberate, correct behavior.
    #[allow(clippy::expect_used)]
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("OS CSPRNG unavailable; cannot generate secure challenge");
    bytes.to_vec()
}

/// Base64url encode (RFC 4648 §5, no padding), as required by the `WebAuthn`
/// JSON serialization conventions.
pub fn base64_encode_urlsafe(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decode (RFC 4648 §5, no padding required; standard alphabet with
/// padding is also accepted by the engine's forgiving handling).
///
/// Returns [`WebauthnError::VerificationFailed`] on malformed input.
///
/// # Requirements
/// REQ-WA-004, REQ-WA-118
pub fn base64_decode_urlsafe(data: &str) -> Result<Vec<u8>, WebauthnError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| WebauthnError::VerificationFailed(format!("base64 decode error: {e}")))
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
pub(crate) mod tests {
    use super::*;

    /// Build a COSE EC2/P-256 key map around the given coordinates.
    pub(crate) fn build_cose_ec2_key(x: &[u8], y: &[u8]) -> Vec<u8> {
        use ciborium::Value;
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
            (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
        buf
    }

    /// Build a COSE RSA key map around the given modulus/exponent.
    pub(crate) fn build_cose_rsa_key(n: &[u8], e: &[u8]) -> Vec<u8> {
        use ciborium::Value;
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(3.into())),
            (Value::Integer(2.into()), Value::Integer((-257).into())),
            (Value::Integer((-1).into()), Value::Bytes(n.to_vec())),
            (Value::Integer((-2).into()), Value::Bytes(e.to_vec())),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_parse_cose_ec2_key() {
        let x = vec![0xAA; 32];
        let y = vec![0xBB; 32];
        let cose_key = build_cose_ec2_key(&x, &y);

        let (alg, key) = parse_cose_key(&cose_key).unwrap();
        assert_eq!(alg, -7);
        match key {
            CosePublicKey::Ec2 { x: kx, y: ky } => {
                assert_eq!(kx, x);
                assert_eq!(ky, y);
            }
            _ => panic!("Expected EC2 key"),
        }
    }

    #[test]
    fn test_parse_cose_rsa_key() {
        let n = vec![0xAA; 256];
        let e = vec![0x01, 0x00, 0x01];
        let cose_key = build_cose_rsa_key(&n, &e);

        let (alg, key) = parse_cose_key(&cose_key).unwrap();
        assert_eq!(alg, -257);
        match key {
            CosePublicKey::Rsa { n: kn, e: ke } => {
                assert_eq!(kn, n);
                assert_eq!(ke, e);
            }
            _ => panic!("Expected RSA key"),
        }
    }

    #[test]
    fn test_parse_cose_key_not_a_map() {
        let buf = [0x00u8]; // CBOR integer 0
        let result = parse_cose_key(&buf);
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_parse_cose_key_missing_kty() {
        use ciborium::Value;
        let map = vec![(Value::Integer(2.into()), Value::Integer((-7).into()))];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
        let result = parse_cose_key(&buf);
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn test_parse_cose_key_okp_unsupported() {
        use ciborium::Value;
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Integer((-8).into())),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
        let result = parse_cose_key(&buf);
        assert!(matches!(
            result,
            Err(WebauthnError::UnsupportedAlgorithm(-8))
        ));
    }

    #[test]
    fn test_verify_cose_signature_es256() {
        use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();

        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        let x = public_key_bytes[1..33].to_vec();
        let y = public_key_bytes[33..65].to_vec();

        let cose_key = CosePublicKey::Ec2 { x, y };
        let message = b"test message for WebAuthn";
        let signature = key_pair.sign(&rng, message).unwrap();

        let result = verify_cose_signature(COSE_ALG_ES256, &cose_key, message, signature.as_ref());
        assert!(result.is_ok());

        let wrong_result = verify_cose_signature(
            COSE_ALG_ES256,
            &cose_key,
            b"wrong message",
            signature.as_ref(),
        );
        assert!(matches!(
            wrong_result,
            Err(WebauthnError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_verify_cose_signature_alg_key_type_mismatch() {
        // RSA key material presented with alg = ES256 must be rejected.
        let n = vec![0xAA; 256];
        let e = vec![0x01, 0x00, 0x01];
        let cose_key = build_cose_rsa_key(&n, &e);
        let (alg, key) = parse_cose_key(&cose_key).unwrap();
        assert_eq!(alg, -257);

        let mismatch = verify_cose_signature(COSE_ALG_ES256, &key, b"data", &[0u8; 64]);
        assert!(matches!(
            mismatch,
            Err(WebauthnError::VerificationFailed(_))
        ));
    }

    #[test]
    fn test_verify_cose_signature_rs256() {
        let n = vec![
            0xC0, 0xE9, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let e = vec![0x01, 0x00, 0x01];
        let cose_key = build_cose_rsa_key(&n, &e);

        let (alg, key) = parse_cose_key(&cose_key).unwrap();
        assert_eq!(alg, -257);
        match key {
            CosePublicKey::Rsa { n: kn, e: ke } => {
                assert_eq!(kn, n);
                assert_eq!(ke, e);
            }
            _ => panic!("Expected RSA key"),
        }

        let rsa_key = RsaPublicKeyDer { n: &n, e: &e };
        let der = rsa_key.to_der().unwrap();
        assert_eq!(der[0], 0x30);
        assert!(der.len() > 40);
    }

    #[test]
    fn test_generate_challenge_bytes_length() {
        let bytes = generate_challenge_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_generate_challenge_bytes_not_all_zero() {
        // 256 zero bits from a CSPRNG is ~2^-256; treat as failure.
        let bytes = generate_challenge_bytes();
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"hello world";
        let encoded = base64_encode_urlsafe(original);
        let decoded = base64_decode_urlsafe(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base64_decode_urlsafe_invalid() {
        let result = base64_decode_urlsafe("NOT_VALID_BASE64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_encode_decode_empty() {
        let encoded = base64_encode_urlsafe(b"");
        let decoded = base64_decode_urlsafe(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_cbor_bytes_from_text_is_lenient() {
        use ciborium::Value;
        let v = Value::Text("abc".to_string());
        assert_eq!(cbor_bytes(&v), Some(b"abc".to_vec()));
        let v = Value::Null;
        assert_eq!(cbor_bytes(&v), None);
    }

    /// REQ-WA-202: DER INTEGER encoding must handle the all-zero value
    /// (single 0x00 octet), strip leading zeros, and prepend 0x00 for
    /// high-bit-set values — all without panicking.
    #[test]
    fn der_integer_encoding_edge_cases() {
        let mut buf = Vec::new();
        RsaPublicKeyDer::encode_integer(&mut buf, &[0u8; 8]);
        assert_eq!(buf, vec![0x02, 0x01, 0x00]);

        buf.clear();
        buf.clear();
        // High-bit-set value: a necessary positive-marker 0x00 is prepended.
        RsaPublicKeyDer::encode_integer(&mut buf, &[0x80, 0x00]);
        assert_eq!(buf, vec![0x02, 0x03, 0x00, 0x80, 0x00]);

        buf.clear();
        RsaPublicKeyDer::encode_integer(&mut buf, &[0x00, 0x00, 0x7F]);
        assert_eq!(buf, vec![0x02, 0x01, 0x7F]);

        buf.clear();
        // Empty modulus degenerates to a zero-length INTEGER (malformed DER);
        // the encoder stays total and `ring` rejects the key at verify time.
        RsaPublicKeyDer::encode_integer(&mut buf, &[]);
        assert_eq!(buf, vec![0x02, 0x00]);
    }

    // ---- error paths of parse_cose_key / verify_cose_signature ----

    /// Fixed 2048-bit RSA test key (PKCS#8 DER, base64). ring cannot
    /// generate RSA keys, so the fixture is pre-generated with openssl.
    pub(crate) const RSA_PKCS8_B64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWaabvRsESS9rP70iKb473SMUwLEeKvSBGd2DcB4CgcjL2b69pqy7Mgp8ZXZlbJ96cK8y0OFZFKzFs5tLGVcG3JbkYSnFAgCHtW+k29N9B7XJe5k5K1p0piKQoeth8GX2QhYTNECABAU+FeKxAwjojTqVPH2oXNs7c7rQe5y03PYFqyrr0IyMt8QIXsjH7VVnTps/ojUQFqCPSqSi8Yb8BxokjtVd1K5IOlwYsfHLYBFefg3YTigQ5J/ZHZoL1oPRihRzPIEgDu4LmIT2Xp9Hzs9QV1DdLK2DxBcaMDyR/JEL1+LhnxD/HkaNdEDA/FA28JVl9GxHkHMEw3oyvEPDRAgMBAAECggEABS5GbbTGLwHQhkZQ/VOyXO9zZfa10CA2Mwx8Qu055PeKAdWpo74dsorykpvCuH0QZy4AXa9tvpwqQPytAzUuTZyjBM8rmh56YgPpwywpXx/1RzIvktb+5XtWDCmPDgHiwqOWsL7UG19sLxtk83tn0pIsPM7G3LMqlOQz7WHmZiH5UZmNKHcs5Gu5LxGoyMTN1weXk5Nx1OG63sUaXwFbaRv10Z+w6KBSpY9+fQDOXuet/5HwOl1cLXOcQeCXBsMDVUIU78+fsyqzZzIl7WL+rD1ulwCHcEFou3JxsFS+AuGXGAo6rIaFEOXR8g5vIF3g20zLCWYEzAByTUJa1hvnMQKBgQDS6gd8pbKi1cbg75s8JrNEFmMp3C2pAA42FvFQuigVy5p+92Lv3dLFM3a+UOz3l2DFwTQEUzm6tDKCCsMr5J2W8OZCQJ+QvvmI4ErN3X4h/HF6zcM9cZScMQN6/qe/jk6UMuzBFkenajbSvvvuKqlzV9zFmSV6+qh88CDTwiwCcwKBgQC2kMSYDFKPDsHqGgHOsaytHsi4lyUUGtIOVo+kvGWKYycr3V6q/sliMJ6v/E1SdVSJCDPyZbWc0fL9+PNhHrF5PGKS+HAjXsvQ+xOzXweByDiAZVmVNKxHmf9LFiAPPzUGIMxzwT9TU823E62aXybfgz7wCCFXx3Eh4sPCjN36qwKBgDKr2QqgQG+QjoxB5HiqD41/F2naJPoiMkfacTVk0/aQiNiSFKnuEBIikBefF59QNgasqROU7xyk6DGH5mXoMdgunhMytWMwDoFM6YvV99Swco7/WjWr0PlJaT2maqTByq0eIvUspiBZizxMd/g7NaSpajfq2C9YgxwpEKnvT2VzAoGAT6SL/wCxK3N2qNe7nh3ohIV/bveQ11pz9IlSlL0TVvG2bu5dlB8eX1VyhLd+S9CflkAb2U0Bk24LoTvvgJjRN2BeaFs1IFkEdSBzEbcNIVLlQy3zjKGz3nCR7IG0brJWQVwhlQXiyEkw3wMYotWLscohtLj3QsHg2rWATOkDFY0CgYEAuc5W0GMzucY940ok8VoIBrsD/FVtpfflsx/FDGUafBjvQ/2kLH7iyfZLX0jFTACiazLpxZESVcxEWYEr2Rz4KG7GGKYkppwMoH43Xk1L+zkR2ZeEHnzTzwLdVhczqGTs90V4HCYwLKzXqgJPZeH/42ngQuA/8dUrQ/9ofV68k4A=";

    /// Decode a DER TLV at `i`; returns `(content, rest)`.
    fn der_tlv(i: &[u8]) -> (&[u8], &[u8]) {
        let l0 = *i.get(1).unwrap();
        let (header, len) = if l0 < 0x80 {
            (2usize, l0 as usize)
        } else {
            let n = (l0 & 0x7F) as usize;
            let mut len = 0usize;
            for b in &i[2..2 + n] {
                len = (len << 8) | *b as usize;
            }
            (2 + n, len)
        };
        (&i[header..header + len], &i[header + len..])
    }

    /// (modulus, exponent, PKCS#8 DER) for the fixed RSA test key.
    pub(crate) fn rsa_test_material() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use base64::Engine as _;
        let pkcs8 = base64::engine::general_purpose::STANDARD
            .decode(RSA_PKCS8_B64)
            .unwrap();
        // PrivateKeyInfo ::= SEQ { version, algorithm, OCTET STRING {
        //   RSAPrivateKey ::= SEQ { version, n, e, ... } } }
        let (info, _) = der_tlv(&pkcs8);
        let (_version, rest) = der_tlv(info);
        let (_algorithm, rest) = der_tlv(rest);
        let (octet, _) = der_tlv(rest);
        let (rsa_key, _) = der_tlv(octet);
        let (_version, rest) = der_tlv(rsa_key);
        let (n, rest) = der_tlv(rest);
        let (e, _) = der_tlv(rest);
        (n.to_vec(), e.to_vec(), pkcs8)
    }

    /// Minimal-encoding SPKI for the fixed RSA test key, as ring's RSA
    /// verifier requires (see `RsaPublicKeyDer::encode_integer`).
    pub(crate) fn rsa_test_spki() -> Vec<u8> {
        let (n, e, _) = rsa_test_material();
        RsaPublicKeyDer { n: &n, e: &e }.to_der().unwrap()
    }

    fn cose_key_from(entries: Vec<(i64, ciborium::Value)>) -> Vec<u8> {
        use ciborium::Value;
        let map: Vec<(Value, Value)> = entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
        buf
    }

    #[test]
    fn parse_cose_key_garbage_cbor_is_error() {
        // 0xFF is a reserved CBOR major type: parse must fail, never panic.
        let result = parse_cose_key(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(matches!(result, Err(WebauthnError::VerificationFailed(_))));
    }

    #[test]
    fn parse_cose_key_ec2_missing_crv() {
        let buf = cose_key_from(vec![
            (1, ciborium::Value::Integer(2.into())),
            (2, ciborium::Value::Integer((-7).into())),
            (-2, ciborium::Value::Bytes(vec![0xAA; 32])),
            (-3, ciborium::Value::Bytes(vec![0xBB; 32])),
        ]);
        assert!(matches!(
            parse_cose_key(&buf),
            Err(WebauthnError::VerificationFailed(_))
        ));
    }

    #[test]
    fn parse_cose_key_ec2_wrong_curve_is_unsupported() {
        let buf = cose_key_from(vec![
            (1, ciborium::Value::Integer(2.into())),
            (2, ciborium::Value::Integer((-7).into())),
            (-1, ciborium::Value::Integer(3.into())), // P-384, not P-256
            (-2, ciborium::Value::Bytes(vec![0xAA; 48])),
            (-3, ciborium::Value::Bytes(vec![0xBB; 48])),
        ]);
        assert!(matches!(
            parse_cose_key(&buf),
            Err(WebauthnError::UnsupportedAlgorithm(-7))
        ));
    }

    #[test]
    fn parse_cose_key_ec2_missing_coordinates() {
        let kty_alg = vec![
            (1, ciborium::Value::Integer(2.into())),
            (2, ciborium::Value::Integer((-7).into())),
            (-1, ciborium::Value::Integer(1.into())),
        ];
        let missing_x = cose_key_from(
            [
                kty_alg.clone(),
                vec![(-3, ciborium::Value::Bytes(vec![0xBB; 32]))],
            ]
            .concat(),
        );
        assert!(matches!(
            parse_cose_key(&missing_x),
            Err(WebauthnError::VerificationFailed(_))
        ));

        let missing_y =
            cose_key_from([kty_alg, vec![(-2, ciborium::Value::Bytes(vec![0xAA; 32]))]].concat());
        assert!(matches!(
            parse_cose_key(&missing_y),
            Err(WebauthnError::VerificationFailed(_))
        ));
    }

    #[test]
    fn parse_cose_key_rsa_missing_modulus_or_exponent() {
        let missing_n = cose_key_from(vec![
            (1, ciborium::Value::Integer(3.into())),
            (2, ciborium::Value::Integer((-257).into())),
            (-2, ciborium::Value::Bytes(vec![0x01, 0x00, 0x01])),
        ]);
        assert!(matches!(
            parse_cose_key(&missing_n),
            Err(WebauthnError::VerificationFailed(_))
        ));

        let missing_e = cose_key_from(vec![
            (1, ciborium::Value::Integer(3.into())),
            (2, ciborium::Value::Integer((-257).into())),
            (-1, ciborium::Value::Bytes(vec![0xAA; 256])),
        ]);
        assert!(matches!(
            parse_cose_key(&missing_e),
            Err(WebauthnError::VerificationFailed(_))
        ));
    }

    #[test]
    fn parse_cose_key_unknown_kty_is_error() {
        let buf = cose_key_from(vec![
            (1, ciborium::Value::Integer(99.into())),
            (2, ciborium::Value::Integer((-7).into())),
        ]);
        assert!(matches!(
            parse_cose_key(&buf),
            Err(WebauthnError::VerificationFailed(_))
        ));
    }

    #[test]
    fn cbor_map_entries_rejects_non_integer_keys() {
        use ciborium::Value;
        let map = Value::Map(vec![(
            Value::Text("kty".to_string()),
            Value::Integer(2.into()),
        )]);
        assert!(cbor_map_entries(&map).is_none());
    }

    #[test]
    fn verify_rs256_with_ec_key_is_rejected() {
        let key = CosePublicKey::Ec2 {
            x: vec![0xAA; 32],
            y: vec![0xBB; 32],
        };
        assert!(matches!(
            verify_cose_signature(COSE_ALG_RS256, &key, b"data", &[0u8; 256]),
            Err(WebauthnError::VerificationFailed(_))
        ));
    }

    #[test]
    fn verify_cose_signature_unknown_alg_is_rejected() {
        let key = CosePublicKey::Ec2 {
            x: vec![0xAA; 32],
            y: vec![0xBB; 32],
        };
        assert!(matches!(
            verify_cose_signature(-47, &key, b"data", &[0u8; 64]),
            Err(WebauthnError::UnsupportedAlgorithm(-47))
        ));
    }

    #[test]
    fn alg_to_name_covers_known_and_unknown() {
        assert_eq!(alg_to_name(COSE_ALG_ES256), "ES256");
        assert_eq!(alg_to_name(COSE_ALG_RS256), "RS256");
        assert_eq!(alg_to_name(0), "unknown");
    }

    /// RS256 end-to-end: a real 2048-bit RSA signature verifies through the
    /// RS256 arm (PKCS#1 v1.5 + SHA-256), a tampered message fails closed.
    #[test]
    fn verify_rs256_real_signature_roundtrip() {
        use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

        let (n, e, pkcs8) = rsa_test_material();
        let rsa = RsaKeyPair::from_pkcs8(&pkcs8).unwrap();
        let modulus_len = rsa.public().modulus_len();
        assert_eq!(modulus_len, 256);

        // Sign with ring, verify through the COSE RS256 arm.
        let rng = ring::rand::SystemRandom::new();
        let message = b"webauthn-kit rs256 vector";
        let mut signature = vec![0u8; modulus_len];
        rsa.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
            .unwrap();

        let key = CosePublicKey::Rsa { n, e };
        assert!(verify_cose_signature(COSE_ALG_RS256, &key, message, &signature).is_ok());

        // One flipped message byte must fail closed.
        let mut tampered = *message;
        tampered[0] ^= 0x01;
        assert!(matches!(
            verify_cose_signature(COSE_ALG_RS256, &key, &tampered, &signature),
            Err(WebauthnError::SignatureVerificationFailed)
        ));
    }

    /// DER long-form length encoding: a 128-byte modulus forces both the
    /// standalone length encoder and the in-place header writer through
    /// their `0x81` (single length byte) branches.
    #[test]
    fn der_long_form_length_encoding() {
        let n = [0x77u8; 128];
        let e = [0x01, 0x00, 0x01];
        let der = RsaPublicKeyDer { n: &n, e: &e }.to_der().unwrap();

        // RSAPublicKey: outer SEQ header uses the 0x81 long form.
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1], 0x81);
        assert_eq!(der[2] as usize + 3, der.len());
        // The 128-byte INTEGER itself also uses the long form.
        assert!(der.windows(3).any(|w| w == [0x02, 0x81, 0x80]));
    }
}
