//! Attestation statement parsing and verification (WebAuthn Level 2 §8).
//!
//! Tranche 1 implements the three formats that cover the overwhelming
//! majority of real registrations:
//!
//! - **`none`** (§8.1): no attestation statement; the ceremony reduces to
//!   proving possession of the credential private key. Enforced strictly:
//!   the statement must be an empty CBOR map ([`AttestationFormat::None`]).
//! - **`packed`** (§8.2): self-attestation (signature with the credential
//!   key) or basic/AttCA attestation (signature with the first certificate's
//!   key, optionally chained to a configured trust anchor).
//! - **`fido-u2f`** (§8.6): the legacy FIDO U2F attestation, verified over
//!   the U2F transport encoding with exactly one attestation certificate.
//!
//! # Trust levels
//!
//! [`TrustLevel`] reports what a *verified* attestation actually proves:
//!
//! - [`TrustLevel::None`]: key possession only (`none` format).
//! - [`TrustLevel::SelfAttested`]: the credential key signed the statement
//!   (packed self-attestation) — possession, not provenance.
//! - [`TrustLevel::BasicAtt`]: a certificate chain internally consistent and
//!   rooted at a self-signed certificate, but **not** anchored to any RP-
//!   configured trust anchor. Anyone can mint such a chain; treat exactly
//!   like self-attestation. A warning is always emitted (see
//!   [`warnings::UNANCHORED_CHAIN`]).
//! - [`TrustLevel::AttCa`]: the chain terminates at a caller-configured
//!   trust anchor — the only level that attests device provenance.
//!
//! # Security notes / threat assumptions
//!
//! - Every statement field arrives from the hostile client. Parsing is total:
//!   malformed input yields `Err`, never a panic (fuzz-tested).
//! - Signature checks are fail-closed: any unexpected certificate property
//!   (unsupported algorithm, non-v3, expired, non-CA intermediate, AAGUID
//!   extension mismatch) aborts verification.
//! - Trust-anchor matching is caller policy: `AttestationPolicy::trust_anchors`
//!   empty accepts unanchored chains *flagged* as [`TrustLevel::BasicAtt`]
//!   with [`warnings::UNANCHORED_CHAIN`] — callers enforcing provenance MUST
//!   configure anchors and inspect [`AttestationResult::trust_level`].
//! - Certificate revocation (OCSP/CRL) is out of scope; see THREAT-MODEL.md.
//!
//! # Requirements
//! REQ-WA-119, REQ-WA-120, REQ-WA-121, REQ-WA-122, REQ-WA-123, REQ-WA-124,
//! REQ-WA-125, REQ-WA-126, REQ-WA-127, REQ-WA-128, REQ-WA-129, REQ-WA-130,
//! REQ-WA-132

use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::Value;
use x509_parser::prelude::*;

use crate::crypto::{
    cbor_bytes, cbor_map_entries, verify_cose_signature, CosePublicKey, COSE_ALG_ES256,
    COSE_ALG_RS256,
};
use crate::error::WebauthnError;

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

/// WebAuthn attestation statement format identifier (WebAuthn L2 §5.1.4).
///
/// Parsed from the `fmt` string of the attestation object. [`AttestationFormat::Unknown`]
/// exists so a registration can be accepted under the documented
/// `allow_unknown_formats` escape hatch while still reporting honestly that
/// its statement was **not** verified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AttestationFormat {
    /// `fmt = "none"`: no attestation statement.
    None,
    /// `fmt = "packed"`: self-attestation or basic/AttCA attestation.
    Packed,
    /// `fmt = "fido-u2f"`: legacy FIDO U2F attestation.
    FidoU2f,
    /// Any other `fmt` value (accepted only via the `allow_unknown_formats`
    /// escape hatch; the statement is never verified).
    Unknown,
}

impl AttestationFormat {
    /// Parse an attestation-object `fmt` string.
    pub fn from_fmt(fmt: &str) -> Self {
        match fmt {
            "none" => AttestationFormat::None,
            "packed" => AttestationFormat::Packed,
            "fido-u2f" => AttestationFormat::FidoU2f,
            _ => AttestationFormat::Unknown,
        }
    }

    /// Canonical `fmt` string for this format (unknown formats report
    /// `"unknown"`; see [`AttestationFormat::Unknown`]).
    pub fn as_fmt(&self) -> &'static str {
        match self {
            AttestationFormat::None => "none",
            AttestationFormat::Packed => "packed",
            AttestationFormat::FidoU2f => "fido-u2f",
            AttestationFormat::Unknown => "unknown",
        }
    }
}

/// What a verified attestation proves about the credential's provenance.
///
/// Ordered from weakest to strongest. See the module docs for the exact
/// semantics — in particular [`TrustLevel::BasicAtt`] chains are *not*
/// anchored to a configured trust anchor and must be treated as
/// [`TrustLevel::SelfAttested`] by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TrustLevel {
    /// No attestation claim (`none` format): key possession only.
    None,
    /// The credential key itself signed the statement (packed
    /// self-attestation): key possession only.
    SelfAttested,
    /// A syntactically valid, internally consistent certificate chain rooted
    /// at a self-signed certificate that is **not** an RP-configured trust
    /// anchor. Equivalent in trust to [`TrustLevel::SelfAttested`]; always
    /// accompanied by [`warnings::UNANCHORED_CHAIN`].
    BasicAtt,
    /// The chain terminates at an RP-configured trust anchor: real device
    /// provenance (AttCA / basic attestation with a trusted root).
    AttCa,
}

/// Warning strings emitted into [`AttestationResult::warnings`].
///
/// Warnings are stable string constants so callers can match on them.
pub mod warnings {
    /// A certificate chain was accepted without any configured trust anchor;
    /// its provenance is equivalent to self-attestation.
    pub const UNANCHORED_CHAIN: &str =
        "attestation chain accepted without a configured trust anchor; \
         treat as self-attested";
    /// An unknown attestation format was accepted via the
    /// `allow_unknown_formats` escape hatch; its statement was NOT verified.
    pub const UNVERIFIED_FORMAT: &str =
        "unknown attestation format accepted via allow_unknown_formats; \
         statement was not verified";
}

/// Result of attestation verification for a registration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AttestationResult {
    /// The attestation format that was used.
    pub format: AttestationFormat,
    /// AAGUID from attested credential data (always present during
    /// registration; U2F authenticators report the all-zero AAGUID).
    pub aaguid: Option<[u8; 16]>,
    /// What the verified attestation proves. Callers enforcing device
    /// provenance MUST require [`TrustLevel::AttCa`].
    pub trust_level: TrustLevel,
    /// Trust-relevant warnings (e.g. [`warnings::UNANCHORED_CHAIN`]).
    pub warnings: Vec<&'static str>,
}

/// Caller policy for attestation verification.
///
/// # Security notes
///
/// - `trust_anchors` empty means *any* internally-consistent, self-rooted
///   chain is accepted at [`TrustLevel::BasicAtt`] with
///   [`warnings::UNANCHORED_CHAIN`] — a deliberate flag-not-block default so
///   unmodified integrations keep working, documented as trust-weakening.
///   Configure your attestation root certificates here to upgrade verified
///   chains to [`TrustLevel::AttCa`].
/// - `allow_unknown_formats = true` is an explicit trust-weakening escape
///   hatch: registrations with unrecognized `fmt` values are accepted with
///   [`warnings::UNVERIFIED_FORMAT`] instead of rejected. Leave it `false`
///   unless you know you need it.
#[derive(Debug, Clone, Default)]
pub struct AttestationPolicy {
    /// DER-encoded X.509 attestation root (trust anchor) certificates.
    /// Empty accepts any self-rooted chain, flagged (see struct docs).
    pub trust_anchors: Vec<Vec<u8>>,
    /// Accept unknown attestation formats with a warning instead of
    /// rejecting them (trust-weakening; see struct docs).
    pub allow_unknown_formats: bool,
}

impl AttestationPolicy {
    /// Strict policy: no trust anchors, unknown formats rejected.
    ///
    /// This still verifies `none`/`packed`/`fido-u2f` self-attestation and
    /// unanchored chains (flagged); add `trust_anchors` to enforce
    /// provenance ([`TrustLevel::AttCa`] only).
    pub fn strict() -> Self {
        Self::default()
    }
}

/// Parsed attestation statement (CBOR `attStmt` map).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttestationStatement {
    /// Empty statement (`none` format).
    None,
    /// Packed statement: COSE algorithm, signature, optional cert chain.
    Packed {
        /// COSE algorithm identifier used for `sig`.
        alg: i32,
        /// Signature over `authData || clientDataHash`.
        sig: Vec<u8>,
        /// Optional X.509 certificate chain (DER), leaf first.
        x5c: Vec<Vec<u8>>,
    },
    /// FIDO U2F statement: signature plus exactly one certificate.
    FidoU2f {
        /// Signature over the U2F registration message.
        sig: Vec<u8>,
        /// The single attestation certificate (DER).
        cert: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// OID constants (compared as DER-encoded bytes via `Oid::as_bytes`)
// ---------------------------------------------------------------------------

/// OID 1.2.840.113549.1.1.11 — sha256WithRSAEncryption.
const OID_SIG_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// OID 1.2.840.10045.4.3.2 — ecdsa-with-SHA256.
const OID_SIG_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// OID 1.2.840.113549.1.1.1 — rsaEncryption.
const OID_ALG_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// OID 1.2.840.10045.2.1 — id-ecPublicKey.
const OID_ALG_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// OID 2.5.29.19 — basicConstraints.
const OID_EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
/// OID 1.3.6.1.4.1.45724.1.1.4 — id-fido-gen-ce-aaguid (FIDO 2.1 §8.2.1).
const OID_EXT_FIDO_GEN_CE_AAGUID: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x14, 0x01, 0x04];

// ---------------------------------------------------------------------------
// Statement parsing
// ---------------------------------------------------------------------------

/// CBOR `attStmt` label: `alg` (COSE algorithm identifier).
const STMT_LABEL_ALG: i64 = 3;
/// CBOR `attStmt` label: `sig` (signature byte string).
const STMT_LABEL_SIG: i64 = 8;
/// CBOR `attStmt` label: `x5c` (X.509 certificate chain array).
const STMT_LABEL_X5C: i64 = 33;

/// Parse the raw `attStmt` CBOR value for the given format.
///
/// `att_stmt` is `None` when the attestation object carried no statement
/// entry at all (only legal for the `none` format).
///
/// # Requirements
/// REQ-WA-119, REQ-WA-128, REQ-WA-132
pub(crate) fn parse_statement(
    format: &AttestationFormat,
    att_stmt: Option<&Value>,
) -> Result<AttestationStatement, WebauthnError> {
    match format {
        AttestationFormat::None => {
            // WebAuthn L2 §8.1: attStmt MUST be an empty CBOR map.
            match att_stmt {
                None => Ok(AttestationStatement::None),
                Some(Value::Map(entries)) if entries.is_empty() => Ok(AttestationStatement::None),
                Some(_) => Err(WebauthnError::AttestationError(
                    "attStmt must be an empty map for the 'none' format".to_string(),
                )),
            }
        }
        AttestationFormat::Packed => {
            let val = att_stmt.ok_or_else(|| {
                WebauthnError::AttestationError(
                    "missing attStmt for the 'packed' format".to_string(),
                )
            })?;
            let entries = cbor_map_entries(val).ok_or_else(|| {
                WebauthnError::AttestationError(
                    "attStmt is not a CBOR map for the 'packed' format".to_string(),
                )
            })?;

            let mut alg: Option<i32> = None;
            let mut sig: Option<Vec<u8>> = None;
            let mut x5c: Vec<Vec<u8>> = Vec::new();

            for (label, v) in &entries {
                match *label {
                    STMT_LABEL_ALG => alg = cbor_alg(v),
                    STMT_LABEL_SIG => sig = cbor_bytes(v),
                    STMT_LABEL_X5C => x5c = cbor_cert_array(v)?,
                    _ => {}
                }
            }

            let alg = alg.ok_or_else(|| {
                WebauthnError::AttestationError("packed attStmt missing 'alg'".to_string())
            })?;
            let sig = sig.ok_or_else(|| {
                WebauthnError::AttestationError("packed attStmt missing 'sig'".to_string())
            })?;

            Ok(AttestationStatement::Packed { alg, sig, x5c })
        }
        AttestationFormat::FidoU2f => {
            let val = att_stmt.ok_or_else(|| {
                WebauthnError::AttestationError(
                    "missing attStmt for the 'fido-u2f' format".to_string(),
                )
            })?;
            let entries = cbor_map_entries(val).ok_or_else(|| {
                WebauthnError::AttestationError(
                    "attStmt is not a CBOR map for the 'fido-u2f' format".to_string(),
                )
            })?;

            let mut sig: Option<Vec<u8>> = None;
            let mut x5c: Vec<Vec<u8>> = Vec::new();

            for (label, v) in &entries {
                match *label {
                    STMT_LABEL_SIG => sig = cbor_bytes(v),
                    STMT_LABEL_X5C => x5c = cbor_cert_array(v)?,
                    _ => {}
                }
            }

            let sig = sig.ok_or_else(|| {
                WebauthnError::AttestationError("fido-u2f attStmt missing 'sig'".to_string())
            })?;
            // WebAuthn L2 §8.6: x5c carries exactly one attestation certificate.
            let [cert] = x5c.as_slice() else {
                return Err(WebauthnError::AttestationError(
                    "fido-u2f attStmt must carry exactly one x5c certificate".to_string(),
                ));
            };

            Ok(AttestationStatement::FidoU2f {
                sig,
                cert: cert.clone(),
            })
        }
        // Unknown formats are a policy decision, never parsed.
        AttestationFormat::Unknown => Err(WebauthnError::AttestationError(
            "unknown attestation format cannot be parsed".to_string(),
        )),
    }
}

/// Extract an `i32` COSE algorithm from a CBOR value.
fn cbor_alg(val: &Value) -> Option<i32> {
    match val {
        Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    }
}

/// Extract the `x5c` certificate array: a CBOR array of byte strings.
fn cbor_cert_array(val: &Value) -> Result<Vec<Vec<u8>>, WebauthnError> {
    match val {
        Value::Array(items) => {
            let mut certs = Vec::with_capacity(items.len());
            for item in items {
                certs.push(cbor_bytes(item).ok_or_else(|| {
                    WebauthnError::AttestationError(
                        "x5c contains a non-byte-string certificate".to_string(),
                    )
                })?);
            }
            Ok(certs)
        }
        _ => Err(WebauthnError::AttestationError(
            "x5c is not a CBOR array".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Verification entry point
// ---------------------------------------------------------------------------

/// Verify an attestation statement for a registration ceremony.
///
/// Dispatches on the parsed format (see the module docs for the per-format
/// verification procedures) and returns the attestation result on success.
///
/// Parameters:
///
/// - `fmt`: the raw `fmt` string from the attestation object.
/// - `att_stmt`: the raw CBOR `attStmt` value (`None` if absent).
/// - `auth_data`: the raw authenticator data bytes.
/// - `client_data_hash`: SHA-256 of the raw `clientDataJSON`.
/// - `credential_id`: the raw credential ID from attested credential data.
/// - `credential_alg` / `credential_key`: the COSE algorithm and parsed
///   public key of the *new credential* (from attested credential data).
/// - `aaguid`: the 16-byte AAGUID from attested credential data.
/// - `policy`: the caller's trust-anchor / unknown-format policy.
///
/// # Requirements
/// REQ-WA-119, REQ-WA-120, REQ-WA-121, REQ-WA-122, REQ-WA-123, REQ-WA-124,
/// REQ-WA-126, REQ-WA-127, REQ-WA-128, REQ-WA-129, REQ-WA-130
#[allow(clippy::too_many_arguments)]
pub fn verify_attestation(
    fmt: &str,
    att_stmt: Option<&Value>,
    auth_data: &[u8],
    client_data_hash: &[u8],
    credential_id: &[u8],
    credential_alg: i32,
    credential_key: &CosePublicKey,
    aaguid: [u8; 16],
    policy: &AttestationPolicy,
) -> Result<AttestationResult, WebauthnError> {
    let format = AttestationFormat::from_fmt(fmt);

    // Unknown format: reject unless the caller opted in (REQ-WA-126).
    if format == AttestationFormat::Unknown {
        if policy.allow_unknown_formats {
            return Ok(AttestationResult {
                format,
                aaguid: Some(aaguid),
                trust_level: TrustLevel::None,
                warnings: vec![warnings::UNVERIFIED_FORMAT],
            });
        }
        return Err(WebauthnError::AttestationError(format!(
            "unsupported attestation format: '{fmt}'"
        )));
    }

    let statement = parse_statement(&format, att_stmt)?;

    match statement {
        AttestationStatement::None => verify_none_statement(aaguid),
        AttestationStatement::Packed { alg, sig, x5c } => {
            if x5c.is_empty() {
                verify_packed_self(
                    &alg,
                    &sig,
                    auth_data,
                    client_data_hash,
                    credential_alg,
                    credential_key,
                    aaguid,
                )
            } else {
                verify_packed_x5c(
                    &alg,
                    &sig,
                    auth_data,
                    client_data_hash,
                    &x5c,
                    aaguid,
                    policy,
                )
            }
        }
        AttestationStatement::FidoU2f { sig, cert } => verify_fido_u2f(
            &sig,
            &cert,
            auth_data,
            client_data_hash,
            credential_id,
            credential_alg,
            credential_key,
            aaguid,
            policy,
        ),
    }
}

/// `none` format: the statement itself was already checked to be an empty
/// map by [`parse_statement`] — the registration ceremony establishes key
/// possession and nothing more.
///
/// # Requirements
/// REQ-WA-119, REQ-WA-128
fn verify_none_statement(aaguid: [u8; 16]) -> Result<AttestationResult, WebauthnError> {
    Ok(AttestationResult {
        format: AttestationFormat::None,
        aaguid: Some(aaguid),
        trust_level: TrustLevel::None,
        warnings: Vec::new(),
    })
}

/// Packed self-attestation (no x5c): the signature over
/// `authData || clientDataHash` MUST verify with the credential public key
/// and the statement `alg` MUST match the credential key's algorithm.
///
/// # Requirements
/// REQ-WA-120, REQ-WA-127
fn verify_packed_self(
    alg: &i32,
    sig: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8],
    credential_alg: i32,
    credential_key: &CosePublicKey,
    aaguid: [u8; 16],
) -> Result<AttestationResult, WebauthnError> {
    if *alg != credential_alg {
        return Err(WebauthnError::AttestationError(format!(
            "packed self-attestation alg {alg} does not match credential key alg {credential_alg}"
        )));
    }

    let signed = signed_data(auth_data, client_data_hash);
    // Cross-checks key type vs alg and verifies with ring (constant-time).
    verify_cose_signature(*alg, credential_key, &signed, sig)?;

    Ok(AttestationResult {
        format: AttestationFormat::Packed,
        aaguid: Some(aaguid),
        trust_level: TrustLevel::SelfAttested,
        warnings: Vec::new(),
    })
}

/// Packed basic/AttCA attestation (x5c present): the signature MUST verify
/// with the first certificate's public key, the statement `alg` MUST match
/// the certificate key type, and the chain MUST satisfy the policy.
///
/// # Requirements
/// REQ-WA-121, REQ-WA-122, REQ-WA-123, REQ-WA-125, REQ-WA-127
fn verify_packed_x5c(
    alg: &i32,
    sig: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8],
    x5c: &[Vec<u8>],
    aaguid: [u8; 16],
    policy: &AttestationPolicy,
) -> Result<AttestationResult, WebauthnError> {
    // The statement signs with the attestation certificate's key; its alg
    // must be one of the algorithms this crate verifies at all.
    if *alg != COSE_ALG_ES256 && *alg != COSE_ALG_RS256 {
        return Err(WebauthnError::UnsupportedAlgorithm(*alg));
    }

    let leaf = Cert::from_der(x5c.first().ok_or_else(|| {
        WebauthnError::AttestationError("packed attStmt has an empty x5c chain".to_string())
    })?)?;

    // Statement alg vs certificate key type cross-check (fail closed on
    // mismatch, mirroring REQ-WA-107 semantics for COSE keys).
    let expected = match *alg {
        COSE_ALG_ES256 => KeyKind::Ec2,
        _ => KeyKind::Rsa,
    };
    if leaf.kind != expected {
        return Err(WebauthnError::AttestationError(
            "packed attestation alg does not match the attestation certificate key type"
                .to_string(),
        ));
    }

    let signed = signed_data(auth_data, client_data_hash);
    verify_signature_with_cert(&leaf, &signed, sig)?;

    // AAGUID extension: if present, MUST match the attested credential data
    // AAGUID (FIDO 2.1 §8.2.1).
    check_aaguid_extension(&leaf, &aaguid)?;

    let (trust_level, warnings) = verify_chain(x5c, policy)?;

    Ok(AttestationResult {
        format: AttestationFormat::Packed,
        aaguid: Some(aaguid),
        trust_level,
        warnings,
    })
}

/// FIDO U2F attestation (WebAuthn L2 §8.6): exactly one certificate; the
/// signature MUST verify over
/// `0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F`
/// with the certificate's ES256 public key, where `publicKeyU2F` is the
/// 65-byte `0x04 || X || Y` transport form of the credential's EC2 key.
///
/// # Requirements
/// REQ-WA-124, REQ-WA-127, REQ-WA-129
#[allow(clippy::indexing_slicing)] // rpIdHash slice is length-guarded above
#[allow(clippy::too_many_arguments)]
fn verify_fido_u2f(
    sig: &[u8],
    cert_der: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8],
    credential_id: &[u8],
    credential_alg: i32,
    credential_key: &CosePublicKey,
    aaguid: [u8; 16],
    policy: &AttestationPolicy,
) -> Result<AttestationResult, WebauthnError> {
    // U2F credentials are always ES256 on P-256; anything else in the
    // credential slot means this is not a U2F transport registration.
    if credential_alg != COSE_ALG_ES256 {
        return Err(WebauthnError::AttestationError(format!(
            "fido-u2f registration requires an ES256 credential key, got alg {credential_alg}"
        )));
    }
    let CosePublicKey::Ec2 { x, y } = credential_key else {
        return Err(WebauthnError::AttestationError(
            "fido-u2f registration requires an EC2 credential key".to_string(),
        ));
    };

    let cert = Cert::from_der(cert_der)?;
    if cert.kind != KeyKind::Ec2 {
        return Err(WebauthnError::AttestationError(
            "fido-u2f attestation certificate must carry an EC P-256 key".to_string(),
        ));
    }

    // publicKeyU2F: 0x04 || X || Y (FIDO U2F Raw Message Formats §4.3).
    if x.len() != 32 || y.len() != 32 {
        return Err(WebauthnError::AttestationError(
            "fido-u2f credential key coordinates must be 32 bytes (P-256)".to_string(),
        ));
    }
    let mut public_key_u2f = Vec::with_capacity(65);
    public_key_u2f.push(0x04);
    public_key_u2f.extend_from_slice(x);
    public_key_u2f.extend_from_slice(y);

    if auth_data.len() < 32 {
        return Err(WebauthnError::AttestationError(
            "authenticator data too short for fido-u2f verification".to_string(),
        ));
    }
    let mut verification_data = Vec::with_capacity(1 + 32 + 32 + credential_id.len() + 65);
    verification_data.push(0x00);
    // rpIdHash is the first 32 bytes of authData; length pre-checked above.
    verification_data.extend_from_slice(&auth_data[..32]); // rpIdHash
    verification_data.extend_from_slice(client_data_hash);
    verification_data.extend_from_slice(credential_id);
    verification_data.extend_from_slice(&public_key_u2f);

    verify_signature_with_cert(&cert, &verification_data, sig)?;

    let (trust_level, warnings) = verify_chain(&[cert_der.to_vec()], policy)?;

    Ok(AttestationResult {
        format: AttestationFormat::FidoU2f,
        aaguid: Some(aaguid),
        trust_level,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// X.509 certificate handling and chain verification
// ---------------------------------------------------------------------------

/// Key material kinds this crate can verify with (mirrors `CosePublicKey`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    /// EC P-256 (`id-ecPublicKey`, ES256).
    Ec2,
    /// RSA (`rsaEncryption`, RS256, ≥2048-bit enforced by ring).
    Rsa,
}

/// Certificate public key in the form `ring` consumes.
enum CertPublicKey {
    /// Uncompressed EC point `0x04 || X || Y`.
    EcPoint(Vec<u8>),
    /// SubjectPublicKeyInfo DER (ring RSA verifiers take SPKI).
    SpkiDer(Vec<u8>),
}

/// A parsed, structurally validated X.509 certificate.
struct Cert {
    /// Raw TBS bytes (the signed content).
    tbs: Vec<u8>,
    /// DER signature value (without the BIT STRING wrapper).
    signature: Vec<u8>,
    /// Signature algorithm OID (DER bytes).
    signature_alg_oid: Vec<u8>,
    /// Verifier input for this certificate's own public key.
    verifier_key: CertPublicKey,
    /// Issuer name (raw DER, for chain linking).
    issuer: Vec<u8>,
    /// Subject name (raw DER, for chain linking).
    subject: Vec<u8>,
    /// This certificate's key kind.
    kind: KeyKind,
    /// Not-before / not-after (unix seconds).
    not_before: i64,
    not_after: i64,
    /// Raw `(oid, value)` extension list.
    extensions: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Cert {
    /// Parse and structurally validate a DER certificate.
    ///
    /// Rejects: malformed DER, trailing bytes after the certificate,
    /// non-v3 certificates, and unsupported public key algorithms.
    ///
    /// # Requirements
    /// REQ-WA-122, REQ-WA-130, REQ-WA-132
    fn from_der(der: &[u8]) -> Result<Self, WebauthnError> {
        let (rem, parsed) = parse_x509_certificate(der).map_err(|e| {
            WebauthnError::AttestationError(format!("attestation certificate parse error: {e}"))
        })?;
        if !rem.is_empty() {
            return Err(WebauthnError::AttestationError(
                "trailing bytes after attestation certificate".to_string(),
            ));
        }

        let tbs = &parsed.tbs_certificate;
        if tbs.version() != X509Version::V3 {
            return Err(WebauthnError::AttestationError(
                "attestation certificate must be X.509 v3".to_string(),
            ));
        }

        let spki = tbs.public_key();
        let spki_alg = spki.algorithm.algorithm.as_bytes();
        let (verifier_key, kind) = if spki_alg == OID_ALG_EC_PUBLIC_KEY {
            let point = spki.subject_public_key.data.to_vec();
            if point.first() != Some(&0x04) || point.len() != 65 {
                return Err(WebauthnError::AttestationError(
                    "attestation certificate EC key is not an uncompressed P-256 point".to_string(),
                ));
            }
            (CertPublicKey::EcPoint(point), KeyKind::Ec2)
        } else if spki_alg == OID_ALG_RSA_ENCRYPTION {
            (CertPublicKey::SpkiDer(spki.raw.to_vec()), KeyKind::Rsa)
        } else {
            return Err(WebauthnError::AttestationError(
                "attestation certificate uses an unsupported public key algorithm".to_string(),
            ));
        };

        let extensions = tbs
            .extensions()
            .iter()
            .map(|ext| (ext.oid.as_bytes().to_vec(), ext.value.to_vec()))
            .collect();

        Ok(Self {
            tbs: tbs.as_ref().to_vec(),
            signature: parsed.signature_value.data.to_vec(),
            signature_alg_oid: parsed.signature_algorithm.algorithm.as_bytes().to_vec(),
            verifier_key,
            issuer: tbs.issuer().as_raw().to_vec(),
            subject: tbs.subject().as_raw().to_vec(),
            kind,
            not_before: tbs.validity().not_before.timestamp(),
            not_after: tbs.validity().not_after.timestamp(),
            extensions,
        })
    }

    /// Validity window contains `now` (unix seconds).
    fn is_valid_at(&self, now: i64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Verify this certificate's own signature with the parent's key.
    ///
    /// Only `ecdsa-with-SHA256` (EC P-256 parent) and
    /// `sha256WithRSAEncryption` (RSA parent) are accepted — anything else
    /// fails closed.
    ///
    /// # Requirements
    /// REQ-WA-122
    fn verify_signed_by(&self, parent: &Cert) -> Result<(), WebauthnError> {
        if self.signature_alg_oid == OID_SIG_ECDSA_WITH_SHA256 {
            if parent.kind != KeyKind::Ec2 {
                return Err(WebauthnError::AttestationError(
                    "certificate signature algorithm does not match issuer key type".to_string(),
                ));
            }
            let CertPublicKey::EcPoint(point) = &parent.verifier_key else {
                return Err(WebauthnError::AttestationError(
                    "issuer key is not an EC point".to_string(),
                ));
            };
            let verifier = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                point,
            );
            verifier
                .verify(&self.tbs, &self.signature)
                .map_err(|_| WebauthnError::SignatureVerificationFailed)
        } else if self.signature_alg_oid == OID_SIG_SHA256_WITH_RSA {
            if parent.kind != KeyKind::Rsa {
                return Err(WebauthnError::AttestationError(
                    "certificate signature algorithm does not match issuer key type".to_string(),
                ));
            }
            let CertPublicKey::SpkiDer(spki) = &parent.verifier_key else {
                return Err(WebauthnError::AttestationError(
                    "issuer key is not an RSA SPKI".to_string(),
                ));
            };
            let verifier = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                spki,
            );
            verifier
                .verify(&self.tbs, &self.signature)
                .map_err(|_| WebauthnError::SignatureVerificationFailed)
        } else {
            Err(WebauthnError::AttestationError(
                "certificate uses an unsupported signature algorithm (only ecdsa-with-SHA256 \
                 and sha256WithRSAEncryption are accepted)"
                    .to_string(),
            ))
        }
    }

    /// basicConstraints `cA` flag; `None` when the extension is absent.
    fn is_ca(&self) -> Option<bool> {
        let (_, value) = self
            .extensions
            .iter()
            .find(|(oid, _)| oid == OID_EXT_BASIC_CONSTRAINTS)?;
        parse_basic_constraints(value)
    }
}

/// Parse a basicConstraints extension value:
/// `SEQUENCE { BOOLEAN DEFAULT FALSE, INTEGER OPTIONAL }`.
///
/// Returns the `cA` flag — `false` when the BOOLEAN is omitted (DER
/// defaulting) or when only a pathLenConstraint INTEGER is present.
fn parse_basic_constraints(value: &[u8]) -> Option<bool> {
    let content = der_content(value, 0x30)?;
    if content.first() == Some(&0x01) && content.len() >= 3 {
        // Explicit BOOLEAN: tag (0x01), length (0x01), value.
        return Some(content.get(2).copied() == Some(0xFF));
    }
    Some(false)
}

/// Return the content octets of a DER TLV with the given tag byte, strictly
/// validating that the declared length matches the available bytes.
fn der_content(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    if bytes.first() != Some(&tag) {
        return None;
    }
    let first = *bytes.get(1)?;
    if first < 0x80 {
        bytes.get(2..2 + first as usize)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in bytes.get(2..2 + n)? {
            len = (len << 8) | (*b as usize);
        }
        bytes.get(2 + n..2 + n + len)
    }
}

/// Verify the AAGUID extension (`id-fido-gen-ce-aaguid`) on the leaf, when
/// present: its value is a DER OCTET STRING wrapping exactly 16 bytes that
/// MUST equal the attested credential data AAGUID.
///
/// # Requirements
/// REQ-WA-125
fn check_aaguid_extension(cert: &Cert, aaguid: &[u8; 16]) -> Result<(), WebauthnError> {
    let Some((_, value)) = cert
        .extensions
        .iter()
        .find(|(oid, _)| oid == OID_EXT_FIDO_GEN_CE_AAGUID)
    else {
        return Ok(()); // extension is optional
    };

    // extnValue content: OCTET STRING (tag 0x04) of length 16 wrapping the
    // AAGUID (FIDO 2.1 §8.2.1).
    let bad = || {
        WebauthnError::AttestationError("id-fido-gen-ce-aaguid extension is malformed".to_string())
    };
    let content = der_content(value, 0x04).ok_or_else(bad)?;
    if content.len() != 16 {
        return Err(bad());
    }
    if content != aaguid.as_slice() {
        return Err(WebauthnError::AttestationError(
            "id-fido-gen-ce-aaguid extension does not match the attested credential data AAGUID"
                .to_string(),
        ));
    }
    Ok(())
}

/// Verify the x5c chain and return the resulting trust level.
///
/// Checks, in order (fail closed):
///
/// 1. Every certificate parses and is X.509 v3 ([`Cert::from_der`]).
/// 2. Every certificate is within its validity window *now* (REQ-WA-130).
/// 3. Each certificate is signed by the next with a supported algorithm;
///    issuer/subject names link byte-exactly; intermediates declare
///    basicConstraints `cA = true` (REQ-WA-122).
/// 4. Anchor policy (REQ-WA-123):
///    - anchors configured → the chain root must equal an anchor, or be
///      signed by one, → [`TrustLevel::AttCa`]; otherwise reject;
///    - no anchors → the chain root must be self-signed (self-signature
///      verified) → [`TrustLevel::BasicAtt`] +
///      [`warnings::UNANCHORED_CHAIN`].
fn verify_chain(
    x5c: &[Vec<u8>],
    policy: &AttestationPolicy,
) -> Result<(TrustLevel, Vec<&'static str>), WebauthnError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| {
            WebauthnError::AttestationError("system clock before unix epoch".to_string())
        })?;

    let mut certs = Vec::with_capacity(x5c.len());
    for der in x5c {
        let cert = Cert::from_der(der)?;
        if !cert.is_valid_at(now) {
            return Err(WebauthnError::AttestationError(
                "attestation certificate is expired or not yet valid".to_string(),
            ));
        }
        certs.push(cert);
    }

    // Signature chain: leaf → intermediate(s) → root. `windows(2)` always
    // yields exactly-2 slices, so the destructuring below is infallible;
    // allow the lint rather than an unreachable expect.
    #[allow(clippy::indexing_slicing)]
    for pair in certs.windows(2) {
        let (child, parent) = (&pair[0], &pair[1]);
        if child.issuer != parent.subject {
            return Err(WebauthnError::AttestationError(
                "attestation chain issuer/subject names do not link".to_string(),
            ));
        }
        child.verify_signed_by(parent)?;
    }

    // Non-leaf certificates must declare CA: true (basicConstraints).
    for parent in certs.iter().skip(1) {
        if parent.is_ca() != Some(true) {
            return Err(WebauthnError::AttestationError(
                "attestation chain intermediate lacks basicConstraints cA=true".to_string(),
            ));
        }
    }

    let root = certs
        .last()
        .ok_or_else(|| WebauthnError::AttestationError("attestation chain is empty".to_string()))?;
    let root_der = x5c
        .last()
        .ok_or_else(|| WebauthnError::AttestationError("attestation chain is empty".to_string()))?;

    // Anchor policy (REQ-WA-123).
    for anchor in &policy.trust_anchors {
        // Case 1: the chain carries the anchor certificate itself.
        if root_der == anchor {
            return Ok((TrustLevel::AttCa, Vec::new()));
        }
        // Case 2: the chain root is issued directly by the anchor.
        let anchor_cert = Cert::from_der(anchor)?;
        if root.issuer == anchor_cert.subject && root.verify_signed_by(&anchor_cert).is_ok() {
            return Ok((TrustLevel::AttCa, Vec::new()));
        }
    }
    if !policy.trust_anchors.is_empty() {
        return Err(WebauthnError::AttestationError(
            "attestation chain does not terminate at a configured trust anchor".to_string(),
        ));
    }

    // No anchors configured: accept only a chain rooted at a self-signed
    // certificate (self-signature verified), and flag it.
    let self_signed = root.issuer == root.subject && root.verify_signed_by(root).is_ok();
    if !self_signed {
        return Err(WebauthnError::AttestationError(
            "attestation chain root is not self-signed and no trust anchors are configured"
                .to_string(),
        ));
    }

    Ok((TrustLevel::BasicAtt, vec![warnings::UNANCHORED_CHAIN]))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The bytes covered by a WebAuthn registration attestation signature:
/// `authenticatorData || SHA-256(clientDataJSON)` (the caller supplies the
/// precomputed hash).
fn signed_data(auth_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(client_data_hash);
    signed
}

/// Verify `data`/`sig` with an X.509 certificate's public key via `ring`.
///
/// Only ES256 (EC P-256) and RS256 (RSA PKCS#1 v1.5, ≥2048-bit) are
/// supported, matching this crate's COSE algorithm support.
///
/// # Requirements
/// REQ-WA-121, REQ-WA-124, REQ-WA-127
fn verify_signature_with_cert(cert: &Cert, data: &[u8], sig: &[u8]) -> Result<(), WebauthnError> {
    match &cert.verifier_key {
        CertPublicKey::EcPoint(point) => {
            let verifier = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                point,
            );
            verifier
                .verify(data, sig)
                .map_err(|_| WebauthnError::SignatureVerificationFailed)
        }
        CertPublicKey::SpkiDer(spki) => {
            let verifier = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                spki,
            );
            verifier
                .verify(data, sig)
                .map_err(|_| WebauthnError::SignatureVerificationFailed)
        }
    }
}
