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
    /// DER `RSAPublicKey` (PKCS#1) — the SubjectPublicKeyInfo BIT STRING
    /// content, which is the encoding `ring`'s RSA verifiers parse.
    RsaKey(Vec<u8>),
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
            // ring's RSA verifier parses PKCS#1 `RSAPublicKey`, i.e. the
            // SPKI's subjectPublicKey BIT STRING content.
            (
                CertPublicKey::RsaKey(spki.subject_public_key.data.to_vec()),
                KeyKind::Rsa,
            )
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
            let CertPublicKey::RsaKey(rsa_key) = &parent.verifier_key else {
                return Err(WebauthnError::AttestationError(
                    "issuer key is not an RSA key".to_string(),
                ));
            };
            let verifier = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                rsa_key,
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
        CertPublicKey::RsaKey(rsa_key) => {
            let verifier = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                rsa_key,
            );
            verifier
                .verify(data, sig)
                .map_err(|_| WebauthnError::SignatureVerificationFailed)
        }
    }
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
    use ring::signature::{
        EcdsaKeyPair, KeyPair as _, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256,
    };
    use sha2::Digest;

    // ------------------------------------------------------------------
    // Minimal DER builder for hand-crafted certificates. Signatures are
    // made with `ring` in exactly the encodings this crate verifies
    // (fixed-length ECDSA per COSE, PKCS#1 v1.5 for RSA), so chains built
    // here exercise the real verification paths. Parse-only variants
    // (junk signatures) cover error paths that abort before any
    // signature check.
    // ------------------------------------------------------------------

    const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    const OID_SIG_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    const OID_SIG_SHA256_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    const OID_SIG_ECDSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];
    const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
    const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
    const OID_FIDO_AAGUID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x14, 0x01, 0x04];
    const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];

    fn rsa_signing_key() -> RsaKeyPair {
        let (_, _, pkcs8) = crate::crypto::tests::rsa_test_material();
        RsaKeyPair::from_pkcs8(&pkcs8).unwrap()
    }

    /// Full RFC 5280 SubjectPublicKeyInfo carrying the fixed test key's
    /// `RSAPublicKey` (what a certificate embeds).
    fn rsa_spki() -> Vec<u8> {
        der_seq(&[&alg_id(OID_RSA_ENCRYPTION), &der_bit(&rsa_pubkey_der())])
    }

    /// PKCS#1 `RSAPublicKey` DER for the fixed test key (what ring parses).
    fn rsa_pubkey_der() -> Vec<u8> {
        crate::crypto::tests::rsa_test_spki()
    }

    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x100 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut content = Vec::new();
        for part in parts {
            content.extend_from_slice(part);
        }
        tlv(0x30, &content)
    }

    fn der_set(content: &[u8]) -> Vec<u8> {
        tlv(0x31, content)
    }

    fn der_integer(bytes: &[u8]) -> Vec<u8> {
        tlv(0x02, bytes)
    }

    fn der_oid(bytes: &[u8]) -> Vec<u8> {
        tlv(0x06, bytes)
    }

    fn der_bit(bytes: &[u8]) -> Vec<u8> {
        let mut content = vec![0x00];
        content.extend_from_slice(bytes);
        tlv(0x03, &content)
    }

    fn der_utf8(s: &str) -> Vec<u8> {
        tlv(0x0C, s.as_bytes())
    }

    fn der_utc(s: &str) -> Vec<u8> {
        tlv(0x17, s.as_bytes())
    }

    fn der_null() -> Vec<u8> {
        vec![0x05, 0x00]
    }

    fn alg_id(oid: &[u8]) -> Vec<u8> {
        der_seq(&[&der_oid(oid), &der_null()])
    }

    fn name_cn(cn: &str) -> Vec<u8> {
        der_seq(&[&der_set(&der_seq(&[&der_oid(OID_CN), &der_utf8(cn)]))])
    }

    fn validity() -> Vec<u8> {
        der_seq(&[&der_utc("240101000000Z"), &der_utc("400101000000Z")])
    }

    fn expired_validity() -> Vec<u8> {
        der_seq(&[&der_utc("200101000000Z"), &der_utc("210101000000Z")])
    }

    fn ec_spki_from(key: &EcdsaKeyPair) -> Vec<u8> {
        let point = key.public_key().as_ref().to_vec();
        der_seq(&[
            &der_seq(&[&der_oid(OID_EC_PUBLIC_KEY), &der_oid(OID_PRIME256V1)]),
            &der_bit(&point),
        ])
    }

    fn ed25519_spki() -> Vec<u8> {
        der_seq(&[&alg_id(OID_ED25519), &der_bit(&[0x42; 32])])
    }

    fn extension(oid: &[u8], value: &[u8]) -> Vec<u8> {
        der_seq(&[&der_oid(oid), &tlv(0x04, value)])
    }

    fn extensions_wrapper(exts: &[Vec<u8>]) -> Vec<u8> {
        let mut content = Vec::new();
        for ext in exts {
            content.extend_from_slice(ext);
        }
        tlv(0xA3, &der_seq(&[&content]))
    }

    /// Build the TBSCertificate bytes (X.509 v3 unless `v1`).
    fn tbs_cert(
        sig_alg_oid: &[u8],
        issuer: &[u8],
        subject: &[u8],
        spki: &[u8],
        exts: &[Vec<u8>],
        validity_bytes: &[u8],
        v1: bool,
    ) -> Vec<u8> {
        let version = tlv(0xA0, &der_integer(&[2]));
        let serial = der_integer(&[1]);
        let sig_alg_tlv = alg_id(sig_alg_oid);
        let mut parts: Vec<&[u8]> = Vec::new();
        if !v1 {
            parts.push(&version);
        }
        parts.push(&serial);
        parts.push(&sig_alg_tlv);
        parts.push(issuer);
        parts.push(validity_bytes);
        parts.push(subject);
        parts.push(spki);
        let ext_wrapper = extensions_wrapper(exts);
        if !exts.is_empty() {
            parts.push(&ext_wrapper);
        }
        der_seq(&parts)
    }

    /// Wrap a signed TBS into a full certificate.
    fn finish_cert(tbs: &[u8], sig_alg_oid: &[u8], sig: &[u8]) -> Vec<u8> {
        der_seq(&[tbs, &alg_id(sig_alg_oid), &der_bit(sig)])
    }

    /// EC P-256 certificate signed with the fixed-length (COSE) encoding
    /// this crate verifies. `signer = None` → self-signed with `key`.
    fn ec_cert(
        subject_cn: &str,
        issuer_name: &[u8],
        key: &EcdsaKeyPair,
        signer: Option<&EcdsaKeyPair>,
        exts: &[Vec<u8>],
        validity_bytes: &[u8],
    ) -> Vec<u8> {
        let subject = name_cn(subject_cn);
        let spki = ec_spki_from(key);
        let tbs = tbs_cert(
            OID_SIG_ECDSA_SHA256,
            issuer_name,
            &subject,
            &spki,
            exts,
            validity_bytes,
            false,
        );
        let rng = ring::rand::SystemRandom::new();
        let sig = signer.unwrap_or(key).sign(&rng, &tbs).unwrap();
        finish_cert(&tbs, OID_SIG_ECDSA_SHA256, sig.as_ref())
    }

    /// Self-signed EC certificate helper.
    fn ec_self_cert(cn: &str, key: &EcdsaKeyPair, exts: &[Vec<u8>]) -> Vec<u8> {
        let name = name_cn(cn);
        ec_cert(cn, &name, key, None, exts, &validity())
    }

    /// RSA certificate signed with PKCS#1 v1.5 SHA-256 (matching SPKI).
    /// `signer = None` → self-signed with `key`.
    fn rsa_cert(
        subject_cn: &str,
        issuer_name: &[u8],
        key: &RsaKeyPair,
        signer: Option<&RsaKeyPair>,
        exts: &[Vec<u8>],
    ) -> Vec<u8> {
        let subject = name_cn(subject_cn);
        let spki = rsa_spki();
        let tbs = tbs_cert(
            OID_SIG_SHA256_RSA,
            issuer_name,
            &subject,
            &spki,
            exts,
            &validity(),
            false,
        );
        let rng = ring::rand::SystemRandom::new();
        let mut sig = vec![0u8; key.public().modulus_len()];
        signer
            .unwrap_or(key)
            .sign(&RSA_PKCS1_SHA256, &rng, &tbs, &mut sig)
            .unwrap();
        finish_cert(&tbs, OID_SIG_SHA256_RSA, &sig)
    }

    /// Parse-only certificate builder (junk signature): for error paths
    /// that abort before any signature check.
    fn hand_cert(sig_alg: &[u8], issuer: &[u8], subject: &[u8], spki: &[u8], v1: bool) -> Vec<u8> {
        let tbs = tbs_cert(sig_alg, issuer, subject, spki, &[], &validity(), v1);
        der_seq(&[&tbs, &alg_id(sig_alg), &der_bit(&[0xAA; 64])])
    }

    /// basicConstraints extension (cA=true).
    fn bc_ca_true() -> Vec<u8> {
        extension(OID_BASIC_CONSTRAINTS, &[0x30, 0x03, 0x01, 0x01, 0xFF])
    }

    /// basicConstraints extension (explicit cA=false).
    fn bc_ca_false() -> Vec<u8> {
        extension(OID_BASIC_CONSTRAINTS, &[0x30, 0x03, 0x01, 0x01, 0x00])
    }

    // ------------------------------------------------------------------
    // Chain fixtures
    // ------------------------------------------------------------------

    fn ec_key() -> EcdsaKeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
    }

    /// `anchor --signs--> issuer --signs--> leaf` (all P-256). Returns
    /// (leaf, issuer, anchor, leaf signing key).
    fn ec_chain() -> (Vec<u8>, Vec<u8>, Vec<u8>, EcdsaKeyPair) {
        let anchor_key = ec_key();
        let issuer_key = ec_key();
        let leaf_key = ec_key();
        let anchor = ec_self_cert("anchor", &anchor_key, &[bc_ca_true()]);
        let issuer = ec_cert(
            "issuer",
            &name_cn("anchor"),
            &issuer_key,
            Some(&anchor_key),
            &[bc_ca_true()],
            &validity(),
        );
        let leaf = ec_cert(
            "leaf",
            &name_cn("issuer"),
            &leaf_key,
            Some(&issuer_key),
            &[],
            &validity(),
        );
        (leaf, issuer, anchor, leaf_key)
    }

    fn subject_raw(cert_der: &[u8]) -> Vec<u8> {
        let (_, cert) = parse_x509_certificate(cert_der).unwrap();
        cert.tbs_certificate.subject().as_raw().to_vec()
    }

    // ------------------------------------------------------------------
    // Ceremony fixtures
    // ------------------------------------------------------------------

    const AAGUID: [u8; 16] = [7u8; 16];
    const CRED_ID: &[u8] = &[0xC1, 0x02, 0x03, 0x04];

    fn rng() -> ring::rand::SystemRandom {
        ring::rand::SystemRandom::new()
    }

    /// (authData, clientDataHash, credential key, credential signing key).
    fn credential() -> (Vec<u8>, Vec<u8>, CosePublicKey, EcdsaKeyPair) {
        let kp = ec_key();
        let pub_bytes = kp.public_key().as_ref().to_vec();
        let key = CosePublicKey::Ec2 {
            x: pub_bytes[1..33].to_vec(),
            y: pub_bytes[33..65].to_vec(),
        };
        let auth_data = vec![0x11u8; 42];
        let client_data_hash = sha2::Sha256::digest(b"client data").to_vec();
        (auth_data, client_data_hash, key, kp)
    }

    fn signed_data(auth_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
        let mut signed = auth_data.to_vec();
        signed.extend_from_slice(client_data_hash);
        signed
    }

    fn cbor_int(v: i64) -> Value {
        Value::Integer(v.into())
    }

    fn cbor_bytes_val(bytes: &[u8]) -> Value {
        Value::Bytes(bytes.to_vec())
    }

    fn cbor_map(entries: Vec<(i64, Value)>) -> Value {
        Value::Map(entries.into_iter().map(|(k, v)| (cbor_int(k), v)).collect())
    }

    fn packed_stmt(alg: i32, sig: &[u8], x5c: Vec<Vec<u8>>) -> Value {
        let mut entries = vec![(3i64, cbor_int(alg as i64)), (8, cbor_bytes_val(sig))];
        if !x5c.is_empty() {
            entries.push((
                33,
                Value::Array(x5c.iter().map(|c| cbor_bytes_val(c)).collect()),
            ));
        }
        cbor_map(entries)
    }

    /// Drive `verify_attestation` with a packed statement and the shared
    /// fixture; returns the raw result.
    fn verify_packed(
        statement: &Value,
        key: &CosePublicKey,
        cred_alg: i32,
        policy: &AttestationPolicy,
    ) -> Result<AttestationResult, WebauthnError> {
        let (auth_data, cdh, _, _) = credential();
        verify_attestation(
            "packed",
            Some(statement),
            &auth_data,
            &cdh,
            CRED_ID,
            cred_alg,
            key,
            AAGUID,
            policy,
        )
    }

    fn u2f_msg(auth_data: &[u8], cdh: &[u8], key: &CosePublicKey) -> Vec<u8> {
        let CosePublicKey::Ec2 { x, y } = key else {
            unreachable!("fixture key is EC2");
        };
        let mut msg = vec![0x00];
        msg.extend_from_slice(&auth_data[..32]);
        msg.extend_from_slice(cdh);
        msg.extend_from_slice(CRED_ID);
        msg.push(0x04);
        msg.extend_from_slice(x);
        msg.extend_from_slice(y);
        msg
    }

    fn u2f_call(
        statement: &Value,
        key: &CosePublicKey,
        cred_alg: i32,
        auth_data: &[u8],
        cdh: &[u8],
    ) -> Result<AttestationResult, WebauthnError> {
        verify_attestation(
            "fido-u2f",
            Some(statement),
            auth_data,
            cdh,
            CRED_ID,
            cred_alg,
            key,
            AAGUID,
            &AttestationPolicy::default(),
        )
    }

    // ------------------------------------------------------------------
    // Format parsing and policy
    // ------------------------------------------------------------------

    #[test]
    fn format_names_roundtrip() {
        assert_eq!(AttestationFormat::from_fmt("none"), AttestationFormat::None);
        assert_eq!(
            AttestationFormat::from_fmt("packed"),
            AttestationFormat::Packed
        );
        assert_eq!(
            AttestationFormat::from_fmt("fido-u2f"),
            AttestationFormat::FidoU2f
        );
        assert_eq!(
            AttestationFormat::from_fmt("android-key"),
            AttestationFormat::Unknown
        );
        assert_eq!(AttestationFormat::None.as_fmt(), "none");
        assert_eq!(AttestationFormat::Packed.as_fmt(), "packed");
        assert_eq!(AttestationFormat::FidoU2f.as_fmt(), "fido-u2f");
        assert_eq!(AttestationFormat::Unknown.as_fmt(), "unknown");
    }

    #[test]
    fn policy_strict_is_default() {
        let policy = AttestationPolicy::strict();
        assert!(policy.trust_anchors.is_empty());
        assert!(!policy.allow_unknown_formats);
    }

    #[test]
    fn parse_none_statement() {
        assert_eq!(
            parse_statement(&AttestationFormat::None, None).unwrap(),
            AttestationStatement::None
        );
        assert_eq!(
            parse_statement(&AttestationFormat::None, Some(&cbor_map(vec![]))).unwrap(),
            AttestationStatement::None
        );
        let err = parse_statement(
            &AttestationFormat::None,
            Some(&cbor_map(vec![(1, cbor_int(0))])),
        )
        .unwrap_err();
        assert!(matches!(err, WebauthnError::AttestationError(msg) if msg.contains("empty map")));
    }

    #[test]
    fn parse_packed_statement_happy_and_missing() {
        let stmt = packed_stmt(COSE_ALG_ES256, &[0xAA; 64], vec![]);
        match parse_statement(&AttestationFormat::Packed, Some(&stmt)).unwrap() {
            AttestationStatement::Packed { alg, sig, x5c } => {
                assert_eq!(alg, COSE_ALG_ES256);
                assert_eq!(sig, vec![0xAA; 64]);
                assert!(x5c.is_empty());
            }
            other => panic!("expected packed statement, got {other:?}"),
        }

        let err = parse_statement(&AttestationFormat::Packed, None).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("missing attStmt"))
        );
    }

    #[test]
    fn parse_packed_statement_errors() {
        // attStmt not a map
        let err = parse_statement(&AttestationFormat::Packed, Some(&cbor_int(5))).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("not a CBOR map"))
        );

        // missing alg (text-string alg is not an integer)
        let no_alg = cbor_map(vec![(8, cbor_bytes_val(&[0xAA; 64]))]);
        let err = parse_statement(&AttestationFormat::Packed, Some(&no_alg)).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("missing 'alg'"))
        );

        // alg does not fit i32
        let huge_alg = cbor_map(vec![
            (3, cbor_int(i64::from(u32::MAX) + 1)),
            (8, cbor_bytes_val(&[0xAA; 64])),
        ]);
        let err = parse_statement(&AttestationFormat::Packed, Some(&huge_alg)).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("missing 'alg'"))
        );

        // missing sig
        let no_sig = cbor_map(vec![(3, cbor_int(COSE_ALG_ES256 as i64))]);
        let err = parse_statement(&AttestationFormat::Packed, Some(&no_sig)).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("missing 'sig'"))
        );

        // x5c not an array
        let bad_x5c = cbor_map(vec![
            (3, cbor_int(COSE_ALG_ES256 as i64)),
            (8, cbor_bytes_val(&[0xAA; 64])),
            (33, cbor_int(1)),
        ]);
        let err = parse_statement(&AttestationFormat::Packed, Some(&bad_x5c)).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("not a CBOR array"))
        );

        // x5c contains a non-byte-string entry
        let bad_entry = cbor_map(vec![
            (3, cbor_int(COSE_ALG_ES256 as i64)),
            (8, cbor_bytes_val(&[0xAA; 64])),
            (33, Value::Array(vec![cbor_int(9)])),
        ]);
        let err = parse_statement(&AttestationFormat::Packed, Some(&bad_entry)).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("non-byte-string"))
        );
    }

    #[test]
    fn parse_fido_u2f_statement() {
        let cert = vec![0x30, 0x01, 0x00]; // structural bytes; not parsed here
        let stmt = cbor_map(vec![
            (8, cbor_bytes_val(&[0xBB; 70])),
            (33, Value::Array(vec![cbor_bytes_val(&cert)])),
        ]);
        match parse_statement(&AttestationFormat::FidoU2f, Some(&stmt)).unwrap() {
            AttestationStatement::FidoU2f { sig, cert: c } => {
                assert_eq!(sig, vec![0xBB; 70]);
                assert_eq!(c, cert);
            }
            other => panic!("expected fido-u2f statement, got {other:?}"),
        }

        // missing attStmt / not a map / missing sig
        let cases: [(Option<Value>, &str); 3] = [
            (None, "missing attStmt"),
            (Some(cbor_int(1)), "not a CBOR map"),
            (
                Some(cbor_map(vec![(
                    33,
                    Value::Array(vec![cbor_bytes_val(&cert)]),
                )])),
                "missing 'sig'",
            ),
        ];
        for (stmt, fragment) in cases {
            let err = parse_statement(&AttestationFormat::FidoU2f, stmt.as_ref()).unwrap_err();
            assert!(
                matches!(err, WebauthnError::AttestationError(msg) if msg.contains(fragment)),
                "unexpected error for {fragment}"
            );
        }

        // x5c must carry exactly one certificate
        let no_cert = cbor_map(vec![
            (8, cbor_bytes_val(&[0u8; 8])),
            (33, Value::Array(vec![])),
        ]);
        let err = parse_statement(&AttestationFormat::FidoU2f, Some(&no_cert)).unwrap_err();
        assert!(matches!(err, WebauthnError::AttestationError(msg) if msg.contains("exactly one")));

        let two_certs = cbor_map(vec![
            (8, cbor_bytes_val(&[0u8; 8])),
            (
                33,
                Value::Array(vec![cbor_bytes_val(&cert), cbor_bytes_val(&cert)]),
            ),
        ]);
        let err = parse_statement(&AttestationFormat::FidoU2f, Some(&two_certs)).unwrap_err();
        assert!(matches!(err, WebauthnError::AttestationError(msg) if msg.contains("exactly one")));
    }

    #[test]
    fn parse_unknown_statement_rejected() {
        let err = parse_statement(&AttestationFormat::Unknown, None).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("cannot be parsed"))
        );
    }

    // ------------------------------------------------------------------
    // verify_attestation dispatch: unknown / none
    // ------------------------------------------------------------------

    #[test]
    fn unknown_format_strict_rejected_escape_allowed() {
        let (auth_data, cdh, key, _) = credential();
        let err = verify_attestation(
            "android-key",
            None,
            &auth_data,
            &cdh,
            CRED_ID,
            COSE_ALG_ES256,
            &key,
            AAGUID,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("unsupported attestation format"))
        );

        let policy = AttestationPolicy {
            allow_unknown_formats: true,
            ..AttestationPolicy::default()
        };
        let result = verify_attestation(
            "android-key",
            None,
            &auth_data,
            &cdh,
            CRED_ID,
            COSE_ALG_ES256,
            &key,
            AAGUID,
            &policy,
        )
        .unwrap();
        assert_eq!(result.format, AttestationFormat::Unknown);
        assert_eq!(result.trust_level, TrustLevel::None);
        assert_eq!(result.warnings, vec![warnings::UNVERIFIED_FORMAT]);
        assert_eq!(result.aaguid, Some(AAGUID));
    }

    #[test]
    fn none_format_verification() {
        let (auth_data, cdh, key, _) = credential();
        let result = verify_attestation(
            "none",
            Some(&cbor_map(vec![])),
            &auth_data,
            &cdh,
            CRED_ID,
            COSE_ALG_ES256,
            &key,
            AAGUID,
            &AttestationPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.format, AttestationFormat::None);
        assert_eq!(result.trust_level, TrustLevel::None);
        assert!(result.warnings.is_empty());
        assert_eq!(result.aaguid, Some(AAGUID));
    }

    // ------------------------------------------------------------------
    // Packed self-attestation
    // ------------------------------------------------------------------

    #[test]
    fn packed_self_attestation_ok() {
        let (auth_data, cdh, key, kp) = credential();
        let sig = kp.sign(&rng(), &signed_data(&auth_data, &cdh)).unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), Vec::new());
        let result = verify_packed(
            &statement,
            &key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.format, AttestationFormat::Packed);
        assert_eq!(result.trust_level, TrustLevel::SelfAttested);
        assert!(result.warnings.is_empty());
        assert_eq!(result.aaguid, Some(AAGUID));
    }

    #[test]
    fn packed_self_alg_mismatch_rejected() {
        // Statement claims RS256, credential key is ES256.
        let (_, _, key, _) = credential();
        let statement = packed_stmt(COSE_ALG_RS256, &[0u8; 256], Vec::new());
        let err = verify_packed(
            &statement,
            &key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("does not match credential key alg"))
        );
    }

    #[test]
    fn packed_self_bad_signature_rejected() {
        let (_, _, key, _) = credential();
        let statement = packed_stmt(COSE_ALG_ES256, &[0u8; 64], Vec::new());
        let err = verify_packed(
            &statement,
            &key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(matches!(err, WebauthnError::SignatureVerificationFailed));
    }

    // ------------------------------------------------------------------
    // ES384 / EdDSA credentials through the attestation paths
    // ------------------------------------------------------------------

    use crate::crypto::{COSE_ALG_EDDSA, COSE_ALG_ES384};

    /// (authData, clientDataHash, P-384 credential key, signing key).
    fn credential_p384() -> (Vec<u8>, Vec<u8>, CosePublicKey, EcdsaKeyPair) {
        use ring::signature::{EcdsaKeyPair as P384Pair, ECDSA_P384_SHA384_FIXED_SIGNING};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = P384Pair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let kp =
            P384Pair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let pub_bytes = kp.public_key().as_ref();
        let key = CosePublicKey::Ec2 {
            x: pub_bytes[1..49].to_vec(),
            y: pub_bytes[49..97].to_vec(),
        };
        let auth_data = vec![0x11u8; 42];
        let client_data_hash = sha2::Sha256::digest(b"client data").to_vec();
        (auth_data, client_data_hash, key, kp)
    }

    /// (authData, clientDataHash, Ed25519 credential key, signing key).
    fn credential_ed25519() -> (
        Vec<u8>,
        Vec<u8>,
        CosePublicKey,
        ring::signature::Ed25519KeyPair,
    ) {
        use ring::signature::Ed25519KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key = CosePublicKey::Okp {
            id: kp.public_key().as_ref().to_vec(),
        };
        let auth_data = vec![0x11u8; 42];
        let client_data_hash = sha2::Sha256::digest(b"client data").to_vec();
        (auth_data, client_data_hash, key, kp)
    }

    /// Packed self-attestation with an ES384 credential key: the signature
    /// over authData ‖ clientDataHash verifies via the ES384 arm.
    #[test]
    fn packed_self_es384_credential_ok() {
        let (auth_data, cdh, key, kp) = credential_p384();
        let sig = kp
            .sign(
                &ring::rand::SystemRandom::new(),
                &signed_data(&auth_data, &cdh),
            )
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES384, sig.as_ref(), Vec::new());
        let result = verify_attestation(
            "packed",
            Some(&statement),
            &auth_data,
            &cdh,
            CRED_ID,
            COSE_ALG_ES384,
            &key,
            AAGUID,
            &AttestationPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.trust_level, TrustLevel::SelfAttested);
    }

    /// Packed self-attestation with an Ed25519 credential key.
    #[test]
    fn packed_self_eddsa_credential_ok() {
        let (auth_data, cdh, key, kp) = credential_ed25519();
        let sig = kp.sign(&signed_data(&auth_data, &cdh));
        let statement = packed_stmt(COSE_ALG_EDDSA, sig.as_ref(), Vec::new());
        let result = verify_attestation(
            "packed",
            Some(&statement),
            &auth_data,
            &cdh,
            CRED_ID,
            COSE_ALG_EDDSA,
            &key,
            AAGUID,
            &AttestationPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.trust_level, TrustLevel::SelfAttested);
    }

    /// `none` attestation is algorithm-agnostic: an ES384 credential
    /// registers with TrustLevel::None and no warnings.
    #[test]
    fn none_format_es384_credential() {
        let (auth_data, cdh, key, _) = credential_p384();
        let result = verify_attestation(
            "none",
            Some(&cbor_map(vec![])),
            &auth_data,
            &cdh,
            CRED_ID,
            COSE_ALG_ES384,
            &key,
            AAGUID,
            &AttestationPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.format, AttestationFormat::None);
        assert_eq!(result.trust_level, TrustLevel::None);
    }

    /// Packed **x5c** attestation statements remain limited to ES256/RS256:
    /// the certificate chain machinery only parses P-256/RSA keys, so an
    /// ES384 statement alg fails closed rather than mis-verifying.
    #[test]
    fn packed_x5c_es384_statement_alg_rejected() {
        let att_key = ec_key();
        let cert_der = ec_self_cert("attestor", &att_key, &[]);
        let (_, _, cred_key, _) = credential();
        let statement = packed_stmt(COSE_ALG_ES384, &[0u8; 96], vec![cert_der]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES384,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WebauthnError::UnsupportedAlgorithm(COSE_ALG_ES384)
        ));
    }

    // ------------------------------------------------------------------
    // Packed x5c attestation
    // ------------------------------------------------------------------

    /// Self-signed EC attestation certificate, no trust anchors configured:
    /// verifies at BasicAtt with the unanchored-chain warning.
    #[test]
    fn packed_x5c_self_signed_ec_is_basic_att() {
        let att_key = ec_key();
        let cert_der = ec_self_cert("attestor", &att_key, &[]);
        let (auth_data, cdh, cred_key, _) = credential();
        let sig = att_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![cert_der]);

        let result = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.trust_level, TrustLevel::BasicAtt);
        assert_eq!(result.warnings, vec![warnings::UNANCHORED_CHAIN]);
        assert_eq!(result.format, AttestationFormat::Packed);
    }

    /// RSA attestation certificate + real RSA statement signature (RS256).
    #[test]
    fn packed_x5c_rsa_attestation_ok() {
        let rsa = rsa_signing_key();
        let cert_der = rsa_self_cert(&rsa, &[]);
        let (auth_data, cdh, cred_key, _) = credential();
        let rng = rng();
        let mut stmt_sig = vec![0u8; 256];
        rsa.sign(
            &RSA_PKCS1_SHA256,
            &rng,
            &signed_data(&auth_data, &cdh),
            &mut stmt_sig,
        )
        .unwrap();
        let statement = packed_stmt(COSE_ALG_RS256, &stmt_sig, vec![cert_der]);

        let result = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap();
        assert_eq!(result.trust_level, TrustLevel::BasicAtt);
    }

    /// Self-signed RSA certificate helper.
    fn rsa_self_cert(key: &RsaKeyPair, exts: &[Vec<u8>]) -> Vec<u8> {
        let name = name_cn("rsa-attestor");
        rsa_cert("rsa-attestor", &name, key, None, exts)
    }

    #[test]
    fn packed_x5c_unsupported_statement_alg_rejected() {
        let att_key = ec_key();
        let cert_der = ec_self_cert("attestor", &att_key, &[]);
        let (_, _, cred_key, _) = credential();
        let statement = packed_stmt(-47, &[0u8; 64], vec![cert_der]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(matches!(err, WebauthnError::UnsupportedAlgorithm(-47)));
    }

    #[test]
    fn packed_x5c_alg_cert_key_type_mismatch_rejected() {
        // RS256 statement with an EC attestation certificate: fail closed.
        let att_key = ec_key();
        let cert_der = ec_self_cert("attestor", &att_key, &[]);
        let (_, _, cred_key, _) = credential();
        let statement = packed_stmt(COSE_ALG_RS256, &[0u8; 256], vec![cert_der]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("does not match the attestation certificate key type"))
        );
    }

    #[test]
    fn packed_x5c_bad_statement_signature_rejected() {
        let att_key = ec_key();
        let cert_der = ec_self_cert("attestor", &att_key, &[]);
        let (_, _, cred_key, _) = credential();
        let statement = packed_stmt(COSE_ALG_ES256, &[0u8; 64], vec![cert_der]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(matches!(err, WebauthnError::SignatureVerificationFailed));
    }

    // -- leaf certificate structural rejections (parsing happens before
    //    any signature check, so junk-signature fixtures suffice) --

    fn x5c_statement(cert_der: Vec<u8>) -> Value {
        packed_stmt(COSE_ALG_ES256, &[0u8; 64], vec![cert_der])
    }

    #[test]
    fn packed_x5c_garbage_certificate_rejected() {
        let statement = x5c_statement(vec![0xFF; 16]);
        let (_, _, cred_key, _) = credential();
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(matches!(err, WebauthnError::AttestationError(msg) if msg.contains("parse error")));
    }

    #[test]
    fn packed_x5c_trailing_bytes_rejected() {
        let mut cert_der = ec_self_cert("attestor", &ec_key(), &[]);
        cert_der.push(0x00);
        let statement = x5c_statement(cert_der);
        let (_, _, cred_key, _) = credential();
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("trailing bytes"))
        );
    }

    #[test]
    fn packed_x5c_v1_certificate_rejected() {
        let cert = hand_cert(
            OID_SIG_ECDSA_SHA256,
            &name_cn("self"),
            &name_cn("self"),
            &ec_spki_from(&ec_key()),
            true, // v1: no explicit version field
        );
        let statement = x5c_statement(cert);
        let (_, _, cred_key, _) = credential();
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("must be X.509 v3"))
        );
    }

    #[test]
    fn packed_x5c_compressed_ec_point_rejected() {
        let compressed_spki = der_seq(&[
            &der_seq(&[&der_oid(OID_EC_PUBLIC_KEY), &der_oid(OID_PRIME256V1)]),
            &der_bit(&[0x02; 33]), // compressed point: not a 0x04-prefixed 65B point
        ]);
        let cert = hand_cert(
            OID_SIG_ECDSA_SHA256,
            &name_cn("self"),
            &name_cn("self"),
            &compressed_spki,
            false,
        );
        let statement = x5c_statement(cert);
        let (_, _, cred_key, _) = credential();
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("uncompressed P-256 point"))
        );
    }

    #[test]
    fn packed_x5c_unsupported_public_key_algorithm_rejected() {
        let cert = hand_cert(
            OID_SIG_ECDSA_SHA256,
            &name_cn("self"),
            &name_cn("self"),
            &ed25519_spki(),
            false,
        );
        let statement = x5c_statement(cert);
        let (_, _, cred_key, _) = credential();
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("unsupported public key algorithm"))
        );
    }

    // -- chain verification through the public entry point --

    #[test]
    fn packed_x5c_chain_carrying_anchor_is_att_ca() {
        // Two-level chain whose root IS the anchor certificate.
        let anchor_key = ec_key();
        let anchor = ec_self_cert("anchor", &anchor_key, &[bc_ca_true()]);
        let leaf_key = ec_key();
        let leaf = ec_cert(
            "leaf",
            &name_cn("anchor"),
            &leaf_key,
            Some(&anchor_key),
            &[],
            &validity(),
        );
        let (auth_data, cdh, cred_key, _) = credential();
        let sig = leaf_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![leaf, anchor.clone()]);
        let policy = AttestationPolicy {
            trust_anchors: vec![anchor],
            ..AttestationPolicy::default()
        };
        let result = verify_packed(&statement, &cred_key, COSE_ALG_ES256, &policy).unwrap();
        assert_eq!(result.trust_level, TrustLevel::AttCa);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn packed_x5c_chain_issued_by_anchor_is_att_ca() {
        // The chain root is *issued by* the anchor, which is not itself in
        // the chain — the second anchor-matching case.
        let anchor_key = ec_key();
        let anchor = ec_self_cert("anchor", &anchor_key, &[bc_ca_true()]);
        let issuer_key = ec_key();
        let issuer = ec_cert(
            "issuer",
            &name_cn("anchor"),
            &issuer_key,
            Some(&anchor_key),
            &[bc_ca_true()],
            &validity(),
        );
        let leaf_key = ec_key();
        let leaf = ec_cert(
            "leaf",
            &name_cn("issuer"),
            &leaf_key,
            Some(&issuer_key),
            &[],
            &validity(),
        );

        let (auth_data, cdh, cred_key, _) = credential();
        let sig = leaf_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![leaf, issuer]);
        let policy = AttestationPolicy {
            trust_anchors: vec![anchor],
            ..AttestationPolicy::default()
        };
        let result = verify_packed(&statement, &cred_key, COSE_ALG_ES256, &policy).unwrap();
        assert_eq!(result.trust_level, TrustLevel::AttCa);
    }

    #[test]
    fn packed_x5c_anchors_configured_without_match_rejected() {
        let (leaf, issuer, _anchor, leaf_key) = ec_chain();
        // Unrelated (but well-formed) anchor.
        let other = ec_self_cert("other", &ec_key(), &[bc_ca_true()]);
        let (auth_data, cdh, cred_key, _) = credential();
        let sig = leaf_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![leaf, issuer]);
        let policy = AttestationPolicy {
            trust_anchors: vec![other],
            ..AttestationPolicy::default()
        };
        let err = verify_packed(&statement, &cred_key, COSE_ALG_ES256, &policy).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("does not terminate at a configured trust anchor"))
        );
    }

    #[test]
    fn packed_x5c_garbage_anchor_is_error() {
        let (leaf, issuer, _anchor, leaf_key) = ec_chain();
        let (auth_data, cdh, cred_key, _) = credential();
        let sig = leaf_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![leaf, issuer]);
        let policy = AttestationPolicy {
            trust_anchors: vec![vec![0x01]],
            ..AttestationPolicy::default()
        };
        let err = verify_packed(&statement, &cred_key, COSE_ALG_ES256, &policy).unwrap_err();
        assert!(matches!(err, WebauthnError::AttestationError(msg) if msg.contains("parse error")));
    }

    #[test]
    fn packed_x5c_two_level_chain_without_root_rejected() {
        // [leaf, issuer] with no anchors: the chain root is not self-signed.
        let (leaf, issuer, _anchor, leaf_key) = ec_chain();
        let (auth_data, cdh, cred_key, _) = credential();
        let sig = leaf_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![leaf, issuer]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("not self-signed"))
        );
    }

    #[test]
    fn packed_x5c_expired_leaf_rejected() {
        let att_key = ec_key();
        let cert_der = ec_cert(
            "attestor",
            &name_cn("attestor"),
            &att_key,
            None,
            &[],
            &expired_validity(),
        );
        let (auth_data, cdh, cred_key, _) = credential();
        let sig = att_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![cert_der]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("expired or not yet valid"))
        );
    }

    #[test]
    fn packed_x5c_broken_name_link_rejected() {
        // Leaf from one CA, "issuer" from an unrelated CA.
        let (leaf, _issuer, _anchor, leaf_key) = ec_chain();
        let stranger = ec_self_cert("stranger", &ec_key(), &[bc_ca_true()]);
        let (auth_data, cdh, cred_key, _) = credential();
        let sig = leaf_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![leaf, stranger]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(matches!(err, WebauthnError::AttestationError(msg) if msg.contains("do not link")));
    }

    #[test]
    fn packed_x5c_intermediate_without_ca_flag_rejected() {
        // basicConstraints cA=false on the parent → must be rejected.
        let int_key = ec_key();
        let int = ec_self_cert("int", &int_key, &[bc_ca_false()]);
        let leaf_key = ec_key();
        let leaf = ec_cert(
            "leaf",
            &name_cn("int"),
            &leaf_key,
            Some(&int_key),
            &[],
            &validity(),
        );

        let (auth_data, cdh, cred_key, _) = credential();
        let sig = leaf_key
            .sign(&rng(), &signed_data(&auth_data, &cdh))
            .unwrap();
        let statement = packed_stmt(COSE_ALG_ES256, sig.as_ref(), vec![leaf, int]);
        let err = verify_packed(
            &statement,
            &cred_key,
            COSE_ALG_ES256,
            &AttestationPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("lacks basicConstraints cA=true"))
        );
    }

    // ------------------------------------------------------------------
    // AAGUID extension
    // ------------------------------------------------------------------

    fn aaguid_ext_cert(ext_value: Vec<u8>) -> Cert {
        let key = ec_key();
        let exts = vec![extension(OID_FIDO_AAGUID, &ext_value)];
        Cert::from_der(&ec_self_cert("attestor", &key, &exts)).unwrap()
    }

    fn aaguid_ext_value() -> Vec<u8> {
        let mut v = vec![0x04, 0x10];
        v.extend_from_slice(&AAGUID);
        v
    }

    #[test]
    fn aaguid_extension_matching_is_ok() {
        let cert = aaguid_ext_cert(aaguid_ext_value());
        assert!(check_aaguid_extension(&cert, &AAGUID).is_ok());
    }

    #[test]
    fn aaguid_extension_mismatch_rejected() {
        let mut aaguid = AAGUID;
        aaguid[0] ^= 0xFF;
        let cert = aaguid_ext_cert(aaguid_ext_value());
        let err = check_aaguid_extension(&cert, &aaguid).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("does not match"))
        );
    }

    #[test]
    fn aaguid_extension_malforms_rejected() {
        let mut wrong_len = vec![0x04, 0x0F];
        wrong_len.extend_from_slice(&[0u8; 15]);
        assert!(check_aaguid_extension(&aaguid_ext_cert(wrong_len), &AAGUID).is_err());

        let mut wrong_tag = vec![0x05, 0x10];
        wrong_tag.extend_from_slice(&AAGUID);
        assert!(check_aaguid_extension(&aaguid_ext_cert(wrong_tag), &AAGUID).is_err());

        let indefinite = vec![0x04, 0x80];
        assert!(check_aaguid_extension(&aaguid_ext_cert(indefinite), &AAGUID).is_err());

        // Absent extension is fine (optional per FIDO 2.1 §8.2.1).
        let plain = Cert::from_der(&ec_self_cert("attestor", &ec_key(), &[])).unwrap();
        assert!(check_aaguid_extension(&plain, &AAGUID).is_ok());
    }

    // ------------------------------------------------------------------
    // basicConstraints / DER content helpers
    // ------------------------------------------------------------------

    #[test]
    fn parse_basic_constraints_variants() {
        // Explicit BOOLEAN.
        assert_eq!(
            parse_basic_constraints(&[0x30, 0x03, 0x01, 0x01, 0xFF]),
            Some(true)
        );
        assert_eq!(
            parse_basic_constraints(&[0x30, 0x03, 0x01, 0x01, 0x00]),
            Some(false)
        );
        // Empty SEQUENCE → DER default (cA = false).
        assert_eq!(parse_basic_constraints(&[0x30, 0x00]), Some(false));
        // BOOLEAN truncated below 3 content bytes → default false.
        assert_eq!(parse_basic_constraints(&[0x30, 0x01, 0x01]), Some(false));
        // Not a SEQUENCE / empty input.
        assert_eq!(parse_basic_constraints(&[0x02, 0x00]), None);
        assert_eq!(parse_basic_constraints(&[]), None);
        // Long-form lengths.
        assert_eq!(
            parse_basic_constraints(&[0x30, 0x81, 0x03, 0x01, 0x01, 0xFF]),
            Some(true)
        );
        assert_eq!(
            parse_basic_constraints(&[0x30, 0x82, 0x00, 0x03, 0x01, 0x01, 0xFF]),
            Some(true)
        );
        // Indefinite length → None; long-form length with empty content →
        // default false.
        assert_eq!(parse_basic_constraints(&[0x30, 0x80]), None);
        assert_eq!(
            parse_basic_constraints(&[0x30, 0x84, 0, 0, 0, 0]),
            Some(false)
        );
        // Declared length beyond available bytes → None.
        assert_eq!(parse_basic_constraints(&[0x30, 0x81, 0x05, 0x01]), None);
    }

    #[test]
    fn is_ca_reflects_certificate_constraints() {
        let ca = Cert::from_der(&ec_self_cert("ca", &ec_key(), &[bc_ca_true()])).unwrap();
        assert_eq!(ca.is_ca(), Some(true));

        let explicit_no_ca =
            Cert::from_der(&ec_self_cert("leaf", &ec_key(), &[bc_ca_false()])).unwrap();
        assert_eq!(explicit_no_ca.is_ca(), Some(false));

        let no_ext = Cert::from_der(&ec_self_cert("leaf", &ec_key(), &[])).unwrap();
        assert_eq!(no_ext.is_ca(), None);
    }

    // ------------------------------------------------------------------
    // verify_signed_by (child, parent) algorithm handling
    // ------------------------------------------------------------------

    #[test]
    fn verify_signed_by_ecdsa_ok_and_tampered() {
        let (leaf, issuer, _anchor, _leaf_key) = ec_chain();
        let child = Cert::from_der(&leaf).unwrap();
        let parent = Cert::from_der(&issuer).unwrap();
        assert!(child.verify_signed_by(&parent).is_ok());

        // Flip the last signature byte (inside the final BIT STRING) — the
        // certificate still parses but the signature must fail.
        let mut tampered = leaf.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let child = Cert::from_der(&tampered).unwrap();
        assert!(matches!(
            child.verify_signed_by(&parent),
            Err(WebauthnError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn verify_signed_by_rsa_ok_and_tampered() {
        // RSA CA signs an EC-SPKI leaf with PKCS#1 v1.5 SHA-256.
        let ca_key = rsa_signing_key();
        let ca = rsa_self_cert(&ca_key, &[bc_ca_true()]);
        let leaf_key = ec_key();

        let subject = name_cn("rsa-leaf");
        let leaf_tbs = tbs_cert(
            OID_SIG_SHA256_RSA,
            &subject_raw(&ca),
            &subject,
            &ec_spki_from(&leaf_key),
            &[],
            &validity(),
            false,
        );
        let rng = rng();
        let mut leaf_sig = vec![0u8; 256];
        ca_key
            .sign(&RSA_PKCS1_SHA256, &rng, &leaf_tbs, &mut leaf_sig)
            .unwrap();
        let leaf = finish_cert(&leaf_tbs, OID_SIG_SHA256_RSA, &leaf_sig);

        let child = Cert::from_der(&leaf).unwrap();
        let parent = Cert::from_der(&ca).unwrap();
        assert!(child.verify_signed_by(&parent).is_ok());

        let mut tampered = leaf.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let child = Cert::from_der(&tampered).unwrap();
        assert!(matches!(
            child.verify_signed_by(&parent),
            Err(WebauthnError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn verify_signed_by_algorithm_issuer_key_type_mismatches() {
        // ECDSA-signed child over an RSA parent.
        let rsa_key_pair = rsa_signing_key();
        let rsa_parent = rsa_self_cert(&rsa_key_pair, &[bc_ca_true()]);
        let parent = Cert::from_der(&rsa_parent).unwrap();
        let child = Cert::from_der(&hand_cert(
            OID_SIG_ECDSA_SHA256,
            &subject_raw(&rsa_parent),
            &name_cn("child"),
            &ec_spki_from(&ec_key()),
            false,
        ))
        .unwrap();
        let err = child.verify_signed_by(&parent).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("does not match issuer key type"))
        );

        // RSA-signed child over an EC parent.
        let ec_key_pair = ec_key();
        let ec_parent = ec_self_cert("ec-parent", &ec_key_pair, &[bc_ca_true()]);
        let parent = Cert::from_der(&ec_parent).unwrap();
        let child = Cert::from_der(&hand_cert(
            OID_SIG_SHA256_RSA,
            &subject_raw(&ec_parent),
            &name_cn("child"),
            &ec_spki_from(&ec_key()),
            false,
        ))
        .unwrap();
        let err = child.verify_signed_by(&parent).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("does not match issuer key type"))
        );

        // Unsupported signature algorithm fails closed.
        let child = Cert::from_der(&hand_cert(
            OID_SIG_ECDSA_SHA512,
            &subject_raw(&ec_parent),
            &name_cn("child"),
            &ec_spki_from(&ec_key()),
            false,
        ))
        .unwrap();
        let err = child.verify_signed_by(&parent).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("unsupported signature algorithm"))
        );
    }

    // ------------------------------------------------------------------
    // FIDO U2F attestation
    // ------------------------------------------------------------------

    #[test]
    fn u2f_attestation_ok() {
        let (auth_data, cdh, key, _) = credential();
        let att_key = ec_key();
        let cert_der = ec_self_cert("u2f", &att_key, &[]);
        let msg = u2f_msg(&auth_data, &cdh, &key);
        let sig = att_key.sign(&rng(), &msg).unwrap();
        let statement = cbor_map(vec![
            (8, cbor_bytes_val(sig.as_ref())),
            (33, Value::Array(vec![cbor_bytes_val(&cert_der)])),
        ]);
        let result = u2f_call(&statement, &key, COSE_ALG_ES256, &auth_data, &cdh).unwrap();
        assert_eq!(result.format, AttestationFormat::FidoU2f);
        assert_eq!(result.trust_level, TrustLevel::BasicAtt);
        assert_eq!(result.warnings, vec![warnings::UNANCHORED_CHAIN]);
        assert_eq!(result.aaguid, Some(AAGUID));
    }

    #[test]
    fn u2f_rejects_non_es256_credential() {
        let (auth_data, cdh, key, _) = credential();
        let att_key = ec_key();
        let cert_der = ec_self_cert("u2f", &att_key, &[]);
        let msg = u2f_msg(&auth_data, &cdh, &key);
        let sig = att_key.sign(&rng(), &msg).unwrap();
        let statement = cbor_map(vec![
            (8, cbor_bytes_val(sig.as_ref())),
            (33, Value::Array(vec![cbor_bytes_val(&cert_der)])),
        ]);
        let err = u2f_call(&statement, &key, COSE_ALG_RS256, &auth_data, &cdh).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("requires an ES256 credential key"))
        );
    }

    #[test]
    fn u2f_rejects_non_ec2_credential_key() {
        let (auth_data, cdh, _, _) = credential();
        let rsa_cred = CosePublicKey::Rsa {
            n: vec![0xAA; 256],
            e: vec![0x01, 0x00, 0x01],
        };
        let cert_der = ec_self_cert("u2f", &ec_key(), &[]);
        // Signature content is irrelevant: the credential key is rejected
        // before any signature check.
        let statement = cbor_map(vec![
            (8, cbor_bytes_val(&[0u8; 64])),
            (33, Value::Array(vec![cbor_bytes_val(&cert_der)])),
        ]);
        let err = u2f_call(&statement, &rsa_cred, COSE_ALG_ES256, &auth_data, &cdh).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("requires an EC2 credential key"))
        );
    }

    #[test]
    fn u2f_rejects_non_ec_attestation_certificate() {
        let (auth_data, cdh, key, _) = credential();
        // RSA attestation certificate (self-signed, real signature).
        let rsa = rsa_signing_key();
        let cert_der = rsa_self_cert(&rsa, &[]);

        let msg = u2f_msg(&auth_data, &cdh, &key);
        let rng = rng();
        let mut sig = vec![0u8; 256];
        rsa.sign(&RSA_PKCS1_SHA256, &rng, &msg, &mut sig).unwrap();
        let statement = cbor_map(vec![
            (8, cbor_bytes_val(&sig)),
            (33, Value::Array(vec![cbor_bytes_val(&cert_der)])),
        ]);
        let err = u2f_call(&statement, &key, COSE_ALG_ES256, &auth_data, &cdh).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("must carry an EC P-256 key"))
        );
    }

    #[test]
    fn u2f_rejects_wrong_coordinate_length() {
        let (auth_data, cdh, _, _) = credential();
        let short_key = CosePublicKey::Ec2 {
            x: vec![0xAA; 31],
            y: vec![0xBB; 32],
        };
        let well_formed = CosePublicKey::Ec2 {
            x: vec![0xAA; 32],
            y: vec![0xBB; 32],
        };
        let att_key = ec_key();
        let cert_der = ec_self_cert("u2f", &att_key, &[]);
        let msg = u2f_msg(&auth_data, &cdh, &well_formed);
        let sig = att_key.sign(&rng(), &msg).unwrap();
        let statement = cbor_map(vec![
            (8, cbor_bytes_val(sig.as_ref())),
            (33, Value::Array(vec![cbor_bytes_val(&cert_der)])),
        ]);
        let err = u2f_call(&statement, &short_key, COSE_ALG_ES256, &auth_data, &cdh).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("must be 32 bytes"))
        );
    }

    #[test]
    fn u2f_rejects_short_auth_data() {
        let (auth_data, cdh, key, _) = credential();
        let att_key = ec_key();
        let cert_der = ec_self_cert("u2f", &att_key, &[]);
        let msg = u2f_msg(&auth_data, &cdh, &key);
        let sig = att_key.sign(&rng(), &msg).unwrap();
        let statement = cbor_map(vec![
            (8, cbor_bytes_val(sig.as_ref())),
            (33, Value::Array(vec![cbor_bytes_val(&cert_der)])),
        ]);
        let err = u2f_call(&statement, &key, COSE_ALG_ES256, &auth_data[..31], &cdh).unwrap_err();
        assert!(
            matches!(err, WebauthnError::AttestationError(msg) if msg.contains("too short for fido-u2f"))
        );
    }
}
