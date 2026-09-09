//! # webauthn-kit
//!
//! Standalone `WebAuthn` / FIDO2 passkey verification kit: real CTAP2/COSE
//! cryptographic verification with zero framework coupling. This is not a
//! wrapper around `navigator.credentials` server emulation — it implements
//! the server side of the protocol directly on `ring`.
//!
//! ## What it does
//!
//! - Full CTAP2 authenticator data parsing (rpIdHash, flags, signCount,
//!   attested credential data incl. AAGUID) — [`protocol`]
//! - `verify_registration` / `verify_authentication` ceremonies — [`protocol`]
//! - Attestation statement verification for the `none`, `packed` (self- and
//!   x5c-based basic/AttCA), and `fido-u2f` formats, with X.509 chain
//!   verification against caller-configured trust anchors — [`attestation`]
//! - COSE public key parsing and signature verification for **ES256**
//!   (ECDSA P-256 + SHA-256) and **RS256** (RSA PKCS#1 v1.5 + SHA-256) via
//!   `ring` — [`crypto`]
//! - Challenge generation from the OS CSPRNG, single-use consumption
//!   (replay protection), freshness/expiry enforcement, and the sign-count
//!   clone-detection state machine — [`challenge`]
//! - Storage-free credential record + browser wire DTOs — [`credential`]
//!
//! ## Quick start
//!
//! ```
//! use webauthn_kit::{
//!     check_sign_count, verify_authentication, verify_registration, AttestationPolicy,
//!     AuthenticationParams, ChallengeStore, WebauthnConfig,
//! };
//!
//! let config = WebauthnConfig {
//!     rp_id: "example.com".into(),
//!     rp_name: "Example".into(),
//!     rp_origins: vec!["https://example.com".into()],
//!     allowed_algorithms: vec![-7, -257],
//!     challenge_timeout_secs: 300,
//!     attestation: AttestationPolicy::default(),
//! };
//!
//! // 1. Issue a challenge (single-use; store the (id, bytes) pair).
//! let store = ChallengeStore::new();
//! let (challenge_b64, create_options) =
//!     store.generate_registration_challenge(&config, "alice", "Alice", &[]);
//! // ... send `create_options` to the browser, receive RegistrationResponse ...
//!
//! // 2. Verify a registration response (see tests/vectors.rs for a full
//! //    roundtrip with a synthetic keypair).
//! // let result = verify_registration(&challenge, &client_data_json_b64,
//! //     &attestation_object_b64, "", &config.rp_id, &config.rp_origins,
//! //     &config.attestation)?;
//!
//! // 3. Verify an assertion; persist result.new_sign_count afterwards.
//! // let result = verify_authentication(&AuthenticationParams { ... })?;
//! ```
//!
//! ## Storage contract (what this crate does NOT do)
//!
//! This crate is deliberately storage-free. The integrator owns:
//!
//! - **Credential persistence**: after [`verify_registration`] succeeds,
//!   store a [`credential::WebauthnCredential`] (credential ID, COSE public
//!   key, sign count, timestamps). After each successful
//!   [`verify_authentication`], atomically persist
//!   [`credential::AuthenticationResult::new_sign_count`].
//! - **Challenge durability**: [`ChallengeStore`] holds pending challenges
//!   in memory; they are lost on restart (users simply retry). Keep the
//!   consume-then-verify ordering so restarts can never enable replays.
//! - **User mapping and session issuance** (cookies, JWTs, ...).
//! - **UI / HTTP layer**: the `credential` DTOs serialize with the `serde`
//!   feature but no HTTP types are included.
//!
//! ## Security notes
//!
//! - `#![forbid(unsafe_code)]`; all cryptography via `ring`.
//! - Every parser accepts hostile input and returns `Err` instead of
//!   panicking (property/fuzz-tested in `tests/fuzz.rs`).
//! - Challenge bytes are 32 bytes from the OS CSPRNG; consumption is
//!   single-use and freshness-bounded.
//! - **Attestation is verified for `none`, `packed`, and `fido-u2f`**;
//!   unknown formats are rejected unless the
//!   `AttestationPolicy::allow_unknown_formats` escape hatch is set
//!   (trust-weakening). Provenance claims are bounded by the configured
//!   trust anchors: with none configured, unanchored certificate chains are
//!   accepted but flagged (`TrustLevel::BasicAtt` + warning) and must be
//!   treated as self-attested. Only `TrustLevel::AttCa` attests device
//!   provenance. Other formats (`android-key`, `tpm`, ...) are tranche-2
//!   work — see [`attestation`].
//! - Supported algorithms: ES256 (COSE -7) and RS256 (COSE -257) only.
//!   Other algorithms (including OKP/Ed25519) are rejected with
//!   [`WebauthnError::UnsupportedAlgorithm`].
//! - Sign-count policy: a stored counter of 0 disables the check
//!   (authenticators without counters); otherwise a strictly decreasing
//!   counter is rejected. Equal counters are allowed by design.
//! - The UV (user verification) flag is reported, never required; enforce
//!   your own policy per ceremony.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aaguid;
pub mod attestation;
pub mod challenge;
pub mod config;
pub mod credential;
pub mod crypto;
pub mod error;
pub mod protocol;

pub use aaguid::known_aaguid;
pub use attestation::{
    verify_attestation, AttestationFormat, AttestationPolicy, AttestationResult, TrustLevel,
};
pub use challenge::{check_sign_count, ChallengeStore};
pub use config::WebauthnConfig;
pub use credential::{
    AllowCredential, AuthenticationOptions, AuthenticationResponse, AuthenticationResult,
    AuthenticatorSelection, ExcludeCredential, PubKeyCredParam, RegistrationOptions,
    RegistrationResponse, RegistrationResult, RelyingParty, WebauthnCredential, WebauthnUser,
};
pub use crypto::{
    alg_to_name, base64_decode_urlsafe, base64_encode_urlsafe, cbor_bytes, cbor_map_entries,
    generate_challenge_bytes, parse_cose_key, verify_cose_signature, CosePublicKey, COSE_ALG_ES256,
    COSE_ALG_RS256, COSE_KTY_EC2, COSE_KTY_OKP, COSE_KTY_RSA,
};
pub use error::WebauthnError;
pub use protocol::{verify_authentication, verify_registration, AuthenticationParams};
