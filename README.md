# webauthn-kit

[![docs.rs](https://docs.rs/webauthn-kit/badge.svg)](https://docs.rs/webauthn-kit)
[![crates.io](https://img.shields.io/crates/v/webauthn-kit.svg)](https://crates.io/crates/webauthn-kit)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Standalone WebAuthn / FIDO2 passkey verification kit for Rust servers: a real,
custom CTAP2/COSE implementation on [`ring`](https://crates.io/crates/ring) —
not a wrapper. Zero framework coupling: no storage, no HTTP types, no config
files.

- **ES256** (ECDSA P-256 + SHA-256), **ES384** (ECDSA P-384 + SHA-384),
  **EdDSA** (Ed25519), and **RS256** (RSA PKCS#1 v1.5 + SHA-256) signature
  verification — all via `ring`, zero additional crypto dependencies
- CTAP2 authenticator data parsing (rpIdHash, flags incl. BE/BS, signCount,
  attested credential data)
- Full `verify_registration` / `verify_authentication` ceremonies
- Enforceable credential policies: user verification (UV), multi-device /
  backup eligibility (BE/BS), registration algorithm allowlists
- Attestation verification for `none`, `packed` (self + x5c), and
  `fido-u2f` with X.509 chain verification against configured trust anchors
- Challenge generation from the OS CSPRNG, single-use consumption (replay
  protection), freshness/expiry enforcement, sign-count clone detection
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

## Quick start

```toml
[dependencies]
webauthn-kit = "0.3"
```

```rust
use webauthn_kit::{
    ChallengeStore, CredentialPolicy, UserVerificationPolicy, WebauthnConfig,
};

let config = WebauthnConfig {
    rp_id: "example.com".into(),
    rp_name: "Example".into(),
    rp_origins: vec!["https://example.com".into()],
    allowed_algorithms: vec![-7, -35, -257], // ES256, ES384, RS256
    challenge_timeout_secs: 300,
    // Server-side enforcement: UV required, synced passkeys rejected.
    credential_policy: CredentialPolicy {
        user_verification: UserVerificationPolicy::Required,
        ..CredentialPolicy::default()
    },
    resident_key: Default::default(),
    attestation_conveyance: Default::default(),
    attestation: Default::default(),
};

// 1. Issue + store a single-use challenge, send options to the browser.
let mut store = ChallengeStore::new();
let (challenge_id, create_options) =
    store.generate_registration_challenge(&config, "alice", "Alice", &[]);
store.store_registration_challenge(&challenge_id, "alice", challenge_id.as_bytes().into());

// 2. On the callback: consume the challenge (single use), then verify.
let (_, challenge_bytes) = store.consume_registration_challenge(&challenge_id, 300)?;
// let registration = webauthn_kit::verify_registration(
//     &challenge_bytes, &resp.client_data_json, &resp.attestation_object,
//     existing_credential_id, &config.rp_id, &config.rp_origins,
//     &config.attestation, &config.credential_policy)?;

// 3. Store a credential record; for logins use verify_authentication and
//    persist AuthenticationResult::new_sign_count (clone detection).
```

A complete synthetic registration→authentication roundtrip lives in
[`tests/vectors.rs`](tests/vectors.rs); hostile-input property tests in
[`tests/fuzz.rs`](tests/fuzz.rs).

## Storage contract (what this crate does NOT do)

This crate is deliberately storage-free. You own:

- **Credential persistence.** After `verify_registration` succeeds, store the
  `WebauthnCredential` (ID, COSE public key, sign count, timestamps). After
  each successful `verify_authentication`, atomically persist
  `AuthenticationResult::new_sign_count` — ideally compare-and-swap so
  concurrent logins cannot both bump the counter.
- **Challenge durability.** `ChallengeStore` keeps pending challenges in
  memory; they are lost on restart (users simply retry). Always
  consume-then-verify so restarts can never enable replays.
- **User mapping, sessions, cookies/JWTs, UI, HTTP DTOs.**
- **Attestation verification** — see below.

## Security notes

- All cryptography is `ring` (constant-time ECDSA/RSA/Ed25519 verification).
  The only hand-written encoding is DER *wrapping* of already-validated RSA
  integers.
- Every parser accepts hostile input and returns `Err` instead of panicking;
  this is enforced with property-based tests (`proptest`) over arbitrary
  bytes, truncations, and malformed CBOR.
- Challenges are 32 bytes from the OS CSPRNG, consumed exactly once, with a
  configurable freshness window.

### Algorithms

| COSE ID | Name   | Key type | Details |
|--------:|--------|----------|---------|
| −7      | ES256  | EC2 (crv 1)  | ECDSA P-256 + SHA-256, fixed-width signatures |
| −35     | ES384  | EC2 (crv 2)  | ECDSA P-384 + SHA-384, fixed-width signatures |
| −8      | EdDSA  | OKP (crv 6)  | Ed25519, raw 32-byte public keys |
| −257    | RS256  | RSA          | PKCS#1 v1.5 + SHA-256, ≥2048-bit modulus |

Curve/algorithm bindings are enforced at *parse time*: a P-256 key claiming
ES384 (or any other cross-curve/cross-type confusion) is rejected before any
signature work. Other algorithms (ES512, RS1, ...) are rejected with
`UnsupportedAlgorithm`.

### Credential policies (0.3.0)

| Policy | Values | Enforcement |
|--------|--------|-------------|
| `user_verification` | `Required` / `Preferred` / `Discouraged` | `Required` rejects UV-clear ceremonies with `UserVerificationRequired`; the others report `user_verified` only |
| `backup` | `Allow` / `RequireDeviceBound` | `RequireDeviceBound` rejects syncable (BE=1) credentials at both ceremonies |
| `allowed_algorithms` | list of COSE IDs (empty = all supported) | registration rejects credentials with disallowed algorithms |
| `resident_key`, `attestation_conveyance` | conveyed in registration options | *preferences only* — the server cannot verify discoverability/attestation conveyance from the response alone |

### User verification and backup flags

- The **UV flag** is enforced per `CredentialPolicy::user_verification`.
  Use `Required` for step-up or high-assurance flows; with `Preferred` (the
  default) the flag is only *reported*, matching 0.2.x behavior.
- **BE (backup eligibility)** marks a credential as syncable/multi-device
  (iCloud Keychain, Google Password Manager, ...). It is set at creation and
  immutable. **BS (backup state)** reports whether it is currently backed up
  and may change over time. Both are parsed from *signed* authenticator
  data and reported on both ceremony results.
- **Account-recovery implication**: a BE=1 credential is only as strong as
  the user's cloud account — platform account recovery (phone number,
  recovery email) can resurrect it. If your threat model requires the
  credential to be confined to one piece of hardware, set
  `BackupPolicy::RequireDeviceBound` and store the registration-time BE
  value.
- Sign-count policy: a stored counter of `0` disables the check
  (counterless authenticators); a strictly decreasing counter is rejected as
  evidence of a cloned authenticator. Equal counters are allowed by design.
- Error strings may echo attacker-controlled input fragments; log them
  server-side, don't forward them to clients.

### Attestation

Attestation statements are verified for `none` (empty-statement enforced),
`packed` (self-attestation and x5c basic/AttCA), and `fido-u2f`, including
X.509 chain verification against caller-configured trust anchors
(`AttestationPolicy::trust_anchors`). Unknown formats are rejected unless
`allow_unknown_formats` is set (trust-weakening escape hatch). Only chains
terminating at a configured anchor report `TrustLevel::AttCa`; unanchored
chains are accepted as `BasicAtt` **with a warning** and must be treated as
self-attested. Packed x5c certificates are limited to EC P-256 / RSA keys.
Other formats (`tpm`, `android-key`, `android-safetynet`, ...) and full
CA-chain policy/revocation are future work — see THREAT-MODEL.md.

## Features

| Feature   | Default | Description                                  |
| --------- | ------- | -------------------------------------------- |
| `std`     | yes     | Timed challenge store (`std::time` clock).   |
| `serde`   | no      | Serde (de)serialization for the wire DTOs.   |

## License

Dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.

## Security

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
