# webauthn-kit

Standalone WebAuthn / FIDO2 passkey verification kit for Rust servers: a real,
custom CTAP2/COSE implementation on [`ring`](https://crates.io/crates/ring) —
not a wrapper. Zero framework coupling: no storage, no HTTP types, no config
files.

- **ES256** (ECDSA P-256 + SHA-256) and **RS256** (RSA PKCS#1 v1.5 + SHA-256)
  signature verification
- CTAP2 authenticator data parsing (rpIdHash, flags, signCount, attested
  credential data)
- Full `verify_registration` / `verify_authentication` ceremonies
- Challenge generation from the OS CSPRNG, single-use consumption (replay
  protection), freshness/expiry enforcement, sign-count clone detection
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

## Quick start

```toml
[dependencies]
webauthn-kit = "0.1"
```

```rust
use webauthn_kit::{ChallengeStore, WebauthnConfig};

let config = WebauthnConfig {
    rp_id: "example.com".into(),
    rp_name: "Example".into(),
    rp_origins: vec!["https://example.com".into()],
    allowed_algorithms: vec![-7, -257], // ES256, RS256
    challenge_timeout_secs: 300,
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
//     existing_credential_id, &config.rp_id, &config.rp_origins)?;

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

- All cryptography is `ring` (constant-time ECDSA/RSA verification). The only
  hand-written encoding is DER *wrapping* of already-validated RSA integers.
- Every parser accepts hostile input and returns `Err` instead of panicking;
  this is enforced with property-based tests (`proptest`) over arbitrary
  bytes, truncations, and malformed CBOR.
- Challenges are 32 bytes from the OS CSPRNG, consumed exactly once, with a
  configurable freshness window.
- Supported algorithms: **ES256** (COSE −7), **RS256** (COSE −257). Other
  algorithms (OKP/Ed25519, ES384/512, P-384, RS1) are rejected with
  `UnsupportedAlgorithm`. Key-type/algorithm mismatches (e.g. RSA key
  claiming ES256) are rejected.
- Sign-count policy: a stored counter of `0` disables the check
  (counterless authenticators); a strictly decreasing counter is rejected as
  evidence of a cloned authenticator. Equal counters are allowed by design.
- The UV (user verification) flag is **reported, never required** — enforce
  your own policy per ceremony from `user_verified` in the results.
- Error strings may echo attacker-controlled input fragments; log them
  server-side, don't forward them to clients.

### Attestation

The attestation object is decoded to extract authenticator data, and the
`fmt` string is recorded informationally. **Attestation statement signatures
are not verified** — any `fmt` ("none", "packed", "fido-u2f",
"android-key", ...) is tolerated. Registration in this kit proves key
possession, not device provenance. If you need verified device provenance,
add an attestation verifier on top.

## Features

| Feature   | Default | Description                                  |
| --------- | ------- | -------------------------------------------- |
| `std`     | yes     | Timed challenge store (`std::time` clock).   |
| `serde`   | no      | Serde (de)serialization for the wire DTOs.   |

## License

Dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
