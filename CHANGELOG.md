# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.3.1] - 2026-09-12

### Added

- `tests/config_matrix.rs` — per-knob behavior matrix for all 9
  `WebauthnConfig` fields. Gap fill: the six options-conveyance knobs
  (`rp_name`, advertised `allowed_algorithms`, `challenge_timeout_secs`,
  `resident_key`, `attestation_conveyance`, UV preference) had no
  observable assertion; verify-time enforcement was verified already
  covered in `src/protocol.rs` / `src/attestation.rs` / `tests/fuzz.rs`.
  No dead knobs found.

## [0.3.0] - 2026-09-12

### Added

- **ES384** (COSE −35, ECDSA P-384 + SHA-384): COSE key parsing (SEC1 P-384
  points) and fixed-width signature verification via `ring`'s
  `ECDSA_P384_SHA384_FIXED`. No new dependencies — `ring` 0.17 already
  provides constant-time P-384, keeping the "all cryptography via ring"
  supply-chain invariant intact.
- **EdDSA** (COSE −8, Ed25519): OKP COSE key parsing (raw 32-byte keys) and
  verification via `ring`'s `ED25519`. Likewise no new dependencies.
- **Credential policies** (`policy` module, enforced server-side):
  - `UserVerificationPolicy` (`Required` / `Preferred` / `Discouraged`) on
    both ceremonies. `Required` rejects assertions/registrations whose UV
    flag is clear with the new `WebauthnError::UserVerificationRequired`.
  - `BackupPolicy` (`Allow` / `RequireDeviceBound`) over the WebAuthn L3
    BE/BS flags (backup eligibility / backup state), which are now parsed
    from signed authenticator data and reported on `RegistrationResult`,
    `AuthenticationResult`, and `WebauthnCredential`. `RequireDeviceBound`
    rejects multi-device (syncable) credentials.
  - `CredentialPolicy::allowed_algorithms`: registration-time server-side
    algorithm allowlist — credentials with disallowed COSE algorithms are
    rejected even when the kit could verify them.
  - `CredentialPolicy::strict()` helper (UV required, device-bound, ES256).
- **Algorithm/curve binding at parse time** (REQ-WA-146): a P-256 key
  claiming ES384, a P-384 key claiming ES256, or an OKP key claiming a
  non-EdDSA algorithm is rejected in `parse_cose_key` before any signature
  work — closing the algorithm-confusion class for the new curves.
- Registration options now convey `residentKey` (with the L2
  `requireResidentKey` flag when required), `userVerification`, and
  `attestation` preferences from the new `WebauthnConfig` fields
  (`resident_key`, `credential_policy.user_verification`,
  `attestation_conveyance`). These are preferences; enforcement lives in
  `CredentialPolicy`.

### Changed

- `verify_registration` takes an additional `&CredentialPolicy` argument;
  `AuthenticationParams` gained a `policy: CredentialPolicy` field.
  `CredentialPolicy::default()` preserves the 0.2.x behavior (UV reported,
  never required).
- `WebauthnConfig::allowed_algorithms` default is now `[-7, -35, -257]`
  (ES256, ES384, RS256); the empty-config advertising fallback matches.
- Packed **x5c** attestation statements remain ES256/RS256-only (the X.509
  chain machinery parses P-256/RSA certificate keys only); packed
  **self**-attestation and `none` support all credential algorithms.

### Security

- **UV enforcement** (was THREAT-MODEL OPEN-4): 0.2.x parsed and reported
  the user-verification flag but never enforced it; callers had to
  hand-roll the check. `UserVerificationPolicy::Required` now enforces it
  server-side in both ceremonies.
- BE/BS flags are authenticated (inside signed authenticator data), so
  `BackupPolicy` decisions cannot be manipulated by the client without
  breaking the assertion signature. See `policy` module docs for the
  account-recovery implications of allowing synced (BE=1) passkeys.

## [0.2.2] - 2026-09-09

### Fixed

- **RS256 verification was non-functional**: `RsaPublicKeyDer::to_der` built
  an RFC 5280 `SubjectPublicKeyInfo`, but `ring`'s RSA verifiers parse
  PKCS#1 `RSAPublicKey` (`SEQUENCE { n, e }`); the encoded algorithm OID was
  `sha256WithRSAEncryption` instead of `rsaEncryption`, and DER INTEGER
  lengths ≥ 128 bytes were written as a single byte (corrupting every
  2048-bit modulus). All three defects are corrected; an end-to-end RS256
  signature roundtrip now verifies.
- **RSA attestation certificates could never verify** (packed x5c /
  fido-u2f): `ring` was handed the full certificate `SubjectPublicKeyInfo`
  instead of the PKCS#1 `RSAPublicKey` it parses (the SPKI BIT STRING
  content). `Cert::from_der` now stores and verifies against the inner
  `RSAPublicKey`.

### Added

- Test suite expanded from 75.2% to 98.6% line coverage (`cargo llvm-cov
  --all-features`), including full `none` / packed (self + x5c EC & RSA) /
  `fido-u2f` attestation verification with real ring-signed certificate
  chains, trust-anchor policy cases, AAGUID extension checks, and every
  parse/verification error path.

## [0.1.0] - 2026-09-04

### Added

- Full `verify_registration` / `verify_authentication` WebAuthn ceremonies.
- ES256 (ECDSA P-256 + SHA-256, COSE −7) and RS256 (RSA PKCS#1 v1.5,
  COSE −257) signature verification via `ring`.
- CTAP2 authenticator data parsing: rpIdHash, flags, signCount, attested
  credential data.
- Challenge generation from the OS CSPRNG with single-use consumption
  (replay protection) via `ChallengeStore`.
- Sign-count policy: stored counter of `0` disables the check.
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`.
