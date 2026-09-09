# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

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
