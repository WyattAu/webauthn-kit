# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

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
