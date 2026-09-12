# Requirements — webauthn-kit

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement. Doc
comments on the implementing public item carry `REQ-WA-NNN` tags.

Threat model summary (from `src/protocol.rs`, `src/challenge.rs`, crate docs):
all base64/JSON/CBOR inputs are attacker-controlled and must be rejected with
`Err` (never panic); challenges are server-side single-use CSPRNG secrets;
attestation is verified for `none`/`packed`/`fido-u2f` (bounded by configured
trust anchors); ES256/ES384/EdDSA/RS256 with parse-time curve/algorithm
binding; credential policies (UV, backup eligibility, algorithm allowlist)
enforced server-side when configured.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WA-001 | `verify_registration` on a valid ES256 attestation object returns `Ok(RegistrationResult)` with the base64url credential ID and recorded attestation format | MUST |
| REQ-WA-002 | `verify_authentication` on a validly-signed ES256 assertion returns `Ok(AuthenticationResult)` with `new_sign_count` equal to the authenticator counter | MUST |
| REQ-WA-003 | `parse_cose_key` extracts EC2 (x/y), RSA (n/e), and OKP (raw key) components with declared `alg` from valid COSE CBOR | MUST |
| REQ-WA-004 | `base64_encode_urlsafe`/`base64_decode_urlsafe` round-trip arbitrary bytes without padding; encode uses the URL-safe alphabet | MUST |
| REQ-WA-005 | `generate_registration_challenge` advertises `pubKeyCredParams` derived from `allowed_algorithms` (sorted, deduped; default ES256+ES384+RS256 when empty) and `excludeCredentials` from existing IDs | SHOULD |
| REQ-WA-006 | `generate_authentication_challenge` returns options embedding `rp_id`, the supplied `allow_credentials`, and the challenge | SHOULD |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WA-100 | Every parse/verify entry point (`verify_registration`, `verify_authentication`, `parse_cose_key`, `parse_authenticator_data`) returns `Ok` or `Err` on arbitrary byte input — never panics | MUST |
| REQ-WA-101 | A client-echoed challenge that does not match the stored server challenge is rejected in both ceremonies | MUST |
| REQ-WA-102 | A `clientDataJSON.type` that does not match the ceremony (`webauthn.create` / `webauthn.get`) is rejected | MUST |
| REQ-WA-103 | An `origin` not on the exact-match allow-list is rejected; an optional client `rpId` not equal to `rp_id` is rejected | MUST |
| REQ-WA-104 | Authenticator data whose `rpIdHash` is not SHA-256(rp_id) is rejected in both ceremonies | MUST |
| REQ-WA-105 | Assertions/registrations without the User Present (UP) flag are rejected | MUST |
| REQ-WA-106 | A signature that does not verify over `authenticatorData ‖ SHA-256(clientDataJSON)` is rejected with `SignatureVerificationFailed` | MUST |
| REQ-WA-107 | Algorithm/key-type mismatches are rejected, never fall back: ES256 requires an EC2/P-256 key, ES384 an EC2/P-384 key, EdDSA an OKP/Ed25519 key, RS256 requires RSA ≥2048-bit | MUST |
| REQ-WA-108 | Challenges are single-use: a second `consume_*_challenge` for the same ID returns `Err` even for the same caller | MUST |
| REQ-WA-109 | A challenge older than the caller's timeout is rejected with `ChallengeExpired`; unknown IDs with `InvalidChallenge` | MUST |
| REQ-WA-110 | Challenge bytes are exactly 32 bytes sourced from the OS CSPRNG (`ring::rand::SystemRandom`) | MUST |
| REQ-WA-111 | A sign counter strictly lower than the stored counter is rejected (clone detection) | MUST |
| REQ-WA-112 | A stored counter of 0 disables the check; an equal counter is accepted | MUST |
| REQ-WA-113 | Re-registration of an existing credential ID is rejected with `DuplicateCredential` | MUST |
| REQ-WA-114 | A credential ID outside `allowed_credential_ids` is rejected before any signature work | MUST |
| REQ-WA-115 | `Debug` for `ChallengeStore` never renders challenge bytes or usernames | MUST |
| REQ-WA-116 | The UV flag is reported (`user_verified`); under the default `Preferred` policy it never causes rejection | SHOULD |
| REQ-WA-117 | A registration whose authenticator data lacks the AT flag (no attested credential data) is rejected | MUST |
| REQ-WA-118 | `base64_decode_urlsafe` on malformed input returns `Err`, never panics | MUST |
| REQ-WA-140 | ES384 (COSE −35, ECDSA P-384 + SHA-384): EC2 keys with `crv = 2` parse and fixed-width signatures verify via `ring` (`ECDSA_P384_SHA384_FIXED`); tampered messages fail closed | MUST |
| REQ-WA-141 | EdDSA (COSE −8, Ed25519): OKP keys with `crv = 6` parse and signatures verify via `ring` (`ED25519`); tampered messages fail closed | MUST |
| REQ-WA-142 | `UserVerificationPolicy::Required` rejects UV-clear registrations/assertions with `UserVerificationRequired`; `Preferred`/`Discouraged` report the flag without rejecting | MUST |
| REQ-WA-143 | A non-empty `CredentialPolicy::allowed_algorithms` rejects registration of credentials whose COSE algorithm is absent from the list | MUST |
| REQ-WA-144 | BE/BS flags are parsed from authenticator data and reported on both ceremony results; `BackupPolicy::RequireDeviceBound` rejects BE=1 credentials | MUST |
| REQ-WA-145 | Registration/authentication options reflect the configured `resident_key` (incl. `requireResidentKey` when required), `user_verification`, and `attestation` conveyance preferences | SHOULD |
| REQ-WA-146 | Curve/algorithm binding at parse time: EC2 `crv = 1` only with ES256, `crv = 2` only with ES384; OKP `crv = 6` only with EdDSA — any other pairing is rejected with `UnsupportedAlgorithm` | MUST |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WA-200 | Challenge consumption removes the store entry before returning, so consumed/unknown/expired are mutually exclusive per call; exclusivity is enforced by `&mut self` (no data races possible) | MUST |
| REQ-WA-201 | Authenticator data truncated at every cut length < 37 bytes is rejected, never panics | MUST |
| REQ-WA-202 | The DER INTEGER encoder handles all-zero and high-bit-set moduli without panic and per DER rules (leading-zero strip, 0x00 prepend) | SHOULD |

## Constant-Time Audit

- AUDIT: signature verification is via `ring` (`ECDSA_P256_SHA256_FIXED`,
  `RSA_PKCS1_2048_8192_SHA256`) — constant-time per ring's guarantees.
  No hand-rolled crypto; DER wrapping touches public keys only.
- FLAG (accepted, documented): the challenge-echo comparison in
  `src/protocol.rs` `validate_client_data` uses `Vec<u8>` `!=` (variable-time
  early exit) between attacker-supplied and server-stored bytes. Exploit
  requires repeating comparisons against the *same* stored secret; challenges
  are 32-byte CSPRNG values consumed single-use (REQ-WA-108/110), so each
  timing sample applies to a fresh unknown challenge and the oracle is
  unusable. Not fixed deliberately; revisit if challenges ever become
  long-lived.

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-WA-001 | `test_verify_registration_valid_es256` (`src/protocol.rs`); `full_roundtrip_registration_then_authentication` (`tests/vectors.rs`) | unit/integration |
| REQ-WA-002 | `test_verify_authentication_valid_es256` (`src/protocol.rs`); `full_roundtrip_registration_then_authentication` (`tests/vectors.rs`) | unit/integration |
| REQ-WA-003 | `test_parse_cose_ec2_key`, `test_parse_cose_rsa_key` (`src/crypto.rs`) | unit |
| REQ-WA-004 | `test_base64_roundtrip`, `test_base64_encode_decode_empty`, `base64url_no_padding_urlsafe_alphabet` (`tests/vectors.rs`) | unit |
| REQ-WA-005 | `test_pub_key_cred_params_from_allowed_algorithms`, `test_registration_options_configurable`, `test_registration_options_serialization` (`src/challenge.rs`) | unit |
| REQ-WA-006 | `test_authentication_options_configurable`, `test_authentication_options_serialization` (`src/challenge.rs`) | unit |
| REQ-WA-100 | `fuzz_registration_arbitrary_attestation`, `fuzz_registration_arbitrary_client_data`, `fuzz_authentication_arbitrary`, `fuzz_registration_attested_data`, `fuzz_malformed_cbor` (`tests/fuzz.rs`) | fuzz/property |
| REQ-WA-101 | `test_verify_registration_challenge_mismatch`, `test_verify_authentication_challenge_mismatch` (`src/protocol.rs`) | unit |
| REQ-WA-102 | `test_verify_registration_wrong_type`, `test_verify_authentication_wrong_type` (`src/protocol.rs`) | unit |
| REQ-WA-103 | `test_verify_registration_wrong_origin`, `test_verify_authentication_wrong_origin`, `origin_mismatch_rejected_and_rp_hash_mismatch_rejected` (`tests/fuzz.rs`), `test_verify_authentication_wrong_rp_id_in_client_data` (`src/protocol.rs`) | unit |
| REQ-WA-104 | `test_verify_registration_wrong_rp_id_hash`, `test_verify_authentication_wrong_rp_id_hash` (`src/protocol.rs`); `origin_mismatch_rejected_and_rp_hash_mismatch_rejected` (`tests/fuzz.rs`) | unit |
| REQ-WA-105 | `test_verify_registration_missing_up_flag`, `test_verify_authentication_missing_up_flag` (`src/protocol.rs`) | unit |
| REQ-WA-106 | `test_verify_authentication_wrong_signature` (`src/protocol.rs`) | unit |
| REQ-WA-107 | `test_parse_cose_key_okp_unsupported`, `test_verify_cose_signature_alg_key_type_mismatch`, `test_verify_authentication_rs256_roundtrip` (`src/protocol.rs`), `rs256_dispatch_rejects_ec2_key_and_small_rsa` (`tests/vectors.rs`) | unit |
| REQ-WA-108 | `test_challenge_registration_flow`, `test_authentication_challenge_flow` (`src/challenge.rs`); `stale_challenge_same_second_ok_then_single_use`, `authentication_challenge_single_use_replay_rejected` (`tests/fuzz.rs`) | unit |
| REQ-WA-109 | `test_challenge_expiration`, `test_expiry_with_injected_clock`, `test_challenge_not_found`, `test_consume_authentication_challenge_expired` (`src/challenge.rs`); `expired_challenge_rejected` (`tests/fuzz.rs`) | unit |
| REQ-WA-110 | `test_generate_challenge_bytes_length`, `test_generate_challenge_bytes_not_all_zero` (`src/crypto.rs`) | unit |
| REQ-WA-111 | `test_check_sign_count_decrease_rejected` (`src/challenge.rs`); `sign_count_decreasing_rejected` (`tests/fuzz.rs`); `test_verify_authentication_sign_count_decrease` (`src/protocol.rs`) | unit |
| REQ-WA-112 | `test_check_sign_count_first_use_zero_stored`, `test_check_sign_count_monotonic` (`src/challenge.rs`); `sign_count_zero_stored_accepts_any_new`, `sign_count_equal_accepted`, `sign_count_huge_monotonic_accepted` (`tests/fuzz.rs`) | unit |
| REQ-WA-113 | `test_verify_registration_duplicate` (`src/protocol.rs`) | unit |
| REQ-WA-114 | `test_verify_authentication_credential_not_allowed` (`src/protocol.rs`) | unit |
| REQ-WA-115 | `test_debug_does_not_leak_challenge_bytes` (`src/challenge.rs`) | unit |
| REQ-WA-116 | `full_roundtrip_registration_then_authentication` (`tests/vectors.rs`, asserts `user_verified` true at registration, false at assertion) | integration |
| REQ-WA-117 | `registration_rejects_missing_at_flag` (`src/protocol.rs`) — **gap test added** | unit |
| REQ-WA-118 | `test_base64_decode_urlsafe_invalid` (`src/crypto.rs`) | unit |
| REQ-WA-140 | `verify_es384_real_signature_roundtrip`, `parse_cose_p384_key` (`src/crypto.rs`); `registration_roundtrip_es384` (`src/protocol.rs`); `packed_self_es384_credential_ok` (`src/attestation.rs`) | unit |
| REQ-WA-141 | `verify_eddsa_real_signature_roundtrip`, `parse_cose_okp_ed25519_key` (`src/crypto.rs`); `registration_authentication_roundtrip_eddsa` (`src/protocol.rs`); `packed_self_eddsa_credential_ok` (`src/attestation.rs`) | unit |
| REQ-WA-142 | `uv_required_rejects_clear_flag_and_accepts_set`, `uv_preferred_and_discouraged_report_only`, `uv_required_enforced_at_authentication` (`src/protocol.rs`) | unit |
| REQ-WA-143 | `registration_rejects_algorithm_outside_allowlist` (`src/protocol.rs`) | unit |
| REQ-WA-144 | `backup_policy_device_bound_enforced_at_registration`, `backup_policy_device_bound_enforced_at_authentication`, `backup_policy_allow_reports_flags` (`src/protocol.rs`) | unit |
| REQ-WA-145 | `test_policy_preferences_plumbed_into_options`, `test_discouraged_resident_key_leaves_require_flag_false` (`src/challenge.rs`) | unit |
| REQ-WA-146 | `parse_p256_key_claiming_es384_rejected`, `parse_p384_key_claiming_es256_rejected`, `parse_okp_claiming_other_algorithms_rejected` (`src/crypto.rs`); `registration_rejects_p256_key_claiming_es384` (`src/protocol.rs`) | unit |
| REQ-WA-200 | Structural (`&mut self` exclusivity) + observable behavior via REQ-WA-108 tests | design/unit |
| REQ-WA-201 | `fuzz_authentication_truncated_auth_data` (`tests/fuzz.rs`) | fuzz/property |
| REQ-WA-202 | `der_integer_encoding_edge_cases` (`src/crypto.rs`) — **gap test added** | unit |

## Test Count Delta

- 0.2.2 baseline: 147 tests (127 unit + 14 fuzz + 5 vectors + 1 doc-test);
  98.67% line coverage (`cargo llvm-cov --all-features`).
- Added in 0.3.0: 29 tests —
  - crypto: ES384/EdDSA roundtrips, P-384/OKP parsing, 5 algorithm-confusion
    regressions, ES384/EdDSA length fail-closed, unknown-label/OKP error
    paths, `alg_to_name` coverage;
  - protocol: ES384 registration roundtrip, EdDSA full roundtrip, ES384
    alg-confusion ceremony rejection, UV matrix (×3), algorithm allowlist
    (×1), BE/BS policy combos (×3);
  - attestation: packed self ES384/EdDSA, `none` ES384, packed x5c ES384
    rejection;
  - policy: wire strings, permissive default, strict preset;
  - challenge/config: policy plumbing into options (×2), config default.
- After: 176 tests (156 unit + 14 fuzz + 5 vectors + 1 doc-test).
- Coverage: **98.98%** line (`cargo llvm-cov --all-features`); clippy
  `-D warnings` clean with `--all-features` and `--no-default-features`;
  `cargo doc` and `cargo fmt --check` clean.

## Future Work (explicitly out of scope for 0.3.0)

- FIDO Metadata Service (MDS) integration: AAGUID → attestation root
  certificates, authenticator capabilities, security notices.
- Additional attestation formats: `tpm`, `android-key`, `android-safetynet`.
- Full CA-chain policy: name constraints, EKU checking, OCSP/CRL revocation.
- ES512 / RSA-PSS (PS256) algorithms.
