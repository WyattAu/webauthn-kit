# Threat Model — webauthn-kit

Status: **v1.0** · Method: STRIDE over the public API surface
(`verify_registration`, `verify_authentication`, `ChallengeStore`,
`check_sign_count`, `parse_cose_key`, `verify_cose_signature`).

Trust boundaries: (1) base64/JSON/CBOR bytes arriving from the browser client
— all of it hostile; (2) the server-side challenge/sign-count state the
integrator persists; (3) the `ring`/`ciborium`/`sha2` dependency tree.

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | Authentication decisions (forged assertion accepted) | Attacker signs `authenticatorData ‖ SHA-256(clientDataJSON)` with their own key but someone else's credential ID |
| A2 | Registration integrity (rogue credential injected for a victim account) | Registration response replayed or crafted with attacker key |
| A3 | Challenge material | Reused or predicted challenges enable replay |
| A4 | Credential state (`sign_count`, credential IDs) | Clone detection bypassed; credential allow-list bypassed |
| A5 | Caller availability | Parser panic / memory growth on hostile CBOR |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | Panic on malformed CTAP2/CBOR input (DoS) | DoS | `parse_authenticator_data`, attestation CBOR, `parse_cose_key` | All parsers total: length pre-checks + `get(..)`, errors are `Result`; `#![forbid(unsafe_code)]` | `tests/fuzz.rs`: `fuzz_registration_arbitrary_attestation`, `fuzz_registration_arbitrary_client_data`, `fuzz_authentication_arbitrary`, `fuzz_authentication_truncated_auth_data`, `fuzz_registration_attested_data`, `fuzz_malformed_cbor` |
| T2 | Forged assertion accepted (wrong key / tampered signature) | Spoofing | `verify_authentication` | `ring` constant-time ECDSA/RSA verification over `authData ‖ SHA-256(clientDataJSON)`; no hand-rolled crypto (only DER *wrapping* of validated RSA integers, `src/crypto.rs`) | `tests/vectors.rs::registration_authentication_roundtrip_es256`, `rs256_key_parse_and_dispatch`; `src/protocol.rs::test_verify_authentication_wrong_signature` |
| T3 | Replay of a used challenge | Replay | `ChallengeStore::consume_*` | Entry removed from the map *before* results are returned — single-use even under concurrency; 32 CSPRNG bytes from OS entropy | `src/challenge.rs::test_challenge_registration_flow` (second consume fails), `tests/fuzz.rs::authentication_challenge_single_use_replay_rejected`, `stale_challenge_same_second_ok_then_single_use` |
| T4 | Stale challenge accepted | Replay | `consume_*` with `timeout_secs` | Creation timestamp compared against injectable clock; expired → `ChallengeExpired` | `test_challenge_expiration`, `test_expiry_with_injected_clock`, `tests/fuzz.rs::expired_challenge_rejected` |
| T5 | Cloned authenticator (counter rollback) | Spoofing | `check_sign_count` | Strictly decreasing counter rejected; stored `0` disables check (counterless authenticators) | `test_check_sign_count_decrease_rejected`, `tests/fuzz.rs::sign_count_decreasing_rejected`, `src/protocol.rs::test_verify_authentication_sign_count_decrease` |
| T6 | Wrong origin / RP binding (phishing relay, cross-RP reuse) | Spoofing | `validate_client_data`, `rpIdHash` check | Origin allow-list; `type` must be `webauthn.create`/`webauthn.get`; `rpIdHash` compared to `SHA-256(rp_id)` | `test_verify_registration_wrong_origin`, `test_verify_authentication_wrong_origin`, `test_verify_registration_wrong_rp_id_hash`, `test_verify_authentication_wrong_rp_id_hash`, `tests/fuzz.rs::origin_mismatch_rejected_and_rp_hash_mismatch_rejected`, `test_verify_registration_wrong_type` |
| T7 | Downgrade / algorithm confusion | Elevation | `parse_cose_key`, `verify_cose_signature` | Allow-list: ES256 (−7) and RS256 (−257) only; OKP/Ed25519, ES384/512, P-384, RS1 → `UnsupportedAlgorithm`; key type cross-checked against `alg` (RSA key claiming ES256 rejected). Extraction observations documented in `src/crypto.rs`: `cbor_bytes` deliberately accepts text-encoded binary fields (leniency is bounded by `ring` rejecting malformed keys at verify time); duplicate CBOR map keys are last-wins | `tests/vectors.rs::rs256_key_parse_and_dispatch`, `test_verify_authentication_rs256_roundtrip`; `src/crypto.rs` module docs |
| T8 | Assertion for a credential not owned/enrolled | Elevation | `verify_authentication` | Credential ID must be member of `allowed_credential_ids` | `src/protocol.rs::test_verify_authentication_credential_not_allowed` |
| T9 | Silent biometricless assertion (no user presence) | Spoofing | flags check | UP flag mandatory for both ceremonies | `test_verify_registration_missing_up_flag`, `test_verify_authentication_missing_up_flag` |
| T10 | Duplicate credential registration (registration injection) | Tampering | `verify_registration` | Attested credential ID compared to existing; `DuplicateCredential` error | `src/protocol.rs::test_verify_registration_duplicate` |
| T11 | Challenge bytes leaked via `Debug` | Info disclosure | `ChallengeStore` | Manual `Debug` impl prints only entry counts, never contents | `src/challenge.rs::test_debug_does_not_leak_challenge_bytes` |
| T12 | Counter-state race: two concurrent authentications both accepted | Elevation | caller persistence | Out of crate: documented obligation to CAS `new_sign_count` (`src/protocol.rs` security notes, README) | documented; no in-crate test (see OPEN-1) |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-1 — sign-count persistence is caller-enforced.** The crate cannot
  detect a challenge used twice across processes, nor enforce compare-and-swap
  on `new_sign_count`. A caller that skips persistence permanently disables
  clone detection (T12). Mitigation lives in docs only.
- **OPEN-2 — `ChallengeStore` has no eviction/capacity bound.** Expired but
  unconsumed entries are never removed; a client able to trigger unlimited
  challenge generation can grow the store without limit (memory DoS). No test
  covers generation-volume limits.
- **OPEN-3 — attestation is parsed, not verified.** Any `fmt` value
  ("none", "packed", "fido-u2f", ...) is tolerated informationally.
  Registration proves key possession, not device provenance (documented
  design decision, README "Attestation").
- **OPEN-4 — UV flag reported, never required.** Per-ceremony user-verification
  policy is entirely the caller's; no in-crate enforcement or test.
- **OPEN-5 — equal sign counters accepted by design.** Hardware keys that
  increment rarely weaken clone detection; accepted trade-off, not testable.
- **OPEN-6 — error strings echo attacker-controlled fragments** (truncation
  offsets, CBOR errors). Documented as server-side-log-only in README; no
  scrubbing layer in-crate.

## Out of Scope

- Browser/authenticator compromise; the client is assumed fully hostile, but
  a *compromised* client that approves prompts is indistinguishable from the
  user.
- HTTP layer, session cookies, user mapping (integrator-owned).
- Cross-process challenge durability (in-memory store by contract).

## Residual Risks

- In-memory `ChallengeStore` loses pending challenges on restart; users retry,
  replays are not enabled (consume-then-verify ordering).
- `cbor_bytes` leniency toward non-conformant authenticators (text-encoded
  binary) expands the parse surface; bounded by `ring` key validation.
- Clock is injectable but defaults to wall time; a caller supplying a bad
  clock can only make challenges look stale, never fresh (fail-safe
  `unix_now` clamps pre-epoch to 0).
