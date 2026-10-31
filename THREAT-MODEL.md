# Threat Model: webauthn-kit
Status: **v1.1** (0.3.0; adds T13/T14/T15, closes OPEN-4) · Method: STRIDE over the public API surface
- all of it hostile; (2) the server-side challenge/sign-count state the
| T3 | Replay of a used challenge | Replay | `ChallengeStore::consume_*` | Entry removed from the map *before* results are returned; single-use even under concurrency; 32 CSPRNG bytes from OS entropy | `src/challenge.rs::test_challenge_registration_flow` (second consume fails), `tests/fuzz.rs::authentication_challenge_single_use_replay_rejected`, `stale_challenge_same_second_ok_then_single_use` |
| T13 | UV bypass: assertion accepted although the ceremony required user verification | Spoofing | `verify_authentication`, `verify_registration` | **0.2.x: UV was parsed and reported but never enforced**; every caller had to hand-roll the check (former OPEN-4). **0.3.x: `CredentialPolicy::user_verification = Required` rejects UV-clear ceremonies** with `UserVerificationRequired`, before any signature work | `src/protocol.rs::uv_required_rejects_clear_flag_and_accepts_set`, `uv_required_enforced_at_authentication`, `uv_preferred_and_discouraged_report_only` |
## OPEN RISKS (missing mitigations: not fabricated)
- **OPEN-1; sign-count persistence is caller-enforced.** The crate cannot
- **OPEN-2; `ChallengeStore` has no eviction/capacity bound.** Expired but
- **OPEN-3; attestation coverage is bounded.** `none`, `packed`, and
  configured trust anchors), but the remaining formats; `tpm`,
  `android-key`, `android-safetynet`; are **future work** and rejected.
- **OPEN-4; CLOSED in 0.3.0 (was: UV reported, never required).**
  MUST opt into `Required`; with the default, a biometricless assertion is
- **OPEN-5; equal sign counters accepted by design.** Hardware keys that
- **OPEN-6; error strings echo attacker-controlled fragments** (truncation
- **OPEN-7; BS-flag lifecycle is informational only.** The backup-*state*
- **OPEN-8; resident-key preference is not verifiable.** `residentKey` /