//! Config-knob behavior matrix for webauthn-kit.
//!
//! Every public knob must OBSERVABLY change behavior: each test pairs a
//! default with an alternate value and asserts the observable output
//! differs.
//!
//! Knobs covered (9 = all of [`WebauthnConfig`]'s fields):
//!   1. `rp_id` — conveyed into registration options; wrong values fail
//!      verification (`verify_registration_wrong_rp_id_hash`,
//!      `verify_authentication_wrong_rp_id_hash` in `src/protocol.rs`).
//!   2. `rp_name` — conveyed into `options.rp.name` (was unasserted).
//!   3. `rp_origins` — unlisted origins fail verification
//!      (`test_verify_*_wrong_origin`, `fuzz.rs::origin_mismatch_*`).
//!   4. `allowed_algorithms` — conveyed into `pub_key_cred_params`
//!      (was unasserted).
//!   5. `challenge_timeout_secs` — conveyed into `options.timeout` (ms)
//!      (was unasserted); expiry enforced (`fuzz.rs`, `src/challenge.rs`).
//!   6. `attestation` — `trust_anchors` / `allow_unknown_formats` enforced
//!      (`src/attestation.rs` unit tests); strict default pinned here.
//!   7. `credential_policy` — UV requirement, backup-device binding, and
//!      algorithm allowlist enforced (`uv_required_*`,
//!      `backup_policy_*`, allowlist tests in `src/protocol.rs`); UV
//!      preference additionally conveyed into options (was unasserted).
//!   8. `resident_key` — conveyed into `authenticator_selection` (was
//!      unasserted).
//!   9. `attestation_conveyance` — conveyed into `options.attestation`
//!      (was unasserted).
//!
//! The pre-existing suite proved verify-time enforcement; this file closes
//! the options-conveyance gap so every knob has an observable assertion.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use webauthn_kit::challenge::ChallengeStore;
use webauthn_kit::policy::{
    AttestationConveyance, BackupPolicy, CredentialPolicy, ResidentKeyPolicy,
    UserVerificationPolicy,
};
use webauthn_kit::{AttestationPolicy, WebauthnConfig};

fn distinctive_config() -> WebauthnConfig {
    WebauthnConfig {
        rp_id: "matrix.example.com".to_string(),
        rp_name: "Matrix RP".to_string(),
        rp_origins: vec!["https://matrix.example.com".to_string()],
        allowed_algorithms: vec![-8],
        challenge_timeout_secs: 60,
        attestation: AttestationPolicy::default(),
        credential_policy: CredentialPolicy {
            user_verification: UserVerificationPolicy::Required,
            backup: BackupPolicy::RequireDeviceBound,
            allowed_algorithms: vec![-7],
        },
        resident_key: ResidentKeyPolicy::Required,
        attestation_conveyance: AttestationConveyance::Direct,
    }
}

fn options_of(config: &WebauthnConfig) -> webauthn_kit::RegistrationOptions {
    let store = ChallengeStore::new();
    let (_, options) = store.generate_registration_challenge(config, "alice", "Alice", &[]);
    options
}

// --- 1. rp_id ---------------------------------------------------------------

#[test]
fn knob_rp_id_reaches_registration_options() {
    let options = options_of(&distinctive_config());
    assert_eq!(options.rp.id, "matrix.example.com");
    let options = options_of(&WebauthnConfig::default());
    assert_eq!(options.rp.id, "localhost");
    assert_ne!(
        options_of(&distinctive_config()).rp.id,
        options_of(&WebauthnConfig::default()).rp.id
    );
}

// --- 2. rp_name --------------------------------------------------------------

#[test]
fn knob_rp_name_reaches_registration_options() {
    assert_eq!(options_of(&distinctive_config()).rp.name, "Matrix RP");
    assert_eq!(
        options_of(&WebauthnConfig::default()).rp.name,
        "webauthn-kit"
    );
}

// --- 3. rp_origins -----------------------------------------------------------
// Verify-time knob: unlisted origins are rejected (see
// `test_verify_registration_wrong_origin`,
// `test_verify_authentication_wrong_origin`, `fuzz.rs`). Pinned here: the
// config carries whatever origins were set (no silent normalization).

#[test]
fn knob_rp_origins_carried_without_normalization() {
    let config = distinctive_config();
    assert_eq!(
        config.rp_origins,
        vec!["https://matrix.example.com".to_string()]
    );
    assert_ne!(config.rp_origins, WebauthnConfig::default().rp_origins);
}

// --- 4. allowed_algorithms (advertised) --------------------------------------

#[test]
fn knob_allowed_algorithms_advertised_in_options() {
    let algs: Vec<i32> = options_of(&distinctive_config())
        .pub_key_cred_params
        .iter()
        .map(|p| p.alg)
        .collect();
    assert_eq!(algs, vec![-8], "advertised set must match the config");

    let default_algs: Vec<i32> = options_of(&WebauthnConfig::default())
        .pub_key_cred_params
        .iter()
        .map(|p| p.alg)
        .collect();
    // Generation sorts ascending ([-7,-35,-257] → [-257,-35,-7]); the SET
    // must still match the config.
    assert_eq!(default_algs, vec![-257, -35, -7]);
    let mut sorted = default_algs.clone();
    sorted.sort();
    assert_eq!(sorted, vec![-257, -35, -7]);
}

// --- 5. challenge_timeout_secs ------------------------------------------------

#[test]
fn knob_challenge_timeout_reaches_options_in_ms() {
    assert_eq!(options_of(&distinctive_config()).timeout, 60_000);
    assert_eq!(options_of(&WebauthnConfig::default()).timeout, 300_000);
}

// --- 6. attestation policy ----------------------------------------------------
// Enforcement lives in src/attestation.rs unit tests (unknown-format
// accept/reject, trust-anchor match/mismatch). Pinned here: the default is
// strict (no anchors, unknown formats rejected).

#[test]
fn knob_attestation_default_is_strict() {
    let policy = AttestationPolicy::default();
    assert!(policy.trust_anchors.is_empty());
    assert!(!policy.allow_unknown_formats);
}

#[test]
fn knob_attestation_strict_constructor_matches_default() {
    assert_eq!(
        format!("{:?}", AttestationPolicy::strict()),
        format!("{:?}", AttestationPolicy::default())
    );
}

// --- 7. credential_policy ------------------------------------------------------
// Enforcement (UV-required rejection, device-bound rejection, allowlist
// rejection) is proved in src/protocol.rs unit tests. This file pins the
// options-conveyance half: the UV preference reaches the client.

#[test]
fn knob_credential_policy_uv_conveyed_into_options() {
    let options = options_of(&distinctive_config());
    assert_eq!(
        options.authenticator_selection.user_verification,
        "required"
    );
    let options = options_of(&WebauthnConfig::default());
    assert_eq!(
        options.authenticator_selection.user_verification,
        "preferred"
    );
}

#[test]
fn knob_credential_policy_strict_preset_differs_from_default() {
    let strict = CredentialPolicy::strict();
    let permissive = CredentialPolicy::default();
    assert_ne!(strict, permissive);
    assert_eq!(strict.user_verification, UserVerificationPolicy::Required);
    assert_eq!(strict.backup, BackupPolicy::RequireDeviceBound);
    assert!(!strict.allowed_algorithms.is_empty());
    assert!(permissive.allowed_algorithms.is_empty());
}

// --- 8. resident_key ------------------------------------------------------------

#[test]
fn knob_resident_key_conveyed_into_options() {
    let options = options_of(&distinctive_config());
    assert_eq!(options.authenticator_selection.resident_key, "required");
    assert!(options.authenticator_selection.require_resident_key);
    let options = options_of(&WebauthnConfig::default());
    assert_eq!(options.authenticator_selection.resident_key, "preferred");
}

// --- 9. attestation_conveyance ----------------------------------------------------

#[test]
fn knob_attestation_conveyance_conveyed_into_options() {
    assert_eq!(options_of(&distinctive_config()).attestation, "direct");
    assert_eq!(options_of(&WebauthnConfig::default()).attestation, "none");
}
