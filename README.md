custom CTAP2/COSE implementation on [`ring`](https://crates.io/crates/ring) -
  verification; all via `ring`, zero additional crypto dependencies
  `AuthenticationResult::new_sign_count`; ideally compare-and-swap so
- **Attestation verification**; see below.
| `resident_key`, `attestation_conveyance` | conveyed in registration options | *preferences only*; the server cannot verify discoverability/attestation conveyance from the response alone |
  the user's cloud account; platform account recovery (phone number,
CA-chain policy/revocation are future work; see THREAT-MODEL.md.