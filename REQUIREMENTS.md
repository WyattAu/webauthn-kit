# Requirements: webauthn-kit
| REQ-WA-100 | Every parse/verify entry point (`verify_registration`, `verify_authentication`, `parse_cose_key`, `parse_authenticator_data`) returns `Ok` or `Err` on arbitrary byte input; never panics | MUST |
| REQ-WA-146 | Curve/algorithm binding at parse time: EC2 `crv = 1` only with ES256, `crv = 2` only with ES384; OKP `crv = 6` only with EdDSA; any other pairing is rejected with `UnsupportedAlgorithm` | MUST |
  `RSA_PKCS1_2048_8192_SHA256`); constant-time per ring's guarantees.
| REQ-WA-117 | `registration_rejects_missing_at_flag` (`src/protocol.rs`); **gap test added** | unit |
| REQ-WA-202 | `der_integer_encoding_edge_cases` (`src/crypto.rs`); **gap test added** | unit |
- Added in 0.3.0: 29 tests -