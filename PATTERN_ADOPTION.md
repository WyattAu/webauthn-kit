# PATTERN_ADOPTION

Pattern relationships for webauthn-kit, declared against the WyattAu
pattern canon per references/adoption-format.md. Rows claim what the
code shows; patterns with no relationship here are omitted.

| Pattern | Status | Evidence |
|---|---|---|
| T1 | adopted | src/protocol.rs:316 (verify_registration parses CTAP2 attestation into typed values; COSE keys parse at src/crypto.rs:159, and policy checks run on the parsed types) |
| P115 | partial | src/policy.rs:174 (registration algorithm allowlist spanning ES256, ES384, EdDSA, and RS256) |
| P67 | adopted | tests/fuzz.rs:51 (arbitrary attestation and client-data bytes; failures must surface as typed verification errors per tests/fuzz.rs:39) |
| P64 | adopted | tests/fuzz.rs:46 (proptest suite drives the verify ceremonies from generated input) |
