# Changelog

## Unreleased — NLS v2 proposal
- Added docs/NLS_V2_HANDSHAKE_CONTROL_DRAFT.md: proposed INIT/RETRY/RESP/FINISH handshake, canonical control TLVs, cookie binding, certificate/status checks, key derivation, state machines, limits, and acceptance tests.
- Added docs/NLS_V2_WIRE_SPEC_DRAFT.md: proposed framing header, AEAD nonce/AAD rules, hop-envelope encoding, relay forwarding, and data-plane acceptance gates; reconciled the header length field and handshake/session identifier with the control draft.
- Added docs/INTEGRATION_IMPACT_ANALYSIS.md: component-impact matrix, routing-integration decision, open-question dispositions, state machines and pre-implementation acceptance gates.
- Added docs/NLS_V2_WORKFLOW.md: workflow, component impact, table responsibilities, open-question disposition, and acceptance/test gates.
- Added docs/NLS_V2_END_TO_END_WORKFLOW.md: full boot/enrollment, cookie-protected adjacent handshake, destination endpoint handshake, per-hop rewrapping, table responsibilities, failure behavior, and staged TUN/OSPFv3/BGP/RIP integration plan.
- Added `pkg/proto/v2cookie.go` and `pkg/proto/v2cookie_test.go`: reusable 40-byte stateless address/port/handshake/nonce/ephemeral-key-bound HMAC-SHA-256 cookie issuance and verification with current/previous bucket and bounded secret-rotation support. The cookie remains a reachability proof, not peer identity authentication.
- Added `pkg/proto/v2control.go` and `pkg/proto/v2control_test.go`: bounded canonical 4-byte control prefix and ordered TLV marshal/parse primitives, exact length handling, reserved-byte checks and unknown-field rejection; KEY_UPDATE remains rejected.
- Added docs/NLS_V2_CROSS_DOCUMENT_REVIEW.md: recorded payload-length ambiguity and endpoint-binding clarification, plus remaining destination-protection, Router-CA status, and key-lifecycle blockers.
- Added docs/NLS_V2_CRYPTO_VECTORS_PLAN.md: byte-exact shared vector plan for codecs, cookies, signatures, transcript/KDF, AEAD, replay and adversarial cases; one fixed-width Router-CA status vector is committed; its signature was independently verified with OpenSSL; parser/policy and full adjacent-hop handshake/cookie transcript vectors and parser/policy coverage remain open.
- Added tests/v2_vectors/router_status_active_001.json and verify_router_status_active_001.py for the fixed-width status object; this does not test X.509 validation or handshake/data-plane behavior.
- Added tests/v2_vectors/router_status_active_001_test.go so Go CI checks the identity fingerprint, exact 304-byte status object, Ed25519 signature, and signature-tamper rejection; X.509 path and Router-CA runtime integration are not covered.
- Added tests/v2_vectors/destination_envelope_001.json and destination_envelope_001_test.go to verify the 72-byte destination envelope header/AAD, 56-byte AES-256-GCM ciphertext/tag, exact 128-byte envelope, valid decryption, and tamper rejection using Go's standard library; the expected ciphertext was generated with Python cryptography.
- Added tests/v2_vectors/destination_handshake_001.json and destination_handshake_001_test.go with deterministic D_INIT/D_RESP/D_FINISH bytes and a Go verifier for certificate/status binding, signatures, transcript, X25519, HKDF and finish AEAD. CI passed at the latest completed vector-test checkpoint in both repositories; full adversarial and multi-router coverage remains open.
- Fixed `router_status_active_001.json`: removed twelve unintended zero bytes so the complete status object is exactly the 240-byte signed prefix plus the 64-byte signature (304 bytes). The earlier Go CI failure correctly detected the fixture-length defect; the corrected fixture subsequently passed in CI.
- Fixed the status fixture's `certificate_serial_u64` decimal value to match its encoded uint64 bytes (`0x0102030405060708`); the previous decimal value caused the Go prefix reconstruction test to fail.
- Clarified `ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md`: status object is authoritative for NLS UDP endpoint authorization, v1 registry/RDR remains unchanged, v2 status push is negotiated on mTLS, and clock rollback fails closed for new sessions.
- Added docs/NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md: proposed D_INIT/D_RESP/D_FINISH transcript, signature and key-derivation rules; still requires review and shared vectors.
- Added docs/NLS_V2_DESTINATION_PROTECTION_PROFILE.md: candidate end-to-end envelope and replay/nonce rules; endpoint handshake and lifecycle remain blockers.
- Added docs/ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md: fixed-width signed status evidence format, endpoint binding, freshness and generation rules; certificate/CA integration remains a review gate.
- Added docs/NLS_V2_SESSION_KEY_LIFECYCLE_PROFILE.md: candidate bounded-session profile covering no session resumption after restart, sequence/byte/lifetime caps, atomic sequence allocation, replay handling, and required tests. Runtime enforcement is not implemented.
- Added `tests/v2_vectors/adjacent_cookie_001.json` with Go and Python verifiers for the exact address-bound HMAC cookie, X25519 ephemeral public key, 40-byte cookie, and binding-mutation negatives. This does not cover the full adjacent-hop handshake.
- Corrected the cookie vector's expected MAC-input hex to include the ASCII `2` in the `NLS2-COOKIE\0` domain label. The first Go run caught this fixture typo before checking the MAC; the corrected vector passed at the latest completed vector-test checkpoint.
- Clarified adjacent-hop handshake signature canonicalization and certificate-chain count/length framing; golden vectors are still required.
- Branch implementation status: standalone v2 status/framing/AEAD/hop-codec primitives and synthetic Go/Python vector tests exist under `pkg/proto` and `tests/v2_vectors/`. The full live handshake/session manager, TUN packet I/O, trust/session table integration, and IPv6/FRR routing integration remain incomplete. NLS v1 wire contract remains unchanged; v2 is not frozen or production-ready.


## v0.1.1
- Specification and scaffolding baseline only; no feature implementation.
