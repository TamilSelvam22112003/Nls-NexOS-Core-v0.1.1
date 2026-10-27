# Changelog

## Unreleased — NLS v2 proposal
- Added docs/NLS_V2_HANDSHAKE_CONTROL_DRAFT.md: proposed INIT/RETRY/RESP/FINISH handshake, canonical control TLVs, cookie binding, certificate/status checks, key derivation, state machines, limits, and acceptance tests.
- Added docs/NLS_V2_WIRE_SPEC_DRAFT.md: proposed framing header, AEAD nonce/AAD rules, hop-envelope encoding, relay forwarding, and data-plane acceptance gates; reconciled the header length field and handshake/session identifier with the control draft.
- Added docs/INTEGRATION_IMPACT_ANALYSIS.md: component-impact matrix, routing-integration decision, open-question dispositions, state machines and pre-implementation acceptance gates.
- Added docs/NLS_V2_WORKFLOW.md: workflow, component impact, table responsibilities, open-question disposition, and acceptance/test gates.
- Added docs/NLS_V2_CROSS_DOCUMENT_REVIEW.md: recorded payload-length ambiguity and endpoint-binding clarification, plus remaining destination-protection, Router-CA status, and key-lifecycle blockers.
- Added docs/NLS_V2_CRYPTO_VECTORS_PLAN.md: byte-exact shared vector plan for codecs, cookies, signatures, transcript/KDF, AEAD, replay and adversarial cases; one fixed-width Router-CA status vector is committed; its signature was independently verified with OpenSSL; parser/policy and destination-handshake vectors remain open.
- Added tests/v2_vectors/router_status_active_001.json and verify_router_status_active_001.py for the fixed-width status object; this does not test X.509 validation or handshake/data-plane behavior.
- Added docs/NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md: proposed D_INIT/D_RESP/D_FINISH transcript, signature and key-derivation rules; still requires review and shared vectors.
- Added docs/NLS_V2_DESTINATION_PROTECTION_PROFILE.md: candidate end-to-end envelope and replay/nonce rules; endpoint handshake and lifecycle remain blockers.
- Added docs/ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md: fixed-width signed status evidence format, endpoint binding, freshness and generation rules; certificate/CA integration remains a review gate.
- Documentation only; v1 wire contract and runtime code unchanged. The v2 drafts are not frozen and have unresolved blockers.


## v0.1.1
- Specification and scaffolding baseline only; no feature implementation.
