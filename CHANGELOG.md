# Changelog

## Unreleased — NLS v2 proposal
- Added docs/NLS_V2_HANDSHAKE_CONTROL_DRAFT.md: proposed INIT/RETRY/RESP/FINISH handshake, canonical control TLVs, cookie binding, certificate/status checks, key derivation, state machines, limits, and acceptance tests.
- Added docs/NLS_V2_WIRE_SPEC_DRAFT.md: proposed framing header, AEAD nonce/AAD rules, hop-envelope encoding, relay forwarding, and data-plane acceptance gates; reconciled the header length field and handshake/session identifier with the control draft.
- Added docs/INTEGRATION_IMPACT_ANALYSIS.md: component-impact matrix, routing-integration decision, open-question dispositions, state machines and pre-implementation acceptance gates.
- Added docs/NLS_V2_WORKFLOW.md: workflow, component impact, table responsibilities, open-question disposition, and acceptance/test gates.
- Added docs/NLS_V2_CROSS_DOCUMENT_REVIEW.md: recorded payload-length ambiguity and endpoint-binding clarification, plus remaining destination-protection, Router-CA status, and key-lifecycle blockers.
- Added docs/NLS_V2_CRYPTO_VECTORS_PLAN.md: byte-exact shared vector plan for codecs, cookies, signatures, transcript/KDF, AEAD, replay and adversarial cases; vectors are not yet generated.
- Added docs/NLS_V2_DESTINATION_PROTECTION_PROFILE.md: candidate end-to-end envelope and replay/nonce rules; endpoint handshake and lifecycle remain blockers.
- Added docs/ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md: fixed-width signed status evidence format, endpoint binding, freshness and generation rules; certificate/CA integration remains a review gate.
- Documentation only; v1 wire contract and runtime code unchanged. The v2 drafts are not frozen and have unresolved blockers.

- Added destination-protection and Router-CA status profile drafts; not frozen or implemented.

## v0.1.1
- Specification and scaffolding baseline only; no feature implementation.
