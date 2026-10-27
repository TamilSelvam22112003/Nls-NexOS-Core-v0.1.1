# Changelog

## Unreleased — NLS v2 proposal
- Added docs/NLS_V2_HANDSHAKE_CONTROL_DRAFT.md: proposed INIT/RETRY/RESP/FINISH handshake, canonical control TLVs, cookie binding, certificate/status checks, key derivation, state machines, limits, and acceptance tests.
- Added docs/NLS_V2_WIRE_SPEC_DRAFT.md: proposed framing header, AEAD nonce/AAD rules, hop-envelope encoding, relay forwarding, and data-plane acceptance gates; reconciled the header length field and handshake/session identifier with the control draft.
- Added docs/INTEGRATION_IMPACT_ANALYSIS.md: component-impact matrix, routing-integration decision, open-question dispositions, state machines and pre-implementation acceptance gates.
- Added docs/NLS_V2_WORKFLOW.md: workflow, component impact, table responsibilities, open-question disposition, and acceptance/test gates.
- Documentation only; v1 wire contract and runtime code unchanged. The v2 drafts are not frozen and have unresolved blockers.

## v0.1.1
- Specification and scaffolding baseline only; no feature implementation.
