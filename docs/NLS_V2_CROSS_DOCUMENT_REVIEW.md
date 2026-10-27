# NLS v2 Cross-Document Security Review

- Status: review findings; proposal only, not a frozen protocol contract.
- Scope: `NLS_V2_WIRE_SPEC_DRAFT.md`, `NLS_V2_HANDSHAKE_CONTROL_DRAFT.md`, `NLS_V2_WORKFLOW.md`, `INTEGRATION_IMPACT_ANALYSIS.md`, and `SPEC_ERRATA.md`.
- Runtime code and the v1 wire contract are unchanged.

## Findings

### F-01 — Encrypted handshake payload-length ambiguity (critical; corrected in this branch)
The handshake draft previously described the payload-length field as the exact control payload length for handshake messages, while FINISH_I and FINISH_R are AEAD protected. The wire draft counts the AEAD tag for encrypted controls. That leaves the two encrypted handshake flights ambiguous and risks incompatible parsers or truncation/tag handling.

**Resolution:** plaintext INIT, RETRY, and RESP lengths count the exact unencrypted control payload bytes. FINISH_I and FINISH_R, like encrypted established-session controls and DATA, count ciphertext plus the 16-byte AES-GCM tag. The control prefix and TLVs are part of the encrypted plaintext for FINISH messages.

### F-02 — RESP endpoint-binding role was underspecified (high; clarified in this branch)
The endpoint-binding field encoded an IPv6 endpoint and router fingerprint but did not explicitly say whose endpoint it represents. Different implementations could bind the initiator's endpoint or the responder's endpoint.

**Resolution:** RESP's endpoint_binding identifies the responder's advertised receiving WAN endpoint: IPv6 address, NLS UDP port, and responder identity fingerprint. It must match the endpoint authorized by the responder certificate/status evidence and the actual responder destination endpoint selected by the initiator. The signed outer tuple separately binds the observed packet direction. Initiator endpoint authorization is checked against the initiator's certificate/status evidence and the outer source tuple in FINISH_I.

### F-03 — Destination-protection profile is not specified (blocking)
The data-plane draft carries a destination-protected inner envelope but does not define its exact bytes, recipient identity binding, key establishment, authentication, replay policy, or how the final endpoint distinguishes it from arbitrary inner bytes.

**Disposition:** do not implement or claim end-to-end destination protection until a separate normative profile and vectors exist. Transit relays must not be given the destination private key.

### F-04 — Router-CA status evidence is structurally underspecified (blocking)
The handshake draft lists required status fields but leaves canonical serialization and signature envelope to Core. Without exact bytes and signature scope, independent implementations cannot validate the same status object.

**Disposition:** Core must define a canonical encoding, algorithm/domain separation, certificate/status binding, freshness rules, generation monotonicity, and revocation semantics before handshake implementation is considered interoperable.

### F-05 — Key-update/restart lifecycle is incomplete (blocking for long-lived sessions)
KEY_UPDATE is reserved. Re-establishment is required before sequence exhaustion or any restart that could repeat a nonce, but no persistent sequence/key-state algorithm or operational restart invariant is specified.

**Disposition:** keep key update unsupported; enforce a bounded session lifetime and fail closed on uncertain nonce state. Do not describe long-lived production sessions as ready until authenticated rekey, crash/restart behavior, key erasure, and race handling are specified and tested.

### F-06 — Routing protocol protection scope must remain explicit (high)
The TUN/socket shim carries NLS data but does not automatically protect native OSPF, OSPFv3, BGP, RIP/RIPng, IPsec, or TLS packets. Native routing integration needs separate adjacency, multicast, TTL/hop-limit, MTU, route authorization, and failure/convergence designs.

**Disposition:** preserve the existing wording: shim-first; no claim that routing daemons or application protocols are secured unless a tested integration actually carries/protects them.

### F-07 — Canonical signature and transcript test vectors are absent (blocking)
The current signature input and transcript hash are specified textually but no independently reproducible byte-level examples prove agreement on TLV serialization, message headers, endpoint tuple order, signature exclusion, transcript input, HKDF outputs, AAD, and nonces.

**Disposition:** use `NLS_V2_CRYPTO_VECTORS_PLAN.md` as the vector-generation checklist. No interoperability claim until both repositories run identical positive and negative vectors.

## Release gates

1. Resolve F-03 through F-05 in normative documents.
2. Generate and commit shared byte-exact vectors for every message and crypto boundary.
3. Implement the shared codec/status-validation primitives in Core only after contract review.
4. Implement NetOS session and packet handling against the same vectors.
5. Pass unit/property/fuzz tests, then the six-node functional lab and ten-router IPv6/FRR lab. Keep performance gates separate.
6. Obtain independent cryptographic/protocol review before production claims.

## Attacker-perspective conclusion

The outer IPv6/UDP relay endpoints, lengths, timing, and traffic volumes remain observable. A compromised authorized relay can observe its own adjacent-hop metadata and can drop, delay, reorder, or selectively forward traffic. A compromised Router-CA can misissue identity/status evidence. These drafts do not yet prove destination confidentiality, replay safety across restart, or interoperability. The corrected length rule removes one concrete ambiguity; it does not close the remaining blockers.

## Profile-draft follow-up (2026-10-27)

The canonical candidate documents already in this branch are NLS_V2_DESTINATION_PROTECTION_PROFILE.md and ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md. The similarly named files with a _DRAFT suffix are marked superseded to avoid competing wire contracts. The fixed-width 304-byte Router-CA status profile remains a proposal and has not been proven compatible with the current implementation. Destination-handshake encoding, status/certificate linkage, key lifecycle and independent parser/policy and destination-handshake vector verification remain open; the status signature itself has been independently verified with OpenSSL. One synthetic positive status-object vector and a verifier are now committed; no runtime protocol code changed.
