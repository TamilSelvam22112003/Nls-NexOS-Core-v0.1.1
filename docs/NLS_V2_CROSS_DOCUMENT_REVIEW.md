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

### F-03 — Destination protection is drafted but not yet interoperable (blocking)
The 72-byte N2DE envelope and its AES-256-GCM AAD/nonce/replay rules are defined in `NLS_V2_DESTINATION_PROTECTION_PROFILE.md`. The source-to-destination D_INIT/D_RESP/D_FINISH handshake is separately drafted in `NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md`; it binds both identities, certificates, status generations, ephemeral X25519 keys, transcript, and directional keys.

**Disposition:** envelope bytes now have a cross-language Go/Python vector, but the destination handshake does not yet have complete shared byte-exact vectors. Keep destination protection disabled in runtime until those vectors, lifecycle rules, and independent review pass. Transit relays must never receive destination traffic keys.

### F-04 — Router-CA status profile is specified as a candidate (high; implementation gate remains)
`ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md` defines a fixed 304-byte N2ST object, exact signature input, endpoint slots, freshness/generation rules, certificate binding, clock rollback policy, and a v2 status-push proposal over the negotiated mTLS control channel. A synthetic positive vector is checked by Go and Python.

**Disposition:** the byte-level candidate is no longer structurally open, but X.509 path/issuance integration, sidecar registry mapping, control capability negotiation, revocation delivery, and real-CA integration tests remain required before implementation can be accepted.

### F-05 — Key-update/restart lifecycle is incomplete (blocking for long-lived sessions)
KEY_UPDATE is reserved. Re-establishment is required before sequence exhaustion or any restart that could repeat a nonce, but no persistent sequence/key-state algorithm or operational restart invariant is specified.

**Disposition:** keep key update unsupported; enforce a bounded session lifetime and fail closed on uncertain nonce state. Do not describe long-lived production sessions as ready until authenticated rekey, crash/restart behavior, key erasure, and race handling are specified and tested.

### F-06 — Routing protocol protection scope must remain explicit (high)
The TUN/socket shim carries NLS data but does not automatically protect native OSPF, OSPFv3, BGP, RIP/RIPng, IPsec, or TLS packets. Native routing integration needs separate adjacency, multicast, TTL/hop-limit, MTU, route authorization, and failure/convergence designs.

**Disposition:** preserve the existing wording: shim-first; no claim that routing daemons or application protocols are secured unless a tested integration actually carries/protects them.

### F-07 — Handshake transcript vectors remain incomplete (blocking)
The status-object and destination data-envelope fixtures have cross-language checks. A deterministic D_INIT/D_RESP/D_FINISH fixture and Go verifier have now been added for the destination endpoint handshake, including signatures, transcript, X25519, HKDF, and finish AEAD. CI verification is pending. Adjacent-hop handshake/cookie vectors and broader parser/policy negatives are still absent.

**Disposition:** use `NLS_V2_CRYPTO_VECTORS_PLAN.md` as the checklist. No interoperability claim until both repositories consume the same fixtures and the complete positive/negative handshake suite passes.

## Release gates

1. Review and freeze the candidate destination envelope, destination endpoint handshake, and Router-CA status profiles; preserve v1 unchanged.
2. Generate shared byte-exact adjacent-hop and destination-handshake vectors, including cookies, signatures, transcript, HKDF, finish AEAD, and negative cases.
3. Complete authenticated key-update/restart/nonce lifecycle decisions and independent protocol review.
4. Implement shared codec/status-validation primitives in Core only after contract review.
5. Implement NetOS session and packet handling against the same fixtures.
6. Pass unit/property/fuzz tests, then the six-node functional lab and ten-router IPv6/FRR lab; keep performance gates separate.
7. Obtain independent cryptographic/protocol review before production claims.

## Attacker-perspective conclusion

The outer IPv6/UDP relay endpoints, lengths, timing, and traffic volumes remain observable. A compromised authorized relay can observe its own adjacent-hop metadata and can drop, delay, reorder, or selectively forward traffic. A compromised Router-CA can misissue identity/status evidence. The status and destination-envelope vectors verify limited byte-level behavior only; they do not prove destination confidentiality, replay safety across restart, or full interoperability. No runtime protocol code changed in this work.
