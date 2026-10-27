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

**Disposition:** the byte-level candidate is no longer structurally open. The first full status-object Go test exposed an overlong synthetic fixture (316 bytes); the fixture has been corrected to prefix(240)||signature(64), but a fresh CI pass is pending. X.509 path/issuance integration, sidecar registry mapping, control capability negotiation, revocation delivery, and real-CA integration tests remain required before implementation can be accepted.

### F-08 — Destination D_INIT signature input was ambiguous (high; corrected in this branch)
The earlier wording appended message_type 0x11 separately even though the canonical control record already begins with that message type. That could cause independent implementations to sign different byte strings.

**Resolution:** D_INIT signs exactly `ASCII("NLS2-E2E-HS-SIG") || 0x00 || canonical_D_INIT_without_signature_TLV`; the 4-byte canonical control prefix includes message_type once. D_RESP signs the length-prefixed exact D_INIT record followed by the length-prefixed canonical D_RESP record without its signature TLV. The deterministic destination-handshake fixture pins both rules; CI verification is pending.

### F-05 — Key-update/restart lifecycle is specified at design level (implementation gate remains)
KEY_UPDATE remains reserved and unsupported. The new `NLS_V2_SESSION_KEY_LIFECYCLE_PROFILE.md` prohibits session resumption across process restarts, requires a fresh full handshake after restart, and defines proposed session lifetime, byte/packet caps, atomic sequence allocation, retransmission, replay-window, session replacement, and secret-redaction invariants.

**Disposition:** the restart policy is now explicit in the candidate design. Runtime enforcement, sequence/replay concurrency tests, crash/restart tests, and review of the proposed caps remain open. Do not claim runtime safety or production readiness until those tests pass.

### F-06 — Routing protocol protection scope must remain explicit (high)
The TUN/socket shim carries NLS data but does not automatically protect native OSPF, OSPFv3, BGP, RIP/RIPng, IPsec, or TLS packets. Native routing integration needs separate adjacency, multicast, TTL/hop-limit, MTU, route authorization, and failure/convergence designs.

**Disposition:** preserve the existing wording: shim-first; no claim that routing daemons or application protocols are secured unless a tested integration actually carries/protects them.

### F-07 — Handshake transcript vectors remain incomplete (blocking)
The status-object and destination data-envelope fixtures have cross-language checks. A deterministic D_INIT/D_RESP/D_FINISH fixture and Go verifier have now been added for the destination endpoint handshake, including signatures, transcript, X25519, HKDF, and finish AEAD. CI verification is pending. Adjacent-hop handshake/cookie vectors and broader parser/policy negatives are still absent.

**Disposition:** use `NLS_V2_CRYPTO_VECTORS_PLAN.md` as the checklist. No interoperability claim until both repositories consume the same fixtures and the complete positive/negative handshake suite passes.

### F-09 — Status-object golden fixture had an invalid total length (critical; corrected)
The first Go CI run rejected the status fixture because `status_object_304_hex` contained twelve extra zero bytes between the 240-byte signed prefix and the 64-byte Ed25519 signature, making the object 316 bytes rather than 304. The canonical prefix and signature were individually valid, but the complete object was not.

**Resolution:** the fixture now sets `status_object_304_hex = status_prefix_240_hex || signature_hex`, and the resulting object is exactly 304 bytes. This was a test-fixture defect, not a runtime-code change. The corrected fixture still needs a fresh completed CI run in both repositories.


### F-10 — Adjacent-hop signature and certificate-chain encoding needed exact canonical rules (high; clarified, vectors still required)
The handshake draft's signature formula redundantly named control_type outside a canonical control record that already contains the control prefix, and the certificate-chain TLV did not fully specify the count/length framing.

**Resolution:** the signature input now binds the version and handshake_id once, followed by the canonical control record with the signature TLV omitted and the ordered outer IPv6/UDP tuple. The certificate-chain value is uint32_be(count) followed by repeated uint32_be(cert_length) || DER_certificate entries, leaf first. Byte-exact adjacent-hop handshake/cookie vectors must still verify these rules independently.

## Release gates

1. Review and freeze the candidate destination envelope, destination endpoint handshake, and Router-CA status profiles; preserve v1 unchanged.
2. Generate shared byte-exact adjacent-hop and destination-handshake vectors, including cookies, signatures, transcript, HKDF, finish AEAD, and negative cases.
3. Review the candidate session lifecycle profile; implement and test its bounded-session, restart invalidation, atomic nonce/replay, and secret-redaction invariants. KEY_UPDATE remains unsupported.
4. Implement shared codec/status-validation primitives in Core only after contract review.
5. Implement NetOS session and packet handling against the same fixtures.
6. Pass unit/property/fuzz tests, then the six-node functional lab and ten-router IPv6/FRR lab; keep performance gates separate.
7. Obtain independent cryptographic/protocol review before production claims.

## Attacker-perspective conclusion

The outer IPv6/UDP relay endpoints, lengths, timing, and traffic volumes remain observable. A compromised authorized relay can observe its own adjacent-hop metadata and can drop, delay, reorder, or selectively forward traffic. A compromised Router-CA can misissue identity/status evidence. The status and destination-envelope vectors verify limited byte-level behavior only; they do not prove destination confidentiality, replay safety across restart, or full interoperability. No runtime protocol code changed in this work.
