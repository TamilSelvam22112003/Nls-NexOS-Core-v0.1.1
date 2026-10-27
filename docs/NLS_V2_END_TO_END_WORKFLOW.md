# NLS v2 End-to-End Workflow and Routing Integration Plan

**Status:** Engineering workflow and implementation plan; proposal only, not a frozen wire contract.  
**Compatibility:** NLS v1 remains unchanged. No implicit downgrade from v2 to v1 and no plaintext fallback for traffic classified `PROTECT`.  
**Initial integration choice:** TUN/socket shim over the existing routed IPv6 underlay (A1).  
**First-contact choice:** random, short-lived opaque token used for bounded demultiplexing only (B1).  
**Normative byte formats:** the linked wire, adjacent-hop handshake, destination-handshake, destination-envelope, and Router-CA status drafts below govern their respective fields; this document describes their intended end-to-end workflow and component responsibilities.

## 1. Security model and packet boundaries

NLS v2 uses two distinct protections:

1. **Adjacent-hop protection** authenticates a neighboring NLS router and encrypts hop-local metadata for that receiver. Each transit relay terminates only its own adjacent-hop layer, checks the previous neighbor/session, then constructs a fresh hop envelope for the next relay.
2. **Destination protection** encrypts the original inner IP packet for the destination NLS security endpoint. Transit relays forward that inner envelope opaquely. Only the source and destination security endpoints hold the end-to-end traffic keys.

The outer IPv6 source and destination fields are **not encrypted in place**. Ordinary IPv6 forwarding needs routable underlay addresses. Each transmitted datagram therefore uses the current relay's routable WAN address as outer source and the next relay's routable WAN address as outer destination. The clear outer header and UDP ports, NLS framing, packet lengths, timing and volume remain observable to the transit network. The immediately receiving relay can observe the previous relay's outer address.

The protected logical source locator is a field inside the authenticated encrypted hop plaintext. It is not the outer IPv6 source address, not a route, and not proof of identity by itself. A relay must validate it against the already authenticated peer identity and the Router-CA-authorized outer endpoint.

### Packet path (conceptual)

```text
Client
  |
  | original IPv4/IPv6 packet
  v
Ingress NLS router
  | destination-protects original packet for destination security endpoint
  | creates hop envelope for R2 using directional key R1->R2
  | outer IPv6: R1-WAN -> R2-WAN
  v
Transit R2
  | authenticates/decrypts only R1->R2 hop envelope
  | validates R1 identity/session/locator/replay/policy
  | leaves destination-protected inner packet opaque
  | creates a fresh hop envelope for R3 using key R2->R3
  | outer IPv6: R2-WAN -> R3-WAN
  v
Transit R3 ... (same per-hop operation)
  |
  v
Destination NLS security endpoint
  | authenticates/decrypts final adjacent-hop envelope
  | validates final relay and removes hop wrapper
  | decrypts destination-protected inner packet
  | forwards original packet to destination LAN/server
  v
Server
```

If the protected application payload must remain confidential after the destination router forwards the inner packet to a separate server, use the application's own end-to-end protection (for example, correctly configured TLS) or define a separate server endpoint profile. NLS destination-router protection must not be described as server-level encryption unless the server itself is the cryptographic endpoint.

## 2. Boot, registration, and readiness

1. **Load trust anchors and local configuration.** The router loads a pinned Router-CA trust anchor, configured underlay/WAN endpoints, permitted roles, protected prefixes, transport port, MTU policy and fail-closed policy. Private keys must be permission-restricted and must never be included in logs, status responses, or repository fixtures.
2. **Establish underlay reachability.** Existing Linux routing and FRR provide routable IPv6 reachability to configured peers and the Router-CA. NLS cannot contact a CA or next hop through an address that the ordinary forwarding plane cannot route.
3. **Enroll or refresh identity.** The router proves control of its identity key to Router-CA, obtains or renews its certificate and authorized endpoint information, and receives current policy/status evidence. Identity signing keys, ephemeral key-agreement keys, adjacent-hop traffic keys, and destination traffic keys have separate roles.
4. **Validate local state.** The router validates certificate/status freshness, local policy, required endpoints, clock health, key-storage permissions, and resource limits. It enters a state that permits protected forwarding only after the necessary services are ready.
5. **Keep routing state separate.** OSPF/OSPFv3 LSDB entries and ordinary routing entries may provide underlay reachability, but neither is cryptographic trust. A router must not promote an identity or install a protected route merely because an address appears in the LSDB.

The current candidate Router-CA status profile is a fixed-size signed v2 status object. It is a proposal requiring real-CA issuance/registry integration and operational review. The v1 RDR and v1 control messages must not be silently reinterpreted as v2 status evidence.

## 3. First contact and adjacent-hop session establishment

The adjacent-hop handshake follows the candidate sequence defined in `NLS_V2_HANDSHAKE_CONTROL_DRAFT.md`:

`INIT -> RETRY(cookie) -> INIT-with-cookie -> RESP -> FINISH_I -> FINISH_R`

1. The initiator resolves the intended peer's authenticated identity and routable endpoint through configured policy/directory/Router-CA information. It validates the peer's status object, certificate binding, endpoint authorization, and status freshness.
2. It generates a cryptographically random `handshake_id`, nonce and ephemeral X25519 key pair. The temporary token is opaque and short-lived; it is not an IPv6 address and does not authenticate a router.
3. The initiator sends INIT to the responder's routable outer IPv6 endpoint. The responder applies message-size limits and rate limiting, and returns a stateless RETRY cookie by default for an untrusted source.
4. The cookie is bound to the outer IPv6 source/destination, UDP source/destination ports, handshake ID, initiator nonce, initiator ephemeral public key and a time bucket. Before the cookie is valid, the responder must not allocate per-peer handshake state or perform expensive certificate/X25519 work.
5. After cookie validation, the responder validates the initiator's certificate/status and endpoint authorization, generates its ephemeral key and nonce, and sends signed RESP material. The signatures and authenticated transcript bind the identities, endpoints, nonces, ephemeral keys, suite and protocol version.
6. Both sides compute the X25519 shared secret, reject an all-zero shared secret, and derive independent directional keys via HKDF-SHA-256 using the specified transcript/salt/info. Signing keys are not traffic keys; a static public key is not used to encrypt every data packet.
7. FINISH_I and FINISH_R confirm the transcript/key possession under the separate directional handshake keys. The responder's session token becomes active only after FINISH_R is authenticated and accepted. The peers install bounded session and replay state atomically only after successful confirmation.
8. If a handshake fails, times out, mismatches status/identity/endpoint, or exceeds a resource limit, the pending state is discarded, temporary secrets are erased best-effort, the peer is not trusted, and protected traffic is dropped or boundedly queued according to local policy. No plaintext fallback is allowed.
9. Handshake/session state is bounded by lifetime, byte and packet caps. The current lifecycle proposal forbids session resumption after process restart and leaves authenticated KEY_UPDATE unsupported. A fresh full handshake is required after restart and before any configured session limit.

Cookie, handshake and transcript formats are drafts. The deterministic cookie test covers its specific MAC construction; it does not establish full handshake interoperability.

## 4. Destination endpoint session

Adjacent-hop keys do not establish destination-protection keys. The source and destination security endpoints use the separate candidate workflow in `NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md` and `NLS_V2_DESTINATION_PROTECTION_PROFILE.md`.

1. The source endpoint validates the destination endpoint's certificate and signed status evidence, including current status generation and authorized role.
2. The source creates a distinct end-to-end handshake with fresh nonces and ephemeral X25519 keys, using a separate transcript domain and key-derivation labels from the adjacent-hop handshake.
3. The destination validates the source identity/status and binds the handshake to the selected endpoint/session. Both endpoints verify signatures/transcript and derive destination-scoped directional AEAD keys.
4. The session is installed only after authenticated FINISH confirmation. Transit routers may forward these records as opaque destination-protected content but must not terminate the exchange or receive its traffic keys.
5. The source encrypts a complete original IPv4/IPv6 packet into the destination envelope. The destination envelope's recipient identity, session, direction, epoch, sequence and AEAD tag are verified before plaintext is released. The receiver checks the inner IP packet and local forwarding policy before delivering it.
6. For return traffic, the destination endpoint uses the reverse directional destination key and an independently maintained replay/sequence space. Hop protection is also constructed independently along the return path.
7. Unknown session, stale/revoked status, wrong recipient, invalid tag, replay, invalid inner IP or policy denial means drop. A successful cryptographic check does not grant route-installation or general forwarding authorization.

The destination envelope currently has a candidate 72-byte N2DE header and a synthetic AES-GCM vector. The endpoint handshake still requires complete independent byte-exact vectors and integration tests. The destination-protection profile is not yet production-ready.

## 5. Per-hop forwarding workflow

For each protected packet:

1. **Ingress policy:** classify traffic as `PROTECT`, explicitly configured `BYPASS`, or `DROP`. A cryptographic failure must not convert `PROTECT` into `BYPASS`.
2. **Prepare destination protection:** obtain or reuse a valid destination endpoint session. The original client/server IP headers and applicable transport metadata remain encrypted inside the destination envelope.
3. **Wrap for first relay:** serialize the hop plaintext, including the authenticated previous-hop identity and logical locator, plus the opaque destination envelope. Allocate a unique outbound sequence number.
4. **Construct framing:** serialize the 44-byte NLS2 header with the correct version/type, session token, key epoch, sequence and exact payload length. For DATA and encrypted controls, payload_length includes ciphertext plus the 16-byte AES-GCM tag.
5. **Encrypt hop envelope:** construct the nonce from the selected key epoch and sequence as specified by the wire profile. Authenticate the common header and observed outer IPv6/UDP tuple as AAD, and encrypt with the current directional adjacent-hop key.
6. **Transmit:** send over UDP with the current relay's routable IPv6 address as source and the next relay's routable IPv6 address as destination. Enforce the configured maximum packet size and IPv6 PMTU/ICMPv6 policy.
7. **Receive:** the next relay validates bounded framing and session lookup, authenticates/decrypts the hop envelope, verifies peer identity/status/endpoint binding and replay window, confirms the locator corresponds to the authenticated peer, and evaluates forwarding policy.
8. **Rewrap:** the relay chooses an authorized next hop, allocates a unique sequence under its own outbound direction key, builds a fresh envelope with its own authenticated locator, and encrypts with the next hop's directional key. The destination envelope must be copied byte-for-byte.
9. **Deliver:** the destination router authenticates the last hop, removes only the hop layer, then passes the destination envelope to the local destination security endpoint for authenticated decryption and inner-packet validation.

The outer source seen by a transit network and the receiving relay remains the previous relay's real routable WAN address. The logical source locator inside the hop ciphertext changes per hop; it does not change the outer IPv6 source field and is not used by OSPF to rewrite every data packet's source address.

## 6. Tables and state ownership

| State store | What it owns | What it must never imply |
|---|---|---|
| VIP / pending-handshake table | Temporary opaque token, handshake ID, selected endpoint, time bucket, expiry, retry/state and resource-accounting fields | Token is not an IP address, identity proof or trust credential |
| Trust table | Stable router identity fingerprint, validated certificate/status, authorized endpoints, revocation generation, policy and permitted capabilities | A route, token, public key or LSDB entry alone does not confer trust |
| Session/replay store | Session token, directional key references, epoch, sequence allocator, replay window, expiry and active/closing state | Session state must not survive process restart in the current lifecycle proposal |
| Destination-session store | Source/destination identities, end-to-end session ID, destination key references, directional sequence/replay state and expiry | Transit relays may not access destination traffic keys |
| OSPF/OSPFv3 LSDB | Routing daemon's link-state/topology data | LSDB adjacency is not cryptographic authorization |
| Router-CA registry/directory | Router enrollment, certificates, endpoint authorization, status generation and audit/revocation records | Never returns private keys or treats a caller as ACTIVE without authenticating and authorizing it |

Promotion to trusted state requires authenticated certificate/status/endpoint validation and successful handshake confirmation. Session key bytes should not be stored in a printable table or ordinary directory object.

## 7. Routing-protocol integration strategy

### Phase 1 — existing routed underlay + TUN/socket shim (initial path)

- Let Linux/FRR continue ordinary underlay routing between routable relay endpoints.
- Carry NLS packet formats over a dedicated NLS socket/UDP transport and then integrate a TUN interface for client packets.
- Configure protected prefixes and routes explicitly; prevent routing loops and accidental plaintext egress.
- Test IPv6 neighbor discovery, PMTU/ICMPv6, asymmetric return paths, route changes, ACL/uRPF/NAT interactions, service restart and control-plane failure.
- Do not change native OSPF/BGP/RIP packet encodings as part of the first data-plane milestone.

### Phase 2 — protected routing control traffic (separate workstream)

For any OSPF/OSPFv3, BGP or RIP/RIPng protection, first decide which packet classes are carried inside NLS and which stay native. The design must specify peer discovery, multicast/broadcast handling where applicable, TTL/hop-limit, neighbor-state transitions, authentication, route authorization, failure/convergence, and interoperability with unmodified peers. An ordinary TUN shim does not automatically secure the native routing protocol.

- **OSPF/OSPFv3:** keep LSDB as routing state; bind adjacency to validated NLS peer identity through explicit policy; test multicast/neighbor discovery, hello/dead timers and convergence independently.
- **BGP:** define whether the TCP session is carried inside NLS or merely used over a protected underlay; separately validate route policy and next-hop semantics.
- **RIP/RIPng:** define whether updates remain native or are carried by a protected mode; test metrics, hop limits and compatibility.
- **Default routes and static routes:** configure routes to NLS underlay endpoints and protected prefixes without circular dependence. An NLS route must not depend on itself to establish its underlay path.
- **IPsec and TLS:** NLS does not replace these or automatically secure their native protocols. They may coexist. Define the security endpoint and avoid double-encryption or confusing router identity with application/server identity.

No routing daemon should advertise an authenticated NLS adjacency until peer identity, status and session establishment have succeeded. A route advertisement never substitutes for Router-CA trust.

## 8. Failure and policy behavior

- Invalid format, unsupported version, unknown critical field, length overflow, expired token/cookie, invalid certificate/status, wrong endpoint binding, failed signature/AEAD, replay, unknown session/epoch or unauthorized next hop: drop.
- CA unavailable: fail closed for new protected sessions when fresh trust evidence is required. Existing-session grace must be explicit, bounded and documented; a valid revocation event terminates affected sessions according to policy.
- DoS/resource pressure: enforce global, interface and source-prefix rate limits; cap pending handshakes, established sessions, directory lookups and replay entries; avoid expensive certificate/X25519 work until the cookie is validated.
- Concurrent traffic: atomically allocate sequence numbers and test-and-mark replay windows. Burn a reserved sequence after encryption failure; never reuse it.
- Restart/snapshot/hot reload: invalidate sessions and require fresh handshakes; never restore old sequence counters without the same protected key state, and the current candidate policy prohibits session resumption entirely.
- MTU/PMTU: calculate real overhead for outer IPv6+UDP, NLS header, hop plaintext, AEAD tag and destination envelope. Honor ICMPv6 Packet Too Big and define the maximum inner packet size; do not rely on fragmentation as the normal path.
- Audit: log bounded event codes, peer identity fingerprints and counters. Never log private/traffic keys, cookie secrets, complete decrypted protected packets, or unauthenticated claims as verified identities.

## 9. Implementation status and required gates

The repositories contain standalone Go v2 status/framing/AEAD/hop-codec primitives, a stateless cookie Issue/Verify primitive, a canonical control/TLV codec, and synthetic tests. These do not by themselves make a running router-to-router NLS system: packet I/O, authenticated adjacent handshake state, destination endpoint handshake/session wiring, trust/session table integration, Linux TUN setup, forwarding policy, and FRR/IPv6 lab validation remain separate milestones.

Before calling NLS v2 interoperable:

1. Freeze aligned wire/status/destination/handshake profiles after independent review.
2. Add shared positive and negative golden vectors for adjacent INIT/RETRY/RESP/FINISH, cookies and transcript/KDF; destination D_INIT/D_RESP/FINISH; data/header codecs; status/endpoint binding; AEAD/AAD/nonces; replay and malformed-length cases.
3. Pass both repositories' CI on the same fixtures; no CI failure is ignored or hidden by changing expected output without validating the contract.
4. Integrate a bounded in-memory adjacent session manager and destination session manager; keep v1 unchanged.
5. Integrate the socket/TUN shim with fail-closed policy and observable diagnostics.
6. Pass six-node functional IPv6 topology tests, then ten-router IPv6/FRR tests, including route changes, reboot/revocation, CA outage, resource exhaustion, no plaintext fallback, MTU/PMTU and return path.
7. Run performance gates separately with recorded hardware/software, workload, CPU, throughput, latency, memory and loss results.
8. Obtain independent cryptographic and protocol review.

## 10. Attacker-perspective critique

The transit network sees real outer relay addresses and traffic-analysis metadata; the destination router sees the inner IP packet after destination decryption; a compromised authorized transit relay can observe its own adjacency, disrupt traffic, and attempt to exploit parser/session defects. A compromised Router-CA can misissue identity/status information. Endpoint compromise exposes plaintext. A nonce reuse, weak state transition, incorrect signature canonicalization, stale revocation cache, route leak, or silent plaintext fallback could defeat intended properties. These risks are why this is an implementation workflow, not a security proof.

## 11. Change record

This document clarifies the intended workflow and staged integration path. It does not freeze v2 wire bytes or claim that a live TUN/router data path or native routing-protocol integration has been completed. NLS v1 remains unchanged.
