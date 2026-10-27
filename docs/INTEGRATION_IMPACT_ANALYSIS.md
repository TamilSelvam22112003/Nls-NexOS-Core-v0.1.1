# NLS Integration Impact Analysis and Open-Question Resolution

- Status: design analysis only; no runtime implementation
- Target: NLS v2 proposal in the `docs/nls-hop-envelope-v2-proposal` branch
- Baseline: v0.1.1 frozen wire protocol remains unchanged
- Related: `PROTOCOL.md`, `PROTOCOL_FREEZE.md`, `THREAT_MODEL.md`, `TEST_PLAN.md`, `SPEC_ERRATA.md`, `NLS_V2_WORKFLOW.md`, ADR-0016
- Decision requested: review this analysis before any code or frozen wire-contract changes.

## 1. Design intent and necessary correction

The intended behavior is to protect the original client/server IP addresses and application traffic from intermediate relays, while allowing each NLS relay to authenticate its adjacent relay and process protected hop metadata.

A conventional IPv6 forwarding plane cannot route a packet whose outer IPv6 source/destination fields are encrypted or replaced with non-routable ciphertext. Therefore, the outer IPv6 header must use real, routable underlay addresses. The encrypted source locator is a field in an NLS hop envelope, not the outer IPv6 source field. Each receiving NLS relay decrypts only its adjacent-hop envelope, validates the sender and session, and creates a fresh envelope for the next relay. The destination-protected inner packet remains opaque to transit relays.

The phrase “change its source IP in OSPF” is not equivalent to changing an IP header in every forwarded data packet. OSPF advertises topology and reachability using its own protocol semantics. If NLS needs OSPF to advertise NLS identities or tunnel endpoints, that requires an explicit, separately specified mapping and must not treat an OSPF LSDB entry as cryptographic proof of trust.

## 2. Existing components and workflows affected

| Component / workflow | Change required for a v2 implementation | Main risk / acceptance gate |
|---|---|---|
| Router identity and local key storage | Define one long-lived identity-signing key and ephemeral key-agreement keys; protect private keys and permissions | No private keys in repository, logs, registry responses or crash output |
| Router-CA enrollment and registry | Bind stable router identity to certificate, authorized routable WAN endpoints, status and revocation generation | Authenticated lookup; freshness; authorization; disable/revoke invalidates sessions |
| Peer directory / lookup | Return signed, bounded peer details to an authenticated caller | Reject stale, unsigned, tampered, ambiguous or unauthorized records |
| First-contact handshake | Challenge/cookie before expensive crypto; bind both identities, endpoints, nonces, ephemeral keys, version and roles | Anti-amplification; transcript integrity; replay and downgrade resistance |
| vIP / VIP Table | Use a short-lived opaque handshake token in NLS framing, not as a substitute for a routable IPv6 destination | Bounded state, expiry, collision detection, atomic consume, rate limits |
| Trust Table | Store stable peer identity, certificate fingerprint, authorized endpoints, status/revocation generation, session/key epoch references | No trust based solely on vIP, IP address, route, or unauthenticated peer claims |
| LSDB and route selection | Keep OSPF route state separate from cryptographic trust; optionally map authenticated NLS peers to allowed tunnel routes | LSDB presence alone never authorizes a peer; route changes cannot bypass policy |
| Packet encoder/decoder | Add versioned outer framing and an AEAD hop envelope around the destination-protected inner packet | Exact lengths, authenticated associated data, strict parsing, nonce uniqueness |
| Per-hop forwarding | Authenticate previous neighbor, enforce session/epoch and replay window, check next-hop authorization, re-envelope for next hop | Drop on any failure; no plaintext fallback for PROTECT traffic |
| Destination endpoint | Validate final hop envelope, then decrypt destination-protected packet at the intended security endpoint | Intermediate relays must not possess destination traffic keys |
| Router-CA client transport | Use the CA's routable endpoint and an authenticated TLS/mTLS or frozen control channel | A CA reply cannot be routed to a hidden/encrypted IP without a separate return-path mechanism |
| Linux TUN/socket integration | Add a dedicated NLS interface, route/policy rules, service lifecycle, MTU and PMTU handling | Loop prevention, no accidental plaintext leakage, clean startup/shutdown |
| FRR / OSPFv2 / OSPFv3 | Initially use existing routing to carry the NLS underlay; separately define whether/how authenticated NLS tunnel routes are advertised | Avoid circular dependency where NLS needs a route that itself requires NLS |
| BGP | Keep BGP peering over a routable underlay or explicitly defined protected transport; define route authorization and next-hop behavior | Do not conflate BGP route acceptance with Router-CA identity trust |
| RIP / RIPng | If supported, specify whether updates remain native or traverse a protected transport; test hop-count/metric semantics | No claim that NLS automatically secures native RIP packets |
| Default routes, ACLs, uRPF, NAT, ICMPv6 | Document policy and behavior for encapsulated packets, return path, errors and PMTU | Spoof checks and troubleshooting must match outer underlay addresses |
| Configuration / CLI / systemd | Add explicit protected prefixes, underlay endpoints, CA pin, limits, key/state paths and fail-closed policy | Least privilege, safe permissions, deterministic configuration |
| CI and lab | Shared protocol vectors, unit/property/fuzz tests, multi-router IPv6 tests, fault injection and separate performance gates | Reproducible evidence before operational claims |

## 3. Integration path decision

### Path A — modify native routing-protocol workflows

This path would add NLS-specific identity/session/policy interactions to OSPF/OSPFv3, BGP, RIP/RIPng, and possibly default-route handling. It would require protocol-specific design and tests for adjacency establishment, peer identity binding, route advertisement authorization, failure handling, route changes, and interoperability with unmodified peers.

**Decision:** do not use this as the first implementation path. It is a large compatibility surface and risks mixing route state with cryptographic trust. Native integration is a separate workstream after the data-plane framing and trust/session behavior are stable.

### Path B — TUN/socket shim over the existing routed underlay

A dedicated NLS interface carries the protected packet/envelope over routable IPv6 endpoints. Existing routing supplies underlay reachability; NLS independently authenticates neighbors and applies policy to protected traffic. Routing daemon integration initially consists of carefully configured reachability and, if needed, explicit routes for NLS endpoints—not an assumption that the daemon automatically understands NLS metadata.

**Decision:** recommended initial path. It isolates the new data plane and makes functional, negative, MTU, and performance tests possible without changing OSPF/BGP/RIP wire behavior.

### Compatibility rule

Unmodified OSPF/BGP/RIP peers remain unmodified. NLS does not claim to encrypt native routing-protocol packets unless a separately specified integration actually carries or protects those packets. Version negotiation is explicit; v1 and v2 are not silently mixed. A handshake or crypto failure MUST NOT downgrade PROTECT traffic to plaintext. BYPASS is allowed only when explicitly selected by local policy.

## 4. Open questions and proposed dispositions

### Q1. Return path for vIP or encrypted source metadata

**Disposition:** keep the actual underlay source/destination IPv6 addresses routable and visible. Use a random, opaque, short-lived token in the NLS framing for pending-handshake demultiplexing only. The Router-CA is contacted at its configured routable endpoint over an authenticated connection; the connection's transport state provides the return path. A vIP must not be the only destination address used by ordinary IPv6 forwarding.

**Still requires protocol review:** token size, generation, binding to initiator/peer/nonce, expiration, retry semantics, collision handling and cleanup.

### Q2. Per-neighbor keys and routing interactions

**Disposition:** use authenticated transcript-bound ephemeral X25519 key agreement, HKDF-SHA-256 with explicit labels, and distinct directional keys. Routing adjacency may inform policy but does not establish cryptographic identity. TTL/hop-limit, ICMPv6/Packet Too Big, PMTU, uRPF, ACLs, NAT and diagnostic visibility must be tested against the outer routable header and the chosen encapsulation.

### Q3. vIP derivation and format

**Disposition:** do not freeze “SHA output truncated to 128 bits as an IP address.” A hash output is not automatically a routable or collision-free address. Prefer a random opaque token in NLS framing. If a network-layer vIP is retained, a new ADR must specify namespace, address validity, exact derivation inputs, truncation, collision handling, return routing, expiry, replay behavior and how it avoids being mistaken for a real underlay address.

### Q4. Two RSA key pairs and symmetric/asymmetric data encryption

**Disposition:** do not introduce two RSA pairs without distinct, justified roles. Proposed roles are:
- Ed25519 identity key: router identity and signatures.
- Ephemeral X25519 key pair: session key agreement and forward-secrecy contribution.
- HKDF-SHA-256: derives independent keys from the shared secret and transcript context.
- Directional AES-256-GCM keys: protect per-hop data envelopes.
- Separate destination-protection key material: protects the inner packet for its intended endpoint.

Use asymmetric cryptography for identity/key establishment and symmetric AEAD for packet data. Do not encrypt every data packet directly with a static public key. Exact nonce, epoch, rekey, key-erasure and failure rules remain to be frozen.

### Q5. Suspicious or invalid peer behavior

**Disposition:** drop the offending packet; do not install trust or routes; update bounded counters; emit rate-limited structured audit events; apply configured quarantine only after a defined threshold/policy; notify Router-CA asynchronously when available. Do not allow attacker-triggered unbounded logs or synchronous CA calls in the forwarding path.

### Q6. Router-CA outage, compromise and revocation

**Disposition:** pin the CA trust anchor; authenticate and freshness-check lookups; track revocation generation. New sessions fail closed for PROTECT traffic if required trust cannot be established. Established-session continuation during CA outage must have an explicit maximum stale-policy/revocation window and a defined revocation limitation. CA compromise requires key rotation/recovery, certificate invalidation and session teardown procedures. HA is not claimed unless implemented and tested.

### Q7. Denial of service

**Disposition:** stateless cookie/challenge before expensive cryptography or per-peer allocation; global, ingress-interface and source-prefix limits; bounded VIP/session tables; concurrency caps; strict message-size limits; replay checks; anti-amplification; rate-limited logging; and resource-exhaustion tests.

### Q8. MTU and performance

**Disposition:** compute exact framing, AEAD tag and encapsulation overhead before the wire format is frozen. Prefer PMTU-safe packet sizing and correct ICMPv6 Packet Too Big handling over reliance on fragmentation. Measure throughput, latency, CPU, memory, packet loss and rekey impact under a reproducible test environment. Functional gates must not depend on performance gates.

### Q9. Technical inconsistencies

- The outer IPv6 source address cannot be encrypted in place while retaining ordinary routing behavior.
- OSPF does not rewrite the source address of every data packet; it distributes routing/topology information.
- A router cannot decrypt an envelope intended for a different next hop.
- A router's route/LSDB entry does not establish cryptographic trust.
- A public key by itself does not prove that a claimed IP address belongs to a peer; the identity certificate and endpoint authorization must bind them.
- The original client/server packet should remain destination-protected; intermediate relays must not have the destination key.
- A destination router may terminate the hop envelope, but the server can decrypt application/inner content only if the design explicitly gives the server the appropriate key or delivers a separately protected payload to it.
- NLS cannot claim to protect native OSPF/BGP/RIP unless the implementation explicitly integrates those packets.
- “Synchronous/asynchronous key” is ambiguous terminology; use “identity-signing key,” “ephemeral key-agreement key,” “directional traffic key,” “nonce,” and “key epoch.”

## 5. Proposed end-to-end state machines

### Router lifecycle
`UNINITIALIZED -> IDENTITY_READY -> CA_VALIDATED -> POLICY_READY -> LISTENING`
Any mandatory trust/configuration failure transitions to `DEGRADED` or `FAIL_CLOSED` for PROTECT traffic. Recovery must revalidate policy and revocation state before forwarding resumes.

### Pending first-contact lifecycle
`NEW -> CHALLENGED -> AUTHENTICATING -> ESTABLISHED`
Failure or timeout transitions to `REJECTED/EXPIRED`; pending state is removed atomically. The opaque token is invalidated on successful completion, timeout, rejection or restart.

### Peer/session lifecycle
`UNKNOWN -> DIRECTORY_VALIDATED -> HANDSHAKE_IN_PROGRESS -> TRUSTED_SESSION`
Revocation, certificate expiry, failed rekey, authentication failure or policy invalidation transitions to `REVOKED/EXPIRED/FAILED`; associated sessions and protected forwarding authorization are removed.

### Packet forwarding
`RECEIVED -> BOUNDS_CHECK -> SESSION_LOOKUP -> AEAD_VERIFY -> REPLAY_CHECK -> PEER/POLICY_CHECK -> NEXT_HOP_SELECT -> RE_ENCAPSULATE -> SEND`
Any failed check transitions to `DROP`. Never forward unauthenticated envelope contents, and never fall back to plaintext for a PROTECT route.

## 6. Required decisions before coding

The design analysis recommends these defaults, but they should be explicitly accepted before implementation:

1. **Initial integration:** Path B, TUN/socket shim over routable IPv6 underlay.
2. **First-contact token:** random opaque, short-lived NLS framing token, not an ordinary IPv6 source address.
3. **Crypto roles:** Ed25519 identity signatures; ephemeral X25519 + HKDF-SHA-256; directional AES-256-GCM hop keys; separate destination-protection key.
4. **Routing state:** LSDB and NLS Trust Table remain separate; explicit mapping/policy only.
5. **Failure behavior:** fail closed for PROTECT traffic; no implicit downgrade or plaintext fallback.
6. **Destination boundary:** intermediate relays only process their adjacent-hop envelope; destination-protected inner content remains unavailable to them.

These defaults resolve design ambiguities for the proposal but do not freeze a wire contract. Exact binary fields, lengths, nonce rules, associated data, error codes, rekey and version negotiation belong in the next normative specification step.

## 7. Acceptance plan before implementation

- [ ] Review and approve the six decisions in §6.
- [ ] Freeze byte-exact v2 framing, fields, limits, associated data, error codes, nonce/epoch rules and negotiation.
- [ ] Create golden vectors consumed by both Core and NetOS.
- [ ] Add strict parser, tamper, replay, wrong-neighbor, stale/revoked peer, nonce uniqueness, downgrade and resource-exhaustion tests.
- [ ] Add Router-CA outage/recovery, restart, token expiry/collision and concurrent handshake tests.
- [ ] Run six-node functional and ten-router IPv6 lab, including route changes and asymmetric return paths.
- [ ] Verify no plaintext leakage for PROTECT traffic.
- [ ] Test minimum IPv6 MTU, PMTU/ICMPv6, packet loss and rekey behavior.
- [ ] Run performance matrix separately and preserve reproducible artifacts.
- [ ] Obtain independent protocol/cryptographic review before production claims.

## 8. Attacker-perspective critique

An authorized but compromised relay can observe its adjacent peers, outer endpoints, traffic volume, timing and packet sizes. It can drop, delay or reorder traffic. A compromised Router-CA may misissue identity material unless recovery, governance and revocation are sound. Endpoint compromise exposes plaintext at that endpoint. Incorrect nonce reuse, replay-window races, parser discrepancies, route-policy bypass, stale revocation state or downgrade logic can invalidate the intended protection. The current document is a design analysis and does not establish implementation correctness, formal verification, interoperability or production readiness.

## 9. Changelog entry

- Added the NLS v2 integration impact matrix, comparison of native routing integration vs TUN/socket shim, proposed resolutions for the nine open questions, lifecycle state machines, pre-implementation decisions and acceptance gates.
- Documentation only; no v1 wire bytes, source code, configuration defaults or tests changed.
