# NLS v2 Workflow and Impact Analysis (Proposal)

- Handshake/control wire draft: [NLS_V2_HANDSHAKE_CONTROL_DRAFT.md](NLS_V2_HANDSHAKE_CONTROL_DRAFT.md)
- Data-plane framing draft: [NLS_V2_WIRE_SPEC_DRAFT.md](NLS_V2_WIRE_SPEC_DRAFT.md)
- Cross-document findings: [NLS_V2_CROSS_DOCUMENT_REVIEW.md](NLS_V2_CROSS_DOCUMENT_REVIEW.md)
- Golden-vector requirements: [NLS_V2_CRYPTO_VECTORS_PLAN.md](NLS_V2_CRYPTO_VECTORS_PLAN.md)
- Destination-protection profile: [NLS_V2_DESTINATION_PROTECTION_PROFILE.md](NLS_V2_DESTINATION_PROTECTION_PROFILE.md)
- Destination-protection handshake draft: [NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md](NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md)
- Router-CA status profile: [ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md](ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md)

- Status: **Design proposal only; not a frozen wire contract**
- Target: a separately versioned NLS v2 / future release after protocol review
- Related: [PROTOCOL.md](PROTOCOL.md), [PROTOCOL_FREEZE.md](PROTOCOL_FREEZE.md), [SPEC_ERRATA.md](SPEC_ERRATA.md), [ADR-0016](adr/0016-per-hop-source-locator-protection.md)
- Scope of this document: impact analysis, workflow, open-question disposition, and acceptance gates. No implementation is implied.

## 1. Design objective

NLS v2 is intended to carry client traffic through authenticated NLS relays while protecting the previous-hop/source-locator metadata separately from destination-protected inner traffic. At each relay, the incoming hop envelope is authenticated and decrypted with the adjacent-hop receive key. The relay validates the previous-hop identity and session, replaces hop-local metadata with its own authenticated locator, and creates a fresh envelope for the next relay. The original client and server addresses remain inside the destination-protected inner packet.

**Important boundary:** the IPv6 source and destination in the outer header are routing fields. Ordinary IP forwarding requires them to be usable by the underlay; NLS cannot encrypt the outer IPv6 source field in place and expect normal routing to continue. The protected source locator is therefore a field in the encrypted hop envelope, not the outer IPv6 header.

## 2. Affected components and workflows

| Component | Required impact | Boundary / acceptance condition |
|---|---|---|
| Shared protocol definitions | Define versioned v2 framing, canonical field encoding, size limits, error codes, and test vectors | v1 bytes remain unchanged |
| Router-CA / enrollment | Bind router identity, certificate, advertised WAN endpoints, key roles, status, and revocation generation | No private key material in registry responses |
| Peer directory / lookup | Authenticated, signed lookup of peer identity and authorized endpoint data | Caller ACTIVE; freshness and revocation checked |
| Handshake/session manager | Establish distinct directional adjacent-hop keys; destination-protection keys require a separate specified profile; transcript binding, expiry, replay prevention, rekey | No static public-key encryption per packet; no key reuse across roles |
| VIP Table | Temporary first-contact state only: token/vIP, nonce, expiry, peer reference, handshake state | Bounded size, one-time use, collision/replay checks, atomic cleanup |
| Trust Table | Verified peer identity, certificate fingerprint, authorized endpoint(s), status/generation, session references | Populate only after mutual validation; revoke invalidates sessions |
| Packet encoder/decoder | Outer IPv6/UDP + minimal NLS framing + AEAD-protected hop envelope + destination-protected inner packet | Exact lengths, authenticated associated data, strict parser |
| Forwarding/data plane | Authenticate inbound neighbor, enforce sequence/replay window, transform hop metadata, forward only to authenticated next hop | Fail closed for PROTECT traffic; no plaintext fallback |
| TUN/socket shim | First integration path for carrying NLS packets across a routed IPv6 underlay | Explicit route policy and MTU/PMTU handling |
| OSPF/OSPFv3, BGP, RIP, default routing | Separate control-plane integration and adjacency policy | Do not claim routing control traffic is secured merely because data uses the shim |
| CLI/config/systemd | Configure underlay endpoints, CA pin, policy, protected prefixes, keys/state paths, logging, limits | Safe permissions, least privilege, auditable configuration |
| CI and lab | Unit/property/fuzz tests, golden vectors, multi-router IPv6, failure and performance gates | Green CI and lab evidence required before operational claims |

## 3. Proposed packet model

### 3.1 Outer underlay packet

- IPv6 source: current relay's routable underlay/WAN address.
- IPv6 destination: next relay's routable underlay/WAN address.
- UDP ports: configured NLS transport ports.
- NLS framing: wire version, opaque session/demultiplexing token, packet sequence number, bounded flags/lengths.
- Hop envelope: AEAD ciphertext for the receiving adjacent relay.
- Inner packet: separately protected for the destination security endpoint.

Transit networks can still observe outer relay addresses, transport ports, packet sizes, timing, packet volume, and traffic patterns. NLS does not claim to hide these without an additional underlay/tunnel design.

### 3.2 Protected hop envelope (logical fields; exact bytes remain to be frozen)

- protocol/context identifier and wire version;
- session identifier and key epoch;
- previous-hop router identity and authenticated source locator;
- intended next-hop identity / locator binding;
- packet sequence number and any required forwarding context;
- inner protected packet or destination-protected envelope;
- AEAD tag.

The receiver MUST authenticate the complete envelope and associated data before using any decrypted field. Unknown critical fields, invalid lengths, wrong session/epoch, replayed sequence numbers, wrong neighbor binding, or failed authentication MUST cause a drop and a rate-limited security event. Never parse unauthenticated plaintext as trusted routing metadata.

### 3.3 Key separation

Use reviewed primitives only. Proposed suite for review: Ed25519 router identity/signatures; ephemeral X25519 key agreement; HKDF-SHA-256 with explicit role/context labels; AES-256-GCM (or another reviewed AEAD chosen before freeze). Derive separate directional keys for A→B and B→A, and separate key material for hop envelopes and destination protection. Enforce nonce uniqueness per AEAD key; rotate/rekey before counter exhaustion and on policy/session changes. Do not use RSA key pairs by default merely because the initial notes mention two RSA pairs; modern signing and ephemeral key-agreement roles are cleaner and already align with the v1 suite. Any alternative suite needs an explicit ADR and cryptographic review.

## 4. End-to-end workflow

### 4.1 Boot and enrollment
1. Router loads a pinned Router-CA trust anchor and its protected local identity/key material.
2. Router validates configuration and underlay reachability, then enrolls or refreshes its certificate and advertised WAN endpoint with Router-CA.
3. Router obtains current policy, directory/revocation generation, and authorized local role.
4. It starts in a non-forwarding state for PROTECT traffic until required identity, policy, and session services are ready.

### 4.2 First contact and mutual authentication
1. Initiator resolves the intended peer through the authenticated directory. It validates certificate chain, identity, status, endpoint authorization, freshness, and revocation generation.
2. Initiator creates a fresh handshake nonce and ephemeral X25519 key pair. A temporary vIP/token may be used only as a bounded first-contact demultiplexing aid; it is not a substitute for authentication or routable return-path information.
3. Initiator sends a versioned handshake message to the peer's routable underlay endpoint. The handshake binds both identities, endpoint data, nonces, ephemeral public keys, protocol version, roles, and requested capabilities.
4. Responder validates the initiator and responds with its own authenticated handshake material. Cookie/challenge protection and rate limits precede expensive state allocation.
5. Both peers validate the full transcript and derive directional hop keys with HKDF. They reject all-zero X25519 shared secrets and invalid signatures.
6. Both sides confirm key possession, install a bounded session, and mark the peer trusted only after successful mutual confirmation. A vIP/token expires after successful completion or timeout and is never accepted as proof of identity by itself.

### 4.3 Forwarding one packet across relays
1. Client packet reaches ingress router. Policy selects PROTECT, BYPASS, or DROP. PROTECT traffic is never sent in plaintext on the WAN.
2. Ingress router determines the destination security endpoint and checks destination trust/session state. If missing or stale, it performs the authenticated peer/session workflow or queues/drops according to bounded policy; it does not silently downgrade.
3. Ingress router creates or preserves the destination-protected inner packet so only the destination security endpoint can recover the original client/server packet. It then wraps it in an AEAD hop envelope using the first adjacent relay's directional hop key.
4. Relay R2 receives the packet at its routable outer IPv6 address. It checks framing bounds and session lookup, authenticates/decrypts the hop envelope, verifies replay state and that the previous-hop identity matches the authenticated adjacency, then checks that the next hop is authorized by current routing/policy state.
5. R2 constructs a fresh envelope for R3 with a fresh sequence/nonce under the R2→R3 key and R2's authenticated hop locator. The destination-protected inner packet remains opaque to R2.
6. Each subsequent relay repeats the same adjacent-hop verification and re-enveloping operation. The destination relay authenticates the last-hop envelope, validates the previous hop, removes the hop wrapper, and passes the destination-protected inner packet to the intended local security endpoint.
7. The destination endpoint decrypts/verifies the inner packet and delivers it to the server. Return traffic follows the independently authorized reverse route with reverse-direction hop keys and its own replay state.

### 4.4 Control-plane integration
- **Initial implementation choice:** TUN/socket shim over the existing IPv6 underlay. It reduces invasive modifications to OSPF/BGP/RIP and makes the NLS data plane testable independently.
- **Routing protocols:** protect routing protocol packets only through a separately specified control-plane mode or secure transport/adjacency integration. Define which packets are carried inside NLS, which remain native, how adjacency discovery and key establishment avoid circular dependencies, and how failures affect route installation.
- OSPF/OSPFv3, BGP, RIP, default routes, ICMP errors, PMTU discovery, TTL/hop-limit behavior, uRPF, ACLs, NAT, and troubleshooting visibility each need explicit tests. NLS does not automatically secure or replace the routing protocol.
- Native protocol modification should be considered only after the shim's packet format, routing semantics, and failure behavior are stable.

## 5. Table responsibilities

### VIP / pending-handshake table
Temporary state only: token/vIP, initiator identity if authenticated, handshake nonce, peer endpoint, creation/expiry time, state, retry count, and resource-accounting fields. It must be size-bounded, rate-limited, collision-safe, atomically consumed, and purged on timeout or completion. Do not store unverified peer details as trusted data.

### Trust / session table
Key by stable router identity and authorized endpoint, not by vIP alone. Store certificate fingerprint/chain reference, router status, revocation generation, verified endpoint list, session ID/key epoch references, replay-window state, creation/expiry times, and policy version. Keep private/session keys in protected key storage rather than logs or public directory responses. Revoke/disable events must invalidate affected sessions and forwarding eligibility.

### LSDB
Keep the routing daemon's LSDB semantics separate from NLS cryptographic trust. A route or adjacency appearing in the LSDB is not proof that the peer is cryptographically trusted; a trusted peer is not automatically authorized to advertise every prefix.

## 6. Open-question disposition

1. **Return path:** Use the sender's routable underlay endpoint for transport return traffic. A vIP is only a handshake/session demultiplexing token and MUST NOT be the sole network-layer destination. Router-CA requests use authenticated TLS/mTLS or the frozen control protocol to the CA's routable endpoint; responses return over that established connection. Do not encrypt an IP header field and expect the CA or routers to route to it.
2. **Per-neighbor keys:** Establish them through an authenticated, transcript-bound handshake with ephemeral key agreement. Routing adjacency is a separate state machine; it may be used as an input/policy signal but must not itself prove identity. Specify interactions with TTL/hop limit, ICMP/PMTU, uRPF, ACL/NAT and diagnostics in implementation ADRs and lab tests.
3. **vIP derivation:** Do not freeze the vague “SHA produces a 128-bit IP” idea. A hash output is not automatically a valid/routable IPv6 address. Prefer a random, opaque, bounded-lifetime token in the NLS framing. If a vIP is retained for compatibility, specify exact namespace, derivation, truncation, collision detection, lifetime, return routing and replay rules in a separate ADR; never rely on secrecy of a hash as authentication.
4. **Key roles:** Prefer Ed25519 identity signatures and ephemeral X25519 key agreement with HKDF-SHA-256. Use AEAD with directional keys for hop envelopes and a separately derived destination-protection key. No “synchronous/asynchronous key” ambiguity: specify identity signing key, ephemeral DH key, directional traffic key, nonce and epoch explicitly.
5. **Suspicious behavior:** Drop the packet; do not install trust or routes; increment bounded counters; emit rate-limited structured audit/security events; optionally quarantine the peer according to policy; notify Router-CA asynchronously when available. Avoid attacker-triggered unbounded logging or synchronous dependencies.
6. **Router-CA failure:** Existing established sessions may continue only within an explicitly frozen maximum stale-policy/revocation window; new sessions and sessions whose status cannot be validated fail closed for PROTECT traffic. Pin trust anchors, define key rotation and recovery, and document compromise response. Do not claim high availability until implemented and tested.
7. **DoS:** Stateless cookie/challenge before expensive cryptography or per-peer allocation; global, per-interface and per-source-prefix rate limits; bounded VIP/session tables; concurrency caps; message-size caps; replay checks; rate-limited logs; anti-amplification limits.
8. **MTU/performance:** Calculate exact header/tag overhead before freezing; use PMTU-safe packet sizing or bounded fragmentation policy (prefer avoiding IP fragmentation); test IPv6 minimum MTU, ICMPv6 Packet Too Big, retransmission behavior, throughput, latency, CPU, memory and packet loss.
9. **Technical correction:** An ordinary transit router cannot read an encrypted outer source IP field to route the packet. Outer IPv6 addresses remain visible and routable. The adjacent NLS relay decrypts only its hop envelope; it must not learn the destination-protected inner packet. OSPF LSDB updates are not a substitute for the NLS Trust Table. Public-key crypto is for authentication/key establishment or small control data; use derived symmetric AEAD keys for packet data.
10. **Compatibility:** v1 and v2 must be explicitly negotiated/versioned. No implicit downgrade and no silent plaintext fallback. BYPASS is a local explicit policy choice, not a fallback caused by handshake failure. Existing native OSPF/BGP/RIP peers remain unchanged unless an explicitly configured integration is deployed.

## 7. Proposed decisions and assumptions

- v1 wire contract remains frozen and untouched.
- v2 uses an encrypted adjacent-hop envelope for source-locator protection and a distinct destination-protected inner packet.
- Outer IPv6/UDP addresses and traffic-analysis metadata remain visible.
- TUN/socket shim is the first implementation path; native routing-protocol integration is a later, separately tested workstream.
- Router-CA and peer-directory responses are authenticated and freshness/revocation checked.
- Protected traffic fails closed on missing trust, failed AEAD, replay, policy denial, or unavailable required control state.
- The document is a proposal, not a claim of implementation, interoperability, formal verification, or production readiness.

## 8. Acceptance and test plan before code is accepted

1. Freeze a byte-exact v2 framing document: fields, byte order, limits, associated data, error behavior, key derivation labels, nonce construction, epoch/rekey rules and version negotiation.
2. Add golden packet/handshake vectors shared by NetOS and NexOS Core.
3. Unit/property/fuzz tests: truncation, trailing bytes, duplicate/unknown fields, oversized lengths, invalid version, invalid signatures, all-zero DH secret, AEAD tamper, nonce uniqueness, replay/window boundaries, reordering, wrong-neighbor/session/epoch, stale/revoked certificate and downgrade attempts.
4. Test return path, CA outage, revocation, router restart, key rotation, token collision/expiry, state exhaustion, rate limiting and concurrent handshakes.
5. IPv6 lab: at least six-node functional topology and ten-router end-to-end topology; include multiple next hops, route changes, asymmetric return path, OSPFv3 and explicit negative tests.
6. MTU/PMTU and ICMPv6 tests; demonstrate no plaintext leakage for PROTECT policy.
7. Performance gates run separately from functional tests, with reproducible environment, throughput/latency/CPU/memory measurements and profile artifacts.
8. Independent cryptographic/protocol review before claiming production readiness.

## 9. Attacker-perspective critique

A compromised relay can observe its adjacent-hop identities, outer network metadata, packet sizes/timing and any plaintext intentionally delivered to that relay; hop-by-hop protection does not hide traffic patterns or protect against a malicious authorized relay. A compromised Router-CA can misissue identity data unless the design adds governance, revocation and recovery controls. Endpoint compromise exposes endpoint plaintext. Bugs in nonce/key-epoch management, replay windows, canonical parsing, route authorization, or downgrade handling can defeat the intended protections. These risks require explicit implementation tests and independent review; this proposal alone does not resolve them.

## 10. Change log

- Added the v2 end-to-end workflow, component-impact matrix, table responsibilities, open-question disposition, assumptions and acceptance gates.
- Documentation only; no wire bytes, runtime code, configuration defaults, or tests changed.
