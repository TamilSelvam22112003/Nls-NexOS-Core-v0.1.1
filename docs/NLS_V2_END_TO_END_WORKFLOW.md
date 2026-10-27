# NLS v2 End-to-End Workflow and Routing Integration Plan

**Status:** Engineering workflow proposal; not a frozen wire contract.  
**Compatibility:** NLS v1 remains unchanged. No implicit downgrade and no plaintext fallback for traffic classified `PROTECT`.  
**Initial integration choice:** TUN/socket shim over the existing routed IPv6 underlay (A1).  
**First-contact choice:** random, short-lived opaque token for bounded demultiplexing only (B1).  
**Scope:** define how enrollment, Router-CA trust, adjacent-hop protection, destination protection, route selection and Linux/FRR fit together. This document does not claim the live NLS data path is complete.

## 1. Security model and packet boundaries

NLS v2 proposes two separate cryptographic protections:

1. **Adjacent-hop protection:** each NLS relay authenticates the immediate NLS peer and decrypts only the hop envelope addressed to it. It validates the sender/session, extracts only authorized hop metadata, selects an authorized next relay and constructs a new hop envelope using a directional key for that next relay.
2. **Destination protection:** the original inner IPv4/IPv6 packet is encrypted for the destination NLS security endpoint. Transit relays carry this inner envelope opaquely and do not possess its destination traffic key.

A conventional IPv6 underlay cannot route using an encrypted or non-routable outer source/destination address. Every UDP datagram therefore needs a real routable underlay IPv6 source (the current relay's WAN endpoint) and destination (the next relay's WAN endpoint). Those outer addresses, UDP ports, packet sizes, timing and traffic volume remain visible. NLS protects selected source-locator and inner-packet fields inside the envelope; it does not encrypt the outer IPv6 header in place.

The v1 RDR, v1 framing and v1 services remain unchanged. NLS v2 is a separately negotiated profile.

## 2. Boot, enrollment and readiness

1. Load the pinned Router-CA trust anchor, routable WAN endpoint configuration, NLS UDP port, permitted roles, protected prefixes, MTU policy, rate limits and fail-closed policy.
2. Establish ordinary IPv6 underlay reachability to the Router-CA and candidate NLS peers. Existing Linux routing and FRR provide reachability; NLS does not make an unroutable CA endpoint reachable by hiding its address.
3. Enroll or refresh the router identity with Router-CA. Validate the leaf certificate, Router-CA-signed v2 status evidence, authorized WAN endpoint tuple, status generation, freshness and local policy. Identity-signing keys, ephemeral key-agreement keys, adjacent-hop traffic keys and destination traffic keys are distinct roles.
4. Start NLS listeners only after required trust anchors, clocks, permissions, configuration and resource bounds validate. New sessions fail closed if required fresh trust evidence cannot be obtained.
5. Maintain separate state for the IP routing table/OSPF LSDB, cryptographic peer trust, first-contact pending tokens, adjacent-hop sessions, destination sessions and packet replay windows. A route or OSPF neighbor entry alone is never proof of cryptographic identity.

## 3. First contact and adjacent-hop session

The adjacent-hop control-message draft defines exact message encodings; this section records the intended control flow.

1. The initiator resolves the peer identity and routable UDP endpoint from configured policy/directory/Router-CA information. It validates the peer certificate, signed status object, status generation and endpoint authorization.
2. Generate a random handshake ID, initiator nonce and ephemeral X25519 key pair. Any first-contact token is a short-lived opaque demultiplexing value. It is not an IP address, route, identity credential or replacement for a routable IPv6 endpoint.
3. Send INIT to the responder's routable IPv6 endpoint. Validate strict lengths/version/type before parsing TLVs. Apply ingress/global limits.
4. For untrusted INIT messages, issue a stateless RETRY cookie bound to the observed outer IPv6 source/destination, UDP source/destination ports, handshake ID, initiator nonce, initiator ephemeral public key and bounded time bucket. Before cookie validation, do not allocate per-peer state or perform expensive certificate/X25519 work.
5. After cookie validation, validate the initiator's certificate/status/endpoint. The responder generates its fresh ephemeral key and nonce, then sends signed RESP. The signature/transcript bind both identities, authorized endpoints, nonces, ephemeral keys, suite and protocol version.
6. Both endpoints compute X25519, reject an all-zero shared secret and derive separate directional keys using the specified HKDF-SHA-256 transcript context. An identity-signing key is not used as a traffic key and public-key encryption is not performed on every data packet.
7. FINISH_I and FINISH_R confirm possession of the derived keys. The responder's opaque session token becomes active only after the initiator authenticates FINISH_R. Install session/replay state atomically after completed confirmation.
8. On failure, expiry, identity/status/endpoint mismatch, replay or a resource cap, discard pending state and temporary secrets best-effort, do not establish trust, and drop or boundedly queue PROTECT traffic. Plaintext fallback is forbidden.
9. Sessions have bounded lifetime, bytes and packet counts. The candidate lifecycle forbids resumption after process restart and leaves KEY_UPDATE unsupported; a new full handshake is required after restart and before any limit is reached.

## 4. Destination endpoint session

1. The source NLS security endpoint validates the destination endpoint's certificate and signed status evidence, including the destination identity fingerprint, status generation, freshness and endpoint role.
2. Establish a separate source-to-destination handshake with fresh nonces and ephemeral X25519 keys. This transcript domain and its key-derivation labels are separate from the adjacent-hop handshake.
3. Both endpoints validate the handshake transcript and signatures, derive destination-scoped directional keys and install a session only after authenticated FINISH confirmation.
4. Encrypt the complete original IPv4/IPv6 packet (including original source and destination addresses) into the destination envelope. Bind recipient identity, flow/session ID, sequence, timestamp/policy fields and framing into AEAD authentication exactly as specified by the selected destination-envelope profile.
5. Transit relays forward the destination envelope as opaque bytes. They do not decrypt it, alter it, or receive destination traffic keys.
6. Return traffic uses the reverse destination directional key and an independently maintained sequence/replay state, plus independently established hop protection along the return route.
7. Unknown session, stale/revoked status, wrong recipient, invalid tag, replay, invalid inner IP packet or policy denial means drop. A successful cryptographic check does not authorize route installation or unrestricted forwarding.

## 5. Per-hop packet forwarding

1. Classify each ingress flow under explicit policy as `PROTECT`, `BYPASS` or `DROP`. A cryptographic failure cannot convert `PROTECT` traffic to `BYPASS`.
2. For `PROTECT`, obtain a valid destination session and encapsulate the complete inner IP packet for the destination endpoint.
3. Select a next-hop NLS relay using an authorized route/policy binding. The route chooses a transport destination; it does not confer trust.
4. Build the hop plaintext containing required sender/neighbor/session context, logical locator/forwarding metadata and the opaque destination envelope. Do not expose original client/server IP addresses outside what the wire profile explicitly permits.
5. Allocate a unique sequence number atomically under the outbound directional adjacent-hop key. Construct the exact NLS v2 common header; use the profile's specified payload length and nonce construction. Authenticate the required header and observed outer IPv6/UDP tuple as AAD.
6. Transmit over UDP with the current relay's routable IPv6 address as outer source and next relay's routable IPv6 address as outer destination. Respect the configured packet cap and IPv6 path-MTU/ICMPv6 policy.
7. The next relay validates framing and bounds before session lookup, authenticates/decrypts the hop envelope, checks peer identity/status/endpoint and replay window, verifies locator-to-peer binding, then makes a forwarding decision.
8. The relay wraps the same destination envelope bytes in a fresh hop envelope for the authorized next relay. It uses its own directional key and fresh sequence; it must not decrypt or rewrite the destination envelope.
9. The destination router authenticates/removes only the final hop layer, then the destination security endpoint authenticates and decrypts the destination envelope. Validate the inner packet and local policy before forwarding it toward the server/host.

## 6. State ownership and tables

| State/table | Owner and responsibility | Must not be confused with |
|---|---|---|
| Routing table / OSPF LSDB | Linux kernel/FRR reachability, adjacency, metrics and convergence | Certificate validation or cryptographic trust |
| Router-CA registry/status | NexOS Core control plane; identity/certificate/status generation/endpoints/revocation evidence | A forwarding route or traffic key |
| Peer trust cache | NetOS local authenticated peer identity, certificate fingerprint, authorized endpoints, status generation/freshness | Opaque token or raw IP alone |
| Pending token table | NetOS bounded first-contact demultiplexing; short TTL and one-time consume rules | Routable virtual IPv6 address or long-lived peer identity |
| Adjacent session table | NetOS directional keys, peer identity, session token, epoch/sequence limits, replay window and expiry | Destination traffic-key state |
| Destination session table | Source/destination endpoint scoped keys, destination identity, flow/session, replay and expiry | A transit relay's adjacent-hop session |
| Audit/metrics | Bounded event codes, identity fingerprints and counters | Secrets, decrypted packets or unauthenticated peer claims as verified facts |

Use expiry, entry-count bounds, rate limits, atomic updates and generation/rollback checks. Do not store private or derived traffic keys in Router-CA lookup results or logs.

## 7. Routing protocol integration strategy

### Phase A — routed IPv6 underlay + UDP/socket shim + TUN (first implementation path)

- Leave native OSPFv2, OSPFv3, BGP, RIP/RIPng encodings and peer compatibility unchanged.
- Let Linux and FRR provide routable reachability to NLS relay endpoints and the Router-CA. Install narrowly scoped routes to relay endpoints outside the protected-prefix route to avoid circular routing dependencies.
- Implement the v2 UDP/socket path and strict framing/session validation first. Then attach a dedicated TUN interface to carry selected client IPv4/IPv6 packets; configure protected prefixes, policy routing, loop prevention and explicit BYPASS/DROP behavior.
- Ensure control-plane traffic needed to build the underlay is not accidentally routed into the NLS TUN. Protect Router-CA and relay endpoint reachability from recursive capture by the protected route.
- Test neighbor discovery, PMTU/ICMPv6, asymmetric return route, route change, service restart, firewall ACL, uRPF, NAT/rebinding policy, packet loops and CA outage before treating the shim as usable.

### Phase B — protect selected routing/control traffic (separate gated workstream)

- **OSPF/OSPFv3:** decide whether selected control packets are carried within the NLS protected interface or whether an explicit authenticated NLS-neighbor binding is used. Preserve LSDB semantics; independently test multicast behavior, adjacency timers and convergence. An LSDB entry remains non-cryptographic.
- **BGP:** explicitly choose whether the TCP peering runs over a protected underlay or inside NLS. Specify peer identity, transport reachability, route policy, next-hop semantics and failure behavior.
- **RIP/RIPng:** explicitly choose whether updates remain native on the underlay or are carried by NLS; test metrics, hop limits, update timers and interoperability with unmodified peers.
- **Static/default routes:** install underlay routes to NLS relay and Router-CA endpoints before protected-prefix routes; prevent a route for the NLS endpoint from depending on the NLS tunnel it is trying to establish.
- **IPsec/TLS:** NLS does not replace these protocols or automatically secure their native packets. They may coexist at distinct layers. Document which endpoint terminates each security layer and avoid conflating router identity with application/server identity or accidental double encryption.

Native routing integrations are not accepted until each protocol's actual packet path and peer behavior is tested in a reproducible lab. “NLS secures OSPF/BGP/RIP” must not be claimed merely because a TUN data plane is running.

## 8. Failure and operational policy

- Malformed/oversized record, unsupported critical field, expired token/cookie, invalid certificate/status, endpoint mismatch, signature/AEAD failure, replay, unknown session/epoch or unauthorized next hop: drop.
- CA unavailable: do not establish a new protected session when fresh trust evidence is required. Existing-session continuation during an outage must use a documented bounded grace policy; valid revocation evidence invalidates affected trust.
- Resource pressure: enforce global, interface and source-prefix limits; cap pending handshakes, sessions, directory lookups and replay entries; rate-limit audit output.
- Concurrent encryption: sequence allocation is atomic; a reserved number is burned after failure. Concurrent replay copies cannot both pass a check-and-mark.
- Restart/snapshot/fork/hot reload: invalidate all sessions and require a full handshake. Do not resume old session keys or token mappings.
- MTU/PMTU: calculate overhead from outer IPv6/UDP, NLS common header, hop plaintext, AEAD tag and destination envelope. Honor ICMPv6 Packet Too Big and define the maximum inner packet size; fragmentation is not the normal path.
- Telemetry must not include private keys, traffic keys, cookie secrets, full decrypted protected packets, or unvalidated fields represented as authenticated identity.

## 9. Repository/component impact matrix

| Component | Phase A change | Phase B change | Gate |
|---|---|---|---|
| `pkg/proto` (shared v2 framing, status, AEAD, hop codec, cookie) | Consume strict codecs and shared golden fixtures | Reuse identical codecs for control traffic | Exact positive/negative vectors, parser/property/fuzz tests |
| NetOS router daemon | Bounded session manager, UDP/socket loop, then TUN, route policy and fail-closed classifier | Protocol-specific routing traffic binding/encapsulation | Unit and race tests, resource caps, six-node then ten-router lab |
| NexOS Core Router-CA/registry/directory | Issue/serve canonical status/endpoint evidence and negotiate v2 control capability where used | Routing-policy/peer-role policy extensions | Real-CA certificate/status/revocation and rollback tests |
| Linux kernel/netlink/route policy | Dedicated TUN, scoped routes, MTU, policy routing, firewall and loop prevention | Per-protocol route mapping where explicitly approved | Reboot/route change/PMTU/no-plaintext-leak tests |
| FRR OSPF/BGP/RIP | No wire changes; underlay reachability only | Separate, protocol-specific integration and convergence tests | Do not conflate route state with trust |
| Systemd/config/CLI | Least-privilege service, permissions, explicit endpoint/prefix/limit config, safe restart | Protocol toggles and peer-policy config | Invalid-config/failure/startup tests |
| CI/lab/performance | Shared fixtures, Go/Python cross-checks, fuzz/race/unit tests, six-node functional IPv6 lab | Ten-router IPv6/FRR, route convergence, control-protocol tests | Functional gates precede separate performance gates |

## 10. Required acceptance gates

1. Independently review and freeze the adjacent-hop handshake/wire, destination handshake/envelope, Router-CA status and lifecycle contracts without changing v1.
2. Commit shared fixtures for every handshake, signature/transcript, cookie, HKDF output, nonce/AAD, AEAD framing, status/endpoint binding, replay, length error and negative policy case. Both repositories must consume identical fixture bytes.
3. Pass formatting, build, test, lint, race/concurrency and parser/fuzz gates in both repositories. Record the exact commit and successful CI run.
4. Implement and test the bounded in-memory adjacent and destination session managers; KEY_UPDATE remains unsupported until separately specified.
5. Integrate UDP/socket shim, then TUN and policy routes. Test fail-closed behavior, return path, MTU/PMTU, route changes and no plaintext egress.
6. Pass six-node functional IPv6 topology tests; then ten-router IPv6/FRR integration tests, including reboot/revocation, CA outage, resource exhaustion, route convergence and asymmetric return paths.
7. Run performance gates separately with reproducible hardware/software, workload, packet size, throughput, latency, CPU, memory and loss measurements.
8. Obtain independent cryptographic/protocol review before production claims or non-draft release.

## 11. Attacker-perspective critique

The outer relay IPv6 addresses, UDP ports, packet length, timing and traffic volume remain visible and can reveal communication patterns. A compromised authorized relay can observe adjacent-hop information, selectively drop/delay/reorder traffic, or attempt to forward toward an unauthorized next hop. The Router-CA is a trust root; its compromise can enable malicious identity/status issuance. An attacker can flood INIT and status/control endpoints, exhaust bounded resources, exploit parser discrepancies, or force path-MTU failures. Replay/restart bugs could cause nonce reuse or duplicate delivery if the lifecycle invariants are not implemented correctly. Destination endpoint compromise exposes inner traffic at that endpoint. These risks are reasons for the listed tests, not evidence that they have already passed.

## 12. Change record

This document consolidates the A1/B1 workflow and integration choice. It is a design/integration plan; it does not itself implement the live session manager, UDP forwarding loop, TUN plumbing, native routing-protocol integration, or the six-/ten-router labs. NLS v1 behavior remains unchanged.
