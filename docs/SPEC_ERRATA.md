# NLS Wire-Protocol Errata Proposal: Per-Hop Source-Locator Protection

- Status: **Proposed; not a frozen contract**
- Target: NLS v0.1.2 or a separately versioned wire protocol after review
- Applies to: NetOS router agent and NexOS Core control plane
- Supersedes: nothing until accepted and the wire version is formally bumped
- Security status: **not production-approved; independent protocol review required**

## 1. Purpose and scope

The NLS workflow requires each adjacent relay to authenticate the previous relay, recover its protected source locator from an authenticated hop envelope, replace that locator with its own authenticated locator, and protect the updated metadata for the next relay. The original client/server IP packet and application payload remain confidential to the intended destination security endpoint.

This proposal resolves a mismatch in the current v0.1.1 frozen contract, which encrypts the complete inner IP packet end-to-end and does not define the per-hop source-locator transformation described above.

This is a documentation proposal only. It does not change the v0.1.1 wire contract or imply that code implements this behavior.

## 2. Non-negotiable networking constraint

An IPv6 source address in the outer IP header cannot be encrypted in place while still being used by ordinary IP forwarding. Transit routers need routable outer source/destination headers for packet delivery and operational functions. Therefore:

- The outer IPv6 source remains the current NLS relay's routable WAN address.
- The outer IPv6 destination remains the next relay's routable WAN address (or the configured destination relay when the path is direct).
- The outer UDP ports and minimum NLS framing remain visible.
- The previous relay's protected source locator/identity is carried inside the encrypted hop envelope, not substituted into the outer IPv6 source field.
- Each relay authenticates/decrypts the hop envelope addressed to it, validates the previous relay against the established adjacent-hop security association, updates the protected source-locator metadata, and encrypts a new envelope for the next hop.
- The inner packet's original source/destination IP addresses and transport/application contents are protected separately for the destination security endpoint.

Consequently, NLS can hide the original client address and per-hop locator metadata from passive transit observers, but it does not hide the routable outer relay addresses, packet timing, packet lengths, traffic volume, or visible transport framing. Any claim of hiding the outer IPv6 source itself is incorrect unless a different routable encapsulation/addressing design is specified.

## 3. Proposed packet layering

A candidate v2 datagram is:

1. Outer IPv6 header: current relay WAN address → next relay WAN address.
2. UDP transport header: configured NLS relay ports.
3. Versioned NLS common framing: wire version, message type, bounded length, flags/reserved fields, and opaque session/demultiplexing token as needed.
4. Per-hop AEAD envelope, encrypted under a directional adjacent-relay traffic key. Authenticated associated data includes the immutable outer-independent framing fields and session/epoch identifiers. The envelope carries:
   - authenticated previous-relay identity/locator metadata;
   - the intended next-hop/session context;
   - hop sequence number and epoch as required by the chosen encoding;
   - the destination-protected inner packet or its ciphertext;
   - no unnecessary cleartext original client/server address.
5. Inner packet protection: the entire original IP packet (including original source/destination, transport headers and payload) is protected to the destination security endpoint where the deployment's trust model requires end-to-end confidentiality.

The exact binary offsets, maximum lengths, cryptographic transcript, nonce construction, error codes, and canonical encodings must be specified in the v2 protocol document before implementation. Do not reuse v1 framing or silently reinterpret a v1 message as v2.

## 4. Key roles and cryptographic construction

- Router-CA identity keys authenticate router enrollment and directory records; they are not packet-by-packet bulk-encryption keys.
- Use authenticated X25519 key agreement to establish an adjacent-relay security association, with HKDF-SHA-256 deriving independent directional keys and nonce material.
- Use AES-256-GCM (or another independently reviewed standard AEAD selected in the frozen suite) for hop-envelope confidentiality and integrity.
- Use distinct keys and domain-separated derivation labels for each direction, purpose, session and key epoch. Never reuse an AEAD nonce under the same key.
- The inner destination-protection key is distinct from the adjacent-hop key. It must be established and rotated under an explicitly defined destination-session protocol; it must not be assumed that a router's static public key directly encrypts arbitrary IP packets.
- Ed25519 identity signatures may authenticate the handshake/transcript; they do not replace key agreement or AEAD.
- Reject invalid peer identity, invalid certificate/status, all-zero X25519 output, invalid authentication tags, replayed packets, unknown critical fields, malformed lengths and invalid state transitions before forwarding plaintext.

Using a recipient's asymmetric public key directly for every data packet is not the proposed data-plane design. Public-key cryptography authenticates/establishes session keys; symmetric AEAD protects packets efficiently and supports explicit replay/nonce controls.

## 5. Relay processing and trust

For each packet, a relay must:

1. Validate the outer destination, UDP port, common framing, version, bounded length, session identifier and key epoch.
2. Resolve the incoming adjacent-hop security association and enforce ingress/interface policy.
3. Check replay-window eligibility, but only commit replay state after successful AEAD authentication.
4. Authenticate/decrypt the hop envelope; release no plaintext on failure.
5. Validate that the authenticated previous-hop identity matches the security association and allowed adjacency.
6. Validate the destination/session/policy binding and the inner packet structure.
7. Apply routing/forwarding policy and select an authorized next hop.
8. Construct new hop metadata using its own authenticated relay identity/locator, allocate a fresh sequence/nonce, and protect the envelope with the next-hop directional key.
9. Forward using its own routable WAN address as the outer IPv6 source.

Missing trust, missing keys, invalid metadata, revoked peers, expired sessions, malformed packets or failed authentication MUST drop protected traffic. Never silently send the packet in plaintext.

## 6. Routing-protocol integration

NLS data-plane encapsulation does not automatically secure OSPF, OSPFv3, BGP, RIP, ICMP errors, or default-route exchange.

The initial implementation path should use a TUN/socket shim and explicit tunnel addressing so routing daemons operate over a defined logical interface. Routing adjacency and control packets must be carried through the protected channel or separately protected by a specifically reviewed integration. Do not rewrite OSPF packet source addresses to the outer NLS source address and claim that this preserves native OSPF semantics.

Native routing-daemon integration is a separate workstream. It must define neighbor discovery, router IDs, TTL/hop-limit behavior, multicast handling, MTU, ICMP/PMTUD, ACL/uRPF/NAT interaction, route recursion, failure detection and convergence.

## 7. Return path and Router-CA access

Replies must use an authenticated session/association mapping or a routable tunnel endpoint. A temporary vIP is not, by itself, an authentication credential or a guarantee of routability.

Router-CA lookups use the authenticated control channel and a known CA endpoint; they must not depend on a peer learning a hidden source address from an unauthenticated packet. The control plane must define request correlation, return routing, timeouts, replay protection, authorization, rate limits and behavior during CA unavailability.

## 8. Compatibility and downgrade

- v1 and proposed v2 are distinct wire versions.
- A v1 parser MUST NOT reinterpret v2 data; a v2 parser MUST NOT downgrade malformed v2 traffic to v1.
- Version negotiation must be authenticated and bind the negotiated version into the handshake transcript.
- Protected-prefix traffic must fail closed if no mutually supported secure version/session exists. Plaintext fallback is prohibited unless an operator explicitly configures a separate BYPASS prefix and the policy makes that exception visible.
- Rollout requires mixed-version behavior, downgrade tests, rollback instructions and a compatibility matrix.

## 9. Required security and interoperability tests

Before implementation can be considered complete, test at least:

- hop envelope tampering, truncation, trailing bytes and unknown critical fields;
- source-locator spoofing and mismatched adjacent-hop identity;
- replay, out-of-window sequence, nonce uniqueness and rekey boundary;
- cross-session/cross-direction/cross-epoch key separation;
- inner source/destination and payload confidentiality at intermediate relays;
- outer relay addresses remain routable and are correctly rewritten at each relay;
- invalid/revoked certificate, directory tampering, Router-CA outage and stale trust;
- vIP collision, expiry, reuse, and replay behavior;
- resource exhaustion, cookie/rate-limit behavior and bounded state;
- MTU, fragmentation avoidance, ICMP/PMTUD, IPv4 and IPv6 inner packets;
- multi-hop return path, route changes, failover and tunnel teardown;
- OSPFv2/OSPFv3/BGP/RIP behavior only for integrations explicitly implemented;
- version negotiation and downgrade resistance;
- reproducible build/install and six-node functional plus ten-router IPv6 lab tests.

## 10. Decision gate

Do not change code until both repositories agree on the same normative v2 contract, the threat model is updated, the wire format is independently reviewed, and test vectors are approved. After that, implement shared wire types and golden vectors in Core first, then NetOS packet/session handling, then routing integration. v0.1.1 remains the existing frozen contract until that gate is passed.
