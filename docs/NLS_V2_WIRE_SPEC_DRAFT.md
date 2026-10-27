# NLS v2 Wire Specification — Draft for Review

**Status:** Proposed; not frozen; not an implementation contract yet  
**Protocol version:** 2  
**Scope:** Router-to-router NLS data-plane envelope and minimum demultiplexing header  
**Compatibility:** NLS v1 remains unchanged. A v1 peer MUST NOT interpret v2 packets as v1.  
**Decision defaults used for this draft:** A1 — TUN/socket shim first; B1 — random short-lived opaque first-contact token; outer IPv6 addresses remain routable.

> This document is a concrete review draft, not evidence of a completed or secure implementation. Do not deploy it on production networks. The wire format, cryptographic transcript, certificate profile, and key lifecycle require independent review and golden-vector tests before implementation is declared stable.

## 1. Core forwarding invariant

The IPv6 source and destination fields are **not encrypted in place**. Ordinary IPv6 forwarding requires routable outer addresses. Every NLS datagram therefore uses:

- Outer IPv6 source: current transmitting NLS relay's routable WAN address.
- Outer IPv6 destination: next NLS relay's routable WAN address.
- UDP ports: configured NLS transport ports.
- Clear NLS framing: only fields needed for versioning, session demultiplexing, nonce construction, bounded parsing, and replay handling.
- Encrypted hop envelope: protected previous-hop locator/identity metadata plus the destination-protected inner packet.
- Inner packet: client/server addresses, transport metadata, and payload remain protected from transit relays by a separate destination-scoped protection layer, if end-to-end protection is enabled.

The next relay authenticates and decrypts only the hop envelope addressed to it. It validates the adjacent peer and session, then creates a new hop envelope under the next hop's independent directional key. It MUST NOT decrypt or rewrite destination-protected inner content.

**Visibility limitation:** The transit network can still observe outer relay addresses, UDP ports, packet lengths, timing, packet volume, and traffic patterns. The immediate receiving relay can observe the previous relay's outer IPv6 source address. This design does not hide those fields from ordinary IP forwarding infrastructure.

## 2. Fixed clear header

All multi-byte integers use network byte order (big-endian). The UDP payload starts with this 44-byte header. Implementations MUST reject a truncated header, unsupported version/type, nonzero reserved fields, invalid lengths, and trailing bytes not accounted for by the selected packet type.

| Offset | Size | Field | Requirement |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `NLS2` (hex `4e 4c 53 32`) |
| 4 | 1 | version | `0x02` |
| 5 | 1 | packet_type | `0x01` DATA; `0x02` CONTROL; other values rejected until specified |
| 6 | 2 | flags | Defined bits only; all currently reserved bits MUST be zero |
| 8 | 2 | header_length | `44` |
| 10 | 2 | reserved | MUST be zero |
| 12 | 16 | session_token | Random opaque session demultiplexing token; not an IP address or an authentication credential by itself |
| 28 | 4 | key_epoch | Unsigned key epoch negotiated for this directional session |
| 32 | 8 | sequence_number | Unsigned monotonically increasing per-direction sequence number |
| 40 | 4 | ciphertext_length | Number of bytes following the header, including the 16-byte AEAD tag |

For DATA, ciphertext_length MUST be at least 16 bytes (the AEAD tag) plus the minimum encoded inner-envelope length defined in Section 4. A receiver MUST enforce a configured maximum datagram size before allocating or decrypting. The UDP payload length MUST equal 44 + ciphertext_length exactly.

### 2.1 Nonce construction and replay

For AES-256-GCM, construct the 96-bit nonce as:

`nonce = uint32_be(key_epoch) || uint64_be(sequence_number)`

This is safe only if each directional AEAD key is unique to one sender direction and the pair (key_epoch, sequence_number) is never reused under that key. A sender MUST persist or safely rotate key material before sequence wrap or process restart could repeat a nonce. Sequence numbers MUST NOT wrap. Key rotation MUST derive a new directional key and increment the epoch under an authenticated key-update procedure; key update messages are not yet specified here and are an implementation blocker.

The receiver maintains a bounded sliding replay window per session and direction. It MUST authenticate the AEAD tag before committing a packet as accepted. Duplicate, too-old, malformed, or unauthenticated packets are dropped. A receiver MUST NOT advance replay state based only on unauthenticated header fields.

### 2.2 AEAD associated data

The exact 44 header bytes, the outer IPv6 source and destination addresses, and the UDP source and destination ports are authenticated as AEAD associated data. Each relay rewraps the packet, so the new hop's outer fields and header are authenticated with the new hop key. Header values are parsed and bounded before use but are not trusted until authentication succeeds.

## 3. Hop key establishment

Each adjacent router pair establishes **independent directional keys** after mutual authentication. Proposed cryptographic roles:

- Ed25519: router identity signatures.
- Ephemeral X25519: authenticated ephemeral key agreement.
- HKDF-SHA-256: derive distinct directional AES-256-GCM keys and session binding values from the shared secret and authenticated transcript.
- AES-256-GCM: per-hop envelope confidentiality and integrity.

The signed transcript MUST bind protocol version, both router identities, both advertised WAN endpoints, both ephemeral public keys, the handshake nonces, negotiated algorithms, and the intended session/token. Directional keys MUST differ. Public-key possession alone does not establish that an IP address belongs to that router; the Router-CA certificate and signed endpoint binding must be validated.

RSA key pairs are not required by this draft. Do not create two RSA pairs without a defined interoperable role. Certificate encoding/profile, handshake message bytes, KDF context labels, transcript hashing, cookie format, and key-update format remain open prerequisites and are intentionally not invented here.

## 4. Encrypted hop plaintext

After AEAD decryption, DATA plaintext contains the following canonical structure. All lengths are unsigned big-endian. Unknown fields are rejected in version 2; duplicate fields are rejected. This section defines the field sequence for review but does not yet freeze a TLV extensibility mechanism.

| Order | Field | Encoding / rule |
|---:|---|---|
| 1 | inner_kind | 1 byte: `0x01` destination-protected IP packet; other values rejected |
| 2 | previous_hop_identity_length | uint16; 1–1024 bytes |
| 3 | previous_hop_identity | Exact certificate identity reference or canonical router identifier; certificate itself is not repeated here |
| 4 | previous_hop_locator_length | uint16; exactly 16 bytes for IPv6 |
| 5 | previous_hop_locator | IPv6 address of the transmitting NLS relay, checked against authenticated peer policy |
| 6 | inner_envelope_length | uint32; exact byte length of the following inner envelope |
| 7 | inner_envelope | Destination-protected inner packet/envelope; opaque to transit relays |

The inner envelope MUST protect the original client/source address, destination/server address, transport metadata that is not required by the transit path, and application payload according to the separately specified destination-protection profile. Transit relays MUST NOT receive a destination private key merely to forward packets. The destination-protection profile and its key-establishment mechanism are not defined by this document and must be specified before implementation.

The receiver MUST check every length with overflow-safe arithmetic, reject truncated or trailing bytes, validate that the previous-hop identity/locator match the authenticated adjacent session, and drop failures without forwarding.

## 5. Relay forwarding procedure

1. Receive UDP on the configured NLS port; validate outer destination/local endpoint and fixed header bounds.
2. Look up the opaque session token in a bounded session table. Unknown tokens do not trigger an unbounded allocation or a large response.
3. Check version, header length, packet type, epoch, and ciphertext length. Apply per-interface and per-source-prefix rate limits.
4. Authenticate and decrypt using the session's inbound directional key and nonce.
5. Validate replay window, peer identity, previous-hop locator, session state, and policy. On any failure, drop and emit a rate-limited audit event; do not install routes or trust state.
6. Validate the inner-envelope length and forwarding policy. The relay does not decrypt the destination-protected inner content.
7. Select the next hop from the approved forwarding decision and an authenticated adjacent session.
8. Allocate the next direction's sequence number; build a fresh header/token/epoch; construct a fresh nonce; encrypt the hop plaintext under the next hop's outbound key with the correct AAD.
9. Send with the next relay's routable outer IPv6 address and configured UDP port. Enforce MTU/PMTU policy and handle ICMPv6 Packet Too Big according to the implementation's network-stack design.

A relay MUST NOT change an IPv6 source address to a fabricated value that ordinary forwarding cannot route. The outer source is the actual transmitting relay's routable address; the protected previous-hop locator is inside the authenticated encrypted envelope.

## 6. First contact and Router-CA lookup

The first-contact token is a cryptographically random 128-bit opaque value with a short, configured lifetime. It is a demultiplexing/correlation value, **not** a routable IPv6 address and not proof of identity. The return path uses a routable endpoint and an authenticated transport connection to the Router-CA; the CA must not be expected to route replies to an arbitrary token.

Before accepting trust, each router validates the peer certificate chain to a pinned Router-CA trust anchor, endpoint binding, validity period, revocation/status freshness, protocol version, and signed handshake transcript. A router MUST NOT add a peer to the Trust Table or install routes solely because it received a public key or a self-asserted IP address.

First-contact anti-DoS requirements: bounded pending-handshake table, stateless cookie/challenge before expensive work where applicable, global/interface/source-prefix rate limits, bounded message sizes and concurrency, anti-amplification, and rate-limited logs. CA outage policy must distinguish new sessions from established sessions; this draft recommends failing closed for new protected sessions and using only an explicitly configured, bounded stale-status interval for existing sessions.

## 7. Routing integration decision

**Initial implementation path: TUN/socket shim.** Carry NLS datagrams between routers without modifying OSPF, BGP, RIP/RIPng packet formats or claiming that those protocols are automatically protected. Keep the existing routing daemon responsible for ordinary route computation. The shim's route selection and adjacency binding must be explicit and must not infer cryptographic trust from an OSPF LSDB entry.

Native routing-protocol integration is a later, separate workstream requiring protocol-specific designs and interoperability tests. OSPF/OSPFv3, BGP, RIP/RIPng, default routes, ICMPv6, uRPF, ACLs, NAT, diagnostics, and MTU behavior are not interchangeable; each requires its own impact and test plan. Do not advertise an NLS-protected adjacency until mutual authentication and policy checks succeed.

## 8. Table separation

- **VIP/pending table:** temporary opaque token, creation/expiry time, handshake state, bounded peer hints, and rate-limit/accounting data. Never treat a token as an IP address or as authenticated identity.
- **Trust table:** validated router identity, certificate fingerprint, authenticated endpoint bindings, status/revocation generation, policy, and permitted capabilities. Session keys should live in a protected session/key store, not in a general-purpose printable table.
- **Session/replay state:** session token, peer identity, directional key references, epoch, inbound replay window, outbound sequence counter, expiry, and lifecycle state.
- **LSDB:** remains the routing protocol's link-state database. Cryptographic trust is a separate predicate; LSDB presence alone MUST NOT create trust.

## 9. Failure behavior

Malformed, unauthenticated, replayed, wrong-peer, stale/revoked, unsupported-version, or policy-denied packets are dropped. They MUST NOT cause route installation, Trust Table promotion, or unbounded work. Record bounded counters and rate-limited audit events. Quarantine, Router-CA notification, and operator alerting are policy extensions and require defined limits before implementation.

## 10. MTU and traffic analysis

The 44-byte NLS header, UDP header, outer IPv6 header, AEAD tag, hop plaintext fields, and inner envelope all contribute to packet size. The implementation MUST calculate overhead from actual encodings, avoid fragmentation assumptions, honor IPv6 PMTU/ICMPv6 Packet Too Big, and define a maximum inner packet size. Functional tests and performance tests must be separate. Packet length, timing, volume, and outer relay endpoints remain observable; padding is not specified in this draft.

## 11. Required acceptance gates before code is treated as interoperable

1. Freeze all message encodings, certificate/endpoint profile, handshake transcript, HKDF labels, cookie and key-update formats, inner-envelope profile, and failure codes.
2. Produce cross-repository golden byte vectors for every message and header field.
3. Unit tests: malformed lengths, unknown flags/types, reserved bits, wrong AAD, tag tamper, wrong neighbor, duplicate/out-of-window replay, epoch mismatch, sequence persistence/restart, expired token, token collision handling, stale/revoked certificate, version downgrade, and parser fuzzing.
4. Integration tests: CA outage/recovery, router restart, concurrent handshakes, table exhaustion, rate limits, wrong endpoint binding, six-node functional lab, and ten-router IPv6/FRR lab.
5. Network tests: no unintended plaintext leakage, MTU/PMTU and ICMPv6 behavior, routing convergence, packet loss/reordering, and return path.
6. Separate reproducible performance gates with declared hardware/software versions and workload; no throughput claim without recorded measurements.
7. Independent cryptographic and protocol review. Keep v1 frozen; no automatic v1 fallback after a v2 authentication failure.

## 12. Explicit unresolved blockers

- Exact handshake/control packet formats and state machine.
- Certificate profile, endpoint binding, revocation freshness, and Router-CA transport.
- Stateless cookie construction and anti-amplification limits.
- Inner destination-protection wire format and key management.
- Authenticated key update and restart-safe nonce/sequence persistence strategy.
- Canonical identity encoding, field encoding rules, error codes, and maximum sizes.
- TUN addressing/routing policy, loop prevention, return routing, ICMPv6/PMTU, and interaction with firewall/uRPF/NAT.
- How routing adjacency is bound to authenticated NLS peer state without treating LSDB state as trust.

**Review request:** Review this draft as a proposal. It must not be called a frozen specification or production-ready protocol until the blockers above are resolved and the acceptance gates pass.
