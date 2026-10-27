# ADR-0016: Per-hop source-locator protection and v2 wire boundary

- Status: **Proposed**
- Date: 2026-10-27
- Owners: NLS NetOS and NexOS Core maintainers
- Related: `docs/PROTOCOL.md`, `docs/PROTOCOL_FREEZE.md`, `docs/THREAT_MODEL.md`, `docs/SPEC_ERRATA.md`

## Context

The product workflow requires each relay to recover authenticated previous-hop locator metadata, replace it with its own relay identity/locator, and re-protect that metadata for the next relay. The current v0.1.1 frozen protocol instead encrypts the complete inner IP packet end-to-end and does not specify this per-hop metadata transformation. The current freeze checklist explicitly requires a wire-version bump and new ADR for any wire change.

The workflow also describes encrypting the IPv6 source address itself. That is not possible in place while relying on ordinary IPv6 forwarding: outer source/destination addresses must remain routable. Source-locator privacy must therefore be provided by an encrypted NLS envelope, while the outer header identifies the current relay and next relay.

## Decision proposed

1. Keep v0.1.1 wire version 1 frozen and unchanged.
2. Specify a separately versioned v2 contract before implementation. The exact version byte is to be allocated in the normative v2 protocol after compatibility review.
3. Keep the outer IPv6 source/destination routable. Put protected previous-hop locator/identity metadata inside a per-hop authenticated-encryption envelope.
4. Separate adjacent-hop keys from destination-protection keys. Establish directional adjacent-hop keys using authenticated ephemeral X25519 and HKDF-SHA-256; use a standard AEAD such as AES-256-GCM with strict nonce uniqueness and replay protection.
5. Keep router identity/signing keys separate from bulk traffic keys. Do not use a static public key as a packet-by-packet data cipher.
6. Treat the full inner IP packet as a separate protection layer when destination confidentiality is required. The relay must not receive plaintext application data merely to rewrite hop metadata.
7. Use the TUN/socket-shim path as the initial routing integration. Native OSPF/BGP/RIP integration remains a separately specified feature; the data protocol alone does not secure routing control traffic.
8. Preserve fail-closed behavior for PROTECT traffic. No automatic plaintext fallback or silent downgrade.
9. Require synchronized protocol docs, threat model, golden test vectors, and independent security review before implementation starts.

## Alternatives considered

- **Encrypt the outer IPv6 source field directly:** rejected; ordinary IPv6 forwarding requires a routable outer header.
- **Use the next-hop public key for every packet:** rejected as the default data-plane mechanism; authenticated key agreement plus directional symmetric AEAD is the proposed design.
- **Treat the existing v1 packet format as per-hop protected:** rejected; that would silently change a frozen wire contract and break interoperability.
- **Modify OSPF/BGP/RIP immediately:** deferred; tunnel/interface behavior, control-plane packet semantics, and convergence require their own design and lab validation.
- **Allow plaintext fallback when negotiation fails:** rejected for PROTECT traffic because it violates the confidentiality invariant.

## Consequences

- A v2 protocol specification and new freeze checklist are required.
- Core must own canonical wire definitions, handshake/key-schedule rules and golden vectors; NetOS must implement relay processing, hop sessions, replay windows and forwarding.
- The threat model must explicitly cover malicious relays, traffic analysis, route manipulation, metadata leakage, replay, downgrade, key compromise, CA compromise/outage, MTU and denial of service.
- Existing v1 deployments remain v1 until a separately reviewed migration path is accepted.
- Outer relay addresses, timing, packet sizes and traffic volume remain observable; the design does not provide complete traffic-analysis resistance.
- This ADR does not authorize production claims. The bespoke handshake requires independent cryptographic review.

## Acceptance criteria

- [ ] A normative v2 wire format exists in both repositories with identical fields, sizes, byte order, limits and error behavior.
- [ ] Version negotiation and downgrade resistance are transcript-bound and tested.
- [ ] Golden vectors cover framing, AEAD, key derivation, replay and rekey.
- [ ] Intermediate relays cannot read original client/server addresses or protected application payload.
- [ ] Every hop can authenticate the previous relay and protect updated hop metadata for the next relay.
- [ ] Outer IPv6 headers remain routable and reflect current/next relay WAN endpoints.
- [ ] Return path, Router-CA access, revocation, control loss and fail-closed behavior are specified.
- [ ] TUN integration and routing-protocol behavior pass multi-router tests.
- [ ] Independent security review is completed before production deployment.
