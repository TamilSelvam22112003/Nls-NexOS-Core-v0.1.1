# ADR-0013: SIGMA-I-style handshake
- Status: Accepted
- Date: 2026-10-19
- Decision: SIGMA-I is the design model: ephemeral X25519, transcript hash, HKDF-SHA256, encrypted identities, Ed25519 transcript signatures and directional keys. This bespoke encoding is not wire-compatible with Noise nor formally verified SIGMA.
- Rationale: identity protection and mutual authentication with RDR identities.
- Alternative rejected: unnamed novel handshake or unsupported Noise compatibility claim.
- Consequence: independent cryptographic review before implementation; one DH shared secret, not duplicate concatenation. See PROTOCOL.md §6.