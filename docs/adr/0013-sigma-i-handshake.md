# ADR-0013: SIGMA-I-style handshake
- Status: Accepted
- Date: 2026-10-19
- Decision: SIGMA-I is the design model: ephemeral X25519, transcript hash, HKDF-SHA256, encrypted identities, Ed25519 transcript signatures and independent directional keys. This custom wire encoding is not claimed to be wire-compatible with Noise or a formally verified SIGMA implementation.
- Rationale: identity protection and mutual authentication while preserving RDR-based identity.
- Alternative rejected: invent a novel unnamed handshake or claim Noise compatibility without matching a published pattern exactly.
- Consequence: independent cryptographic review is a pre-implementation gate; deviations are enumerated in PROTOCOL.md §6. The DH output is one 32-byte shared secret, not duplicate concatenation.