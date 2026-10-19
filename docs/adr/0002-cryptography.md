# ADR-0002: Cryptographic suite
- Status: Accepted
- Date: 2026-10-19
- Decision: Ed25519, X25519, HKDF-SHA256 and AES-256-GCM; Go stdlib and x/crypto only where needed.
- Rationale: reviewed standard primitives and no custom crypto.
- Alternative rejected: custom primitives or larger suite complexity.
- Consequence: suite 1 fixed; transcript binding and nonce uniqueness mandatory. See PROTOCOL.md §§1,7.