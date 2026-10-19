# ADR-0002: Cryptographic suite
- Status: Proposed.
- Decision: Ed25519, X25519, HKDF-SHA256, AES-256-GCM; Go stdlib and x/crypto only where needed.
- Rationale: standard reviewed primitives, no custom crypto.
- Alternative rejected: RSA key exchange or home-grown suite, for complexity and attack surface.
- Consequence: fixed suite 1, domain separation, transcript binding and nonce uniqueness mandatory.