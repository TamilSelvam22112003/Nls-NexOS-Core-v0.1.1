# ADR-0015: Local administration and CA key backup
- Status: Accepted
- Date: 2026-10-19
- Decision: local CLI only; CA key encrypted at rest with Argon2id; encrypted export/import is backup path. CA rotation and multi-node HA out of scope for v0.1.1.
- Rationale: small auditable initial administrative surface.
- Alternative rejected: remote admin API, plaintext key or HA in initial release.
- Consequence: proposed Argon2id defaults 64 MiB, 3 iterations, parallelism 1; export uses AES-256-GCM with authenticated metadata. Container needs version and resource caps. See PROTOCOL.md Objections/Open.