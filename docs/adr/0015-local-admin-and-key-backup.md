# ADR-0015: Local administration and CA key backup
- Status: Accepted
- Date: 2026-10-19
- Decision: local CLI only; CA private key encrypted at rest with Argon2id; encrypted export/import is the supported backup path. CA rotation and multi-node HA are out of scope for v0.1.1.
- Rationale: small, auditable administrative surface for initial version.
- Alternative rejected: remote admin API, unencrypted key file, or HA scope in initial release.
- Consequence: encrypted container must be versioned and parameter-capped; proposed Argon2id defaults are memory 64 MiB, 3 iterations, parallelism 1; export uses AES-256-GCM. See PROTOCOL.md §Objections / Open and THREAT_MODEL.md.