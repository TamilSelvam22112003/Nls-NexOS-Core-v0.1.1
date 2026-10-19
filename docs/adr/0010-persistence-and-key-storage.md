# ADR-0010: Persistence and key storage
- Status: Accepted
- Date: 2026-10-19
- Decision: Core uses bbolt for registry/revocation/audit metadata. CA private key is separately encrypted at rest using Argon2id; root-only directory mode 0700 and key file mode 0600. NetOS keys are root-owned mode 0600 in mode-0700 /var/lib/nls/keys.
- Rationale: single-node initial deployment with separation of data store and signing key.
- Alternative rejected: private keys stored in DB or mandatory external database.
- Consequence: encrypted key and export formats must be versioned and resource-capped. Proposed Argon2id defaults: 64 MiB, 3 iterations, parallelism 1; export uses AES-256-GCM with authenticated metadata. See PROTOCOL.md Objections/Open.