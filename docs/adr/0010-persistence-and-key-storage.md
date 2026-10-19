# ADR-0010: Persistence/key storage
- Status: Proposed.
- Decision: Core uses bbolt for registry/revocation/audit metadata; CA key separate, root-owned 0600 in 0700 directory, preferably encrypted at rest. NetOS keys root-owned 0600 under 0700 /var/lib/nls/keys.
- Rationale: simple single-node storage and separate secret boundary.
- Alternative rejected: storing private keys in DB or requiring external DB service.
- Consequence: backup/HA and unlock-key lifecycle need owner decisions; permission checks fail closed.