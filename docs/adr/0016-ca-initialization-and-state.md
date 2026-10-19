# ADR-0016: CA initialization and durable local state

- Status: Accepted for the v0.1.1 bootstrap implementation
- Date: 2026-10-19

## Decision

Initialize a unique Ed25519 CA identity and trust registry, encrypt the private
key at rest using AES-256-GCM with an Argon2id-derived key (3 iterations,
64 MiB, one lane), and atomically persist a versioned state document. Persist
router registry and revocation state alongside enrollment metadata, policy,
and access controls. Restrict the state directory to mode 0700 and files to
0600. Store enrollment token digests, not plaintext tokens. Expose local admin
commands for initialization, enrollment credential creation, policy/access
configuration, and status.

## Readiness invariant

The CLI must print exactly `ready for enrollment` only after the encrypted
identity decrypts and matches the public identity, the CA identity is present
in the trust registry, all registries are structurally valid, an unexpired
unused enrollment credential exists, policy is configured, and enrollment
access is explicitly enabled. Any parse, integrity, or passphrase failure
returns a non-zero exit status and must not authorize enrollment.

## Consequences and limits

Initialization is intentionally not sufficient to enable enrollment. Operators
must configure credentials, policy, and access controls before readiness.
Wrong passphrases fail AES-GCM authentication; no plaintext-key fallback exists.
The current milestone implements durable local state only: token redemption,
router certificate issuance, network service, audit-chain integrity, CA
rotation, and HA remain separate work. This ADR does not claim production
readiness or replace independent cryptographic review.
