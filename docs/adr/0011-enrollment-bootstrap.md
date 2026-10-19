# ADR-0011: Enrollment bootstrap
- Status: Accepted
- Date: 2026-10-19
- Decision: server-authenticated TLS with pinned CA root fingerprint; single-use token expiring within 10 minutes, scoped to one router name and bound to SHA-256 of CSR Ed25519 public key. mTLS starts after certificate issuance.
- Rationale: supports secure first enrollment without a pre-existing client certificate.
- Alternative rejected: pre-issue mTLS certificate or bearer token without CSR binding.
- Consequence: atomic token redemption and audit redaction are mandatory. See PROTOCOL.md §3.