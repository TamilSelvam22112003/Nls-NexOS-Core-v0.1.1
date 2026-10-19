# ADR-0011: Enrollment bootstrap
- Status: Accepted
- Date: 2026-10-19
- Decision: server-authenticated TLS with pinned CA root fingerprint; single-use token expires within 10 minutes, scoped to one router name and bound to SHA-256 of CSR Ed25519 public key. mTLS begins after issuance.
- Rationale: secure enrollment without a pre-existing client certificate.
- Alternative rejected: unbound bearer token or pre-issue mTLS.
- Consequence: atomic redemption and audit redaction. See PROTOCOL.md §3.