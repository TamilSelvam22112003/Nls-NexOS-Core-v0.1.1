# ADR-0004: Control channel and enrollment bootstrap
- Status: Accepted
- Date: 2026-10-19
- Decision: TLS 1.3. Bootstrap uses server-authenticated TLS, configured Router-CA root fingerprint pinning, and single-use expiring token scoped to router name and bound to SHA-256(CSR public key). mTLS begins only after certificate issuance. X.509 is only for control TLS.
- Rationale: secure first enrollment without a pre-existing client certificate.
- Alternative rejected: require mTLS before issuance or custom unauthenticated enrollment.
- Consequence: atomic token consumption; never log tokens. See PROTOCOL.md §3.