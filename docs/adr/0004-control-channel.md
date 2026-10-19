# ADR-0004: Control channel and enrollment bootstrap
- Status: Accepted
- Date: 2026-10-19
- Decision: TLS 1.3. Enrollment bootstrap uses server-authenticated TLS, configured Router-CA root fingerprint pinning, and a single-use expiring token scoped to one router name and bound to SHA-256(CSR public key). mTLS begins only after certificate issuance. Thereafter X.509 Ed25519 certificate is used only for TLS control.
- Rationale: authenticated bootstrap without requiring a certificate that does not yet exist.
- Alternative rejected: require mTLS before issuance or use a custom unauthenticated enrollment transport.
- Consequence: token consumption must be atomic and tokens must never be logged. See PROTOCOL.md §3.