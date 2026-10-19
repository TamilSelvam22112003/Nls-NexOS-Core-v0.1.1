# ADR-0014: Protected routing fail-closed
- Status: Accepted
- Date: 2026-10-19
- Decision: policy prefixes are installed as routes through TUN nls0; each is PROTECT or BYPASS. Missing directory, policy or session state drops PROTECT traffic; never plaintext fallback.
- Rationale: fail-closed confidentiality invariant.
- Alternative rejected: automatic plaintext fallback for availability.
- Consequence: policy install is atomic and explicit BYPASS is the only non-protected route. See PROTOCOL.md §4.