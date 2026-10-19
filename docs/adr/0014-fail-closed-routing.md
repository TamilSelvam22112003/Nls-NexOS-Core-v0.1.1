# ADR-0014: Protected routing fail-closed
- Status: Accepted
- Date: 2026-10-19
- Decision: policy prefixes route through TUN nls0; each is PROTECT or BYPASS. Missing directory, policy or session drops PROTECT traffic; never plaintext fallback.
- Rationale: confidentiality invariant.
- Alternative rejected: plaintext fallback for availability.
- Consequence: policy install atomic; explicit BYPASS only. See PROTOCOL.md §4.