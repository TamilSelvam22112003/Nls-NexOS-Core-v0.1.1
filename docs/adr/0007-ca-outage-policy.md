# ADR-0007: CA outage/cache
- Status: Accepted
- Date: 2026-10-19
- Decision: fail closed for new handshakes when online CA lookup fails; RDR cache TTL 300s does not authorize a new handshake. Revocation push tears down affected sessions within 30s; control loss over 300s drops existing sessions. These three thresholds are configurable with stated defaults.
- Rationale: prioritize authorization freshness over availability.
- Alternative rejected: new handshakes from stale cache.
- Consequence: CA/control outages can interrupt protected traffic. See PROTOCOL.md §§4, 12.