# ADR-0007: CA outage/cache
- Status: Accepted
- Date: 2026-10-19
- Decision: fail closed for new handshakes if online CA lookup fails; RDR cache TTL 300s does not authorize new handshake. Revocation push tears down affected sessions within 30s; control loss >300s drops existing sessions. Values configurable.
- Rationale: authorization freshness over availability.
- Alternative rejected: new handshakes from stale cache.
- Consequence: CA/control outages can interrupt protected traffic. See PROTOCOL.md §§4,12.