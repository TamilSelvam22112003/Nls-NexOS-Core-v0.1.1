# ADR-0006: Stateless M1 defense
- Status: Proposed.
- Decision: 16-byte truncated HMAC-SHA256 cookie over source/destination IPv6+ports, router ID and 10-minute bucket; echo cookie before allocating state; accept current/previous bucket.
- Rationale: proves return reachability before state allocation.
- Alternative rejected: allocate pending state on first M1, vulnerable to spoofed-source exhaustion.
- Consequence: global/per-source-prefix rate limits; owner must approve added challenge/echo flight.