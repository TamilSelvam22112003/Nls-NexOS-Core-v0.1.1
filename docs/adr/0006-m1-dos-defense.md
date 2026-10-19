# ADR-0006: Stateless M1 defense
- Status: Accepted
- Date: 2026-10-19
- Decision: always issue stateless address-bound HMAC cookie before allocating handshake state. M1 padded to 128 bytes; M1_COOKIE 60 bytes. Accept current/previous 10-minute bucket.
- Rationale: reachability proof before allocating state, with no response larger than request.
- Alternative rejected: state allocation on unauthenticated first M1.
- Consequence: cookie rotation and source rate limits required. See PROTOCOL.md §6.