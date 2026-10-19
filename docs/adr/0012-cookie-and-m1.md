# ADR-0012: Stateless cookie and M1 framing
- Status: Accepted
- Date: 2026-10-19
- Decision: M1_INIT → M1_COOKIE → M1_INIT(cookie) → M2 → M3 → M4. M1 total framed size 128 bytes; M1_COOKIE 60 bytes. Cookie is address/nonce-bound HMAC, current/previous 10-minute bucket.
- Rationale: prove return reachability before allocating handshake state.
- Alternative rejected: state allocation on first unauthenticated M1.
- Consequence: retain prior cookie secret bucket and rate limit sources. See PROTOCOL.md §6.