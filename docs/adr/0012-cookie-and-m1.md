# ADR-0012: Stateless cookie and M1 framing
- Status: Accepted
- Date: 2026-10-19
- Decision: every handshake uses M1_INIT → M1_COOKIE → M1_INIT(cookie) → M2 → M3 → M4. M1 is padded to 128 bytes including framing; M1_COOKIE is 60 bytes, so it cannot amplify packet size. Cookie is source/destination tuple- and nonce-bound HMAC, accepted for current/previous 10-minute bucket.
- Rationale: prove return reachability before allocating handshake state.
- Alternative rejected: allocate state on first unauthenticated M1.
- Consequence: cookie secrets rotate with one prior bucket retained; source-prefix rate limits still required. See PROTOCOL.md §6.