# ADR-0012: Stateless cookie and M1 framing

- Status: Accepted for pre-release v1-rc2; not yet released.
- Date: 2026-10-19
- Decision: M1_INIT → M1_COOKIE → M1_INIT(cookie) → M2 → M3 → M4. M1 total framed size 128 bytes; M1_COOKIE 60 bytes. Cookie is an address/nonce-bound HMAC using 60-second time buckets; accept current and previous bucket only (maximum age less than 120 seconds).
- Rationale: prove return reachability before allocating handshake state while limiting cookie lifetime.
- Alternative rejected: state allocation on first unauthenticated M1; long-lived cookie buckets.
- Consequence: rotate the cookie secret every 60 seconds and retain the immediately previous secret for validation of the previous bucket. See PROTOCOL.md §6 and SPEC_ERRATA.md E-003.
