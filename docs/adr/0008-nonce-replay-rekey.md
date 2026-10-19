# ADR-0008: Nonce/replay/rekey
- Status: Accepted
- Date: 2026-10-19
- Decision: data nonce = direction-specific 4-byte salt || big-endian u64 sequence; separate keys/counters per direction, start 1, never wrap. Replay window 1024. Rekey at 2^32 packets or 1 hour; hard stop at 2^32+2^20 if rekey fails.
- Rationale: nonce uniqueness and bounded reordering.
- Alternative rejected: random per-packet nonce.
- Consequence: if rekey fails and CA unreachable, terminate session; revoked peer terminates immediately. See PROTOCOL.md §§7–9.