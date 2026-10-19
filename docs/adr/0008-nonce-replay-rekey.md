# ADR-0008: Nonce/replay/rekey
- Status: Proposed.
- Decision: nonce = direction salt[4] || big-endian sequence:u64; separate key/salt per direction; sequence starts 1, never wraps. Replay window 1024. Rekey after 2^32 packets or 1 hour; stop at 2^32+2^20 if rekey fails.
- Rationale: deterministic nonce uniqueness and bounded reordering.
- Alternative rejected: random per-packet nonce due collision/state overhead.
- Consequence: sessions do not survive process restart; re-handshake.