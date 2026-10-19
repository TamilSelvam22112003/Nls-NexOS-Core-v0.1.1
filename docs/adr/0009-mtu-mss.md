# ADR-0009: MTU/MSS
- Status: Accepted
- Date: 2026-10-19
- Decision: total outer overhead is 104 bytes: IPv6 40 + UDP 8 + NLS framing 8 + data header 32 + GCM tag 16. At WAN MTU 1500, TUN MTU 1396; MSS 1356 inner IPv4 and 1336 inner IPv6.
- Rationale: conservative baseline avoids relying on fragmentation.
- Alternative rejected: PMTUD-only.
- Consequence: recompute for real path MTU, TCP options and IPv6 extensions. See PROTOCOL.md §10.