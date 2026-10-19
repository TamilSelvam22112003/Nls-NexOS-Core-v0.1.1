# ADR-0009: MTU/MSS
- Status: Accepted
- Date: 2026-10-19
- Decision: outer overhead = IPv6 40 + UDP 8 + NLS framing 8 + data header 32 + GCM tag 16 = 104 bytes. WAN MTU 1500 gives TUN MTU 1396; MSS 1356 inner IPv4 and 1336 inner IPv6.
- Rationale: avoid reliance on fragmentation.
- Alternative rejected: PMTUD-only.
- Consequence: recalculate for actual path MTU, TCP options and IPv6 extensions. See PROTOCOL.md §10.