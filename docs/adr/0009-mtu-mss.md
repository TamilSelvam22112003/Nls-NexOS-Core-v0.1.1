# ADR-0009: MTU/MSS

- Status: Accepted for pre-release v1-rc2; not yet released.
- Date: 2026-10-19
- Decision: DATA/REKEY datagrams use a single 32-byte NLS header; no separate 8-byte common framing prefix. Outer overhead = IPv6 40 + UDP 8 + NLS header 32 + GCM tag 16 = 96 bytes.
- Arithmetic: WAN MTU 1500 − 96 = TUN MTU 1404. IPv4 TCP MSS = 1404 − 20 IPv4 − 20 TCP = 1364. IPv6 TCP MSS = 1404 − 40 IPv6 − 20 TCP = 1344.
- Rationale: avoid relying on fragmentation and remove duplicate data-plane framing.
- Alternative rejected: retaining redundant framing and using PMTUD alone.
- Consequence: recalculate for actual path MTU, TCP options and IPv6 extensions. See PROTOCOL.md §10 and SPEC_ERRATA.md E-002/E-005.
