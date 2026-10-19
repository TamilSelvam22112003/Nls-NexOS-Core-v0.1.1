# ADR-0009: MTU/MSS
- Status: Proposed.
- Decision: overhead = IPv6 40 + UDP 8 + NLS header 32 + tag 16 = 96 bytes. For WAN MTU 1500, TUN MTU 1404; MSS clamp 1364 for inner IPv4 and 1344 for inner IPv6.
- Rationale: avoid baseline fragmentation.
- Alternative rejected: rely on PMTUD/fragmentation alone, vulnerable to ICMP filtering.
- Consequence: reduce MTU/MSS for lower path MTU or extension headers; assumes base IP and TCP headers.