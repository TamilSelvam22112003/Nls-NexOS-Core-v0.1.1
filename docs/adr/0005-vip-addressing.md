# ADR-0005: Temporary vIP
- Status: Proposed.
- Decision: temporary IPv6 address from router's own routed WAN prefix; bind to WAN and use as M1 outer source. IPv4-only WAN unsupported in v0.1.1.
- Rationale: destination needs a routable return path for M2.
- Alternative rejected: arbitrary unrouteable address.
- Consequence: define prefix delegation, DAD, collision, firewall and cleanup behavior; remove only after authenticated M4.