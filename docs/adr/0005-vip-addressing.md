# ADR-0005: Temporary vIP
- Status: Accepted
- Date: 2026-10-19
- Decision: random 64-bit interface ID inside router's routed WAN IPv6 prefix; duplicate address detection before use; inbound UDP to vIP allowed only on handshake port; remove after success or 10s timeout. IPv4-only WAN unsupported.
- Rationale: routable M2 return path and bounded temporary address lifetime.
- Alternative rejected: arbitrary unrouteable address.
- Consequence: prefix routing, DAD and firewall rules are prerequisites. See PROTOCOL.md §11.