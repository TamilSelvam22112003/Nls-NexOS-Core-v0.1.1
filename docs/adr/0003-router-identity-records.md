# ADR-0003: Router identity and RDR
- Status: Accepted
- Date: 2026-10-19
- Decision: one Ed25519 key per router is the NLS identity. The CA-signed compact RDR binds router_id, Ed25519 public key, exactly one IPv6 endpoint in v1, certificate serial and validity. Handshake signatures validate against the RDR key; data path does not parse X.509.
- Rationale: fixed canonical schema and clear separation of NLS identity from TLS transport identity.
- Alternative rejected: use X.509 as the NLS identity; it expands data-path parser and couples handshake identity to TLS PKI representation.
- Consequence: strict canonical RDR parsing and registry binding required. See PROTOCOL.md §5.