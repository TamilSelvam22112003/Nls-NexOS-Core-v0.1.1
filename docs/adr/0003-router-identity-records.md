# ADR-0003: Router identity and RDR
- Status: Accepted
- Date: 2026-10-19
- Decision: one Ed25519 key per router is the NLS identity. CA-signed compact RDR binds router_id, public key, exactly one IPv6 endpoint, certificate serial and validity. Handshake signatures verify against RDR key; data path does not parse X.509.
- Rationale: fixed canonical schema and separation of NLS identity from TLS transport identity.
- Alternative rejected: X.509 as NLS identity, due to data-path parser and PKI coupling.
- Consequence: strict canonical parsing and registry binding. See PROTOCOL.md §5.