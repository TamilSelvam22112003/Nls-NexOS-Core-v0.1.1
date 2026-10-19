# ADR-0003: Router certificate and RDR
- Status: Proposed.
- Decision: compact canonical binary CA-signed records as in PROTOCOL.md.
- Rationale: fixed schema and bounded parser surface.
- Alternative rejected: X.509 router identity for general-purpose extensions and chain complexity.
- Consequence: strict parsing/signatures/expiry; conflicts with Go TLS X.509 requirement and blocks implementation pending owner decision.