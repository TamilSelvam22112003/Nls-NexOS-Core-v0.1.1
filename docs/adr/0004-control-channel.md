# ADR-0004: Control channel
- Status: Proposed.
- Decision: TLS 1.3 mutual authentication plus explicit router-ID authorization.
- Rationale: mature transport confidentiality/integrity and key handling.
- Alternative rejected: custom authenticated TCP.
- Consequence: standard Go TLS expects X.509; owner must select X.509 router certs or separate TLS transport identity and compact NLS identity before Step 2.