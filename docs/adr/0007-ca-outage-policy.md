# ADR-0007: CA outage/cache
- Status: Proposed.
- Decision: fail closed for new handshakes when online CA lookup fails; RDR TTL 300 seconds, but cache never authorizes a new session. Existing locally valid sessions may continue until revocation is known.
- Rationale: avoid stale authorization for revoked peers.
- Alternative rejected: stale-cache handshake during outage.
- Consequence: availability loss during outage; define revocation-sync expiry before production.