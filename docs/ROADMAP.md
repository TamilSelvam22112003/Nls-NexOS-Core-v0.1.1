# NLS v0.1.1 Roadmap
Specification-first. No feature implementation is included in Step 1. Frozen contract: PROTOCOL.md; any wire change requires a protocol version bump and new ADR.

1. Step 1 — Freeze specification and scaffold: acceptance: all five flows mapped to protocol messages; ADRs accepted; CI green; protocol freeze checklist complete.
2. Step 2 — Shared protocol library in Core pkg/proto: byte-for-byte golden vectors for every message; strict parser/fuzzer tests; no business logic.
3. Step 3 — Router-CA init: encrypted Ed25519 CA key, root certificate, local CLI and safe permissions.
4. Step 4 — Enrollment/directory/revocation service: token one-time semantics, RDR signatures, lookup and audit tests.
5. Step 5 — NetOS enrollment + TLS 1.3 mTLS control: pinned root, issued router certificate, heartbeat and policy/revocation sync.
6. Step 6 — Packet selection: nls0 TUN routes, PROTECT/BYPASS behavior and no plaintext fallback.
7. Step 7 — Handshake: cookie, transcript, online lookups, M1–M4, timeout and failure cleanup.
8. Step 8 — Data plane: AES-GCM, replay window, rekey, MTU/MSS.
9. Step 9 — Integration lab using Linux network namespaces: two routers, client/server namespaces, IPv4/IPv6 inner traffic, failure injection, capture-based privacy checks.
10. Step 10 — Packaging + release: Ubuntu 22.04/24.04 packages, service hardening, upgrade/rollback, SBOM, reproducible build and signed release.

Each step gates the next; no implementation may redefine PROTOCOL.md without version bump and ADR.
