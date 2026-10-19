# Protocol Freeze Checklist
Date: 2026-10-19. Contract: [PROTOCOL.md](PROTOCOL.md). Any wire change requires a version bump and new ADR.

- [x] P0-1 identity/X.509 conflict resolved: PROTOCOL.md §§1, 5.
- [x] P0-2 cookie challenge sequence resolved: §§2, 6, 11.
- [x] P0-3 transcript, DH, identity encryption and signatures specified: §§6–7; security review objection retained.
- [x] P0-4 router ID and one endpoint schema frozen: §5.
- [x] P1-5 RDR freshness, revocation and control-loss behavior: §§4, 12.
- [x] P1-6 TUN routes and fail-closed PROTECT policy: §§4, 11.
- [x] P2-7 local CLI, Argon2id-encrypted CA key and encrypted export/import: §§10, Objections/Open.
- [x] P2-8 CA rotation and multi-node HA explicitly out of scope: §§Threat Model and Roadmap.
- [x] Enrollment bootstrap, token scope, expiry, one-time use and CSR key binding: §3.
- [x] All five architecture flows map to named protocol messages: §§3–9 and ARCHITECTURE.md.
- [x] Cookie and rekey messages defined: §§6, 9.
- [x] Every message has fixed byte layout and validation/error behavior: §§2–9.
- [x] Enums, status codes and error codes frozen: §2 and §12.
- [x] Policy payload schema and canonical TLV rules frozen: §§2, 4.
- [x] Replay, nonce, key schedule and rekey limits defined: §§7–9.
- [x] MTU/MSS recalculated: §10.
- [x] Negative validation tests listed: TEST_PLAN.md.
- [x] Router and handshake state machines updated: ARCHITECTURE.md.
- [x] Overlapping docs synchronized between repos: verify via matching content hashes before release.
