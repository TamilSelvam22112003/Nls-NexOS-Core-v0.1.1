# Acceptance Test Plan

| Flow | Positive | Negative |
|---|---|---|
| 1 CA init | identity/registry/revocation persist across restart; ready only after durable write | malformed config, unsafe permissions, duplicate init, unwritable storage |
| 2 enrollment/control | valid CSR+credential issues cert; mTLS and policy/revocation sync work | bad credential, malformed CSR, revoked/expired cert, bad mTLS identity, stale generation |
| 3 selection | prefix routes to TUN; directory and policy select protected path | unknown destination, expired cache, deny, control unavailable; no plaintext fallback |
| 4 handshake | cookie and M1-M4 establish matching session/directional keys; remove vIP after M4 | spoofed M1 no state, bad cookie, revoked/unknown peer, tampered M2/M3/M4, bad signature, CA down, timeout |
| 5 data plane | full inner IPv4/IPv6 packet round-trip both ways; capture confirms inner metadata hidden | replay, out-of-window sequence, wrong GCM tag, altered header, unknown session, oversized packet, sequence exhaustion |

CI: golden vectors for every message, truncation at every field boundary, unknown enums/version, reserved-field violations, trailing bytes, signature-domain tests and fuzzing with no panic/unbounded allocation. Integration uses Linux namespaces/veths on Ubuntu 22.04/24.04 without public network dependency; record commit, Go/kernel versions, command, captures and failure signature.