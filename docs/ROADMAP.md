# Roadmap

| Step | Scope | Acceptance gate |
|---:|---|---|
| 1 | Specs/scaffolding | owner resolves P0; CI build/test/lint green |
| 2 | shared Core pkg/proto; NetOS imports immutable version tag | golden vectors, strict parsers, fuzz tests; no feature logic |
| 3 | CA init | persistent Ed25519 identity, permissions and recovery semantics |
| 4 | enrollment/directory/revocation | CSR/credential checks, signed RDR, audit and rate limits |
| 5 | NetOS enrollment + control | mTLS, reconnect/sync, negative credential/revocation tests |
| 6 | packet selection | namespace route/TUN tests; unknown destination fails closed |
| 7 | handshake | stateless cookie, M1-M4 transcript and tamper tests |
| 8 | data plane | full-packet AES-GCM, replay, reverse path, rekey and MTU |
| 9 | namespace lab | end-to-end traffic, revocation and outage scenarios |
| 10 | packaging/release | reproducible binaries, hardened systemd, install/upgrade/uninstall Ubuntu 22.04/24.04 |