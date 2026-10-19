# NLS v0.1.1 Threat Model
Status: aligned with frozen PROTOCOL.md, 2026-10-19.

## Assets
Router Ed25519 private keys, CA signing key, enrollment tokens, TLS credentials, RDR integrity/freshness, policy and revocation state, ephemeral DH secrets, session keys, inner packets, replay windows, audit logs.

## Adversaries
On-path/off-path attackers, spoofed-source UDP senders, malicious enrolled routers, compromised router hosts, stolen enrollment tokens, compromised CA/admin host, passive WAN observers, resource-exhaustion attackers.

## Security properties
NLS encrypts the complete inner IP packet: client/server IP addresses, transport ports and payload. It authenticates the packet with AES-256-GCM, provides per-direction keys and sequence-based replay protection, and authenticates router identities against signed RDRs. Enrollment tokens are single-use, expiring and bound to the CSR public-key hash. Control traffic uses TLS 1.3.

## Explicitly not hidden
Outer router WAN IPv6 endpoints, UDP protocol use, packet sizes, timing, direction, approximate traffic volume and connection activity. Traffic analysis remains possible. The destination router must see the decrypted inner packet to forward it.

## Threat handling
- Replay: per-direction 1024-packet sliding window; update only after GCM authentication.
- Spoofed M1/DoS: stateless address-bound cookie always required before allocating state; M1_COOKIE smaller than padded M1; rate limits still required.
- Downgrade: only protocol version 1 and suite 1 accepted; unknown versions/suites rejected.
- Revoked router: revocation push tears down sessions within 30s; new handshake requires online lookup; revoked peer immediately terminates rekey/session.
- CA unreachable: fail closed for new handshakes; existing sessions dropped after control outage exceeds 300s.
- Key compromise: compromised router key permits impersonation until revocation propagates; compromised CA key compromises issued identities. CA key encrypted at rest with Argon2id; offline backup/export encrypted. CA rotation and HA are out of scope.
- Wrong tag/signature/transcript/cookie: silent UDP drop, tentative state and keys erased.
- Unknown destination or missing PROTECT state: drop; never plaintext fallback.
- Compromised router host: keys and decrypted traffic on that host are exposed; NLS cannot defend a fully compromised endpoint.
