# Threat Model

Assets: CA/router private keys, enrollment credentials, directory/policy/revocation integrity, session keys/sequence state, inner packet confidentiality/integrity and availability. Adversaries include passive WAN observers, on-path injectors/modifiers/replayers, spoofed-source M1 senders, compromised clients, malicious enrolled routers and temporary CA/network outages. Compromised endpoints see plaintext; CA compromise permits forged identities.

**Hidden:** inner client/server IPs, transport ports/headers and payload (entire inner IP packet is AES-256-GCM ciphertext). **Visible:** outer router WAN IPv6 endpoints, UDP ports, packet sizes, timing, direction, rate and volume; traffic analysis remains possible.

| Threat | Required mitigation | Residual risk |
|---|---|---|
| Replay | per-direction sequence, 1024-window; authenticate before advancing | implementation flaws |
| Spoofed M1/DoS | stateless HMAC cookie before state; global/per-prefix limits; bounded datagrams | bandwidth/CPU DoS |
| Downgrade | fixed suite 1; bind version/suite into transcript; reject unknown | future upgrades need explicit version |
| Revoked router | fresh online lookup for each new handshake; ACTIVE required; teardown on sync | existing session until sync |
| CA unreachable | fail closed for new handshakes; stale cache never authorizes; existing locally valid sessions may continue until revocation known | availability loss |
| Router key compromise | revoke, rotate, terminate sessions, audit; keys 0600 in dirs 0700 | impersonation until revocation |
| CA key compromise | offline encrypted backup, least privilege, audit and root rotation | full trust domain compromised |
| Tampering | GCM authenticates header as AAD and ciphertext | drop/delay possible |
| Unknown destination | protected prefixes fail closed; no plaintext fallback | misconfiguration outage |
| Credential theft | scoped credentials, TLS, no logs, expiry/revocation | bootstrap remains critical |

Never log secrets, keys, cookies, or full inner packets. Log timestamp, router ID, event code and request ID.