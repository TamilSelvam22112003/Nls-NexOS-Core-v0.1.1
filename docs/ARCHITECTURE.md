# NLS v0.1.1 Architecture
Status: aligned with frozen PROTOCOL.md, 2026-10-19.

## Repository ownership
- Nls-NexOS-Core-v0.1.1: Router-CA, local admin CLI, enrollment/token service, X.509 issuance for TLS only, RDR registry/signing, directory, policy, revocation, control service and shared pkg/proto.
- Nls-NetOS-v0.1.1: Ubuntu router agent, enrollment client, mTLS control client, nls0 TUN, packet selection, vIP, handshake and encrypted data plane.
- One Ed25519 key per router is the NLS identity; RDR binds router ID, key, endpoint, certificate serial and validity. X.509 is only the TLS control-channel identity; data path does not parse X.509.

## Flow 1 — Router-CA initialization
```mermaid
sequenceDiagram
  actor Admin
  participant CA as Router-CA
  Admin->>CA: local CLI initialize
  CA->>CA: create CA identity and trust registry
  Admin->>CA: configure scoped enrollment tokens
  Admin->>CA: configure policy and access controls
  CA->>CA: persist registry and revocation state
  CA-->>Admin: ready for enrollment
```

## Flow 2 — Boot and enrollment
```mermaid
sequenceDiagram
  participant R as Router
  participant CA as Router-CA
  R->>R: boot Ubuntu, networking, load keys/config
  R->>CA: server-auth TLS pinned root + token + CSR
  CA->>CA: validate token, name, key hash and CSR
  CA-->>R: issued X.509 certificate + result
  R->>CA: establish TLS 1.3 mTLS control
  CA-->>R: policy and revocation sync
```

## Flow 3 — Packet selection
```mermaid
sequenceDiagram
  participant C as Client
  participant R as Local Router
  participant T as nls0 TUN
  participant D as Directory/Trust Cache
  C->>R: original IP packet (server destination)
  R->>T: route PROTECT prefix through nls0
  T->>D: resolve destination router and RDR
  D-->>T: identity and endpoint
  T->>T: policy check
  T->>R: protected packet for NLS processing
```

## Flow 4 — Handshake
```mermaid
sequenceDiagram
  participant I as Initiator
  participant R as Responder
  participant CA as Router-CA
  I->>R: M1_INIT (outer source=vIP)
  R-->>I: M1_COOKIE (stateless, always)
  I->>R: M1_INIT(cookie)
  R-->>I: M2 (ephemeral, encrypted identity, signature)
  I->>CA: online lookup responder RDR
  I->>R: M3 (encrypted initiator identity, signature)
  R->>CA: online lookup initiator RDR
  R-->>I: M4 (authenticated finish)
  I->>I: switch to real WAN endpoints; remove vIP
```

## Flow 5 — Data plane
```mermaid
sequenceDiagram
  participant C as Client
  participant I as Local Router
  participant R as Destination Router
  participant S as Server
  C->>I: original IP packet
  I->>R: IPv6/UDP + NLS header + AES-GCM ciphertext
  R->>R: session lookup, replay check, GCM verify/decrypt
  R->>S: restored original IP packet
  S-->>R: response packet
  R-->>I: encrypted reverse-direction packet
  I-->>C: restored response
```

## Router state machine
```mermaid
stateDiagram-v2
  [*] --> BOOT
  BOOT --> ENROLLING
  ENROLLING --> ENROLLED: certificate issued
  ENROLLING --> FAILED: bad token/config/CA
  ENROLLED --> CONTROL_UP: mTLS established
  ENROLLED --> FAILED: invalid certificate
  CONTROL_UP --> SESSION_HANDSHAKING: protected flow needs session
  SESSION_HANDSHAKING --> SESSION_ESTABLISHED: M4 valid
  SESSION_HANDSHAKING --> FAILED: timeout or validation failure
  SESSION_ESTABLISHED --> CONTROL_UP: session removed
  CONTROL_UP --> REVOKED: local router revoked
  SESSION_ESTABLISHED --> REVOKED: local router revoked
  FAILED --> BOOT: operator restart/reconfigure
  REVOKED --> [*]
```

## Handshake state machines
Initiator: IDLE → M1_SENT → COOKIE_RECEIVED → M1_COOKIE_SENT → M2_VALIDATING → M3_SENT → M4_VALIDATING → ESTABLISHED. Every wait has bounded retries; cookie wait 1s, M2/M4 waits 3s, overall 10s. Any malformed frame, bad cookie, stale/revoked RDR, failed signature/tag/transcript or timeout → FAILED and erase tentative keys. vIP removed on success or 10s timeout.
Responder: IDLE → COOKIE_SENT (no state) → COOKIE_VALIDATED → M2_SENT → M3_VALIDATING → M4_SENT → ESTABLISHED. No state before cookie validation. M3 wait 3s; invalid cookie, unknown/revoked source, malformed frame, bad signature/tag/transcript or timeout → drop and erase tentative state.

## Trust boundaries
1. Administrator/local CLI to CA key store.
2. Router to CA enrollment before certificate issuance (pinned server TLS + single-use token).
3. Router-to-CA control plane (TLS 1.3 mTLS).
4. WAN UDP (untrusted; cookie, signatures, AEAD and replay defenses).
5. TUN/kernel boundary (privileged packet input; PROTECT fails closed).
6. Router host filesystem (root-only keys and configuration).

## Open Questions for the owner
See PROTOCOL.md § Objections / Open. CA rotation and multi-node HA are explicitly out of scope for v0.1.1.
