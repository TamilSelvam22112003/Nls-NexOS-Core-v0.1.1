# NLS Architecture v0.1.1

Specification/scaffolding only. Core owns Router-CA, enrollment, trust registry, router directory, policy, revocation, control service and shared `pkg/proto`; NetOS owns the Ubuntu router agent, enrollment client, mTLS client, TUN selection, handshake and data plane. CA signing key never leaves Core; Core never sees user payload; NetOS cannot self-authorize peers.

## Flow 1 — CA init
```mermaid
sequenceDiagram
 actor Admin
 participant CA as Router-CA
 participant DB as Trust Registry
 Admin->>CA: initialize
 CA->>CA: create CA identity
 CA->>DB: initialize registry and revocation
 Admin->>CA: configure credentials, policy and access
 CA->>DB: persist registry/revocation
 CA-->>Admin: ready for enrollment
```
## Flow 2 — boot/enrollment
```mermaid
sequenceDiagram
 participant R as Router Agent
 participant OS as Ubuntu
 participant CA as Router-CA
 participant C as Control Service
 R->>OS: boot/network init
 R->>R: load keys/config
 R->>CA: ENROLL_REQUEST(CSR, credential)
 CA->>CA: validate credential, CSR, policy
 CA-->>R: ENROLL_RESULT(certificate/status)
 R->>C: TLS 1.3 mutual authentication
 C-->>R: CONTROL_READY + policy/revocation sync
```
## Flow 3 — packet selection
```mermaid
sequenceDiagram
 participant Client
 participant R as Local Router
 participant T as Routing/NLS TUN
 participant D as Directory/Trust Cache
 participant P as Policy
 Client->>R: original packet (dst=Server IP)
 R->>T: route destination prefix
 T->>D: resolve destination router/trust
 D-->>T: identity and WAN endpoint
 T->>P: protected-path check
 P-->>T: protect/bypass/drop
 T->>R: selected original packet
```
## Flow 4 — handshake
```mermaid
sequenceDiagram
 participant A as Local Router
 participant CA as Router-CA
 participant B as Destination Router
 A->>A: allocate temporary IPv6 vIP from own WAN prefix
 A->>B: M1_INIT (outer source=vIP)
 B-->>A: M1_COOKIE (stateless challenge)
 A->>B: M1_INIT cookie echo
 B->>B: validate cookie, then allocate state
 B->>A: M2 sealed response
 A->>CA: fresh lookup of B
 CA-->>A: signed RDR
 A->>A: validate M2/RDR
 A->>B: M3 sealed identity + key agreement
 B->>CA: fresh lookup of A
 CA-->>B: signed RDR
 B->>B: validate identity and derive keys
 B->>A: M4 authenticated completion
 A->>A: verify M4, switch endpoint, remove vIP
```
## Flow 5 — data plane
```mermaid
sequenceDiagram
 participant C as Client
 participant A as Local Router
 participant B as Destination Router
 participant S as Server
 C->>A: inner client-to-server IP packet
 A->>A: AES-256-GCM encrypt entire inner packet
 A->>B: outer IPv6/UDP + NLS header + ciphertext/tag
 B->>B: session lookup, replay check, authenticate/decrypt
 B->>S: restore original packet
 S-->>B: response packet
 B-->>A: reverse encrypted packet
 A-->>C: restore response
```
## Router state machine
```mermaid
stateDiagram-v2
 [*] --> BOOT
 BOOT --> ENROLLING
 ENROLLING --> ENROLLED: certificate issued
 ENROLLING --> FAILED: enrollment error
 ENROLLED --> CONTROL_UP: mTLS + sync
 CONTROL_UP --> SESSION_HANDSHAKING: protected packet
 SESSION_HANDSHAKING --> SESSION_ESTABLISHED: M1-M4 valid
 SESSION_HANDSHAKING --> FAILED: timeout/bad message
 SESSION_ESTABLISHED --> CONTROL_UP: close/rekey
 CONTROL_UP --> REVOKED: revocation sync
 ENROLLED --> REVOKED: revoked
 CONTROL_UP --> FAILED: fatal local error
 FAILED --> ENROLLING: operator retry
 REVOKED --> [*]
```
## Open Questions for owner (ranked)
1. **P0:** compact custom router certificate conflicts with Go TLS's X.509 requirement. Choose X.509 identity or separate X.509 transport identity plus compact NLS identity.
2. **P0:** approve M1 cookie challenge/echo; original diagram shows only one M1.
3. **P0:** finalize M2/M3/M4 transcript order, key derivation and envelope lengths before Step 2.
4. **P0:** confirm 16-byte random router ID and one IPv6+UDP endpoint per RDR.
5. **P1:** approve 300-second RDR TTL and online lookup for each new handshake.
6. **P1:** confirm Linux TUN/policy routing and fail-closed unknown-destination behavior.
7. **P2:** define first-admin bootstrap, CA unlock, backup/restore and HA.
## Ambiguities/contradictions
Cookie defense adds a flight absent from the diagram. Fresh lookup makes CA reachability mandatory for new sessions. vIP requires a routable IPv6 WAN prefix; IPv4-only WAN is unsupported. Full inner-packet encryption hides inner addresses/ports/payload but not outer endpoints, packet sizes or timing.