# NLS v2 Handshake and Control-Message Draft

**Status:** Proposed, review-required, not frozen.  
**Compatibility:** This is a separately versioned v2 proposal. It does not change the v1 wire contract.  
**Related:** [NLS v2 wire specification draft](NLS_V2_WIRE_SPEC_DRAFT.md), [integration impact analysis](INTEGRATION_IMPACT_ANALYSIS.md).

This document fills the handshake/control-plane gap in the data-plane draft. It is deliberately documentation-only. Implementations MUST NOT be described as interoperable until both documents are reconciled, reviewed, and backed by shared golden vectors.

## 1. Goals and invariants

1. Establish mutually authenticated adjacent-router sessions with independent directional keys.
2. Prevent unauthenticated senders from forcing unbounded state allocation, expensive public-key work, or large responses.
3. Bind router identities to certificate-authorized endpoint identities; an IP address, vIP/token, OSPF neighbor entry, or public key alone is not identity proof.
4. Keep v1 behavior unchanged and do not silently downgrade after a v2 authentication failure.
5. Use a routable outer IPv6 source/destination for UDP delivery. No fabricated or encrypted-in-place IPv6 source address is used for routing.
6. Keep the NLS first-contact token separate from an IPv6 address. It is an opaque demultiplexing value, not a route or a credential.

## 2. Transport and canonical control encoding

Handshake and control messages are UDP payloads beginning with the common 44-byte NLS2 header defined in `NLS_V2_WIRE_SPEC_DRAFT.md`. For control packets, the 16-byte header identifier is the random **handshake_id** until a session is established. Once established, it is the **session_token**. These identifiers occupy the same field but MUST NOT be reused across handshake transactions or active sessions.

The header length is exactly 44. For INIT, RETRY, and RESP, flags MUST be zero, key_epoch MUST be zero, and sequence_number MUST be zero. For FINISH_I and FINISH_R, key_epoch and sequence_number MUST both be zero because each message uses a fresh directional handshake key and nonce zero; the header's exchange_id MUST equal the handshake_id. CLOSE uses the established session token and the established session's epoch/sequence/replay rules. The control payload begins with a 4-byte control prefix:

| Size | Field | Rule |
|---:|---|---|
| 1 | control_type | Message code from Section 3 |
| 1 | control_flags | MUST be zero in this draft |
| 2 | reserved | MUST be zero |

The rest of the control payload is a sequence of TLVs:

| Size | Field | Rule |
|---:|---|---|
| 2 | type | Unsigned big-endian. High bit means critical; lower 15 bits identify the field |
| 4 | length | Unsigned big-endian byte count of value |
| length | value | Exact bytes for the field |

TLVs MUST be strictly ascending by their full 16-bit type value. Duplicate types, out-of-order types, truncated TLVs, arithmetic overflow, fields exceeding the per-message cap, and unknown critical fields MUST be rejected. Unknown non-critical fields may be ignored only where this draft explicitly allows extension. All currently specified fields are critical. No padding bytes or trailing bytes are allowed. Maximum UDP payload is a local configurable cap no greater than the IPv6 path MTU minus outer IPv6 and UDP headers; the initial implementation must publish its chosen cap and enforce it before allocation.

For handshake messages, the header's payload-length field is the exact control payload length and is not assumed to include an AEAD tag. For encrypted established-session controls and DATA, the payload length includes the AEAD tag. This distinction MUST be explicit in the common-header errata before implementation; see Section 10.

### 2.1 Canonical signature input

For signed handshake messages, signature input is:

`ASCII("NLS2-HANDSHAKE-SIG") || 0x00 || version(1 byte) || control_type(1 byte) || handshake_id(16 bytes) || canonical_control_payload_without_signature_TLV || outer_source_ipv6(16) || outer_destination_ipv6(16) || udp_source_port(2) || udp_destination_port(2)`

The signature TLV is omitted entirely from the canonical payload used for signing. The signature algorithm is Ed25519 and signature length is exactly 64 bytes. Implementations MUST sign and verify the exact canonical byte sequence, not a reserialized map whose ordering is ambiguous.

## 3. Message codes and order

| Code | Name | Protection | Purpose |
|---:|---|---|---|
| 0x01 | INIT | Unsigned, stateless | Request a session and advertise initiator's ephemeral key and nonce |
| 0x02 | RETRY | Stateless cookie | Prove return-path reachability before responder allocates handshake state |
| 0x03 | RESP | Responder certificate signature | Authenticate responder and contribute ephemeral key |
| 0x04 | FINISH_I | AEAD-protected; includes initiator signature | Authenticate initiator and provide its certificate/status evidence |
| 0x05 | FINISH_R | AEAD-protected | Confirm responder accepted initiator and bind the established session |
| 0x06 | CLOSE | AEAD-protected | Close a session |
| 0x07 | KEY_UPDATE | AEAD-protected | Reserved until Section 9 is fully specified; MUST be rejected for now |

A valid exchange is INIT → RETRY → INIT-with-cookie → RESP → FINISH_I → FINISH_R. The responder MAY omit RETRY only when local policy explicitly permits it for a pre-authenticated, rate-limited peer; the default MUST require RETRY for an untrusted source. A receiver MUST reject messages out of state, repeated finalization, or messages with a mismatched handshake_id.

### 3.1 INIT (0x01)

Required TLVs, exact values:

| Type | Field | Size |
|---:|---|---:|
| 0x8001 | initiator_router_id | 32-byte SHA-256 fingerprint of canonical DER SubjectPublicKeyInfo for the initiator's Ed25519 identity key |
| 0x8002 | responder_router_id | 32-byte SHA-256 fingerprint of responder identity key |
| 0x8003 | nonce_i | 32 random bytes from a CSPRNG |
| 0x8004 | ephemeral_x25519_i | 32-byte X25519 public key |
| 0x8005 | suite_list | 2-byte count followed by count 2-byte suite IDs, ascending, unique; this draft defines only suite 0x0001 |
| 0x8006 | cookie | absent in first INIT; required in retried INIT; format below |

Suite 0x0001 means Ed25519 identity signatures, ephemeral X25519, HKDF-SHA-256, and AES-256-GCM. A peer MUST fail closed if no mutually supported suite exists. It MUST NOT fall back to v1 or a weaker suite after a v2 failure.

### 3.2 RETRY (0x02)

Required TLV 0x8006 cookie: exactly 40 bytes: `time_bucket(8-byte uint64 big-endian) || mac(32 bytes)`. The MAC is HMAC-SHA-256 under a rotating responder-local secret over:

`ASCII("NLS2-COOKIE") || 0x00 || outer_source_ipv6 || outer_destination_ipv6 || udp_source_port || udp_destination_port || handshake_id || nonce_i || ephemeral_x25519_i || time_bucket`

The responder accepts only the current or immediately preceding configured time bucket. Secret rotation and bucket duration are configuration parameters and MUST be documented; a recommended starting bucket duration is 30 seconds, with a two-bucket acceptance window. The cookie is not a credential and does not authenticate the initiator. RETRY MUST not be larger than the triggering INIT payload plus 64 bytes, and the responder MUST not allocate per-client handshake state before cookie validation.

### 3.3 RESP (0x03)

Required TLVs:

| Type | Field | Size / format |
|---:|---|---|
| 0x8001 | responder_certificate_chain | uint32 length-prefixed DER certificates, leaf first; total <= 16 KiB |
| 0x8002 | responder_status_evidence | uint32 length-prefixed Router-CA-signed status object; total <= 4 KiB |
| 0x8003 | nonce_r | 32 CSPRNG bytes |
| 0x8004 | ephemeral_x25519_r | 32-byte X25519 public key |
| 0x8005 | selected_suite | 2-byte suite ID, exactly 0x0001 |
| 0x8006 | endpoint_binding | canonical endpoint tuple: address family (1 byte, value 6), IPv6 address (16 bytes), UDP port (2 bytes), router identity fingerprint (32 bytes) |
| 0x8007 | signature | exactly 64-byte Ed25519 signature over the canonical signature input |

The responder MUST validate the cookie before sending RESP. The initiator MUST validate the certificate chain to a pinned Router-CA trust anchor, identity fingerprint, endpoint binding, certificate validity, status signature and freshness, and RESP signature before accepting the responder. The responder's certificate must authorize the advertised endpoint under the profile defined by the deployment; if no such profile is provisioned, handshake establishment MUST fail.

### 3.4 Key derivation after RESP

Both sides compute the X25519 shared secret from their ephemeral private key and the peer's ephemeral public key. Reject an all-zero shared secret. Let `T0` be SHA-256 over the exact encoded INIT-with-cookie and RESP datagrams, excluding only outer IPv6/UDP headers. Let `salt = SHA-256(ASCII("NLS2-HS-SALT") || nonce_i || nonce_r || T0)`. Use HKDF-SHA-256 with the X25519 shared secret as input keying material and `salt` as salt. Derive distinct 32-byte keys using these exact info labels:

- `NLS2 initiator-to-responder handshake key v1`
- `NLS2 responder-to-initiator handshake key v1`
- `NLS2 initiator-to-responder data key v1`
- `NLS2 responder-to-initiator data key v1`

Derive 32 bytes for each label. Handshake keys protect FINISH_I/FINISH_R; data keys are not used until FINISH_R validates. Do not reuse an AEAD key across directions, peers, epochs, or protocol purposes. The exact transcript definition is an interoperability gate: implementations must publish golden vectors before coding is considered complete.

### 3.5 FINISH_I (0x04)

FINISH_I is AES-256-GCM protected under the initiator-to-responder handshake key, with header key_epoch=0, sequence_number=0, and nonce `uint32_be(0) || uint64_be(0)`. The exchange_id in the common header is still the handshake_id for this message. AAD is the exact common header plus outer IPv6 addresses and UDP ports. The decrypted control payload MUST contain:

- 0x8001 initiator_certificate_chain: DER chain, leaf first, total <= 16 KiB.
- 0x8002 initiator_status_evidence: Router-CA-signed status object, total <= 4 KiB.
- 0x8003 transcript_hash: exactly 32 bytes, SHA-256 over INIT-with-cookie and RESP datagrams.
- 0x8004 initiator_signature: exactly 64 bytes, Ed25519 signature over the Section 2.1 canonical signature input with control_type FINISH_I and the canonical decrypted payload excluding this signature TLV.

The responder MUST validate the initiator's certificate, fingerprint, endpoint binding, status evidence freshness/signature, transcript hash, and signature. It MUST NOT mark the peer ACTIVE or install routes before every check succeeds. If the responder has no valid Router-CA status evidence, it MUST reject new sessions.

### 3.6 FINISH_R (0x05)

FINISH_R is protected under the responder-to-initiator handshake key, nonce `uint32_be(0) || uint64_be(0)), and AAD formed in the same way. Its decrypted payload contains:

- 0x8001 transcript_hash: 32 bytes, same value as FINISH_I.
- 0x8002 session_token: 16 random bytes from the responder CSPRNG; MUST be unique among active sessions and not all zero.
- 0x8003 session_lifetime_seconds: uint32; nonzero and bounded by local policy.
- 0x8004 status_generation: uint64 version/generation from Router-CA status evidence used during validation.

The initiator MUST validate AEAD and transcript hash before marking the peer ACTIVE. The responder commits the session only after sending FINISH_R; the initiator commits only after accepting FINISH_R. Duplicate FINISH messages are handled idempotently within a bounded handshake cache and MUST NOT create duplicate sessions. A retransmission MUST resend the same encoded message bytes; it MUST NOT reuse the nonce with different plaintext.

### 3.7 CLOSE (0x06)

CLOSE is AEAD-protected under the established directional key and has one required TLV:

- 0x8001 close_reason: uint16 enumerated code: 1 normal shutdown, 2 idle timeout, 3 policy revocation, 4 rekey required, 5 protocol error.

Close packets are authenticated, replay-checked, and idempotent. Unknown close reasons are rejected. A receiver may locally expire a session without receiving CLOSE.

## 4. Router-CA status evidence and endpoint binding

Status evidence MUST be signed by the pinned Router-CA and bind at least: router identity fingerprint, certificate serial/fingerprint, status (ACTIVE, REVOKED, SUSPENDED), monotonically increasing status generation, issued-at time, expiry time, and authorized endpoint binding(s). The canonical encoding, CA signature envelope, and certificate profile must be specified by the Core repository before implementation. Evidence must be fresh under a configured maximum age. REVOKED/SUSPENDED or stale/invalid evidence prevents new session establishment.

If the Router-CA is unreachable, a router fails closed for new protected sessions. Established sessions may continue only for a bounded, explicitly configured stale-status interval; revocation push or a fresh status result terminates affected sessions. CA compromise requires trust-anchor rotation and re-enrollment; pinning alone does not protect against compromise of the pinned CA.

## 5. State machine

### Initiator

`IDLE → INIT_SENT → COOKIE_RECEIVED → INIT_COOKIE_SENT → RESP_VALIDATED → FINISH_I_SENT → ACTIVE`

Transitions to ACTIVE only after FINISH_R validates. Any timeout, unsupported suite, invalid signature/certificate/status, transcript mismatch, AEAD failure, wrong endpoint, or state mismatch leads to FAILED and erasure of ephemeral private material. Retry count and total handshake lifetime are bounded by local policy.

### Responder

`LISTENING → RETRY_SENT (default) → COOKIE_VALIDATED → RESP_SENT → FINISH_I_VALIDATED → ACTIVE`

No per-peer state is retained before cookie validation except bounded global anti-abuse counters and the rotating cookie secret. ACTIVE is reached only after successful FINISH_I validation and creation of FINISH_R. Failure returns to LISTENING and releases ephemeral state. Duplicate valid handshake messages are answered from a bounded retransmission cache.

### Trust Table and route installation

The Trust Table records authenticated identity, certificate/status generation, authorized endpoint, policy, and active session reference. It MUST NOT store printable raw private keys or treat the handshake_id/session_token as an identity. Routes and routing-protocol adjacency authorization are installed only after ACTIVE and explicit local policy approval. OSPF LSDB state is not cryptographic trust.

## 6. Resource limits and anti-DoS

- Require RETRY cookie for untrusted peers before allocating per-peer state or doing certificate validation / X25519.
- Apply global, interface, and source-prefix token buckets; cap handshake concurrency, retransmissions, certificate sizes, TLV count, and parsing work.
- Use bounded duplicate/retransmission caches with explicit expiry.
- Do not send certificate chains or CA status objects in response to an INIT without a valid cookie.
- Rate-limit errors and never emit detailed certificate/parser errors to unauthenticated peers.
- Do not reflect traffic to an arbitrary third-party address; outer source address/port are bound into the cookie.
- If any resource cap is exceeded, drop without creating state.

## 7. Retransmission and timeouts

Retransmissions use the same datagram bytes. Initiator and responder apply exponential backoff with jitter, a bounded retry count, and an absolute handshake deadline. Suggested initial values for lab-only configuration: 500 ms initial timeout, maximum 4 retransmissions per flight, 10-second overall handshake deadline. These are starting values, not universal network recommendations; they must be configurable and tested under WAN latency/loss. A timeout erases ephemeral keys and pending state.

## 8. Key epochs and key updates

KEY_UPDATE is intentionally reserved and MUST be rejected in this draft. A session MUST be closed and re-established with fresh ephemeral X25519 keys before an epoch or sequence counter would wrap, before process restart could repeat a nonce, or when local key-lifetime policy expires. A production protocol needs an authenticated key-update message and crash-safe sequence persistence before long-lived sessions can be considered complete. The current data-plane nonce scheme is not implementation-ready until this lifecycle is resolved.

## 9. Interaction with routing protocols and application traffic

This handshake authenticates NLS router-to-router sessions. It does not itself modify or encrypt OSPF, OSPFv3, BGP, RIP/RIPng, IPsec, or TLS packets. Initial integration uses a TUN/socket shim carrying NLS data between authenticated adjacent relays. Native routing-protocol protection requires separate per-protocol design, control-plane filtering, adjacency binding, and lab interoperability tests. Do not state that an OSPF LSDB entry or neighbor state establishes NLS trust.

## 10. Cross-document contradictions to resolve before implementation

1. **Common header length field:** the wire draft currently names field 40–43 `ciphertext_length` and says it includes a tag. This handshake draft requires `payload_length` because INIT/RETRY/RESP are not AEAD ciphertext. Rename it to `payload_length`; for DATA and encrypted controls, the value includes the AEAD tag; for plaintext signed/stateless handshake controls, it is the exact control payload size.
2. **Control header identifier:** call it `exchange_id` at handshake time and `session_token` after establishment; same 16-byte slot, different lifecycle. Do not treat either as a routable IP or identity.
3. **Nonce and transcript definition:** exact datagram transcript bytes, handshake AAD, and signature canonicalization need independent implementation vectors. In particular, signature verification must use the original sender/receiver endpoint tuple and must not be recomputed with a different direction's tuple.
4. **Certificate profile:** the exact Router-CA certificate/status encoding and endpoint authorization profile remain Core-specific prerequisites.
5. **Destination protection:** this handshake establishes adjacent-hop keys only. The destination-protection envelope and its key-management protocol remain separate and unspecified.
6. **Key update:** reserved and unsupported; re-handshake before key/sequence exhaustion. Do not ship long-lived sessions without an explicit rotation/restart plan.
7. **Transport details:** source/destination ports and outer address fields are authenticated as AAD for encrypted traffic; signed handshake messages bind their endpoint tuple through the signature input. NAT rebinding requires a separate authenticated migration procedure and is unsupported here.

## 11. Acceptance tests required

- Golden byte vectors for each message, TLV ordering, signatures, cookie MAC, transcript hash, HKDF outputs, and AEAD AAD/nonces.
- Cookie source-address/port binding, expired cookie, previous-bucket cookie, secret rotation, and reflection/amplification checks.
- Wrong identity fingerprint, wrong endpoint, untrusted/expired/revoked certificate, stale status, bad CA signature, bad Ed25519 signature, transcript mismatch, all-zero X25519 shared secret, unsupported suite, and downgrade attempts.
- Duplicate/out-of-order handshake messages, retransmission byte identity, concurrent same-identity handshakes, cache exhaustion, and timeout cleanup.
- CA outage/recovery and status-generation changes.
- Interop tests in both repositories, followed by six-node functional and ten-router IPv6/FRR lab tests.
- Fuzz all length fields and TLV parsing; verify no unbounded allocation or route/trust promotion on failure.

## 12. Attacker-perspective critique

A spoofing attacker can send INIT packets, but should not trigger per-peer state or expensive certificate work without a valid address-bound cookie. An on-path attacker can observe outer IPv6 endpoints, ports, sizes, timing, and traffic volume; this draft does not hide those. An attacker can drop, delay, reorder, or replay packets; AEAD, transcript binding, replay windows, bounded retransmission and timeout handling must limit the effect. A compromised router can see its adjacent link metadata and any inner information legitimately exposed to it; hop protection cannot hide traffic patterns from a relay that forwards the traffic. A compromised Router-CA can issue fraudulent status/certificate material within its authority; trust-anchor pinning does not solve CA compromise. A malformed-message flood can still consume network/CPU resources, so rate limits and parser fuzzing are required. No security claim is accepted until independent review and reproducible tests support it.

## 13. Review status

This is a concrete draft, not a frozen specification. It resolves the proposed message sequence and field inventory at the design level, but the exact Router-CA certificate/status encoding, destination-protection profile, key-update design, and shared cryptographic vectors remain blockers. Do not begin production implementation or claim interoperability until these are resolved and the user has reviewed the specification.
