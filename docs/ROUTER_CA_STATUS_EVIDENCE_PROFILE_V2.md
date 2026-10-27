# Router-CA v2 Certificate and Status-Evidence Profile (Proposal)

**Status:** Core-owned proposal for review; not frozen. Existing APIs and NLS v1 remain unchanged.
**Purpose:** Define canonical identity, endpoint authorization, and signed status evidence required by NLS v2.

## 1. Encoding and cryptographic suite
Status evidence is fixed binary encoding, not JSON/YAML or implementation-dependent serialization. Integers are unsigned big-endian; IPv6 addresses are 16 network-order bytes. No padding, duplicate fields, unknown fields, or trailing bytes. Suite 0x0001 uses Ed25519. The status-signing key is pinned out of band; a status object cannot select or replace the trust anchor. Signatures use domain separation.

## 2. Router identity and certificate profile
Router identity fingerprint is SHA-256 of the DER SubjectPublicKeyInfo for its Ed25519 identity public key. The v2 leaf certificate MUST bind that identity key, a unique positive serial in the range 1..2^64-1, and a validity interval. The leaf MUST have BasicConstraints CA=false and KeyUsage digitalSignature; the issuing CA certificate MUST be authorized for certificate signing. The leaf public key MUST be Ed25519. The certificate chain and status object are validated separately; subject names are not router identities.

**Endpoint authorization decision:** the signed 304-byte status object in Section 3 is the sole authorization source for NLS UDP endpoint tuples. No custom X.509 OID or SAN-with-port encoding is required. A certificate SAN may be used for TLS control-channel naming, but it MUST NOT override or independently authorize an NLS WAN UDP endpoint. The status object's certificate fingerprint/serial binds endpoint authorization to the validated identity certificate. All successfully enrolled router identities have the NLS-v2-router role; local policy still decides whether a peer may be used for a particular route or destination. NAT rebinding is unsupported unless separately specified.

## 3. Status object encoding
The status object is exactly 304 bytes. All offsets are from its first byte.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `N2ST` |
| 4 | 1 | version | `0x01` |
| 5 | 1 | status | 1 ACTIVE, 2 SUSPENDED, 3 REVOKED |
| 6 | 2 | flags | MUST be zero |
| 8 | 4 | total_length | MUST be 304 |
| 12 | 32 | router_identity_fingerprint | SHA-256 of identity SPKI DER |
| 44 | 32 | certificate_fingerprint | SHA-256 of exact leaf certificate DER |
| 76 | 8 | certificate_serial | Unsigned big-endian; nonzero |
| 84 | 8 | status_generation | Monotonic per router identity; never reused |
| 92 | 8 | issued_at_unix_seconds | Unsigned Unix seconds |
| 100 | 8 | expires_at_unix_seconds | Must be greater than issued_at |
| 108 | 1 | endpoint_count | 1..4 |
| 109 | 3 | reserved | MUST be zero |
| 112 | 72 | authorized_endpoints | Four 18-byte slots: IPv6 address (16) + UDP port (2), sorted by address then port; unused slots all zero |
| 184 | 56 | reserved | MUST be zero |
| 240 | 64 | signature | Ed25519 signature over the 240-byte prefix |

Canonical signature input is `ASCII("NLS2-ROUTER-STATUS") || 0x00 || status_object_bytes[0:240]`. The 240-byte prefix includes the total_length value 304; append the 64-byte signature to produce the 304-byte object. Maximum evidence remains bounded by the 4 KiB handshake TLV cap.

## 4. Validation rules
A verifier MUST:
1. Check exact size, magic, version, reserved zeros, status enum, endpoint count, sorted endpoints, zero unused slots, and all integer constraints.
2. Verify the signature with the pinned Router-CA status-signing key.
3. Match identity fingerprint, certificate fingerprint, and serial to the validated leaf certificate.
4. Enforce `issued_at <= now + allowed_clock_skew`, `expires_at > now - allowed_clock_skew`, and `expires_at > issued_at`. Local policy bounds lifetime; proposed default maximum is 300 seconds and clock skew 30 seconds.
5. Require ACTIVE for new sessions. SUSPENDED and REVOKED prevent new sessions; default policy invalidates sessions immediately for either state when learned.
6. Reject a generation below the highest accepted generation. Equal generation is accepted only if the whole object is byte-identical; same generation with different bytes is equivocation and MUST be rejected and audited.
7. Verify the relevant observed/advertised endpoint is authorized by both certificate and status evidence.

Generation is monotonic across status transitions. A REVOKED identity cannot return to ACTIVE under the same identity lineage; re-enrollment after revocation requires a new identity key and certificate.

## 5. Outage, cache, and revocation
New protected sessions fail closed without fresh valid evidence. Existing sessions may continue only under explicit bounded stale-status policy; proposed maximum during transient CA outage is 300 seconds for last-known ACTIVE status, and zero for SUSPENDED/REVOKED. Fresh REVOKED status or authenticated revocation event terminates sessions for that identity. CA lookups are authenticated, rate-limited, and audited; private keys are never returned. This draft assumes a pinned Ed25519 status-signing key; key rotation/overlap must be provisioned out of band.

## 6. Required tests and open gates
Test byte-exact status vectors, signature tamper, wrong trust anchor, certificate/status mismatch, stale/future evidence, generation rollback/equivocation, endpoint mismatch, status transitions, CA outage, expiry, malformed lengths, and concurrent cache updates.

## 6. Control-plane delivery, clock rollback, and registry compatibility

### 6.1 V2 status push over the existing mTLS control channel
The v1 `REVOCATION_PUSH` TLV (0x0030) and its 16-byte router IDs remain unchanged. A v2-capable control channel MAY negotiate a separate `ROUTER_STATUS_PUSH_V2` TLV (0x0031), whose value is:

- `control_generation:u64` — monotonically increasing CA event generation;
- `entry_count:u16` — 1..8;
- `reserved:u16` — zero;
- repeated entries sorted by 32-byte router identity fingerprint:
  - `router_identity_fingerprint[32]`;
  - `status_generation:u64`;
  - `status_object_length:u16` — exactly 304;
  - `status_object[304]`.

The TLV value length MUST equal `12 + entry_count * 346` and remain below the configured control-message cap. The receiver verifies every status object, requires its identity and generation to match the entry, and applies the batch atomically. Duplicate/unsorted identities, stale control generations, invalid signatures, and generation rollback reject the batch. The ACK TLV `ROUTER_STATUS_PUSH_ACK_V2` (0x0032) has value `control_generation:u64 || status:u16 || error_code:u16`; status is 0 accepted or 1 rejected. These TLVs are sent only after explicit v2 control capability negotiation; v1 control messages are not changed. A fresh REVOKED/SUSPENDED object invalidates sessions for that identity immediately after successful application.

### 6.2 Clock rollback
Maintain a durable wall-clock high-water mark and use a monotonic clock for elapsed-time cache limits within a process. If wall time falls more than the configured 30-second skew behind the persisted high-water mark, fail closed for new handshakes and new destination-protection sessions, emit an operator-visible clock-integrity event, and do not extend any status object's validity. Resume only after time is corrected or an explicit privileged recovery procedure resets the clock high-water mark with an audit record.

### 6.3 Core registry compatibility
Do not change the v1 RDR layout, existing APIs, or v1 16-byte router IDs. Store the v2 status object and its 32-byte identity-fingerprint index as a versioned sidecar/record keyed by the SHA-256 identity fingerprint. Core must explicitly map a v1 registry identity to the corresponding v2 identity certificate; it MUST NOT truncate a 32-byte fingerprint or silently reinterpret a v1 router ID as a v2 fingerprint.

### 6.4 Remaining operational gate
The status-object byte layout, signature input, serial width, endpoint encoding, freshness, generation, and v2 push transport are now specified as a proposal. Out-of-band trust-anchor rotation remains a deployment prerequisite; it is intentionally not negotiated by an untrusted status object. Do not change deployed APIs or runtime code until this proposal is reviewed.
