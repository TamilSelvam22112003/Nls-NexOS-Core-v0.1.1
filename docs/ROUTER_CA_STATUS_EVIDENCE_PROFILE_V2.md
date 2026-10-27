# Router-CA v2 Certificate and Status-Evidence Profile (Proposal)

**Status:** Core-owned proposal for review; not frozen. Existing APIs and NLS v1 remain unchanged.
**Purpose:** Define canonical identity, endpoint authorization, and signed status evidence required by NLS v2.

## 1. Encoding and cryptographic suite
Status evidence is fixed binary encoding, not JSON/YAML or implementation-dependent serialization. Integers are unsigned big-endian; IPv6 addresses are 16 network-order bytes. No padding, duplicate fields, unknown fields, or trailing bytes. Suite 0x0001 uses Ed25519. The status-signing key is pinned out of band; a status object cannot select or replace the trust anchor. Signatures use domain separation.

## 2. Router identity and certificate profile
Router identity fingerprint is SHA-256 of the DER SubjectPublicKeyInfo for its Ed25519 identity public key. A v2 certificate MUST bind that identity, unique certificate serial, public key, permitted NLS role(s), one or more authorized WAN endpoints (IPv6 address + UDP port), validity interval, and profile version. Validation checks chain signatures, validity, key usage, basic constraints, supported algorithms, and identity fingerprint. A received packet's claimed address alone never authorizes an endpoint. NAT rebinding is unsupported unless separately specified.

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

Before implementation, resolve X.509 profile/OIDs/SAN representation, serial extraction/width, status-signing key rotation, revocation-push transport, clock rollback, and compatibility with the existing Core registry schema. Do not change deployed APIs or runtime code until this proposal is reviewed.
