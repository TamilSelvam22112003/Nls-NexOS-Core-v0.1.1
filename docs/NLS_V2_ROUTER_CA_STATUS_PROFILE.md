# NLS v2 Router-CA Status Evidence Profile — Draft

**Status:** Concrete proposal for review; not frozen.  
**Compatibility:** Separate v2 object; does not change the frozen v1 RDR or v1 wire contract.  
**Owner:** NexOS Core defines issuance and canonical encoding; NetOS verifies without inventing defaults.

## 1. Purpose and trust model

This object binds a router's Ed25519 identity, issued certificate, authorization status, authorized routable endpoints, and two separate X25519 destination-protection public keys to the pinned Router-CA signing key. It is the canonical status evidence consumed by the NLS v2 handshake and destination-protection profile.

The object is not a replacement for the v1 RDR and MUST NOT be parsed as one. The pinned Router-CA Ed25519 public key verifies this object's signature. The router's X.509 leaf certificate is separately validated to the configured CA trust anchor; its Ed25519 public key and serial must match the status object.

## 2. Exact object encoding

The object is exactly `header(8) || body(196 + 19*endpoint_count bytes) || signature(64)`. All multi-byte integers are unsigned big-endian.

### Header

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `NLS2` |
| 4 | 1 | object_type | `0x01` = Router status evidence |
| 5 | 1 | schema_version | `0x01` |
| 6 | 2 | body_length | Exact body length; MUST equal `196 + 19*endpoint_count` |

### Body

| Body offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | status | `1 ACTIVE`, `2 REVOKED`, `3 SUSPENDED` |
| 1 | 1 | endpoint_count | 1–8 for ACTIVE; 0–8 for REVOKED/SUSPENDED |
| 2 | 2 | reserved | MUST be zero |
| 4 | 8 | generation | Nonzero monotonically increasing per router |
| 12 | 8 | issued_at_unix_ms | Unix milliseconds |
| 20 | 8 | expires_at_unix_ms | Unix milliseconds, strictly greater than issued_at |
| 28 | 32 | router_identity_fingerprint | SHA-256 of canonical DER SubjectPublicKeyInfo for router Ed25519 identity key |
| 60 | 8 | certificate_serial | Positive X.509 serial, restricted to 1..2^64−1 |
| 68 | 32 | certificate_der_sha256 | SHA-256 of exact DER leaf certificate |
| 100 | 16 | sender_auth_key_id | First 16 bytes of SHA-256(`ASCII("NLS2-DEST-SENDER-AUTH-KEY") || 0x00 || sender_auth_X25519_public_key[32]`) |
| 116 | 32 | sender_auth_x25519_public_key | Raw X25519 public key used only for HPKE Auth-mode sender authentication |
| 148 | 16 | recipient_key_id | First 16 bytes of SHA-256(`ASCII("NLS2-DEST-RECIPIENT-KEY") || 0x00 || recipient_X25519_public_key[32]`) |
| 164 | 32 | recipient_x25519_public_key | Raw X25519 public key used only for HPKE recipient decryption |
| 196 | 19 each | authorized_endpoint | Repeated endpoint tuple described below |

Each endpoint tuple is `address_family:u8(6) || ipv6_address[16] || udp_port:u16`; port must be 1..65535. Tuples MUST be sorted lexicographically by the 16 address bytes, then numeric port, with no duplicates. IPv4-mapped IPv6 addresses, unspecified addresses, multicast addresses, and loopback addresses are forbidden for advertised WAN endpoints. ACTIVE status requires at least one authorized endpoint.

### Signature and exact total length

The signature is a 64-byte Ed25519 signature by the pinned Router-CA signing key over:

`ASCII("NLS2-ROUTER-STATUS") || 0x00 || header[8] || body[body_length]`.

The signature is not included in the signed bytes. The complete object length MUST equal `8 + body_length + 64` (minimum 268 bytes, maximum 420 bytes). Trailing bytes are rejected. No alternate encodings, omitted fields, padding, or normalization are permitted.

## 3. Validation procedure

A verifier MUST perform bounded structural checks before signature verification, then validate the CA signature before trusting any field. After signature verification:

1. Validate status enum, reserved bytes, exact lengths, endpoint count/order/uniqueness, and key-ID recomputation.
2. Validate the leaf certificate chain and validity period against the configured Router-CA trust anchor.
3. Recompute the router identity fingerprint from the leaf certificate's Ed25519 SPKI; require equality with `router_identity_fingerprint`.
4. Require the certificate serial and SHA-256 of the exact leaf DER to match the object.
5. Require each X25519 public key to be a valid raw 32-byte encoding; reject all-zero or unusable X25519 public keys during key agreement. The public-key role is determined by its distinct field and key ID.
6. Validate endpoint binding against the actual configured/selected endpoint and local routing policy; an endpoint in this object is authorization evidence, not a route.
7. Enforce freshness and per-router generation rules below before using the object for a new handshake or destination-protection flow.

A malformed or invalid object MUST NOT update a cache, promote a peer to ACTIVE, install a route, or tear down a currently valid peer merely because an unauthenticated invalid object claims revocation. A valid higher-generation REVOKED/SUSPENDED object MUST invalidate trust and terminate affected sessions according to the revocation policy.

## 4. Freshness and generation

Default profile limits:
- Maximum object lifetime: 300 seconds (`expires_at - issued_at <= 300000 ms`).
- Maximum tolerated future issue time: 30 seconds.
- Object is expired when current time is greater than `expires_at`.
- `issued_at` must not be later than now + 30000 ms.
- `generation` must be nonzero and strictly increase when status, certificate binding, endpoints, or either destination key changes.

For a router with a cached verified object:
- Lower generation: reject as rollback.
- Same generation and byte-identical object: accept only while fresh.
- Same generation but different object bytes: reject and raise an equivocation/security event.
- Higher generation: accept only after full signature/certificate/freshness validation; atomically replace cached state and invalidate sessions/flows no longer authorized by the new object.

For new sessions and new destination-protection flows, require a fresh object. During CA outage, fail closed for new sessions/flows. Existing established sessions may use the separately documented, bounded stale-status grace policy; a valid revocation push terminates affected sessions within 30 seconds. Do not silently extend expiry.

## 5. Status mapping and key rotation

V2 status values are ACTIVE=1, REVOKED=2, SUSPENDED=3. Core's existing v1 registry status DISABLED maps to v2 SUSPENDED; it MUST NOT be encoded as an undocumented fourth value.

This profile authorizes one active sender-authentication X25519 key and one active recipient-decryption X25519 key per router. Key rotation changes the corresponding public key/key ID and increments generation. The first profile does not authorize overlapping key generations; packets naming a superseded key are rejected. Key erasure, backup, and local file permissions remain operational requirements.

CA signing-key rotation and multi-node CA high availability are out of scope for v0.1.1 and require a separate trust-anchor rollover procedure.

## 6. Implementation and test gates

Core must expose one canonical encoder and verifier for this object. NetOS must consume the same byte-level fixture set and must not independently reserialize fields for signature verification.

Required vectors include ACTIVE with one and eight endpoints; REVOKED/SUSPENDED with zero endpoints; wrong body length; unknown status; nonzero reserved bits; unsorted/duplicate endpoints; invalid port; bad CA signature; certificate/serial/fingerprint mismatch; key-ID mismatch; expired/future/overlong object; generation rollback; same-generation equivocation; and valid higher-generation key rotation/revocation.

This is a review proposal, not a frozen implementation contract.
