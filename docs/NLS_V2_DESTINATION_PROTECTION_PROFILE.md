# NLS v2 Destination-Protection Profile (Proposal)

**Status:** Design proposal for security review; not frozen and not implementation-ready.  
**Compatibility:** NLS v1 remains unchanged. This profile is separately versioned and applies only to NLS v2.  
**Security boundary:** Only the source security endpoint and final destination security endpoint hold this profile's traffic keys. Transit relays must never receive these keys.

## 1. Goals and non-goals

This profile specifies a candidate end-to-end encrypted inner envelope independent of adjacent-hop encryption. Hop protection prevents a transit network from reading the current hop envelope; destination protection prevents authorized transit relays from reading the original inner packet. These are separate protections and require separate key material.

It does not hide outer IPv6 relay addresses, UDP ports, lengths, timing, or traffic volume. It does not secure native OSPF/OSPFv3, BGP, RIP/RIPng, IPsec, or TLS automatically. It does not authorize a destination solely from an IP address.

## 2. Endpoint identity and key establishment

The source and destination security endpoints are Router-CA identities, not the current adjacent-hop identities. Each endpoint validates the peer's certificate chain and signed status evidence under the Router-CA profile before creating an end-to-end session.

Candidate establishment reuses the reviewed X25519/Ed25519 primitives but uses a separate end-to-end transcript domain and distinct HKDF labels. The endpoint handshake is carried inside the already authenticated hop-protected forwarding path as opaque control content. Transit relays may forward it but cannot validate or terminate it. The endpoint transcript binds: protocol identifier/version, source and destination router identity fingerprints, source and destination certificate fingerprints, endpoint-status generations, both 32-byte nonces, both ephemeral X25519 public keys, selected suite, and a monotonically unique 16-byte end-to-end session identifier. It MUST NOT bind mutable outer-hop IPv6 addresses/ports because relays legitimately change them.

Use suite 0x0001: Ed25519 signatures, ephemeral X25519, HKDF-SHA-256, AES-256-GCM. Reject all-zero X25519 shared secrets. Authentication signatures use the domain string `NLS2-E2E-HS-SIG\0`; key derivation uses `NLS2-E2E-HS-SALT\0` and distinct labels prefixed with `NLS2 E2E`. Candidate message encodings, signature inputs, transcript hashing, and HKDF context encoding are specified in [NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md](NLS_V2_DESTINATION_HANDSHAKE_DRAFT.md). That separate draft remains an implementation blocker until byte-exact shared vectors and independent review pass. No destination-protection session may be claimed interoperable yet.

## 3. Destination envelope encoding

All integers are unsigned big-endian. No padding, extensions, or trailing bytes are permitted in this profile version.

### 3.1 Fixed 72-byte header

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `N2DE` |
| 4 | 1 | version | `0x01` for this profile |
| 5 | 1 | flags | MUST be zero |
| 6 | 2 | header_length | MUST be 72 |
| 8 | 16 | e2e_session_id | Random opaque session ID, nonzero; unique among active sessions |
| 24 | 4 | key_epoch | Starts at zero; key-update profile is not defined |
| 28 | 8 | sequence_number | Starts at zero independently in each direction |
| 36 | 32 | recipient_key_fingerprint | SHA-256 of recipient Ed25519 public key's canonical DER SubjectPublicKeyInfo |
| 68 | 4 | ciphertext_length | Includes the 16-byte AES-256-GCM tag |

The 72-byte header is AEAD associated data (AAD). The encrypted plaintext is exactly one complete inner IPv4 or IPv6 packet, including its IP header and payload. `ciphertext_length` MUST equal plaintext length + 16 and the total envelope size MUST equal 72 + ciphertext_length. A receiver MUST reject lengths below 16, overflow, truncation, trailing bytes, unsupported version, nonzero flags, wrong recipient fingerprint, unknown session, wrong epoch, or a failed tag before exposing plaintext.

### 3.2 Nonce and replay rules

The nonce is `uint32_be(key_epoch) || uint64_be(sequence_number)`, exactly 12 bytes. Each directional key is independent. The sender MUST never encrypt different plaintext under the same directional key/nonce. Sequence numbers are strictly increasing per direction and epoch; retransmission repeats the identical serialized envelope bytes. Receiver replay protection uses a 128-packet sliding window with a highest-seen sequence number and bitmap. Authenticate first, then atomically test-and-mark replay state; concurrent duplicate packets must not both be accepted. Duplicate or too-old packets are dropped.

This profile has no key-update message. An endpoint MUST close and re-establish the end-to-end session with fresh ephemeral keys before epoch/sequence exhaustion, on uncertain sequence state after restart, or at the configured maximum session lifetime. If the implementation cannot prove nonce uniqueness, it MUST fail closed and discard the affected session.

### 3.3 Direction and recipient checks

For source-to-destination traffic, `recipient_key_fingerprint` identifies the destination endpoint. For return traffic, it identifies the original source endpoint and uses the reverse directional key. The receiver checks that the envelope's session ID, direction, epoch, and recipient fingerprint match the installed session before decryption. A transit relay forwards the inner envelope byte-for-byte and MUST NOT rewrite its header or attempt to decrypt it.

The inner IPv6 source/destination addresses and transport metadata are confidential to the endpoints. If an intermediate router needs routing information, it uses explicit outer-hop forwarding metadata and policy; it MUST NOT inspect the protected inner IPv6 header.

## 4. MTU, resource, and failure policy

The envelope adds 72 bytes plus a 16-byte tag and is then carried inside the hop-protected NLS packet. Implementations MUST compute the combined overhead from actual framing, honor IPv6 Path MTU Discovery and ICMPv6 Packet Too Big, and define a maximum inner packet size. They MUST NOT rely on IPv6 fragmentation as the normal solution. Before allocation, validate the declared length against local caps.

Any malformed envelope, invalid tag, unknown session, replay, recipient mismatch, expired/revoked peer, or policy denial is a drop. Never fall back to plaintext for traffic classified PROTECT. Log only rate-limited, bounded diagnostic information.

## 5. Required tests and remaining gates

Required tests: byte-exact header/envelope vectors; valid and tampered AEAD; wrong recipient/session/direction/epoch; duplicate and out-of-order packets; concurrent replay race; process restart and sequence uncertainty; session expiry; malformed lengths; maximum packet/PMTU behavior; no transit-relay access to destination keys; and multi-hop forwarding that preserves the inner envelope byte-for-byte.

**Remaining gates:** the separate endpoint-handshake draft must be vector-tested with this envelope; status-generation freshness and revocation interactions need integration tests; authenticated key update and crash-safe session lifecycle remain unspecified; endpoint-handshake golden vectors are not yet committed. This document defines a candidate envelope format, not a complete or interoperable destination-protection protocol.
