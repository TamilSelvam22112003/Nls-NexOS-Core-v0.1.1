# NLS v2 Destination-Protection Handshake (Draft)

Status: proposal for review; not frozen. This document extends, but does not replace, NLS_V2_DESTINATION_PROTECTION_PROFILE.md. NLS v1 and adjacent-hop handshake behavior remain unchanged.

## 1. Scope and transport

This handshake establishes a source-to-destination NLS session whose keys are unavailable to transit relays. The records are carried inside the existing hop-protected path. Transit relays forward the destination-control records without changing their bytes or terminating the exchange. Outer hop addresses and ports are deliberately excluded from the end-to-end transcript because relays legitimately change them.

All integers are unsigned big-endian. A plaintext control record begins with a 4-byte prefix: message_type (1 byte), flags (1 byte, zero), reserved (2 bytes, zero), followed by TLVs. Each TLV is type (uint16), length (uint32), value (exact bytes). TLVs must be strictly ascending by full type, unique, bounded, and without padding or trailing bytes. All listed TLVs are critical. Message type codes are 0x11 D_INIT, 0x12 D_RESP, 0x13 D_FINISH_I, and 0x14 D_FINISH_R.

Suite 0x0001 uses Ed25519 identity signatures, ephemeral X25519, HKDF-SHA-256, and AES-256-GCM. Router identity is SHA-256 over DER SubjectPublicKeyInfo. Status evidence uses the fixed 304-byte candidate object in [ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md](ROUTER_CA_STATUS_EVIDENCE_PROFILE_V2.md). The validated certificate binds the identity and serial; the ACTIVE, fresh status object authorizes endpoint tuples. Local policy must also permit the peer/flow before session activation.

## 2. D_INIT (0x11)

Required TLVs, in exact ascending order:
- 0x8011 e2e_session_id: 16 random bytes, nonzero; must be unique among active sessions at both endpoints.
- 0x8012 initiator_router_id: 32-byte identity fingerprint.
- 0x8013 responder_router_id: 32-byte identity fingerprint.
- 0x8014 initiator_certificate_chain: uint32 count followed by repeated uint32 certificate_length plus exact DER certificate bytes, leaf first; lengths must be nonzero and bounded, total at most 4 KiB.
- 0x8015 initiator_status_object: exactly 304 bytes.
- 0x8016 nonce_i: 32 fresh CSPRNG bytes.
- 0x8017 ephemeral_x25519_i: 32-byte X25519 public key.
- 0x8018 suite_id: exactly two bytes, 0x0001.
- 0x8019 initiator_signature: exactly 64-byte Ed25519 signature.

D_INIT signature input is `ASCII("NLS2-E2E-HS-SIG") || 0x00 || canonical_D_INIT_without_signature_TLV`, where the canonical control record includes its 4-byte control prefix (including message_type 0x11) and TLVs 0x8011–0x8018 in exact encoded order. Do not append a second message-type byte outside the control record. The signature binds both identities, session ID, certificate/status evidence, nonce, ephemeral key, and suite. The receiver validates bounds before parsing large objects and applies per-authenticated-hop rate/concurrency limits.

## 3. D_RESP (0x12)

Required TLVs:
- 0x8021 e2e_session_id: the exact ID from D_INIT.
- 0x8022 responder_router_id: 32-byte identity fingerprint.
- 0x8023 responder_certificate_chain: same DER-chain encoding, total at most 4 KiB.
- 0x8024 responder_status_object: exactly 304 bytes.
- 0x8025 nonce_r: 32 fresh CSPRNG bytes.
- 0x8026 ephemeral_x25519_r: 32-byte X25519 public key.
- 0x8027 selected_suite: exactly 0x0001 as a two-byte value.
- 0x8028 responder_signature: exactly 64-byte Ed25519 signature.

D_RESP signature input is ASCII NLS2-E2E-HS-SIG, one zero byte, uint32_be(length of D_INIT), exact encoded D_INIT, uint32_be(length of D_RESP without signature), then the canonical D_RESP control prefix/TLVs excluding responder_signature. The responder signs only after validating the initiator certificate, status, role, signature, and session-ID collision state. The initiator validates the responder chain/status/role, identity, selected suite, and signature before deriving keys. Unsupported suite, identity mismatch, stale/revoked status, or any signature failure aborts the exchange.

## 4. Transcript and key derivation

Let transcript_hash be SHA-256 of ASCII NLS2-E2E-TRANSCRIPT, one zero byte, uint32_be(length of D_INIT), exact encoded D_INIT, uint32_be(length of D_RESP), and exact encoded D_RESP including signatures. No outer IPv6/UDP fields are included.

Both endpoints compute X25519(ephemeral_private_local, ephemeral_public_peer) and reject an all-zero shared secret. Let salt be SHA-256 of ASCII NLS2-E2E-HS-SALT, one zero byte, nonce_i, nonce_r, and transcript_hash. HKDF-SHA-256 uses the X25519 shared secret as input keying material. Derive 32-byte keys with these exact info labels:
- NLS2 E2E initiator-to-responder handshake key v1
- NLS2 E2E responder-to-initiator handshake key v1
- NLS2 E2E initiator-to-responder data key v1
- NLS2 E2E responder-to-initiator data key v1

Keys are separate from adjacent-hop keys and from one another. Data keys must not be used until D_FINISH_R validates. Any change to canonical bytes, domain strings, or labels changes the protocol and requires new vectors.

## 5. D_FINISH_I and D_FINISH_R

Encrypted finish records use a fixed 24-byte header: message_type (1 byte), flags (1 byte zero), reserved (2 bytes zero), e2e_session_id (16 bytes), ciphertext_length (4 bytes, includes the 16-byte GCM tag). The exact 24-byte header is AEAD associated data. The nonce for each directional handshake key is uint32_be(0) concatenated with uint64_be(0); each key is used for only one logical finish plaintext, and retransmission must resend identical bytes.

D_FINISH_I (0x13) uses the initiator-to-responder handshake key and contains transcript_hash (32 bytes) plus initiator_status_generation (8-byte unsigned integer). D_FINISH_R (0x14) uses the responder-to-initiator handshake key and contains transcript_hash (32 bytes), responder_status_generation (8-byte unsigned integer), and session_lifetime_seconds (4-byte unsigned integer). The decrypted plaintext length is exact; no trailing bytes are allowed. Each finish status_generation must equal the generation in that endpoint's validated signed status object.

The responder installs the session only after D_FINISH_I AEAD and transcript validation succeed and after its D_FINISH_R bytes are committed to the bounded retransmission cache. The initiator installs the session only after D_FINISH_R AEAD and transcript validation succeed. Duplicate finish records are idempotent and must not create duplicate sessions. A mismatched session ID, transcript, status generation, or lifetime outside local policy aborts activation.

## 6. Failure, replay and lifecycle

- Pending exchanges are bounded by per-hop, global, and per-identity limits; expire on a configured deadline; and are removed atomically on failure.
- All-zero X25519 shared secrets, bad signatures, unknown or unsupported fields, non-canonical TLVs, stale/revoked status, invalid role, and session-ID collision are rejected.
- The session ID is not an identity or route. It is an opaque demultiplexing value only.
- Destination data uses the 72-byte envelope header and nonce rule in NLS_V2_DESTINATION_PROTECTION_PROFILE.md. Each direction has a separate key and replay window.
- Until authenticated rekey and crash-safe sequence persistence are defined, sessions have bounded lifetime and must be discarded on restart or uncertain sequence state. Do not resume with uncertain nonce state.
- Transit relays never receive destination traffic keys. The destination endpoint validates and decrypts; a separate secure delivery boundary is required if the actual server is not that endpoint.

## 7. Mandatory vectors before implementation

A positive deterministic vector for D_INIT/D_RESP encoding and signatures, transcript hash, X25519 shared secret, HKDF salt and all four keys, and both FINISH headers/AAD/nonces/plaintexts/ciphertexts/tags is committed at `tests/v2_vectors/destination_handshake_001.json`; `destination_handshake_001_test.go` independently checks these values with Go's standard library. CI verification is pending. Remaining mandatory negatives include invalid/expired/revoked status, wrong certificate/status binding, unknown suites/downgrade, session-ID collision, duplicate/reordered finish handling, timeout/race behavior, and parser resource caps. This draft is not interoperable or implementation-ready until both repositories pass the full positive/negative suite and the wire/status profiles receive independent review.
