# NLS v2 Destination Protection (Draft)

Status: proposal only; not frozen. NLS v1 remains unchanged.

## Boundary

This profile protects the inner packet between source and destination NLS security endpoints. Transit relays must not possess destination-session keys. Relays can still observe outer IPv6/UDP endpoints, lengths, timing and volume, and can drop, delay, duplicate or reorder traffic. This does not by itself authenticate the original host application.

## Proposed handshake

Carry end-to-end destination control records as opaque content inside adjacent-hop envelopes: D_INIT, D_RESP, D_FINISH_I and D_FINISH_R. The exchange binds protocol version, suite, both router identities, endpoint roles, fresh nonces, ephemeral X25519 public keys and a random exchange ID. Use Router-CA-certified Ed25519 identity keys to sign the canonical transcript; validate fresh ACTIVE status and endpoint-role authorization at both ends. Transit relays forward these records without terminating the destination handshake.

Proposed primitives: Ed25519, ephemeral X25519, HKDF-SHA-256 and AES-256-GCM. Reject all-zero shared secrets. Derive distinct directional destination keys using transcript-bound, domain-separated labels. Never reuse adjacent-hop keys for destination protection or treat the hop token as a destination token. Exact binary encodings, transcript bytes and key labels require shared golden vectors before implementation.

## Data and replay

The protected plaintext is a bounded record containing version, record type, sequence number, payload length and exact payload. Authenticate the record header, destination token, direction, epoch and sequence as AEAD associated data. Proposed nonce is uint32_be(epoch) || uint64_be(sequence). Each direction has an independent key and replay window. Authenticate before updating replay state. Until rekey and crash-safe sequence persistence are specified and tested, sessions must be bounded and discarded on restart or nonce-state uncertainty. Retransmit identical bytes; never encrypt different plaintext under a reused nonce.

## Forwarding and tests

Relays decrypt only their adjacent-hop envelope and forward the unchanged destination-protected bytes under the next-hop key. Only the destination NLS endpoint may decrypt the inner envelope. If the server is not that endpoint, a separate secure delivery boundary is required; this draft does not claim application-level end-to-end security to the server.

Tests must cover recipient-only decryption, relay non-decryption, identity/status/role failures, transcript and AEAD tampering, key separation, replay, concurrency, expiry, restart, MTU/PMTU and malformed lengths. Message encoding, transcript, key labels, replay-window width, token lifecycle and session lifetime remain open. Do not claim interoperability until the contract is frozen and vectors pass in both repositories.
