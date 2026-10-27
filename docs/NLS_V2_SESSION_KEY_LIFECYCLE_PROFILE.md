# NLS v2 Session-Key Lifecycle Profile (Proposal)

**Status:** Candidate lifecycle contract for review; not frozen. NLS v1 and existing runtime behavior remain unchanged.
**Scope:** Adjacent-hop and destination-protection ephemeral sessions. This profile does not define an authenticated KEY_UPDATE message.

## 1. Design decision

NLS v2 sessions are **ephemeral and never resumed across process restarts**. Session keys, ephemeral private keys, sequence counters, replay windows, pending handshakes, and active session-token mappings MUST NOT be persisted for restoration. On every process start, the session table starts empty and every session requires a fresh authenticated handshake with fresh ephemeral X25519 key pairs. Any recovered or partially written session state MUST be discarded.

This avoids depending on crash-safe persistent nonce counters. It does not excuse reusing a key/nonce within a process: each directional AEAD key still has a single, strictly increasing sequence space.

## 2. Initial profile limits

The following are conservative **proposal defaults** and MUST be configurable within locally enforced upper bounds:

- Maximum established-session lifetime: 3,600 seconds.
- Maximum plaintext protected by one directional AES-256-GCM key: 2^36 bytes (64 GiB), counted before encryption.
- Maximum protected packets per direction: 2^32.
- Initial key_epoch: zero. KEY_UPDATE is unsupported; do not increment the epoch locally.
- Initial DATA sequence_number: zero independently per direction and session.
- FINISH_I and FINISH_R each use their own directional handshake key with nonce 0; these keys are never used for any other message.
- Before the first applicable limit is reached, the sender MUST stop sending on that session and establish a fresh session with fresh ephemeral keys. If re-establishment fails, PROTECT traffic MUST be dropped or held in a strictly bounded queue; plaintext fallback is forbidden.

The byte, packet, and lifetime caps apply separately to each directional data key. Implementations MUST also respect AES-GCM's algorithmic input limits and stricter local cryptographic policy.

## 3. Nonce and concurrency invariants

For each directional DATA key, nonce is uint32_be(key_epoch) || uint64_be(sequence_number). The sequence allocator MUST be atomic with respect to concurrent packet encryption: two goroutines/threads must never obtain the same sequence number under one key. Reserve a sequence number before encryption; if encryption fails after reservation, the number is burned and MUST NOT be reused. Sequence numbers never wrap.

A retransmission MUST resend the exact original serialized datagram bytes. It MUST NOT re-encrypt a different plaintext under the original nonce. FINISH retransmission follows the same byte-for-byte rule.

The receiver authenticates before committing replay-window state. Replay-window check-and-mark MUST be atomic so concurrent copies of a packet cannot both be accepted.

## 4. Shutdown, restart, and crash behavior

- Graceful shutdown stops new protected sends, expires/closes sessions, drops in-memory session and replay state, and makes a best-effort wipe of key buffers.
- Startup MUST NOT load session keys, ephemeral private keys, sequence counters, or replay windows from disk, snapshots, caches, or crash-recovery files.
- A crash/restart always invalidates every prior session. The new process starts with an empty session table and fresh ephemeral keys. It MUST NOT restore an old session token as active.
- A sequence number reserved before a crash is irrelevant after restart because its directional key is not resumed. This invariant depends on never persisting/resuming session keys.
- Diagnostic logs, core dumps, telemetry, crash reports, and support bundles MUST NOT include private keys, derived session keys, cookie secrets, plaintext protected packets, or full status objects unless an explicitly reviewed test-only fixture requires them.
- If a platform, fork model, VM snapshot, or hot-reload mechanism can duplicate live process memory and resume the same key state, it MUST be disabled for the protocol process or treated as a session-invalidating event before any further encryption.

## 5. Session replacement and simultaneous handshakes

The implementation MUST allow at most one active session per (peer identity, direction, protocol profile) unless a separate multi-session policy is explicitly specified. Concurrent handshakes may be pending under bounded limits, but activation is atomic. The winning session is installed only after the complete handshake confirmation validates; losing or superseded handshakes erase ephemeral private material and derived keys.

When replacing a session, send authenticated CLOSE if possible, stop allocating new sequence numbers under the old session, atomically detach its forwarding reference, and erase old key material best-effort. A delayed packet from an old session MUST fail session-token/key lookup and MUST NOT recreate the old session.

## 6. Required tests

1. Concurrent sequence allocation returns no duplicate values under stress.
2. A failed encryption burns its sequence number.
3. Sequence limit, byte limit, packet limit, and lifetime each stop transmission before the configured bound.
4. Retransmission returns byte-identical datagrams and never re-encrypts changed plaintext under a reused nonce.
5. Graceful restart and simulated crash/restart load no previous session/key/sequence/replay state.
6. Replayed packets from a pre-restart session are rejected after restart.
7. Concurrent replay copies cannot both pass check-and-mark.
8. Concurrent same-peer handshakes activate at most one session; losing keys are discarded.
9. Snapshot/fork/hot-reload test verifies session invalidation or the mechanism is explicitly unsupported.
10. Secret redaction tests cover logs, metrics, diagnostics, and error paths.

## 7. Remaining review boundary

This profile makes the restart policy explicit by prohibiting session resumption; it does not make KEY_UPDATE available. A future authenticated rekey protocol requires a separately reviewed message, transcript/key derivation, epoch transition rules, old/new key overlap policy, replay-state transition, simultaneous-update behavior, and byte-exact positive/negative vectors. Until then, sessions are bounded and replaced by a new full handshake.

The profile is a design proposal. It is not evidence that runtime session management, atomic sequence allocation, key erasure, or restart tests have been implemented.