# NLS v2 Profile Golden Vectors (Draft)

**Status:** Deterministic candidate vectors generated and locally verified; not yet consumed by repository tests or independently verified by a second implementation.
**WARNING:** All keys, identities, and certificate bytes below are synthetic TEST-ONLY values. Never use them in production.
**Generator:** Python `cryptography 46.0.4`; vector revision `nls-v2-profiles-proposal-2026-10-27`.

## Vector 1 — Router-CA status evidence, valid signature

Inputs:
- Router Ed25519 seed: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- Router SPKI DER: `302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`
- Router identity fingerprint SHA-256: `a050837d85070582ccf7394b0988847cc312cb88259b894899f6f239cf1791a5`
- Synthetic certificate bytes (not a real X.509 certificate): `4e4c532d56322d544553542d4f4e4c592d43455254494649434154452d4445522d3031`
- Certificate fingerprint SHA-256: `85f8abee2197c75967efef4c3d9e665f200bda03633881b03fe9a750d2be4ddd`
- Status signing Ed25519 seed: `a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf`
- Status: ACTIVE (1); serial 1; generation 7; issued_at 1800000000; expires_at 1800000300; endpoint `2001:db8::1:4433/UDP`.
- Signature input: `ASCII("NLS2-ROUTER-STATUS") || 00 || signed_prefix`, where signed_prefix is exactly 240 bytes.

Expected signed prefix (hex):
`4e3253540101000000000130a050837d85070582ccf7394b0988847cc312cb88259b894899f6f239cf1791a585f8abee2197c75967efef4c3d9e665f200bda03633881b03fe9a750d2be4ddd00000000000000010000000000000007000000006b49d200000000006b49d32c0100000020010db800000000000000000000000111510000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`

Expected Ed25519 signature (64 bytes):
`73c3895d24989ac062abf78485f126adc3c573d306746a27e04e9ef7b89fc9d724c6fa0f5c51dd5b7dbf4fb98c87264907a781f0ced52bf24b9fa5da0a380903`

Expected object length: 304 bytes. Verification succeeded using the corresponding synthetic status-signing public key. Negative checks required: flip any signature bit → reject; total_length 303 → reject; lower generation than previously accepted → reject rollback.

## Vector 2 — Destination envelope, valid AES-256-GCM

Inputs:
- Recipient Ed25519 seed: `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`
- Recipient SPKI DER: `302a300506032b657003210029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7`
- Recipient fingerprint SHA-256: `824c89aa8efb95ef93629b4519599129cace4adac9a6180daba31ceed41ecee6`
- AES-256-GCM test key: `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f`
- Session ID: `11111111111111111111111111111111`; epoch 0; sequence 0; nonce `000000000000000000000000`.
- Plaintext IPv6 packet (40 bytes): `6000000000003b4020010db800000000000000000000000120010db8000000000000000000000002`

Expected 72-byte header/AAD:
`4e3244450100004811111111111111111111111111111111000000000000000000000000824c89aa8efb95ef93629b4519599129cace4adac9a6180daba31ceed41ecee600000038`

Expected ciphertext plus 16-byte tag (56 bytes):
`3a3430789468e9ebf88a954b3ffd62462f82009e9616b1509ba5d045ee301246c333b9821c9f04437ca9b2b95566ae9e054f1fb97cc35589`

Expected total envelope length: 128 bytes. Local decryption round-trip succeeded. Flipping the final tag bit was rejected. Additional required negatives: change recipient fingerprint without recomputing tag → reject authentication; append a byte → reject length; unknown session ID → reject session lookup.

## Conformance caveats
These are two profile-level vectors, not complete NLS v2 interoperability vectors. The endpoint handshake encoding, its canonical transcript, authenticated key update, crash-safe nonce lifecycle, and full certificate validation remain unspecified. Repository CI has not yet consumed these vectors, and a second independent implementation/reviewer must verify them before they become release gates.
