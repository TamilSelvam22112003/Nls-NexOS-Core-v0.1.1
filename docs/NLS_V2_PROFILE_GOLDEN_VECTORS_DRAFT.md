# NLS v2 Profile Golden Vectors (Draft)

**Status:** Python and Go checks validate the status prefix/signature, but an initial full-object test exposed twelve extra zero bytes; the fixture is corrected to exactly 304 bytes, and the decimal serial input now matches the encoded uint64; a fresh CI result is pending. The destination-envelope vector is checked by Go standard-library AES-GCM against Python cryptography output. One deterministic D_INIT/D_RESP/D_FINISH fixture and Go verifier are committed; CI verification is pending. Broader adjacent-hop, parser/policy, and adversarial suites remain open; these are draft vectors, not a frozen protocol contract.
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

## Vector 3 — Destination endpoint handshake and FINISH records

The exact deterministic fixture is committed as [`tests/v2_vectors/destination_handshake_001.json`](../tests/v2_vectors/destination_handshake_001.json); the independent Go verifier is [`destination_handshake_001_test.go`](../tests/v2_vectors/destination_handshake_001_test.go). It contains valid synthetic X.509 chains, two signed 304-byte status objects, exact D_INIT/D_RESP records, both signature inputs as reconstructed from the canonical records, the transcript hash, X25519 shared secret, HKDF salt/PRK and four derived keys, and both FINISH headers/AAD/nonces/plaintexts/ciphertexts/tags.

Expected D_INIT length: 881 bytes. Expected D_RESP length: 843 bytes. Expected transcript hash: `274204ad7036b3700d2f574a503bcdd5eaf682017801810fa9c0cb849ec99296`. Expected X25519 shared secret: `559ed2171b98fa0c0f417b78b5c5a43e971990d7605860038d940284d3245142`. Expected HKDF salt: `c34d503f4e6a28cbce03d1b5ed1a7c8138ede754af66807ea6e6028d0d2bded5`.

This fixture is deterministic test material only. The Go test is intended to independently verify certificate paths, status signatures/bindings, control TLV canonicalization, D_INIT/D_RESP signatures, transcript, X25519, HKDF outputs, and both FINISH AEAD records. CI verification is pending; the fixture is not an interoperability claim.

## Conformance caveats
These two vectors cover the fixed-width status-object encoding/signature and the 72-byte destination data-envelope AES-256-GCM framing. The destination envelope was generated with Python cryptography and is checked by Go's standard-library AES-GCM implementation. The status vector tests a synthetic certificate fingerprint, not X.509 path validation. The destination endpoint handshake still lacks byte-exact shared vectors; authenticated adjacent-hop key update, crash-safe nonce lifecycle, parser/policy fuzzing, and full Router-CA integration remain open. Passing these vector tests does not make NLS v2 interoperable or production-ready.
