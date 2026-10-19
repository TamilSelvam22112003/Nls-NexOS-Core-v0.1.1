# NLS Protocol Contract v0.1.1

Normative proposed encoding. Multi-byte integers are unsigned big-endian; reserved bytes zero; reject unknown versions/types, malformed lengths and trailing bytes. **Implementation is blocked by P0 questions in ARCHITECTURE.md.**

## UDP common header (12 bytes)
| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | magic ASCII NL (0x4e4c) |
| 2 | 1 | version=1 |
| 3 | 1 | type |
| 4 | 2 | flags=0 |
| 6 | 2 | header_len=12 |
| 8 | 4 | body_len |
Datagram size exactly 12+body_len; types 01 M1_INIT, 02 M1_COOKIE, 03 M2, 04 M3, 05 M4, 10 DATA, 20 ERROR. Handshake datagrams max 1200 bytes.

## TLS control framing (8 bytes)
version:u8=1, type:u8, flags:u16=0, body_len:u32, body; max body 1 MiB. TLS 1.3 mutual auth.
| Type | Message | Body fields in order |
|---:|---|---|
| 01 | ENROLL_REQUEST | request_id[16], credential_id[16], credential_secret[32], csr_len:u32, csr_der[csr_len], features:u32 |
| 02 | ENROLL_RESULT | request_id[16], status:u16, router_id[16], cert_len:u32, cert, issued_at:u64, expires_at:u64, error:u16 |
| 03 | ENROLL_STATUS | request_id[16], status:u16, error:u16 |
| 04 | ENROLL_REVOKE | router_id[16], reason:u16, effective_at:u64, nonce[16] |
| 10 | CONTROL_READY | router_id[16], session_id[16], server_time:u64, policy_gen:u64, revocation_gen:u64 |
| 11 | POLICY_SYNC | generation:u64, payload_len:u32, canonical payload |
| 12 | REVOCATION_SYNC | generation:u64, count:u32, repeated(router_id[16], status:u8, effective_at:u64) |
| 13 | DIRECTORY_LOOKUP | request_id[16], router_id[16] |
| 14 | DIRECTORY_RESULT | request_id[16], status:u16, rdr_len:u32, RDR, error:u16 |
| 15 | HEARTBEAT | sequence:u64, sent_at:u64 |
| 16 | CONTROL_ERROR | related_type:u8, error:u16, detail_len:u16, UTF-8 detail |
Credentials only inside authenticated TLS; never log secrets.

## Certificate and Router Directory Record
Proposed compact canonical binary records, not X.509; this conflicts with Go TLS and is unresolved. Certificate unsigned body 112 bytes: version:u8=1, sig_alg:u8=1 Ed25519, reserved:u16=0, router_id[16], ed25519_pubkey[32], not_before:u64, not_after:u64, serial[16], capabilities:u32, policy_epoch:u64, issuer_key_id[16]. Signature[64] over ASCII `NLS-CERT-v1\0` || body; total 176 bytes.
RDR unsigned body: version:u8=1, sig_alg:u8=1, reserved:u16=0, router_id[16], wan_ipv6[16], udp_port:u16, status:u8 (1 ACTIVE,2 REVOKED,3 DISABLED), reserved:u8=0, cert_len:u16=176, cert[176], generation:u64, issued_at:u64, expires_at:u64, nonce[16]. Signature[64] over `NLS-RDR-v1\0` || unsigned body. TTL 300s; cert max 90 days; one IPv6 endpoint.

## Handshake
Cookie = first 16 bytes HMAC-SHA256(secret, source IPv6[16] || source port:u16 || destination IPv6[16] || destination port:u16 || router_id[16] || bucket:u64). Rotate secret every 10 min; accept current/previous bucket; allocate no state before validation.
- M1_INIT first body 116 bytes: client_nonce[32], initiator_id[16], destination_id[16], ephemeral_X25519_pub[32], suite:u16=1, reserved:u16=0. M1_COOKIE body 56 bytes: client_nonce[32], cookie[16], bucket:u64. M1 echo body 132 bytes: first body + cookie[16].
- M2: responder_nonce[32], responder_ephemeral_pub[32], responder_id[16], sealed_len:u16, sealed bytes. Plaintext certificate[176]+transcript_hash[32]. Envelope nonce[12]+ciphertext+tag[16]. Proposed key HKDF-SHA256(X25519 secret, salt=both nonces, info=`NLS-v1 M2`||both IDs, L=32).
- M3: initiator_id[16], sealed_len:u16, envelope. Plaintext certificate[176]+transcript_hash[32]+key_confirm[32]. Proposed HKDF info `NLS-v1 M3`||both IDs; AAD binds M1+M2 bytes.
- M4: sealed plaintext session_id[16]+responder_key_confirm[32]+transcript_hash[32]+status:u16=0 (82 bytes). Envelope nonce[12]+ciphertext[82]+tag[16]=110 bytes. Proposed key HKDF info `NLS-v1 confirm`||transcript hash.
Suite 1 = Ed25519+X25519+HKDF-SHA256+AES-256-GCM; no downgrade/fallback. **Owner must finalize transcript sequencing and M2/M3 key schedule before implementation.**

## Data plane
Outer IPv6(40)+UDP(8)+NLS header(32)+ciphertext(entire inner IP packet)+tag(16). Header is AAD: offset 0 magic[2] NL, 2 version:u8=1, 3 type:u8=0x10, 4 flags:u16=0, 6 header_len:u16=32, 8 session_id[16], 24 sequence:u64. Nonce direction_salt[4]||sequence:u64; separate keys/salts per direction; sequence starts at 1 and never wraps. Replay window 1024; authenticate before advancing. Rekey at 2^32 packets or 1h; stop at 2^32+2^20 if rekey fails.

Error codes: enrollment 0000 OK, 0001 BAD_CREDENTIAL, 0002 BAD_CSR, 0003 NOT_AUTHORIZED, 0004 ALREADY_ENROLLED, 0005 REVOKED, 0006 POLICY_DENIED, 0007 INTERNAL. Control 0100 UNKNOWN_ROUTER, 0101 REVOKED, 0102 STALE_GENERATION, 0103 BAD_SIGNATURE, 0104 RATE_LIMITED, 0105 INVALID_MESSAGE, 0106 UNAVAILABLE. Handshake 0200 BAD_VERSION, 0201 BAD_LENGTH, 0202 BAD_COOKIE, 0203 BAD_SIGNATURE, 0204 REVOKED, 0205 UNKNOWN_ROUTER, 0206 BAD_TRANSCRIPT, 0207 BAD_TAG, 0208 UNSUPPORTED_SUITE, 0209 CA_UNAVAILABLE, 020a RATE_LIMITED, 020b TIMEOUT. Data 0300 UNKNOWN_SESSION, 0301 REPLAY, 0302 BAD_TAG, 0303 TOO_LARGE, 0304 POLICY_DROP.
