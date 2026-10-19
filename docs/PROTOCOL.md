# NLS v0.1.1 Wire Protocol — FROZEN CONTRACT
**Version:** 1 (wire version byte `0x01`) · **Status:** Frozen subject to the Objections/Open section below · **Accepted date:** 2026-10-19

This document is normative. All integers are unsigned big-endian unless stated. Fixed-size messages have exactly the stated size; parsers reject truncation, trailing bytes, duplicate fields, non-minimal lengths, unknown critical TLVs, invalid enums, and values outside stated bounds. No implicit padding except where explicitly defined. UDP messages are never fragmented by the protocol. Strings are UTF-8 NFC, no NUL, length-delimited; identifiers are opaque bytes, not strings.

## 1. Cryptographic suite and signature contexts
Suite 1: Ed25519 signatures; X25519 ephemeral DH; HKDF-SHA256; AES-256-GCM; SHA-256. No custom primitives. X25519 all-zero shared secret is rejected. Public keys are 32-byte raw Ed25519/X25519 encodings. Signatures are 64 bytes. Hash is 32 bytes. AES-GCM tag is 16 bytes. Context strings below include the terminating NUL byte and are exact:
- `NLS-v1-ENROLL-CSR\0`
- `NLS-v1-RDR\0`
- `NLS-v1-M2-SIG\0`
- `NLS-v1-M3-SIG\0`
- `NLS-v1-M4-FIN\0`
- `NLS-v1-CONTROL-EXPORT\0`
Signatures sign context || defined canonical bytes (or transcript hash where stated). No X.509 parsing occurs in the data path. One Ed25519 router key is used for RDR and handshake signatures; its X.509 certificate, issued by Router-CA, is only for TLS control-channel mTLS.

## 2. Common framing, enums, errors
UDP datagram prefix is `version:u8(1), type:u8, flags:u16(0), body_len:u16, reserved:u16(0)` (8 bytes), followed by exactly body_len bytes. UDP payload maximum is 1200 bytes in v1. Unknown message type is silently dropped before state allocation. All offsets below are relative to the message body unless stated.

Message type codes: 0x01 M1_INIT; 0x02 M1_COOKIE; 0x03 M2; 0x04 M3; 0x05 M4; 0x10 DATA; 0x11 REKEY_INIT; 0x12 REKEY_ACK. Control TLV type IDs: 0x0001 heartbeat, 0x0002 heartbeat_ack, 0x0010 enrollment_request, 0x0011 enrollment_response, 0x0020 policy_sync, 0x0021 policy_ack, 0x0030 revocation_push, 0x0040 directory_lookup, 0x0041 directory_response, 0x7fff error. TLV critical bit is high bit of type; unknown critical rejects the message, unknown noncritical may be skipped. Control TLV framing: type:u16, length:u32, value[length], big-endian, sorted by type ascending; duplicates forbidden.

Error codes: 0x0001 MALFORMED; 0x0002 UNSUPPORTED_VERSION; 0x0003 BAD_CREDENTIAL; 0x0004 TOKEN_EXPIRED; 0x0005 TOKEN_REUSED; 0x0006 BAD_CA_FINGERPRINT; 0x0007 BAD_SIGNATURE; 0x0008 BAD_COOKIE; 0x0009 COOKIE_EXPIRED; 0x000A REPLAY; 0x000B REVOKED; 0x000C UNKNOWN_ROUTER; 0x000D STALE_RDR; 0x000E POLICY_DENIED; 0x000F NO_SESSION; 0x0010 BAD_TAG; 0x0011 RATE_LIMITED; 0x0012 CA_UNAVAILABLE; 0x0013 EXPIRED_CERT; 0x0014 BAD_TRANSCRIPT; 0x0015 REKEY_REQUIRED; 0x0016 INTERNAL. Control error TLV value = code:u16, offending_type:u16 (0 if none), retry_after_seconds:u32, detail_len:u16, detail UTF-8 bytes; detail <=256 bytes. Errors on unauthenticated UDP are silent drops except M1_COOKIE.

## 3. Enrollment over server-authenticated TLS
Router pins SHA-256 fingerprint of configured Router-CA root certificate and verifies TLS server chain and exact root fingerprint. Enrollment token is single-use, expires within 10 minutes, scoped to one router name and bound to SHA-256(CSR Ed25519 public key). TLS 1.3 server-authenticated only before issuance; mTLS starts after certificate issuance. Token must never appear in logs.

### ENROLLMENT_REQUEST (control TLV 0x0010; router → CA)
Value is fixed prefix plus CSR:
| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 1 | schema_version | u8=1 |
| 1 | 1 | name_len | u8, 1..128 |
| 2 | 2 | token_len | u16, 1..512 |
| 4 | 2 | csr_len | u16, 1..4096 |
| 6 | name_len | router_name | UTF-8 NFC |
| next | token_len | enrollment_token | opaque bytes |
| next | csr_len | csr | canonical DER PKCS#10 with Ed25519 public key |
CSR signature proves possession of the bound private key. Request is TLS protected, not additionally encrypted. TLS authenticates server; token authorizes enrollment.

### ENROLLMENT_RESPONSE (0x0011; CA → router)
| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 1 | schema_version | u8=1 |
| 1 | 1 | status | 1 issued, 2 rejected |
| 2 | 2 | error_code | enum above; zero on issued |
| 4 | 4 | cert_len | u32, 0..8192 |
| 8 | cert_len | router_certificate | DER X.509 Ed25519 cert |
| next | 8 | serial | u64 |
Issued certificate must contain the same public key as CSR. TLS protects response. Validation order: pin root fingerprint → validate TLS → parse bounded request → validate name/token/expiry/single-use/key hash → validate CSR signature → issue certificate and consume token atomically. On any failure return defined error, never issue cert.

## 4. Control channel messages (mTLS TLS 1.3)
All control messages are TLVs inside TLS application data. TLS provides encryption and integrity; do not add independent message encryption. Every request has a unique request_id:u64 first in value where specified. TLS peer certificate must chain to Router-CA; certificate public key/router registry status must be ACTIVE.

### HEARTBEAT / HEARTBEAT_ACK (0x0001 / 0x0002)
Value: request_id:u64, sender_time_unix_ms:u64, control_epoch:u64, last_revocation_generation:u64 (32 bytes). ACK echoes request_id and sender_time, and adds receiver_time_unix_ms:u64 (40 bytes). Validate length exactly, epoch monotonic, clock skew policy configured. Failure closes control session.

### POLICY_SYNC / POLICY_ACK (0x0020 / 0x0021)
POLICY_SYNC value:
| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 8 | generation | u64 |
| 8 | 4 | entry_count | u32, max 4096 |
| 12 | variable | entries | sorted by prefix, unique |
Each entry: action:u8 (1 PROTECT, 2 BYPASS), family:u8 (4 or 6), prefix_len:u8 (0..32 or 0..128), reserved:u8=0, address[4 or 16]. Reject host bits set in prefix, overlap with conflicting actions, duplicate prefixes, unsupported family, and trailing bytes. POLICY_ACK: generation:u64, status:u16 (0 accepted, 1 rejected), error_code:u16. Accepted policy atomically replaces previous policy; absent policy is not permissive. Policy route install is via TUN device nls0; PROTECT missing directory/policy/session means drop, never plaintext.

### REVOCATION_PUSH (0x0030; CA → router)
Value: generation:u64, count:u32 (max 65536), then sorted unique entries router_id[16], status:u8 (1 ACTIVE, 2 REVOKED, 3 DISABLED), reserved[7]=0, effective_unix_ms:u64. Exact size per entry 32 bytes. Generation must increase. Revoked/disabled peer tears down affected sessions within 30 seconds. ACK is POLICY_ACK-shaped status response with generation.

### DIRECTORY_LOOKUP / DIRECTORY_RESPONSE (0x0040 / 0x0041)
Lookup value: request_id:u64, router_id[16]. Response value: request_id:u64, status:u16 (0 found, 1 unknown, 2 revoked, 3 unavailable), rdr_len:u16, rdr[rdr_len]. Online CA lookup required for every new handshake. RDR must be current, signed, status ACTIVE, and expiry valid. Cache TTL default 300s is for lookup optimization only and does not permit a new handshake without successful online freshness check.

## 5. Router Directory Record (RDR v1)
Unsigned body 258 bytes; signature 64 bytes; total signed RDR 322 bytes. Certificate serial and validity bind the router identity to Router-CA issuance. Exactly one endpoint in v1.

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 1 | version | u8=1 |
| 1 | 1 | sig_alg | u8=1 Ed25519 |
| 2 | 2 | flags | u16=0 |
| 4 | 16 | router_id | opaque bytes |
| 20 | 32 | ed25519_public_key | raw Ed25519 |
| 52 | 1 | endpoint_count | u8 MUST equal 1 |
| 53 | 1 | endpoint_family | u8=6 |
| 54 | 16 | endpoint_ipv6 | 16-byte IPv6 |
| 70 | 2 | endpoint_udp_port | u16, 1..65535 |
| 72 | 8 | certificate_serial | u64 |
| 80 | 8 | not_before_unix_ms | u64 |
| 88 | 8 | not_after_unix_ms | u64 |
| 96 | 1 | status | 1 ACTIVE, 2 REVOKED, 3 DISABLED |
| 97 | 7 | reserved | all zero |
| 104 | 8 | generation | u64 |
| 112 | 16 | record_nonce | random |
| 128 | 66 | reserved_extension | zero in v1 |
| 258 | 64 | signature | Ed25519 over context || unsigned body bytes 0..257 |

**Length correction:** the earlier report's 322-byte total was wrong for its earlier proposed field layout (258-byte unsigned body + 64-byte signature arithmetic was correct, but that layout's listed fields did not total 258). This frozen layout explicitly reserves 64 extension bytes: unsigned body = 258, total = 322. Verifier checks canonical fields/reserved zero, signature, validity, status, serial/cert registry binding and endpoint_count=1. Expiry and status checked before use.

## 6. Handshake and transcript
Pattern basis: SIGMA-I (SIGn-and-MAc / identity protection), using the published SIGMA-I construction as the design model. It is **not** claimed to be wire-compatible with Noise; deviations: (1) fixed CA-signed RDR directory lookup instead of certificate exchange in the handshake, to keep data path independent of X.509; (2) stateless cookie challenge before state allocation, to mitigate spoofed M1 DoS; (3) UDP framing and explicit four-message M1–M4 split; (4) fixed suite 1 and deterministic binary encodings. These deviations require independent cryptographic review before production. Transcript hash TH is SHA-256 of the exact concatenation of full framed messages in order, including cookie exchange, excluding retransmissions. Each message carries transcript hash of all prior canonical messages; signatures cover context || current transcript hash. Identity blobs are encrypted with handshake AEAD keys. Handshake AEAD uses AES-256-GCM, 12-byte nonce = 4 zero bytes || u64 counter 0 (handshake key is single-use); associated data = message framing || prior transcript hash.

### M1_INIT (0x01; initiator → responder)
Body 100 bytes:
| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 32 | initiator_nonce | random |
| 32 | 16 | initiator_router_id | opaque |
| 48 | 16 | destination_router_id | opaque |
| 64 | 32 | initiator_ephemeral_x25519 | raw |
| 96 | 2 | suite | u16=1 |
| 98 | 2 | reserved | zero |
Full framed M1_INIT = 108 bytes. To guarantee M1_COOKIE <= M1_INIT, M1_INIT UDP payload is padded to 128 bytes with zero padding outside body_len? **No**: framing body_len includes padding. Define body 120 bytes: fields above plus 20 zero padding bytes, so total = 128 bytes. Parser requires padding zero. Initiator retransmits exact M1 bytes. M1_INIT has no encrypted fields; unauthenticated and rate-limited. Responder validates version/length/padding/suite/IDs before generating cookie; no state allocated.

### M1_COOKIE (0x02; responder → initiator)
Body 52 bytes: initiator_nonce[32], cookie[16], time_bucket:u32. Framed size 60 bytes, less than 128-byte M1_INIT. Cookie = first 16 bytes HMAC-SHA256(cookie_secret, source IPv6 || source UDP port || destination IPv6 || destination UDP port || initiator_router_id || destination_router_id || initiator_nonce || time_bucket:u32). Accept current and previous 10-minute bucket. Cookie secret rotates every 10 minutes while retaining prior key for one bucket. Wrong/expired cookie silently dropped. Cookie carries no identity claims and is not signed.

### M1_INIT(cookie) (0x01; initiator → responder)
Same 120-byte body as padded M1_INIT, cookie occupies bytes 100..115 and reserved padding bytes 116..119 are zero; add cookie_present:u8? **Wire v1 fixed layout:** byte 100 cookie_present=1, bytes 101..116 cookie[16], bytes 117..119 zero. Initial M1 has byte100=0 and bytes101..119 zero. This changes padded body to 120 bytes; total framed size 128. Cookie HMAC proves source address reachability only, not identity. Responder validates cookie before allocating bounded state.

### M2 (0x03; responder → initiator)
Body 244 bytes:
| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 32 | responder_nonce | random |
| 32 | 32 | responder_ephemeral_x25519 | raw |
| 64 | 32 | transcript_hash_prior | SHA-256 |
| 96 | 2 | encrypted_identity_len | u16=80 |
| 98 | 80 | encrypted_identity | AES-256-GCM ciphertext+tag |
| 178 | 2 | signature_len | u16=64 |
| 180 | 64 | signature | Ed25519 over context || SHA256(prior transcript || M2 fields excluding signature) |
M2 framing adds 8 bytes; total framed M2 size is 252 bytes. The encrypted identity plaintext is router_id[16] + RDR_generation:u64 + RDR_hash[32] + reserved[8] = 64 bytes, encrypted to 80 bytes. Key/nonce/AD per key schedule below. Initiator validates lengths, transcript, decrypts identity, online-lookups responder RDR, verifies signature against RDR key, status and validity before proceeding. Failure sends no detailed UDP error.

### M3 (0x04; initiator → responder)
Body 178 bytes: transcript_hash_prior[32], encrypted_identity_len:u16=80, encrypted_identity[80], signature[64]. Encrypted identity plaintext is router_id[16] + RDR_generation:u64 + RDR_hash[32] + reserved[8] = 64 bytes. Signature is Ed25519 over context || SHA256(prior transcript || M3 fields excluding signature). Initiator must have completed online lookup of responder RDR before M3. Responder performs online lookup of initiator RDR, validates signature and decrypted identity against RDR before deriving established data keys. Framed size 186 bytes.

### M4 (0x05; responder → initiator)
Body 64 bytes: transcript_hash_prior[32], finish_mac[32]. finish_mac = HMAC-SHA256(k_finish_responder, context || transcript_hash_prior). Framed size 72 bytes. Initiator verifies constant-time, then session is established. M4 has no encrypted identity; it authenticates handshake completion. Bad tag/signature/transcript silently drops and tears down tentative state.

## 7. Key schedule
Let TH0 = SHA-256(full padded initial M1_INIT || M1_COOKIE || cookie-bearing M1_INIT). Let DH1 = X25519(initiator ephemeral private, responder ephemeral public), DH2 = X25519(responder ephemeral private, initiator ephemeral public). Reject zero output. IKM = DH1 || DH2. Salt = TH0. HKDF-SHA256 extract/expand:
| Output | HKDF info bytes (ASCII, exact) | Length | Use |
|---|---|---:|---|
| k_hs_i2r | `NLS-v1 hs i2r` || TH0 | 32 | M3 identity encryption |
| k_hs_r2i | `NLS-v1 hs r2i` || TH0 | 32 | M2 identity encryption |
| k_finish_responder | `NLS-v1 finish r` || TH0 | 32 | M4 finish MAC |
| k_data_i2r | `NLS-v1 data i2r` || TH0 | 32 | AES-256-GCM initiator→responder |
| k_data_r2i | `NLS-v1 data r2i` || TH0 | 32 | AES-256-GCM responder→initiator |
| salt_i2r | `NLS-v1 nonce i2r` || TH0 | 4 | data nonce prefix |
| salt_r2i | `NLS-v1 nonce r2i` || TH0 | 4 | data nonce prefix |
HKDF-Expand is called separately for each output using the stated info; output lengths as shown. Identity encryption nonce is 12 bytes: 4 zero bytes || u64 counter 0; each handshake key is single-use. Identity encryption AAD = message type/version/framing || TH prior. Data nonce = direction_salt[4] || sequence:u64 big-endian. Never reuse a key/nonce pair. Separate per-direction keys and monotonically increasing sequence counters starting at 1.

**Cryptographic objection:** the above two DH values describe the same X25519 exchange twice (each side computes the same shared secret); they are not two independent DH contributions. Implementers must set IKM to one shared DH output, not concatenate duplicate DH values. This is a necessary correction to avoid pretending there is extra entropy. The exact key schedule is therefore IKM = DH1 (32 bytes), with DH2 computed by responder as the equivalent shared secret and equality implicit. This is normative.

## 8. Data plane
NLS data UDP datagram: common 8-byte framing header with type 0x10, then 32-byte NLS data header, then encrypted entire inner IP packet, then 16-byte GCM tag. Data header is authenticated as AAD. Header:
| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 1 | version | u8=1 |
| 1 | 1 | flags | u8=0 |
| 2 | 2 | session_id | u16, nonzero |
| 4 | 16 | session_nonce_id | random per session |
| 20 | 8 | sequence | u64 big-endian, starts 1 |
Inner plaintext is the entire original IPv4 or IPv6 packet, including inner source/destination IP headers, transport header and payload. Outer IPv6/UDP destination is destination router WAN endpoint; outer endpoints remain visible. AAD = common framing header || NLS data header. AES-256-GCM ciphertext length equals plaintext length; tag 16 bytes. Receiver looks up session, checks session ID/nonce ID, replay window, verifies GCM tag before releasing plaintext, then validates inner IP packet and forwards. No plaintext on any failure.

Replay window: 1024 sequence values per direction. Reject sequence <=0, duplicates, or values older than highest_seen-1023. Update replay window only after successful GCM authentication. At 2^32 packets or one hour initiate rekey; hard stop before sequence reaches 2^32+2^20 if rekey has not succeeded.

## 9. Rekey
REKEY_INIT type 0x11 and REKEY_ACK type 0x12, both use current session data key and normal data header sequence/replay protections. Body after header: epoch:u32, new_ephemeral_x25519[32], transcript_hash[32], signature[64] (132 bytes); ACK uses epoch:u32, responder_ephemeral[32], transcript_hash[32], signature[64] (132 bytes). Signature context is `NLS-v1-REKEY\0` and signs transcript hash plus epoch and ephemeral public key. Derive replacement data keys from X25519(new ephemeral private, peer ephemeral public), salt = SHA-256(old transcript hash || rekey transcript hash), info labels `NLS-v1 rekey i2r` and `NLS-v1 rekey r2i` (32 bytes each) and fresh 4-byte salts. New epoch must be current+1; retransmit identical message on timeout, max 3 attempts over 3 seconds. Switch atomically after authenticated ACK; old keys accepted for 3 seconds only for in-flight packets. If rekey fails and CA unreachable, terminate session and drop PROTECT traffic; if peer is revoked, terminate immediately and erase keys. Re-handshake requires online CA lookup.

## 10. Sizes and MTU arithmetic
- Earlier report said initial M1 fields total 100 bytes and plus 16 cookie = 116 bytes; this was incomplete because it omitted padding and cookie-presence framing. Frozen body is 120 bytes, UDP protocol framing is 8 bytes, so both initial and cookie-bearing M1 are 128 bytes. M1_COOKIE body 52 + framing 8 = 60 bytes and is smaller than M1.
- RDR: fixed unsigned body 258 bytes + Ed25519 signature 64 = 322 bytes.
- NLS overhead excluding common protocol framing ambiguity: outer IPv6 40 + UDP 8 + common NLS framing 8 + data header 32 + GCM tag 16 = 104 bytes. For WAN MTU 1500, TUN MTU = 1500 − 104 = 1396 bytes. TCP MSS: inner IPv4 1396 − 20 IPv4 − 20 TCP = 1356; inner IPv6 1396 − 40 IPv6 − 20 TCP = 1336. These assume no IPv6 extension headers and standard TCP headers; reduce further for options/extensions or lower path MTU.

## 11. Validation order and state machine
Initiator: BOOT → ENROLLING → ENROLLED → CONTROL_UP → SESSION_HANDSHAKING → SESSION_ESTABLISHED. Any revoked state → REVOKED; unrecoverable parse/credential/config failure → FAILED. Handshake: send padded M1_INIT; wait M1_COOKIE up to 1s (retry up to 3, exact same M1); validate cookie response nonce/source; send cookie M1; wait M2 up to 3s; validate frame/version/length, transcript, encrypted identity/tag, online RDR lookup, RDR status/expiry, signature; send M3; wait M4 up to 3s; validate transcript and finish MAC; then switch to real WAN endpoint and remove vIP. Total handshake timeout 10s; remove vIP on success or timeout.
Responder: drop malformed/unknown versions; validate M1 structural fields and rate limits; issue stateless cookie; on cookie-bearing M1 validate cookie before allocating state; generate ephemeral key and M2; await M3 up to 3s; online lookup source RDR; validate transcript, decrypt identity, RDR binding and signature; derive session and send M4; only then accept data. Any failure destroys tentative keys/state. vIP inbound UDP allowed only on handshake port; DAD before use. vIP is random 64-bit interface ID inside routed WAN IPv6 prefix; IPv4-only WAN unsupported.

## 12. Configuration defaults and status
RDR cache TTL 300 seconds (cache alone never authorizes new handshake); revocation push teardown deadline 30 seconds; control-loss session drop threshold 300 seconds; cookie bucket 600 seconds; replay window 1024; rekey 2^32 packets or 1 hour; hard stop 2^32+2^20; handshake total timeout 10 seconds. All three freshness values (RDR TTL, revocation teardown deadline, control-loss threshold) configurable with these defaults.

Router status: 1 ACTIVE, 2 REVOKED, 3 DISABLED. Enrollment status: 1 ISSUED, 2 REJECTED. Policy action: 1 PROTECT, 2 BYPASS. Address family: 4 IPv4, 6 IPv6. Lookup status: 0 FOUND, 1 UNKNOWN, 2 REVOKED, 3 UNAVAILABLE. Policy ACK status: 0 ACCEPTED, 1 REJECTED. Reserved bits/bytes must be zero.

## Objections / Open
1. **Blocking security review:** SIGMA-I is a published protocol family, but this bespoke binary realization is not a formally verified SIGMA-I or Noise implementation. Independent cryptographic protocol review and test vectors are required before implementation is considered production safe. Proposed default: implement only after review signs off.
2. **RDR layout accounting:** the extension reserve is intentionally explicit to make the 258-byte unsigned body match the 322-byte signed total; owner should confirm whether the 64-byte zero reserve is wanted. Proposed default: keep it for v1 forward compatibility.
3. **Rekey signature key binding:** rekey signatures use the session's authenticated router Ed25519 identity keys; wire needs explicit router ID fields if implementations cannot unambiguously bind session direction. Proposed default: bind IDs from established session state.
4. **Control policy overlap:** conflicting PROTECT/BYPASS prefixes are rejected unless longest-prefix match yields an unambiguous winner. Proposed default: longest-prefix match; equal-prefix conflicts reject the entire sync.
5. **Admin key encryption parameters:** argon2id parameters and encrypted export container need a versioned format and resource caps. Proposed default: memory 64 MiB, iterations 3, parallelism 1; export AES-256-GCM with authenticated metadata.
6. CA rotation and multi-node HA are explicitly out of scope for v0.1.1.
