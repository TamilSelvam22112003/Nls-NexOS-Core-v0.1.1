# NLS v0.1.1 Test Plan
Normative test cases for later implementation; protocol contract in PROTOCOL.md.

## Flow 1 — Router-CA initialization
- CA creates unique Ed25519 signing identity and protected registry; CA key encrypted at rest; permissions are 0700/0600.
- Wrong passphrase fails without writing plaintext key; encrypted export/import round trip preserves registry and audit data.
- Invalid config, malformed state DB and permission mismatch fail closed.
- CA rotation and HA are out of scope.

## Flow 2 — Enrollment and control
- Valid pinned root + valid unexpired unused token + matching CSR key hash issues X.509 Ed25519 certificate.
- Negative: bad token, expired token, reused token, token for different router name, CSR key-hash mismatch, invalid CSR signature, wrong CA root fingerprint, bad TLS chain, malformed lengths, trailing bytes, duplicate TLVs, unknown critical TLV, unknown enum.
- Certificate issued only after token consumption is atomic; mTLS rejected before issuance and accepted after issuance.
- Heartbeat round trip; policy sync sorted canonical prefixes; revocation generation monotonic; revoked peer session teardown <=30s.
- Control loss >300s drops established sessions; fresh handshakes fail closed if CA lookup unavailable.

## Flow 3 — Packet selection
- PROTECT prefix routes through nls0; BYPASS prefix bypasses NLS by explicit policy.
- Unknown destination, absent directory/policy/session, expired RDR or revoked peer drops PROTECT traffic; assert no plaintext on WAN.
- Reject host bits in prefixes, conflicting duplicate prefixes, invalid family/prefix lengths, unsorted or trailing policy bytes.

## Flow 4 — Handshake
- Happy path M1_INIT → M1_COOKIE → cookie-bearing M1_INIT → M2 → M3 → M4; verify transcript and key agreement on both routers.
- Negative: tampered M1 fields, bad cookie, expired cookie, replayed M1, wrong source/destination tuple, unsupported version/suite, malformed padding, duplicate handshake, unknown router, stale RDR, expired RDR, revoked initiator, revoked responder, mismatched RDR key, tampered M2, tampered M3, tampered M4, wrong AEAD tag, bad transcript hash, all-zero X25519 output.
- No state allocated before valid cookie. M1_COOKIE <= M1_INIT. vIP removed after success and after 10s timeout; DAD collision prevents use.
- Every failure erases tentative keys and never establishes session.

## Flow 5 — Data plane and rekey
- IPv4 and IPv6 inner packets preserve original source/destination, transport header and payload after decrypt.
- Negative: replayed packet, old sequence outside 1024 window, duplicate sequence, wrong GCM tag, unknown session, mismatched session ID/nonce ID, malformed inner packet, oversized UDP datagram, sequence wrap, wrong direction key.
- Rekey round-trip switches atomically, rejects epoch rollback/skip, replayed rekey, tampered rekey signature, bad ACK, and timeout after three attempts.
- If rekey fails while CA unreachable, session terminates and PROTECT traffic drops; if peer revoked, session terminates immediately.
- MTU tests verify 1396 TUN MTU at WAN MTU 1500 and MSS clamp 1356/1336 under stated header assumptions.

## Canonical parser fuzz/property tests
For each control TLV and UDP message: truncation at every byte, trailing bytes, duplicate fields, non-minimal length, integer overflow, invalid enums, unknown critical types, non-zero reserved bytes, excessive counts/lengths, unsorted records, duplicate prefixes, invalid UTF-8/NFC, and deterministic round-trip vectors.
