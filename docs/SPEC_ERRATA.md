# Specification Errata — NLS v1-rc2

**Status:** Pre-release correction set; not released. The wire protocol version remains 1 because no compatible v1 release has been published. These corrections must be implemented consistently in both Core and NetOS before the protocol library is written.

## E-001 — RDR extension length and canonical size
**Affected:** PROTOCOL.md §5, ADR/RDR validation.
**Correction:** Remove the 130-byte reserved extension padding. At offset 128, add extensions_len:u16; it MUST equal zero in v1 and any nonzero value MUST be rejected. Unsigned body = 130 bytes; Ed25519 signature = 64 bytes; signed RDR = 194 bytes.
**Reason:** The prior padding existed only to inflate the body to 258 bytes and did not encode an extension length. The new layout is canonical, length-delimited, and rejects extensions until a future protocol revision defines them.

## E-002 — Merge data-plane framing into the fixed 32-byte header
**Affected:** PROTOCOL.md §§2, 8–10; ADR-0009; ADR-0016.
**Correction:** Handshake messages retain the 8-byte common framing. DATA, REKEY_INIT, and REKEY_ACK use one 32-byte header containing version:u8, type:u8, flags:u16, receiver_index:u32, session_nonce_id[16], and sequence:u64. No additional common framing prefix is present. Datagram length provides the payload boundary, so body_len is redundant.
**Reason:** The old data datagram repeated version/flags and paid an extra 8 bytes of overhead without adding required information. Receiver index and type/version remain present within the 32-byte header.

## E-003 — Cookie lifetime
**Affected:** PROTOCOL.md §§6, 12; ADR-0012.
**Correction:** Use 60-second buckets. Accept only the current and immediately previous bucket; rotate the cookie secret every 60 seconds and retain the prior secret for verification of the previous bucket. Maximum accepted cookie age is less than 120 seconds.
**Reason:** Reduce the exposure window while retaining boundary tolerance.

## E-004 — Receiver index and session nonce identifier semantics
**Affected:** PROTOCOL.md §§6, 8.
**Correction:** Each router allocates a nonzero receiver_index unique among its active receive sessions and includes it in the encrypted identity it sends (responder in M2, initiator in M3). The peer uses that value for packets sent to that router. session_nonce_id is the first 16 bytes of SHA-256("NLS-v1 session-id\0" || TH4), where TH4 hashes the full canonical framed handshake messages through M4.
**Reason:** The previous text described a random session_nonce_id and session_id without specifying how either value was communicated to the peer, preventing interoperable data-plane demultiplexing.

## E-005 — Recalculated packet overhead and MTU/MSS
**Affected:** PROTOCOL.md §10; ADR-0009.
**Correction:** Overhead = outer IPv6 40 + UDP 8 + single NLS data header 32 + GCM tag 16 = 96 bytes. At WAN MTU 1500: TUN MTU 1404; IPv4 TCP MSS 1364; IPv6 TCP MSS 1344.
**Reason:** The redundant 8-byte common framing header is removed from data-plane packets.

## E-006 — Recompute dependent size claims
**Affected:** PROTOCOL.md §§5, 8–10.
**Correction:** Signed RDR is 194 bytes. M1_INIT and cookie-bearing M1_INIT remain 128 bytes; M1_COOKIE 60 bytes; M2 252 bytes; M3 186 bytes; M4 72 bytes. REKEY_INIT and REKEY_ACK each occupy a 180-byte UDP payload (32-byte header + 132-byte encrypted body + 16-byte tag).
**Reason:** Keep every published wire-size and MTU calculation consistent with the corrected layouts.
