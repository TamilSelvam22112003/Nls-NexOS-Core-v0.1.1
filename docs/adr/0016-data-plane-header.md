# ADR-0016: Single data-plane header and session demultiplexing

- Status: Proposed for pre-release v1-rc2; not released.
- Date: 2026-10-19
- Context: The prior data-plane datagram used an 8-byte common prefix followed by a 32-byte data header, duplicating version and flags while omitting a defined peer-visible receiver index and session nonce identifier derivation.
- Decision: Keep the 8-byte common framing for handshake messages. DATA, REKEY_INIT and REKEY_ACK use one 32-byte header: version:u8, type:u8, flags:u16, receiver_index:u32, session_nonce_id[16], sequence:u64. The receiving router allocates a unique nonzero receiver_index per active receive session and sends it in the encrypted identity field of M2/M3. Both peers derive session_nonce_id from the final handshake transcript. No separate body_len is used; UDP datagram length bounds the payload.
- Consequences: data-plane overhead is 96 bytes including outer IPv6, UDP, NLS header and GCM tag. The receiver_index must be validated and collision-free among active local sessions. This wire format and its cryptographic use require independent security review before release.
- References: PROTOCOL.md §§6, 8–10; SPEC_ERRATA.md E-002 and E-004.
