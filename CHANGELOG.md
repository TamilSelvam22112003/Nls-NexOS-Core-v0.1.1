# Changelog
## Unreleased
- Add strict NLS v1 common datagram framing encoder/parser and regression/fuzz-seed tests in the shared protocol package.
- Reject unsupported versions, unknown message types, nonzero reserved fields, malformed lengths, and oversized datagrams before message processing.

## v0.1.1
- Specification and scaffolding baseline only; no feature implementation.
