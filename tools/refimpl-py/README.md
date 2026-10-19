# NLS Python reference implementation

This is a deterministic, I/O-free reference implementation derived from docs/PROTOCOL.md.
It is used to validate canonical encodings and cryptographic constructions before the Go port.
It opens no sockets, accesses no files at runtime, and starts no background tasks.

EXPERIMENTAL — not cryptographically reviewed. This is not production-ready protocol software.

Run from the repository root:

    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -r tools/refimpl-py/requirements.txt
    python -m unittest discover -s tools/refimpl-py -p 'test_*.py' -v

The fixed fixture uses deterministic Ed25519/X25519 private keys, nonces, cookie secret,
record nonces, and receiver indexes. Never use fixture secrets in a deployed system.
