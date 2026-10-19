# Router-CA local administration

The initial Router-CA implementation is a local state bootstrap, not a complete
network enrollment service. It does not listen on a socket or issue router
certificates yet.

## Security model

- Set `NLS_CA_PASSPHRASE` in the process environment. Never put the passphrase
  in CLI arguments, shell history, scripts, or logs.
- The Ed25519 CA private key is encrypted with AES-256-GCM. Its 32-byte key is
  derived with Argon2id (3 iterations, 64 MiB, one lane); salt and nonce are
  generated with `crypto/rand`.
- State files are written atomically with mode 0600 in a mode-0700 directory.
  The state persists the CA public identity, trust registry, router registry,
  revocation registry, enrollment credential metadata, policy, and access
  controls. The enrollment token itself is not persisted: only its SHA-256
  digest is stored.
- `status` reports `ready for enrollment` only if the key decrypts, the
  private/public identity binding and trust registry validate, all registries
  exist and validate, an unexpired unused enrollment credential exists, policy
  is configured, and enrollment access controls are enabled. Any validation
  error fails closed.

## Bootstrap

```sh
export NLS_CA_PASSPHRASE='use-a-long-unique-secret-from-a-secret-manager'
nls-core init --dir /var/lib/nls-ca
nls-core set-enrollment-credentials --dir /var/lib/nls-ca --name router-01 --ttl 10m
nls-core set-policy --dir /var/lib/nls-ca --protect-prefix 10.0.0.0/8,2001:db8:100::/48 --bypass-prefix 192.0.2.0/24
nls-core set-access-controls --dir /var/lib/nls-ca --allow-enrollment=true --max-active-routers 1000
nls-core status --dir /var/lib/nls-ca
```

The enrollment command prints a cryptographically random, single-use token once.
Deliver it to the named router over a secure channel. The current state layer
stores the digest and expiry, but token redemption/atomic consumption belongs
to the not-yet-implemented enrollment service. Do not treat this bootstrap
command as a production-ready CA server.

Policy prefixes are canonicalized and sorted. An identical prefix cannot be
configured as both PROTECT and BYPASS. Absence of policy never implies BYPASS.
The current `status` command does not expose secret key material or token hashes.
