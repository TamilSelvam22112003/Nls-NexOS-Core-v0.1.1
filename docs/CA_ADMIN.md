# Router-CA enrollment and control service

This milestone adds the TLS enrollment endpoint and the mTLS control endpoint. The
service is a prototype implementation of the v1 protocol and must pass CI and
integration testing before deployment.

## Server startup

Use the same DNS name for both listeners and export the CA root certificate with
that DNS name before distributing it to routers:

```sh
export NLS_CA_PASSPHRASE='use-a-long-unique-secret-from-a-secret-manager'
nls-core export-ca-cert --dir /var/lib/nls-ca --tls-name ca.example --out ca-cert.pem
nls-core serve-enrollment --dir /var/lib/nls-ca --tls-name ca.example --listen :8443
nls-core serve-control --dir /var/lib/nls-ca --tls-name ca.example --listen :8444
```

Run the two listeners as separate processes/services. Both require TLS 1.3.
Enrollment uses server-authenticated TLS; control requires a client certificate
issued by this CA and a registry entry in ACTIVE state.

## Key-bound enrollment

The router first generates its Ed25519 private key and PKCS#10 CSR locally. The
administrator obtains the SHA-256 hash of the raw Ed25519 public key and creates
a one-time credential scoped to the router name, public-key hash, and advertised
IPv6/UDP endpoint:

```sh
nls-core set-enrollment-credentials --dir /var/lib/nls-ca \
  --name router-01 --public-key-sha256 <64-hex-character-hash> \
  --endpoint-ipv6 2001:db8::10 --endpoint-udp-port 51820 --ttl 10m
```

The token is displayed once and must be delivered over a secure channel. The
CA verifies the CSR signature and exact key hash, issues an Ed25519 X.509 router
certificate, signs the 322-byte RDR v1, and atomically records token consumption
and the router registry entry before returning certificate bytes. Replays and
expired tokens are rejected.

## Revocation and readiness

```sh
nls-core revoke-router --dir /var/lib/nls-ca --router-id <32-hex-character-id> --reason "key compromise"
nls-core status --dir /var/lib/nls-ca
```

Control authentication checks both certificate/key binding and ACTIVE registry
status. The control channel sends heartbeat acknowledgements, policy snapshots,
revocation snapshots, and supports online RDR lookup. A revoked router is
rejected on the next authorization check and cannot establish a new control
connection.

The implementation persists CA state locally with restricted permissions.
Token redemption, certificate issuance and revocation are serialized with an
OS file lock. Deployment still requires review of service supervision, rate
limits, audit retention, key backup/rotation, and external integration tests.
