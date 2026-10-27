# NLS v2 Router-CA Status Profile (Draft)

Status: proposed; not frozen. Existing APIs and NLS v1 remain unchanged.

## Requirements

A router identity is SHA-256 over DER SubjectPublicKeyInfo for its Ed25519 identity key. Certificate validity and current status are separate checks. Status evidence binds router ID, certificate serial and fingerprint, status, monotonic status generation, issue and expiry times, authorized endpoints and roles, issuer key ID, and CA-wide revocation generation. Missing, invalid, stale, rolled-back, suspended, or revoked evidence rejects new PROTECT sessions.

## Encoding proposal

Use deterministic CBOR per RFC 8949 with integer keys. Reject duplicate keys, indefinite-length values, non-canonical encodings, and unknown critical fields. Required fields: profile version; router ID; certificate serial; certificate fingerprint; ACTIVE/SUSPENDED/REVOKED status; per-router status generation; issue and expiry times; sorted authorized IPv6 endpoints; sorted authorized role IDs; issuer key ID; CA-wide revocation generation; and policy ID.

Use COSE_Sign1 per RFC 9052. The protected header contains EdDSA and issuer key ID; unprotected headers are empty; payload is embedded; external AAD is ASCII NLS2-ROUTER-STATUS-v1 without a trailing NUL. Validate the issuer against the pinned CA trust configuration before trusting the payload. Prefer a dedicated CA status-signing key.

## Validation

Initial lab defaults: maximum status age 300 seconds and clock skew 30 seconds. Reject future, expired, stale, non-canonical, invalidly signed, revoked, suspended, or generation-rollback evidence. Persist the highest accepted per-router status generation and CA-wide revocation generation. The observed IPv6 address and UDP port must match an authorized endpoint; the requested role must be authorized. CA unavailability fails closed for new PROTECT sessions; any stale grace period for established sessions must be explicit and bounded.

## Release gates

Review certificate extension OIDs and path constraints, status-key rotation, endpoint/role representation, policy ID semantics, generation persistence/HA, and strict CBOR/COSE validation. Add shared deterministic byte vectors and independently verify them before implementation is treated as interoperable. This draft does not claim compatibility with the existing Router-CA implementation.
