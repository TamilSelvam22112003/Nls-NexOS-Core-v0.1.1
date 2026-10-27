package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

type statusVectorV2 struct {
	IssuerPrivateSeedHex string `json:"issuer_private_seed_hex_test_only"`
	IssuerPublicSPKIDERHex string `json:"issuer_public_spki_der_hex"`
	StatusObjectHex        string `json:"status_object_304_hex"`
}

func loadStatusVectorV2(t *testing.T) statusVectorV2 {
	t.Helper()
	raw, err := os.ReadFile("../../tests/v2_vectors/router_status_active_001.json")
	if err != nil {
		t.Fatal(err)
	}
	var v statusVectorV2
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func statusFixtureKey(t *testing.T, v statusVectorV2) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicDER, err := hex.DecodeString(v.IssuerPublicSPKIDERHex)
	if err != nil {
		t.Fatal(err)
	}
	publicAny, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := publicAny.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected Ed25519 status key")
	}
	seed, err := hex.DecodeString(v.IssuerPrivateSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("invalid test seed length: %d", len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		t.Fatal("test-only status private seed does not match public key")
	}
	return publicKey, privateKey
}

func decodeStatusFixture(t *testing.T, v statusVectorV2) []byte {
	t.Helper()
	object, err := hex.DecodeString(v.StatusObjectHex)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func TestParseStatusObjectV2Golden(t *testing.T) {
	v := loadStatusVectorV2(t)
	object := decodeStatusFixture(t, v)
	publicKey, privateKey := statusFixtureKey(t, v)
	now := time.Unix(1793099850, 0)
	verified, err := ParseStatusObjectV2(object, publicKey, now, 300*time.Second, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Evidence.State != StatusActive ||
		verified.Evidence.Generation != 7 ||
		verified.Evidence.CertificateSerial != 0x0102030405060708 ||
		len(verified.Evidence.Endpoints) != 1 ||
		verified.Evidence.Endpoints[0].Address != netip.MustParseAddr("2001:db8::1") ||
		verified.Evidence.Endpoints[0].Port != 4444 {
		t.Fatalf("unexpected status evidence: %+v", verified.Evidence)
	}
	if !bytes.Equal(verified.Bytes(), object) {
		t.Fatal("Bytes must reproduce the exact signed object")
	}
	encoded, err := MarshalStatusObjectV2(verified.Evidence, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, object) {
		t.Fatal("status encoder did not reproduce golden object")
	}
}

func TestParseStatusObjectV2RejectsMalformedTamperedAndExpired(t *testing.T) {
	v := loadStatusVectorV2(t)
	object := decodeStatusFixture(t, v)
	publicKey, _ := statusFixtureKey(t, v)
	now := time.Unix(1793099850, 0)

	malformed := append([]byte(nil), object...)
	malformed[6] = 1
	if _, err := ParseStatusObjectV2(malformed, publicKey, now, 300*time.Second, 30*time.Second); !errors.Is(err, ErrStatusEncoding) {
		t.Fatalf("nonzero flags should fail canonical encoding, got %v", err)
	}
	tampered := append([]byte(nil), object...)
	tampered[127] ^= 1
	if _, err := ParseStatusObjectV2(tampered, publicKey, now, 300*time.Second, 30*time.Second); err == nil {
		t.Fatal("tampered signed status object accepted")
	}
	expired := time.Unix(1793100400, 0)
	if _, err := ParseStatusObjectV2(object, publicKey, expired, 300*time.Second, 30*time.Second); !errors.Is(err, ErrStatusFreshness) {
		t.Fatalf("expired status should fail freshness, got %v", err)
	}
	longLifetimePolicy := 301 * time.Second
	if _, err := ParseStatusObjectV2(object, publicKey, now, longLifetimePolicy, 30*time.Second); err != nil {
		t.Fatalf("a policy permitting a longer lifetime should still parse a 300-second object: %v", err)
	}
}

func signedStatusVariant(t *testing.T, base StatusEvidence, state StatusState, generation uint64, port uint16, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, now time.Time) VerifiedStatus {
	t.Helper()
	variant := base
	variant.State = state
	variant.Generation = generation
	variant.Endpoints = append([]StatusEndpoint(nil), base.Endpoints...)
	variant.Endpoints[0].Port = port
	object, err := MarshalStatusObjectV2(variant, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := ParseStatusObjectV2(object, publicKey, now, 300*time.Second, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestStatusTrackerRejectsRollbackEquivocationAndRevokedReactivation(t *testing.T) {
	v := loadStatusVectorV2(t)
	object := decodeStatusFixture(t, v)
	publicKey, privateKey := statusFixtureKey(t, v)
	now := time.Unix(1793099850, 0)
	current, err := ParseStatusObjectV2(object, publicKey, now, 300*time.Second, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var tracker StatusTracker
	if err := tracker.Apply(current); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Apply(current); err != nil {
		t.Fatalf("identical replay should be idempotent: %v", err)
	}
	lower := signedStatusVariant(t, current.Evidence, StatusActive, 6, 4444, privateKey, publicKey, now)
	if err := tracker.Apply(lower); !errors.Is(err, ErrStatusRollback) {
		t.Fatalf("expected generation rollback rejection, got %v", err)
	}
	equivocation := signedStatusVariant(t, current.Evidence, StatusActive, 7, 4445, privateKey, publicKey, now)
	if err := tracker.Apply(equivocation); !errors.Is(err, ErrStatusEquivocation) {
		t.Fatalf("expected same-generation equivocation rejection, got %v", err)
	}
	revoked := signedStatusVariant(t, current.Evidence, StatusRevoked, 8, 4444, privateKey, publicKey, now)
	if err := tracker.Apply(revoked); err != nil {
		t.Fatal(err)
	}
	reactivated := signedStatusVariant(t, current.Evidence, StatusActive, 9, 4444, privateKey, publicKey, now)
	if err := tracker.Apply(reactivated); !errors.Is(err, ErrStatusRevoked) {
		t.Fatalf("expected revoked-lineage rejection, got %v", err)
	}
	if got, ok := tracker.Lookup(current.Evidence.IdentityFingerprint); !ok || got.Evidence.State != StatusRevoked {
		t.Fatal("revocation state was not preserved")
	}
}
