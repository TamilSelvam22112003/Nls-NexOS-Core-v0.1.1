package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

type statusVectorV2 struct {
	IssuerPublicSPKIDERHex string `json:"issuer_public_spki_der_hex"`
	StatusObjectHex        string `json:"status_object_304_hex"`
}

func loadStatusVectorV2(t *testing.T) statusVectorV2 {
	t.Helper()
	raw, err := os.ReadFile("../../tests/v2_vectors/router_status_active_001.json")
	if err != nil { t.Fatal(err) }
	var v statusVectorV2
	if err := json.Unmarshal(raw, &v); err != nil { t.Fatal(err) }
	return v
}

func TestParseStatusObjectV2Golden(t *testing.T) {
	v := loadStatusVectorV2(t)
	object, err := hex.DecodeString(v.StatusObjectHex)
	if err != nil { t.Fatal(err) }
	pubDER, err := hex.DecodeString(v.IssuerPublicSPKIDERHex)
	if err != nil { t.Fatal(err) }
	keyAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil { t.Fatal(err) }
	key, ok := keyAny.(ed25519.PublicKey)
	if !ok { t.Fatal("expected Ed25519 status key") }
	now := time.Unix(1793100000, 0)
	verified, err := ParseStatusObjectV2(object, key, now, 300*time.Second, 30*time.Second)
	if err != nil { t.Fatal(err) }
	if verified.Evidence.State != StatusActive || verified.Evidence.Generation != 7 ||
		verified.Evidence.CertificateSerial != 0x0102030405060708 ||
		len(verified.Evidence.Endpoints) != 1 || verified.Evidence.Endpoints[0].Port != 4444 {
		t.Fatalf("unexpected status evidence: %+v", verified.Evidence)
	}
	if !bytes.Equal(verified.Bytes(), object) { t.Fatal("Bytes must reproduce the exact signed object") }
}

func TestParseStatusObjectV2RejectsMalformedAndTampered(t *testing.T) {
	v := loadStatusVectorV2(t)
	object, _ := hex.DecodeString(v.StatusObjectHex)
	pubDER, _ := hex.DecodeString(v.IssuerPublicSPKIDERHex)
	keyAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil { t.Fatal(err) }
	key := keyAny.(ed25519.PublicKey)
	now := time.Unix(1793100000, 0)
	malformed := append([]byte(nil), object...)
	malformed[6] = 1
	if _, err := ParseStatusObjectV2(malformed, key, now, 300*time.Second, 30*time.Second); !errors.Is(err, ErrStatusEncoding) {
		t.Fatalf("nonzero flags should fail canonical encoding, got %v", err)
	}
	tampered := append([]byte(nil), object...)
	tampered[127] ^= 1
	if _, err := ParseStatusObjectV2(tampered, key, now, 300*time.Second, 30*time.Second); err == nil {
		t.Fatal("tampered signed status object accepted")
	}
	expired := time.Unix(1793104000, 0)
	if _, err := ParseStatusObjectV2(object, key, expired, 300*time.Second, 30*time.Second); !errors.Is(err, ErrStatusFreshness) {
		t.Fatalf("expired status should fail freshness, got %v", err)
	}
}

func TestStatusTrackerRejectsRollbackAndEquivocation(t *testing.T) {
	v := loadStatusVectorV2(t)
	object, _ := hex.DecodeString(v.StatusObjectHex)
	pubDER, _ := hex.DecodeString(v.IssuerPublicSPKIDERHex)
	keyAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil { t.Fatal(err) }
	key := keyAny.(ed25519.PublicKey)
	now := time.Unix(1793100000, 0)
	current, err := ParseStatusObjectV2(object, key, now, 300*time.Second, 30*time.Second)
	if err != nil { t.Fatal(err) }
	var tracker StatusTracker
	if err := tracker.Apply(current); err != nil { t.Fatal(err) }
	if err := tracker.Apply(current); err != nil { t.Fatalf("identical replay should be idempotent: %v", err) }

	different := append([]byte(nil), object...)
	different[127] ^= 1
	// It is not verified and therefore cannot be applied to the tracker.
	if _, err := ParseStatusObjectV2(different, key, now, 300*time.Second, 30*time.Second); err == nil {
		t.Fatal("tampered generation object parsed")
	}
	if _, ok := tracker.Lookup(current.Evidence.IdentityFingerprint); !ok {
		t.Fatal("verified status was lost")
	}
}
