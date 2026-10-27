package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
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


func makeRouterCertificateFixture(t *testing.T, now time.Time) (*x509.Certificate, *x509.CertPool, ed25519.PrivateKey, StatusEvidence) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NLS v2 test Router-CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0x1234),
		Subject:               pkix.Name{CommonName: "NLS v2 test router"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCertificate, leafPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)

	statusSeed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
	statusPrivate := ed25519.NewKeyFromSeed(statusSeed)
	identityFingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	certificateFingerprint := sha256.Sum256(leaf.Raw)
	evidence := StatusEvidence{
		State:                  StatusActive,
		IdentityFingerprint:    identityFingerprint,
		CertificateFingerprint: certificateFingerprint,
		CertificateSerial:      leaf.SerialNumber.Uint64(),
		Generation:             1,
		IssuedAt:               now.Add(-time.Second).UTC(),
		ExpiresAt:              now.Add(299 * time.Second).UTC(),
		Endpoints: []StatusEndpoint{{
			Address: netip.MustParseAddr("2001:db8::10"),
			Port:    4242,
		}},
	}
	return leaf, roots, statusPrivate, evidence
}

func TestParseAndVerifyRouterStatusObjectV2BindsCertificateAndChain(t *testing.T) {
	now := time.Unix(1793099850, 0).UTC()
	leaf, roots, statusPrivate, evidence := makeRouterCertificateFixture(t, now)
	object, err := MarshalStatusObjectV2(evidence, statusPrivate)
	if err != nil {
		t.Fatal(err)
	}
	statusPublic := statusPrivate.Public().(ed25519.PublicKey)
	verified, err := ParseAndVerifyRouterStatusObjectV2(object, statusPublic, leaf, roots, nil, now, 300*time.Second, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.verified {
		t.Fatal("combined verifier did not return a verified status")
	}

	wrongRoot := x509.NewCertPool()
	_, wrongRootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongRootPrivate
	if _, err := ParseAndVerifyRouterStatusObjectV2(object, statusPublic, leaf, wrongRoot, nil, now, 300*time.Second, 30*time.Second); !errors.Is(err, ErrStatusCertificate) {
		t.Fatalf("wrong CA trust root should be rejected, got %v", err)
	}

	mismatched := evidence
	mismatched.CertificateFingerprint[0] ^= 0x80
	badObject, err := MarshalStatusObjectV2(mismatched, statusPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndVerifyRouterStatusObjectV2(badObject, statusPublic, leaf, roots, nil, now, 300*time.Second, 30*time.Second); !errors.Is(err, ErrStatusCertificate) {
		t.Fatalf("certificate/status fingerprint mismatch should be rejected, got %v", err)
	}
}
