package v2_vectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"testing"
)

type statusVector struct {
	IssuerPublicSPKIDERHex       string `json:"issuer_public_spki_der_hex"`
	RouterIdentitySPKIDERHex     string `json:"router_identity_spki_der_hex"`
	RouterIdentityFingerprintHex string `json:"router_identity_fingerprint_hex"`
	CertificateFingerprintHex    string `json:"certificate_fingerprint_hex"`
	CertificateSerialU64         uint64 `json:"certificate_serial_u64"`
	StatusGeneration             uint64 `json:"status_generation"`
	IssuedAt                     uint64 `json:"issued_at_unix_seconds"`
	ExpiresAt                    uint64 `json:"expires_at_unix_seconds"`
	EndpointIPv6                 string `json:"endpoint_ipv6"`
	EndpointUDPPort              uint16 `json:"endpoint_udp_port"`
	SignatureInputHex            string `json:"signature_input_hex"`
	StatusPrefixHex              string `json:"status_prefix_240_hex"`
	SignatureHex                 string `json:"signature_hex"`
	StatusObjectHex              string `json:"status_object_304_hex"`
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid hex fixture: %v", err)
	}
	return b
}

func loadStatusVector(t *testing.T) statusVector {
	t.Helper()
	raw, err := os.ReadFile("router_status_active_001.json")
	if err != nil {
		t.Fatal(err)
	}
	var v statusVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRouterStatusActive001(t *testing.T) {
	v := loadStatusVector(t)
	identitySPKI := decodeHex(t, v.RouterIdentitySPKIDERHex)
	identityFingerprint := sha256.Sum256(identitySPKI)
	if hex.EncodeToString(identityFingerprint[:]) != v.RouterIdentityFingerprintHex {
		t.Fatal("router identity fingerprint does not match SPKI DER")
	}

	certFingerprint := decodeHex(t, v.CertificateFingerprintHex)
	if len(certFingerprint) != sha256.Size {
		t.Fatal("certificate fingerprint must be 32 bytes")
	}
	ip := net.ParseIP(v.EndpointIPv6).To16()
	if ip == nil || v.EndpointUDPPort == 0 {
		t.Fatal("invalid IPv6 endpoint in fixture")
	}

	prefix := make([]byte, 240)
	copy(prefix[0:4], []byte("N2ST"))
	prefix[4], prefix[5] = 1, 1
	binary.BigEndian.PutUint32(prefix[8:12], 304)
	copy(prefix[12:44], identityFingerprint[:])
	copy(prefix[44:76], certFingerprint)
	binary.BigEndian.PutUint64(prefix[76:84], v.CertificateSerialU64)
	binary.BigEndian.PutUint64(prefix[84:92], v.StatusGeneration)
	binary.BigEndian.PutUint64(prefix[92:100], v.IssuedAt)
	binary.BigEndian.PutUint64(prefix[100:108], v.ExpiresAt)
	prefix[108] = 1
	copy(prefix[112:128], ip)
	binary.BigEndian.PutUint16(prefix[128:130], v.EndpointUDPPort)

	if got := hex.EncodeToString(prefix); got != v.StatusPrefixHex {
		t.Fatal("fixed-width 240-byte status prefix mismatch")
	}
	signed := append([]byte("NLS2-ROUTER-STATUS\x00"), prefix...)
	if got := hex.EncodeToString(signed); got != v.SignatureInputHex {
		t.Fatal("status signature input mismatch")
	}
	signature := decodeHex(t, v.SignatureHex)
	if len(signature) != ed25519.SignatureSize {
		t.Fatal("signature must be 64 bytes")
	}
	publicDER := decodeHex(t, v.IssuerPublicSPKIDERHex)
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatalf("parse issuer public key: %v", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatal("issuer status key is not Ed25519")
	}
	if !ed25519.Verify(publicKey, signed, signature) {
		t.Fatal("status signature verification failed")
	}
	object := append(append([]byte(nil), prefix...), signature...)
	if len(object) != 304 || hex.EncodeToString(object) != v.StatusObjectHex {
		t.Fatal("complete 304-byte status object mismatch")
	}
	if object[6] != 0 || object[7] != 0 || object[109] != 0 || object[110] != 0 || object[111] != 0 {
		t.Fatal("reserved status fields are nonzero")
	}
	for _, b := range object[130:184] {
		if b != 0 {
			t.Fatal("unused endpoint slots must be zero")
		}
	}
	for _, b := range object[184:240] {
		if b != 0 {
			t.Fatal("reserved suffix must be zero")
		}
	}
}

func TestRouterStatusActive001RejectsSignatureChanges(t *testing.T) {
	v := loadStatusVector(t)
	signed := decodeHex(t, v.SignatureInputHex)
	signature := decodeHex(t, v.SignatureHex)
	parsed, err := x509.ParsePKIXPublicKey(decodeHex(t, v.IssuerPublicSPKIDERHex))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatal("issuer status key is not Ed25519")
	}
	alteredMessage := append([]byte(nil), signed...)
	alteredMessage[len(alteredMessage)-1] ^= 1
	if ed25519.Verify(publicKey, alteredMessage, signature) {
		t.Fatal("altered status signature input was accepted")
	}
	alteredSignature := append([]byte(nil), signature...)
	alteredSignature[0] ^= 1
	if ed25519.Verify(publicKey, signed, alteredSignature) {
		t.Fatal("altered status signature was accepted")
	}
}
