package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

type v2CookieVector struct {
	FixedValidationTime int64 `json:"fixed_validation_time_unix_seconds"`
	Outer struct {
		SourceIPv6 string `json:"source_ipv6"`
		DestinationIPv6 string `json:"destination_ipv6"`
		SourcePort uint16 `json:"source_udp_port"`
		DestinationPort uint16 `json:"destination_udp_port"`
	} `json:"outer_tuple"`
	Inputs struct {
		SecretHex string `json:"cookie_secret_hex"`
		HandshakeIDHex string `json:"handshake_id_hex"`
		NonceIHex string `json:"nonce_i_hex"`
		EphemeralPublicHex string `json:"ephemeral_x25519_public_hex"`
		TimeBucket uint64 `json:"time_bucket"`
	} `json:"test_only_inputs"`
	Expected struct {
		MACInputHex string `json:"mac_input_hex"`
		MACHex string `json:"mac_hex"`
		CookieHex string `json:"cookie_hex"`
		CookieLength int `json:"cookie_length_bytes"`
	} `json:"expected"`
}

func loadV2CookieVector(t *testing.T) v2CookieVector {
	t.Helper()
	raw, err := os.ReadFile("../../tests/v2_vectors/adjacent_cookie_001.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector v2CookieVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func decodeV2CookieHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid cookie fixture hex: %v", err)
	}
	return decoded
}

func v2CookieClaimsFromVector(t *testing.T, vector v2CookieVector) V2CookieClaims {
	t.Helper()
	var claims V2CookieClaims
	claims.Outer = OuterTuple{
		SourceIPv6: netip.MustParseAddr(vector.Outer.SourceIPv6),
		DestinationIPv6: netip.MustParseAddr(vector.Outer.DestinationIPv6),
		SourcePort: vector.Outer.SourcePort,
		DestinationPort: vector.Outer.DestinationPort,
	}
	handshakeID := decodeV2CookieHex(t, vector.Inputs.HandshakeIDHex)
	nonceI := decodeV2CookieHex(t, vector.Inputs.NonceIHex)
	ephemeral := decodeV2CookieHex(t, vector.Inputs.EphemeralPublicHex)
	if len(handshakeID) != len(claims.HandshakeID) || len(nonceI) != len(claims.NonceI) || len(ephemeral) != len(claims.EphemeralPublicKey) {
		t.Fatal("cookie vector fields have invalid lengths")
	}
	copy(claims.HandshakeID[:], handshakeID)
	copy(claims.NonceI[:], nonceI)
	copy(claims.EphemeralPublicKey[:], ephemeral)
	return claims
}

func TestV2CookieGoldenVector(t *testing.T) {
	vector := loadV2CookieVector(t)
	secret := decodeV2CookieHex(t, vector.Inputs.SecretHex)
	manager, err := NewV2CookieManager(secret, nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(vector.FixedValidationTime, 0)
	claims := v2CookieClaimsFromVector(t, vector)
	bucket := binary.BigEndian.Uint64([]byte{0, 0, 0, 0, 3, 0x90, 0x04, 0x72})
	input := makeV2CookieMACInput(claims, bucket)
	if !bytes.Equal(input, decodeV2CookieHex(t, vector.Expected.MACInputHex)) {
		t.Fatal("canonical cookie MAC input differs from the shared vector")
	}
	mac := v2CookieMAC(secret, input)
	if !bytes.Equal(mac[:], decodeV2CookieHex(t, vector.Expected.MACHex)) {
		t.Fatal("cookie HMAC differs from the shared vector")
	}
	cookie, err := manager.Issue(claims, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(cookie) != vector.Expected.CookieLength || !bytes.Equal(cookie, decodeV2CookieHex(t, vector.Expected.CookieHex)) {
		t.Fatal("issued cookie differs from the shared 40-byte vector")
	}
	if err := manager.Verify(cookie, claims, now); err != nil {
		t.Fatalf("valid cookie rejected: %v", err)
	}
}

func TestV2CookieRejectsClaimMutations(t *testing.T) {
	vector := loadV2CookieVector(t)
	secret := decodeV2CookieHex(t, vector.Inputs.SecretHex)
	manager, err := NewV2CookieManager(secret, nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(vector.FixedValidationTime, 0)
	claims := v2CookieClaimsFromVector(t, vector)
	cookie, err := manager.Issue(claims, now)
	if err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name string
		change func(*V2CookieClaims)
	}{
		{name: "source address", change: func(c *V2CookieClaims) { c.Outer.SourceIPv6 = netip.MustParseAddr("2001:db8::9") }},
		{name: "destination address", change: func(c *V2CookieClaims) { c.Outer.DestinationIPv6 = netip.MustParseAddr("2001:db8::9") }},
		{name: "source port", change: func(c *V2CookieClaims) { c.Outer.SourcePort++ }},
		{name: "destination port", change: func(c *V2CookieClaims) { c.Outer.DestinationPort++ }},
		{name: "handshake ID", change: func(c *V2CookieClaims) { c.HandshakeID[0] ^= 1 }},
		{name: "initiator nonce", change: func(c *V2CookieClaims) { c.NonceI[0] ^= 1 }},
		{name: "ephemeral public key", change: func(c *V2CookieClaims) { c.EphemeralPublicKey[0] ^= 1 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := claims
			mutation.change(&changed)
			if err := manager.Verify(cookie, changed, now); !errors.Is(err, ErrV2CookieAuthentication) {
				t.Fatalf("mutated claim should fail cookie authentication, got %v", err)
			}
		})
	}
	tampered := append([]byte(nil), cookie...)
	tampered[len(tampered)-1] ^= 1
	if err := manager.Verify(tampered, claims, now); !errors.Is(err, ErrV2CookieAuthentication) {
		t.Fatalf("tampered cookie MAC should fail authentication, got %v", err)
	}
}

func TestV2CookieTimeWindowAndSecretRotation(t *testing.T) {
	vector := loadV2CookieVector(t)
	oldSecret := decodeV2CookieHex(t, vector.Inputs.SecretHex)
	var newSecret [sha256.Size]byte
	for i := range newSecret {
		newSecret[i] = 0x88
	}
	oldManager, err := NewV2CookieManager(oldSecret, nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(vector.FixedValidationTime, 0)
	claims := v2CookieClaimsFromVector(t, vector)

	previousBucketCookie, err := oldManager.Issue(claims, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := oldManager.Verify(previousBucketCookie, claims, now); err != nil {
		t.Fatalf("immediately preceding bucket should be accepted: %v", err)
	}
	expiredCookie, err := oldManager.Issue(claims, now.Add(-60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := oldManager.Verify(expiredCookie, claims, now); !errors.Is(err, ErrV2CookieWindow) {
		t.Fatalf("cookie two buckets old must be rejected, got %v", err)
	}
	futureCookie, err := oldManager.Issue(claims, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := oldManager.Verify(futureCookie, claims, now); !errors.Is(err, ErrV2CookieWindow) {
		t.Fatalf("future bucket must be rejected, got %v", err)
	}

	rotatedManager, err := NewV2CookieManager(newSecret[:], oldSecret, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	currentCookie, err := oldManager.Issue(claims, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotatedManager.Verify(currentCookie, claims, now); err != nil {
		t.Fatalf("previous secret should verify within rotation overlap: %v", err)
	}
	withoutPrevious, err := NewV2CookieManager(newSecret[:], nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := withoutPrevious.Verify(currentCookie, claims, now); !errors.Is(err, ErrV2CookieAuthentication) {
		t.Fatalf("old secret must fail without overlap: %v", err)
	}
}

func TestNewV2CookieManagerRejectsInvalidConfigurationAndClaims(t *testing.T) {
	if _, err := NewV2CookieManager([]byte("short"), nil, 30*time.Second); !errors.Is(err, ErrV2CookieConfiguration) {
		t.Fatalf("short secret should fail configuration, got %v", err)
	}
	secret := bytes.Repeat([]byte{0x66}, sha256.Size)
	if _, err := NewV2CookieManager(secret, nil, 0); !errors.Is(err, ErrV2CookieConfiguration) {
		t.Fatalf("zero bucket duration should fail configuration, got %v", err)
	}
	if _, err := NewV2CookieManager(secret, nil, 30*time.Second+time.Millisecond); !errors.Is(err, ErrV2CookieConfiguration) {
		t.Fatalf("fractional bucket duration should fail configuration, got %v", err)
	}
	vector := loadV2CookieVector(t)
	manager, err := NewV2CookieManager(secret, nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(vector.FixedValidationTime, 0)
	claims := v2CookieClaimsFromVector(t, vector)
	claims.HandshakeID = [16]byte{}
	if _, err := manager.Issue(claims, now); !errors.Is(err, ErrV2CookieInput) {
		t.Fatalf("all-zero handshake ID should be rejected, got %v", err)
	}
	claims = v2CookieClaimsFromVector(t, vector)
	claims.Outer.SourcePort = 0
	if _, err := manager.Issue(claims, now); !errors.Is(err, ErrV2CookieInput) {
		t.Fatalf("zero source port should be rejected, got %v", err)
	}
}
