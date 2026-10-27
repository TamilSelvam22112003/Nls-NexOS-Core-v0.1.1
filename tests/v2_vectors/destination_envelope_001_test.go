package v2_vectors

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
)

type destinationEnvelopeVector struct {
	KeyHex             string `json:"key_hex"`
	NonceHex           string `json:"nonce_hex"`
	HeaderAADHex       string `json:"header_aad_hex"`
	CiphertextAndTagHex string `json:"ciphertext_and_tag_hex"`
	PlaintextHex       string `json:"plaintext_ipv6_packet_hex"`
	CompleteEnvelopeHex string `json:"complete_envelope_hex"`
	ExpectedHeaderLength int `json:"expected_header_length"`
	ExpectedCiphertextLength int `json:"expected_ciphertext_length"`
	ExpectedTotalLength int `json:"expected_total_length"`
}

func loadDestinationEnvelopeVector(t *testing.T) destinationEnvelopeVector {
	t.Helper()
	raw, err := os.ReadFile("destination_envelope_001.json")
	if err != nil {
		t.Fatal(err)
	}
	var v destinationEnvelopeVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDestinationEnvelopeAES256GCM001(t *testing.T) {
	v := loadDestinationEnvelopeVector(t)
	key := decodeHex(t, v.KeyHex)
	nonce := decodeHex(t, v.NonceHex)
	aad := decodeHex(t, v.HeaderAADHex)
	ciphertext := decodeHex(t, v.CiphertextAndTagHex)
	plaintext := decodeHex(t, v.PlaintextHex)
	envelope := decodeHex(t, v.CompleteEnvelopeHex)

	if len(key) != 32 || len(nonce) != 12 {
		t.Fatalf("wrong AES-256-GCM key/nonce length: %d/%d", len(key), len(nonce))
	}
	if len(aad) != v.ExpectedHeaderLength || len(aad) != 72 {
		t.Fatalf("wrong header/AAD length: %d", len(aad))
	}
	if string(aad[:4]) != "N2DE" || aad[4] != 1 || aad[5] != 0 {
		t.Fatal("invalid N2DE magic/version/flags")
	}
	if binary.BigEndian.Uint16(aad[6:8]) != uint16(v.ExpectedHeaderLength) {
		t.Fatal("header_length mismatch")
	}
	if int(binary.BigEndian.Uint32(aad[68:72])) != len(ciphertext) ||
		len(ciphertext) != v.ExpectedCiphertextLength {
		t.Fatal("ciphertext_length mismatch")
	}
	if len(envelope) != v.ExpectedTotalLength ||
		len(envelope) != len(aad)+len(ciphertext) ||
		!bytes.Equal(envelope[:len(aad)], aad) ||
		!bytes.Equal(envelope[len(aad):], ciphertext) {
		t.Fatal("complete envelope does not match header || ciphertext")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("valid vector rejected: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted plaintext does not match the fixed IPv6 packet")
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := gcm.Open(nil, nonce, tampered, aad); err == nil {
		t.Fatal("tampered ciphertext/tag was accepted")
	}

	alteredAAD := append([]byte(nil), aad...)
	alteredAAD[36] ^= 1 // first byte of recipient_key_fingerprint
	if _, err := gcm.Open(nil, nonce, ciphertext, alteredAAD); err == nil {
		t.Fatal("altered recipient fingerprint in AAD was accepted")
	}

	if len(append(append([]byte(nil), envelope...), 0)) == v.ExpectedTotalLength {
		t.Fatal("appended byte was not reflected in exact-length check")
	}
}
