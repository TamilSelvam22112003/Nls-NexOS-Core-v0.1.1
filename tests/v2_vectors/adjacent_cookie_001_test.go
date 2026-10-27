package v2_vectors

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"testing"
)

type adjacentCookieVector struct {
	Outer struct {
		SourceIPv6 string `json:"source_ipv6"`
		DestinationIPv6 string `json:"destination_ipv6"`
		SourcePort uint16 `json:"source_udp_port"`
		DestinationPort uint16 `json:"destination_udp_port"`
	} `json:"outer_tuple"`
	Inputs struct {
		Secret string `json:"cookie_secret_hex"`
		HandshakeID string `json:"handshake_id_hex"`
		NonceI string `json:"nonce_i_hex"`
		EphemeralPrivate string `json:"ephemeral_x25519_private_hex"`
		EphemeralPublic string `json:"ephemeral_x25519_public_hex"`
		TimeBucket uint64 `json:"time_bucket"`
	} `json:"test_only_inputs"`
	Expected struct {
		MACInput string `json:"mac_input_hex"`
		MAC string `json:"mac_hex"`
		Cookie string `json:"cookie_hex"`
		Length int `json:"cookie_length_bytes"`
	} `json:"expected"`
}

func loadAdjacentCookieVector(t *testing.T) adjacentCookieVector {
	t.Helper()
	raw, err := os.ReadFile("adjacent_cookie_001.json")
	if err != nil { t.Fatal(err) }
	var v adjacentCookieVector
	if err := json.Unmarshal(raw, &v); err != nil { t.Fatal(err) }
	return v
}

func cookieInput(v adjacentCookieVector, source, destination []byte, sourcePort, destinationPort uint16, handshakeID, nonceI, ephemeralPublic []byte, bucket uint64) []byte {
	out := append([]byte("NLS2-COOKIE\x00"), source...)
	out = append(out, destination...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], sourcePort); out = append(out, port[:]...)
	binary.BigEndian.PutUint16(port[:], destinationPort); out = append(out, port[:]...)
	out = append(out, handshakeID...)
	out = append(out, nonceI...)
	out = append(out, ephemeralPublic...)
	var timeBytes [8]byte
	binary.BigEndian.PutUint64(timeBytes[:], bucket)
	return append(out, timeBytes[:]...)
}

func cookieMAC(secret, input []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(input)
	return mac.Sum(nil)
}

func TestAdjacentHopCookie001(t *testing.T) {
	v := loadAdjacentCookieVector(t)
	source := net.ParseIP(v.Outer.SourceIPv6).To16()
	destination := net.ParseIP(v.Outer.DestinationIPv6).To16()
	secret := decodeHex(t, v.Inputs.Secret)
	handshakeID := decodeHex(t, v.Inputs.HandshakeID)
	nonceI := decodeHex(t, v.Inputs.NonceI)
	privateKey, err := ecdh.X25519().NewPrivateKey(decodeHex(t, v.Inputs.EphemeralPrivate))
	if err != nil { t.Fatal(err) }
	ephemeralPublic := privateKey.PublicKey().Bytes()
	if !bytes.Equal(ephemeralPublic, decodeHex(t, v.Inputs.EphemeralPublic)) { t.Fatal("X25519 public key mismatch") }
	input := cookieInput(v, source, destination, v.Outer.SourcePort, v.Outer.DestinationPort, handshakeID, nonceI, ephemeralPublic, v.Inputs.TimeBucket)
	if !bytes.Equal(input, decodeHex(t, v.Expected.MACInput)) { t.Fatal("cookie MAC input mismatch") }
	mac := cookieMAC(secret, input)
	if !bytes.Equal(mac, decodeHex(t, v.Expected.MAC)) { t.Fatal("HMAC-SHA-256 cookie MAC mismatch") }
	cookie := append(make([]byte, 8), mac...)
	binary.BigEndian.PutUint64(cookie[:8], v.Inputs.TimeBucket)
	if len(cookie) != v.Expected.Length || !bytes.Equal(cookie, decodeHex(t, v.Expected.Cookie)) { t.Fatal("40-byte cookie mismatch") }

	// Every bound field must change the MAC and invalidate the fixed cookie.
	changedSource := append([]byte(nil), source...); changedSource[15] ^= 1
	changedID := append([]byte(nil), handshakeID...); changedID[0] ^= 1
	changedNonce := append([]byte(nil), nonceI...); changedNonce[0] ^= 1
	changedPublic := append([]byte(nil), ephemeralPublic...); changedPublic[0] ^= 1
	changedSecret := append([]byte(nil), secret...); changedSecret[0] ^= 1
	cases := [][]byte{
		cookieInput(v, changedSource, destination, v.Outer.SourcePort, v.Outer.DestinationPort, handshakeID, nonceI, ephemeralPublic, v.Inputs.TimeBucket),
		cookieInput(v, source, destination, v.Outer.SourcePort, v.Outer.DestinationPort+1, handshakeID, nonceI, ephemeralPublic, v.Inputs.TimeBucket),
		cookieInput(v, source, destination, v.Outer.SourcePort, v.Outer.DestinationPort, changedID, nonceI, ephemeralPublic, v.Inputs.TimeBucket),
		cookieInput(v, source, destination, v.Outer.SourcePort, v.Outer.DestinationPort, handshakeID, changedNonce, ephemeralPublic, v.Inputs.TimeBucket),
		cookieInput(v, source, destination, v.Outer.SourcePort, v.Outer.DestinationPort, handshakeID, nonceI, changedPublic, v.Inputs.TimeBucket),
	}
	for i, changedInput := range cases {
		if hmac.Equal(cookieMAC(secret, changedInput), mac) { t.Fatalf("mutation %d did not invalidate cookie", i) }
	}
	if hmac.Equal(cookieMAC(changedSecret, input), mac) { t.Fatal("rotated cookie secret did not invalidate cookie") }
}
