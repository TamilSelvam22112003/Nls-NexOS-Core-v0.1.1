package directory

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	RDRBodyLen      = 130
	RDRSignatureLen = ed25519.SignatureSize
	RDRLen          = RDRBodyLen + RDRSignatureLen
)

var (
	ErrMalformedRDR = errors.New("malformed RDR")
	ErrBadSignature = errors.New("invalid RDR signature")
	ErrNotCurrent   = errors.New("RDR outside validity interval")
)

var rdrContext = []byte("NLS-v1-RDR\x00")

const (
	StatusActive   byte = 1
	StatusRevoked  byte = 2
	StatusDisabled byte = 3
)

// RDRFields contains the signed v1-rc2 Router Directory Record fields.
type RDRFields struct {
	RouterID         [16]byte
	EndpointIPv6     [16]byte
	EndpointPort     uint16
	CertificateSerial uint64
	NotBeforeUnixMS  uint64
	NotAfterUnixMS   uint64
	Status           byte
	Generation       uint64
	RecordNonce      [16]byte
}

// IssueRDR signs the canonical 130-byte RDR body and returns exactly 194 bytes.
func IssueRDR(privateKey ed25519.PrivateKey, fields RDRFields) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !validFields(fields) {
		return nil, fmt.Errorf("%w: invalid key or field values", ErrMalformedRDR)
	}
	body := make([]byte, RDRBodyLen)
	body[0], body[1] = 1, 1
	copy(body[4:20], fields.RouterID[:])
	copy(body[20:52], privateKey.Public().(ed25519.PublicKey))
	body[52], body[53] = 1, 6
	copy(body[54:70], fields.EndpointIPv6[:])
	binary.BigEndian.PutUint16(body[70:72], fields.EndpointPort)
	binary.BigEndian.PutUint64(body[72:80], fields.CertificateSerial)
	binary.BigEndian.PutUint64(body[80:88], fields.NotBeforeUnixMS)
	binary.BigEndian.PutUint64(body[88:96], fields.NotAfterUnixMS)
	body[96] = fields.Status
	binary.BigEndian.PutUint64(body[104:112], fields.Generation)
	copy(body[112:128], fields.RecordNonce[:])
	// bytes 2..3, 97..103, and extensions_len 128..129 are canonical zeroes.
	signature := ed25519.Sign(privateKey, append(append([]byte(nil), rdrContext...), body...))
	return append(body, signature...), nil
}

// VerifyRDR validates exact size, canonical reserved fields, zero extensions_len,
// field constraints, optional validity time, and the Ed25519 signature.
func VerifyRDR(record []byte, nowUnixMS uint64) (RDRFields, error) {
	var fields RDRFields
	if len(record) != RDRLen {
		return fields, fmt.Errorf("%w: length %d, want %d", ErrMalformedRDR, len(record), RDRLen)
	}
	body, signature := record[:RDRBodyLen], record[RDRBodyLen:]
	if body[0] != 1 || body[1] != 1 || binary.BigEndian.Uint16(body[2:4]) != 0 ||
		body[52] != 1 || body[53] != 6 || !allZero(body[97:104]) ||
		binary.BigEndian.Uint16(body[128:130]) != 0 {
		return fields, fmt.Errorf("%w: noncanonical header, endpoint, reserved bytes, or extensions_len", ErrMalformedRDR)
	}
	copy(fields.RouterID[:], body[4:20])
	copy(fields.EndpointIPv6[:], body[54:70])
	fields.EndpointPort = binary.BigEndian.Uint16(body[70:72])
	fields.CertificateSerial = binary.BigEndian.Uint64(body[72:80])
	fields.NotBeforeUnixMS = binary.BigEndian.Uint64(body[80:88])
	fields.NotAfterUnixMS = binary.BigEndian.Uint64(body[88:96])
	fields.Status = body[96]
	fields.Generation = binary.BigEndian.Uint64(body[104:112])
	copy(fields.RecordNonce[:], body[112:128])
	if !validFields(fields) {
		return RDRFields{}, fmt.Errorf("%w: invalid field values", ErrMalformedRDR)
	}
	if nowUnixMS != 0 && (nowUnixMS < fields.NotBeforeUnixMS || nowUnixMS >= fields.NotAfterUnixMS) {
		return RDRFields{}, ErrNotCurrent
	}
	publicKey := ed25519.PublicKey(append([]byte(nil), body[20:52]...))
	message := make([]byte, 0, len(rdrContext)+RDRBodyLen)
	message = append(message, rdrContext...)
	message = append(message, body...)
	if !ed25519.Verify(publicKey, message, signature) {
		return RDRFields{}, ErrBadSignature
	}
	return fields, nil
}

func validFields(fields RDRFields) bool {
	if fields.EndpointPort == 0 || fields.Status < StatusActive || fields.Status > StatusDisabled ||
		fields.NotAfterUnixMS <= fields.NotBeforeUnixMS {
		return false
	}
	// The v1 record carries one IPv6 endpoint; reject unspecified and multicast endpoints.
	ip := netip.AddrFrom16(fields.EndpointIPv6)
	return ip.Is6() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// RDRHash returns SHA-256 of the complete signed record.
func RDRHash(record []byte) [32]byte {
	return sha256.Sum256(record)
}

// NewRecordNonce returns a cryptographically random record nonce.
func NewRecordNonce() ([16]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}
