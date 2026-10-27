// Package proto contains versioned NLS wire and trust-evidence primitives.
package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	StatusObjectV2Size       = 304
	statusObjectV2PrefixSize = 240
	statusObjectV2Version    = 1
	statusEndpointOffset     = 112
	statusEndpointSize       = 18
	statusMaxEndpoints       = 4
	statusDefaultMaxLifetime = 300 * time.Second
	statusDefaultClockSkew  = 30 * time.Second
)

var (
	ErrStatusLength      = errors.New("NLS v2 status object has invalid length")
	ErrStatusEncoding    = errors.New("NLS v2 status object is not canonically encoded")
	ErrStatusSignature   = errors.New("NLS v2 status signature is invalid")
	ErrStatusFreshness   = errors.New("NLS v2 status object is outside its freshness window")
	ErrStatusCertificate = errors.New("NLS v2 status object does not match the router certificate")
	ErrStatusRollback    = errors.New("NLS v2 status generation rollback")
	ErrStatusEquivocation = errors.New("NLS v2 status generation equivocation")
	ErrStatusRevoked     = errors.New("a revoked NLS v2 identity cannot become active again")
)

var statusSignatureDomain = []byte("NLS2-ROUTER-STATUS\x00")

type StatusState uint8

const (
	StatusActive    StatusState = 1
	StatusSuspended StatusState = 2
	StatusRevoked   StatusState = 3
)

// StatusEndpoint is an IPv6 address and the UDP port authorized for NLS v2.
type StatusEndpoint struct {
	Address netip.Addr
	Port    uint16
}

// StatusEvidence is the decoded, signed content of an NLS v2 N2ST object.
type StatusEvidence struct {
	State              StatusState
	IdentityFingerprint [32]byte
	CertificateFingerprint [32]byte
	CertificateSerial  uint64
	Generation         uint64
	IssuedAt            time.Time
	ExpiresAt           time.Time
	Endpoints           []StatusEndpoint
}

// VerifiedStatus can only be trusted when returned by ParseStatusObjectV2.
// Its private fields prevent callers from fabricating a tracker-accepted value.
type VerifiedStatus struct {
	Evidence StatusEvidence
	object   [StatusObjectV2Size]byte
	verified bool
}

// Bytes returns a defensive copy of the exact signed status object.
func (v VerifiedStatus) Bytes() []byte {
	out := make([]byte, len(v.object))
	copy(out, v.object[:])
	return out
}

// ParseStatusObjectV2 validates canonical encoding, signature, freshness and endpoints.
// certificate binding is a separate step because status vectors may use synthetic
// certificate fingerprints and the certificate chain must be validated by the caller.
func ParseStatusObjectV2(raw []byte, statusSigningKey ed25519.PublicKey, now time.Time, maxLifetime, clockSkew time.Duration) (VerifiedStatus, error) {
	var result VerifiedStatus
	if len(raw) != StatusObjectV2Size {
		return result, ErrStatusLength
	}
	if len(statusSigningKey) != ed25519.PublicKeySize {
		return result, fmt.Errorf("%w: status-signing public key must be 32 bytes", ErrStatusEncoding)
	}
	if now.IsZero() {
		return result, fmt.Errorf("%w: validation time is required", ErrStatusFreshness)
	}
	if maxLifetime <= 0 {
		maxLifetime = statusDefaultMaxLifetime
	}
	if clockSkew < 0 {
		return result, fmt.Errorf("%w: negative clock skew", ErrStatusFreshness)
	}
	if clockSkew == 0 {
		clockSkew = statusDefaultClockSkew
	}
	if !bytes.Equal(raw[:4], []byte("N2ST")) ||
		raw[4] != statusObjectV2Version ||
		raw[5] < byte(StatusActive) || raw[5] > byte(StatusRevoked) ||
		binary.BigEndian.Uint16(raw[6:8]) != 0 ||
		binary.BigEndian.Uint32(raw[8:12]) != StatusObjectV2Size {
		return result, ErrStatusEncoding
	}
	issuedRaw := binary.BigEndian.Uint64(raw[92:100])
	expiresRaw := binary.BigEndian.Uint64(raw[100:108])
	if issuedRaw > uint64(1<<63-1) || expiresRaw > uint64(1<<63-1) {
		return result, fmt.Errorf("%w: timestamp exceeds supported range", ErrStatusFreshness)
	}
	if allZero(raw[12:44]) || allZero(raw[44:76]) ||
		binary.BigEndian.Uint64(raw[76:84]) == 0 ||
		binary.BigEndian.Uint64(raw[84:92]) == 0 {
		return result, fmt.Errorf("%w: zero identity, certificate, serial or generation", ErrStatusEncoding)
	}
	if raw[109] != 0 || raw[110] != 0 || raw[111] != 0 || !allZero(raw[184:240]) {
		return result, fmt.Errorf("%w: reserved bytes are nonzero", ErrStatusEncoding)
	}
	endpointCount := int(raw[108])
	if endpointCount < 1 || endpointCount > statusMaxEndpoints {
		return result, fmt.Errorf("%w: endpoint_count must be 1..4", ErrStatusEncoding)
	}
	endpointBytes := raw[statusEndpointOffset : statusEndpointOffset+statusMaxEndpoints*statusEndpointSize]
	usedEndpointBytes := endpointCount * statusEndpointSize
	if !allZero(endpointBytes[usedEndpointBytes:]) {
		return result, fmt.Errorf("%w: unused endpoint slots are nonzero", ErrStatusEncoding)
	}

	evidence := StatusEvidence{
		State: StatusState(raw[5]),
		CertificateSerial: binary.BigEndian.Uint64(raw[76:84]),
		Generation: binary.BigEndian.Uint64(raw[84:92]),
		IssuedAt: time.Unix(int64(issuedRaw), 0).UTC(),
		ExpiresAt: time.Unix(int64(expiresRaw), 0).UTC(),
		Endpoints: make([]StatusEndpoint, 0, endpointCount),
	}
	copy(evidence.IdentityFingerprint[:], raw[12:44])
	copy(evidence.CertificateFingerprint[:], raw[44:76])
	if evidence.IssuedAt.Unix() > now.Add(clockSkew).Unix() ||
		evidence.ExpiresAt.Unix() <= now.Add(-clockSkew).Unix() ||
		!evidence.ExpiresAt.After(evidence.IssuedAt) ||
		expiresRaw <= issuedRaw || expiresRaw-issuedRaw > uint64(maxLifetime/time.Second) {
		return result, ErrStatusFreshness
	}
	for i := 0; i < endpointCount; i++ {
		offset := statusEndpointOffset + i*statusEndpointSize
		var addressBytes [16]byte
		copy(addressBytes[:], raw[offset:offset+16])
		address := netip.AddrFrom16(addressBytes)
		port := binary.BigEndian.Uint16(raw[offset+16 : offset+18])
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() ||
			address.IsLoopback() || port == 0 {
			return result, fmt.Errorf("%w: invalid authorized endpoint", ErrStatusEncoding)
		}
		if i > 0 {
			prev := evidence.Endpoints[i-1]
			if compareEndpoint(prev, StatusEndpoint{Address: address, Port: port}) >= 0 {
				return result, fmt.Errorf("%w: endpoints must be sorted and unique", ErrStatusEncoding)
			}
		}
		evidence.Endpoints = append(evidence.Endpoints, StatusEndpoint{Address: address, Port: port})
	}
	signed := make([]byte, 0, len(statusSignatureDomain)+statusObjectV2PrefixSize)
	signed = append(signed, statusSignatureDomain...)
	signed = append(signed, raw[:statusObjectV2PrefixSize]...)
	if !ed25519.Verify(statusSigningKey, signed, raw[statusObjectV2PrefixSize:]) {
		return result, ErrStatusSignature
	}
	copy(result.object[:], raw)
	result.Evidence = evidence
	result.verified = true
	return result, nil
}

// ValidateStatusCertificateBinding binds verified status evidence to a validated leaf.
// The caller must separately validate the certificate chain using the configured trust root.
func ValidateStatusCertificateBinding(status VerifiedStatus, leaf *x509.Certificate, now time.Time) error {
	if !status.verified || leaf == nil || now.IsZero() {
		return ErrStatusCertificate
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 ||
		leaf.SerialNumber.BitLen() > 64 ||
		!now.Before(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return ErrStatusCertificate
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return ErrStatusCertificate
	}
	identityFP := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	certificateFP := sha256.Sum256(leaf.Raw)
	if !bytes.Equal(identityFP[:], status.Evidence.IdentityFingerprint[:]) ||
		!bytes.Equal(certificateFP[:], status.Evidence.CertificateFingerprint[:]) ||
		leaf.SerialNumber.Cmp(new(big.Int).SetUint64(status.Evidence.CertificateSerial)) != 0 {
		return ErrStatusCertificate
	}
	return nil
}

// VerifyStatusCertificateChain verifies the leaf against an explicitly configured trust root.
func VerifyStatusCertificateChain(leaf *x509.Certificate, roots, intermediates *x509.CertPool, now time.Time) error {
	if leaf == nil || roots == nil || now.IsZero() {
		return ErrStatusCertificate
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ErrStatusCertificate
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return ErrStatusCertificate
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots,
		Intermediates: intermediates,
		CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("%w: certificate chain: %v", ErrStatusCertificate, err)
	}
	return nil
}

// StatusTracker applies verified status generations atomically per router identity.
type StatusTracker struct {
	mu      sync.Mutex
	entries map[[32]byte]VerifiedStatus
}

// Apply rejects generation rollback/equivocation and prevents a revoked identity
// from being reactivated with the same identity fingerprint.
func (t *StatusTracker) Apply(status VerifiedStatus) error {
	if !status.verified {
		return ErrStatusEncoding
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make(map[[32]byte]VerifiedStatus)
	}
	fingerprint := status.Evidence.IdentityFingerprint
	current, exists := t.entries[fingerprint]
	if exists {
		if status.Evidence.Generation < current.Evidence.Generation {
			return ErrStatusRollback
		}
		if status.Evidence.Generation == current.Evidence.Generation {
			if bytes.Equal(status.object[:], current.object[:]) {
				return nil
			}
			return ErrStatusEquivocation
		}
		if current.Evidence.State == StatusRevoked && status.Evidence.State == StatusActive {
			return ErrStatusRevoked
		}
	}
	t.entries[fingerprint] = status
	return nil
}

// Lookup returns the latest verified evidence for an identity fingerprint.
func (t *StatusTracker) Lookup(identityFingerprint [32]byte) (VerifiedStatus, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	status, ok := t.entries[identityFingerprint]
	return status, ok
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func compareEndpoint(a, b StatusEndpoint) int {
	aa, bb := a.Address.As16(), b.Address.As16()
	if compared := bytes.Compare(aa[:], bb[:]); compared != 0 {
		return compared
	}
	if a.Port < b.Port {
		return -1
	}
	if a.Port > b.Port {
		return 1
	}
	return 0
}

// MarshalStatusObjectV2 encodes and signs an N2ST object using the pinned CA status key.
func MarshalStatusObjectV2(evidence StatusEvidence, signingKey ed25519.PrivateKey) ([]byte, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: status-signing private key must be 64 bytes", ErrStatusEncoding)
	}
	if evidence.State < StatusActive || evidence.State > StatusRevoked ||
		evidence.CertificateSerial == 0 || evidence.Generation == 0 ||
		evidence.IssuedAt.IsZero() || evidence.ExpiresAt.IsZero() ||
		!evidence.ExpiresAt.After(evidence.IssuedAt) ||
		len(evidence.Endpoints) < 1 || len(evidence.Endpoints) > statusMaxEndpoints ||
		allZero(evidence.IdentityFingerprint[:]) || allZero(evidence.CertificateFingerprint[:]) {
		return nil, ErrStatusEncoding
	}
	if evidence.IssuedAt.Unix() < 0 || evidence.ExpiresAt.Unix() < 0 || {
		return nil, ErrStatusEncoding
	}
	endpoints := append([]StatusEndpoint(nil), evidence.Endpoints...)
	sort.Slice(endpoints, func(i, j int) bool { return compareEndpoint(endpoints[i], endpoints[j]) < 0 })
	for i, endpoint := range endpoints {
		if !endpoint.Address.Is6() || endpoint.Address.IsUnspecified() || endpoint.Address.IsMulticast() ||
			endpoint.Address.IsLoopback() || endpoint.Port == 0 {
			return nil, ErrStatusEncoding
		}
		if i > 0 && compareEndpoint(endpoints[i-1], endpoint) == 0 {
			return nil, ErrStatusEncoding
		}
	}
	raw := make([]byte, StatusObjectV2Size)
	copy(raw[:4], "N2ST")
	raw[4], raw[5] = statusObjectV2Version, byte(evidence.State)
	binary.BigEndian.PutUint32(raw[8:12], StatusObjectV2Size)
	copy(raw[12:44], evidence.IdentityFingerprint[:])
	copy(raw[44:76], evidence.CertificateFingerprint[:])
	binary.BigEndian.PutUint64(raw[76:84], evidence.CertificateSerial)
	binary.BigEndian.PutUint64(raw[84:92], evidence.Generation)
	binary.BigEndian.PutUint64(raw[92:100], uint64(evidence.IssuedAt.Unix()))
	binary.BigEndian.PutUint64(raw[100:108], uint64(evidence.ExpiresAt.Unix()))
	raw[108] = byte(len(endpoints))
	for i, endpoint := range endpoints {
		offset := statusEndpointOffset + i*statusEndpointSize
		address := endpoint.Address.As16()
		copy(raw[offset:offset+16], address[:])
		binary.BigEndian.PutUint16(raw[offset+16:offset+18], endpoint.Port)
	}
	message := make([]byte, 0, len(statusSignatureDomain)+statusObjectV2PrefixSize)
	message = append(message, statusSignatureDomain...)
	message = append(message, raw[:statusObjectV2PrefixSize]...)
	signature := ed25519.Sign(signingKey, message)
	copy(raw[statusObjectV2PrefixSize:], signature)
	return raw, nil
}
