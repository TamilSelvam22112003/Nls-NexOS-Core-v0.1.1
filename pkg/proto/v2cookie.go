package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// V2CookieSize is the 40-byte stateless RETRY cookie.
	V2CookieSize = 8 + sha256.Size
	v2CookieBucketSize = 8
	v2CookieDomain = "NLS2-COOKIE\x00"
)

var (
	ErrV2CookieConfiguration  = errors.New("invalid NLS v2 cookie configuration")
	ErrV2CookieInput          = errors.New("invalid NLS v2 cookie input")
	ErrV2CookieLength         = errors.New("invalid NLS v2 cookie length")
	ErrV2CookieWindow         = errors.New("NLS v2 cookie is outside the accepted time window")
	ErrV2CookieAuthentication = errors.New("NLS v2 cookie authentication failed")
)

// V2CookieClaims are the unauthenticated fields bound into an NLS v2 stateless cookie.
// Outer is the routable IPv6/UDP tuple observed by the responder.
type V2CookieClaims struct {
	Outer              OuterTuple
	HandshakeID        [16]byte
	NonceI             [32]byte
	EphemeralPublicKey [32]byte
}

// V2CookieManager issues and verifies stateless cookies without retaining per-peer state.
// It is immutable after construction and safe for concurrent use.
type V2CookieManager struct {
	currentSecret  [sha256.Size]byte
	previousSecret [sha256.Size]byte
	hasPrevious    bool
	bucketSeconds  uint64
}

// NewV2CookieManager creates a cookie manager with a 32-byte current secret and an
// optional 32-byte previous secret for bounded rotation overlap. bucketDuration must be
// a positive whole number of seconds. Rotate by constructing a new manager with the new
// secret as current and the old current secret as previous.
func NewV2CookieManager(currentSecret, previousSecret []byte, bucketDuration time.Duration) (*V2CookieManager, error) {
	if len(currentSecret) != sha256.Size {
		return nil, fmt.Errorf("%w: current secret must be 32 bytes", ErrV2CookieConfiguration)
	}
	if len(previousSecret) != 0 && len(previousSecret) != sha256.Size {
		return nil, fmt.Errorf("%w: previous secret must be empty or 32 bytes", ErrV2CookieConfiguration)
	}
	if bucketDuration <= 0 || bucketDuration%time.Second != 0 {
		return nil, fmt.Errorf("%w: bucket duration must be a positive whole number of seconds", ErrV2CookieConfiguration)
	}
	manager := &V2CookieManager{bucketSeconds: uint64(bucketDuration / time.Second)}
	copy(manager.currentSecret[:], currentSecret)
	if len(previousSecret) != 0 {
		copy(manager.previousSecret[:], previousSecret)
		manager.hasPrevious = true
	}
	return manager, nil
}

// Issue creates a stateless cookie bound to the outer tuple, handshake ID, initiator
// nonce and initiator ephemeral public key. It does not retain per-peer state.
func (m *V2CookieManager) Issue(claims V2CookieClaims, now time.Time) ([]byte, error) {
	if m == nil || m.bucketSeconds == 0 {
		return nil, ErrV2CookieConfiguration
	}
	if err := validateV2CookieClaims(claims); err != nil {
		return nil, err
	}
	bucket, err := m.timeBucket(now)
	if err != nil {
		return nil, err
	}
	input := makeV2CookieMACInput(claims, bucket)
	mac := v2CookieMAC(m.currentSecret[:], input)
	cookie := make([]byte, V2CookieSize)
	binary.BigEndian.PutUint64(cookie[:v2CookieBucketSize], bucket)
	copy(cookie[v2CookieBucketSize:], mac[:])
	return cookie, nil
}

// Verify validates cookie length, accepts only the current or immediately preceding
// time bucket, and checks the MAC using the current secret or optional previous secret.
// A valid cookie proves return-path reachability only; it does not authenticate identity.
func (m *V2CookieManager) Verify(cookie []byte, claims V2CookieClaims, now time.Time) error {
	if m == nil || m.bucketSeconds == 0 {
		return ErrV2CookieConfiguration
	}
	if len(cookie) != V2CookieSize {
		return ErrV2CookieLength
	}
	if err := validateV2CookieClaims(claims); err != nil {
		return err
	}
	currentBucket, err := m.timeBucket(now)
	if err != nil {
		return err
	}
	bucket := binary.BigEndian.Uint64(cookie[:v2CookieBucketSize])
	if bucket > currentBucket || currentBucket-bucket > 1 {
		return ErrV2CookieWindow
	}

	input := makeV2CookieMACInput(claims, bucket)
	gotMAC := cookie[v2CookieBucketSize:]
	currentMAC := v2CookieMAC(m.currentSecret[:], input)
	validCurrent := hmac.Equal(gotMAC, currentMAC[:])
	validPrevious := false
	if m.hasPrevious {
		previousMAC := v2CookieMAC(m.previousSecret[:], input)
		validPrevious = hmac.Equal(gotMAC, previousMAC[:])
	}
	if !validCurrent && !validPrevious {
		return ErrV2CookieAuthentication
	}
	return nil
}

func (m *V2CookieManager) timeBucket(now time.Time) (uint64, error) {
	if now.IsZero() || now.Unix() < 0 {
		return 0, ErrV2CookieInput
	}
	return uint64(now.Unix()) / m.bucketSeconds, nil
}

func validateV2CookieClaims(claims V2CookieClaims) error {
	if err := validateOuterTuple(claims.Outer); err != nil {
		return fmt.Errorf("%w: invalid outer tuple", ErrV2CookieInput)
	}
	if claims.Outer.SourceIPv6.IsLoopback() || claims.Outer.SourceIPv6.IsLinkLocalUnicast() ||
		claims.Outer.DestinationIPv6.IsLoopback() || claims.Outer.DestinationIPv6.IsLinkLocalUnicast() ||
		v2CookieAllZero(claims.HandshakeID[:]) ||
		v2CookieAllZero(claims.NonceI[:]) ||
		v2CookieAllZero(claims.EphemeralPublicKey[:]) {
		return ErrV2CookieInput
	}
	return nil
}

func makeV2CookieMACInput(claims V2CookieClaims, bucket uint64) []byte {
	input := make([]byte, 0, len(v2CookieDomain)+16+16+4+16+32+32+8)
	input = append(input, v2CookieDomain...)
	source := claims.Outer.SourceIPv6.As16()
	destination := claims.Outer.DestinationIPv6.As16()
	input = append(input, source[:]...)
	input = append(input, destination[:]...)
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[:2], claims.Outer.SourcePort)
	binary.BigEndian.PutUint16(ports[2:], claims.Outer.DestinationPort)
	input = append(input, ports[:]...)
	input = append(input, claims.HandshakeID[:]...)
	input = append(input, claims.NonceI[:]...)
	input = append(input, claims.EphemeralPublicKey[:]...)
	var bucketBytes [8]byte
	binary.BigEndian.PutUint64(bucketBytes[:], bucket)
	input = append(input, bucketBytes[:]...)
	return input
}

func v2CookieMAC(secret, input []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(input)
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func v2CookieAllZero(value []byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}
