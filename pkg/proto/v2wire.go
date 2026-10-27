package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

const (
	V2HeaderSize           = 44
	V2Version              = 2
	V2PacketData            = 1
	V2PacketControl         = 2
	V2AEADTagSize           = 16
	V2DefaultMaxDatagram    = 65527
	V2ReplayWindowSize      = 1024
	v2HopPlaintextKindIP    = 1
	v2HopIdentitySize       = 32
	v2HopLocatorSize        = 16
	v2HopPlaintextFixedSize = 1 + 2 + v2HopIdentitySize + 2 + v2HopLocatorSize + 4
)

var (
	ErrV2Frame             = errors.New("invalid NLS v2 frame")
	ErrV2Crypto            = errors.New("NLS v2 authentication failed")
	ErrV2Replay            = errors.New("NLS v2 packet replay or sequence outside replay window")
	ErrV2ReplayWindow      = errors.New("NLS v2 replay window is required")
	ErrV2OuterTuple        = errors.New("invalid NLS v2 outer IPv6/UDP tuple")
	ErrV2HopPlaintext      = errors.New("invalid NLS v2 hop plaintext")
	ErrV2InnerEnvelopeSize = errors.New("NLS v2 inner envelope exceeds configured limit")
)

// V2Header is the fixed, clear 44-byte NLS v2 UDP payload header.
type V2Header struct {
	PacketType    uint8
	Flags         uint16
	SessionToken  [16]byte
	KeyEpoch      uint32
	Sequence      uint64
	PayloadLength uint32
}

// OuterTuple is the routable IPv6/UDP tuple and is authenticated as AEAD AAD.
type OuterTuple struct {
	SourceIPv6      netip.Addr
	DestinationIPv6 netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

// HopPlaintext contains only adjacent-hop metadata plus an opaque destination envelope.
// PreviousHopIdentity is the SHA-256 identity fingerprint from the Router-CA profile.
// PreviousHopLocator is an NLS logical locator; it is not the routable outer IPv6 source.
type HopPlaintext struct {
	PreviousHopIdentity [32]byte
	PreviousHopLocator  netip.Addr
	InnerEnvelope       []byte
}

// MarshalV2Header serializes a canonical NLS v2 header.
func MarshalV2Header(header V2Header) ([]byte, error) {
	if header.PacketType != V2PacketData && header.PacketType != V2PacketControl {
		return nil, fmt.Errorf("%w: unsupported packet type", ErrV2Frame)
	}
	if header.Flags != 0 {
		return nil, fmt.Errorf("%w: reserved flags are nonzero", ErrV2Frame)
	}
	out := make([]byte, V2HeaderSize)
	copy(out[:4], []byte("NLS2"))
	out[4] = V2Version
	out[5] = header.PacketType
	binary.BigEndian.PutUint16(out[6:8], header.Flags)
	binary.BigEndian.PutUint16(out[8:10], V2HeaderSize)
	binary.BigEndian.PutUint16(out[10:12], 0)
	copy(out[12:28], header.SessionToken[:])
	binary.BigEndian.PutUint32(out[28:32], header.KeyEpoch)
	binary.BigEndian.PutUint64(out[32:40], header.Sequence)
	binary.BigEndian.PutUint32(out[40:44], header.PayloadLength)
	return out, nil
}

// ParseV2Datagram validates the exact frame length and fixed-header rules.
// It returns the payload as a slice into the supplied datagram.
func ParseV2Datagram(datagram []byte, maxDatagram uint32) (V2Header, []byte, error) {
	var header V2Header
	if maxDatagram == 0 {
		maxDatagram = V2DefaultMaxDatagram
	}
	if maxDatagram < V2HeaderSize || uint64(len(datagram)) > uint64(maxDatagram) || len(datagram) < V2HeaderSize {
		return header, nil, ErrV2Frame
	}
	if !bytes.Equal(datagram[:4], []byte("NLS2")) ||
		datagram[4] != V2Version ||
		(datagram[5] != V2PacketData && datagram[5] != V2PacketControl) ||
		binary.BigEndian.Uint16(datagram[6:8]) != 0 ||
		binary.BigEndian.Uint16(datagram[8:10]) != V2HeaderSize ||
		binary.BigEndian.Uint16(datagram[10:12]) != 0 {
		return header, nil, ErrV2Frame
	}
	payloadLength := binary.BigEndian.Uint32(datagram[40:44])
	if uint64(V2HeaderSize)+uint64(payloadLength) != uint64(len(datagram)) {
		return header, nil, ErrV2Frame
	}
	if datagram[5] == V2PacketData && payloadLength < V2AEADTagSize {
		return header, nil, ErrV2Frame
	}
	header.PacketType = datagram[5]
	header.Flags = binary.BigEndian.Uint16(datagram[6:8])
	copy(header.SessionToken[:], datagram[12:28])
	header.KeyEpoch = binary.BigEndian.Uint32(datagram[28:32])
	header.Sequence = binary.BigEndian.Uint64(datagram[32:40])
	header.PayloadLength = payloadLength
	return header, datagram[V2HeaderSize:], nil
}

// SealV2Data encrypts one DATA plaintext using the specified directional AES-256-GCM key.
// The caller owns sequence allocation and MUST never reuse the (epoch, sequence) pair under a key.
func SealV2Data(key []byte, header V2Header, outer OuterTuple, plaintext []byte, maxDatagram uint32) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: AES-256-GCM key must be 32 bytes", ErrV2Crypto)
	}
	if err := validateOuterTuple(outer); err != nil {
		return nil, err
	}
	if header.PacketType != V2PacketData || header.Flags != 0 {
		return nil, fmt.Errorf("%w: DATA packet type and zero flags are required", ErrV2Frame)
	}
	if maxDatagram == 0 {
		maxDatagram = V2DefaultMaxDatagram
	}
	if maxDatagram < V2HeaderSize+V2AEADTagSize ||
		uint64(V2HeaderSize)+uint64(len(plaintext))+V2AEADTagSize > uint64(maxDatagram) {
		return nil, ErrV2Frame
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: create AES cipher: %v", ErrV2Crypto, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: create AES-GCM: %v", ErrV2Crypto, err)
	}
	header.PayloadLength = uint32(len(plaintext) + aead.Overhead())
	headerBytes, err := MarshalV2Header(header)
	if err != nil {
		return nil, err
	}
	nonce := v2Nonce(header.KeyEpoch, header.Sequence)
	aad := makeV2AAD(headerBytes, outer)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	return append(headerBytes, ciphertext...), nil
}

// OpenV2Data authenticates and decrypts a DATA frame. Replay state is committed only
// after AEAD authentication; a nil replay window is rejected to avoid accidental replay bypass.
func OpenV2Data(key []byte, datagram []byte, outer OuterTuple, expectedToken [16]byte, expectedEpoch uint32, replay *ReplayWindow, maxDatagram uint32) (V2Header, []byte, error) {
	var zeroHeader V2Header
	if len(key) != 32 {
		return zeroHeader, nil, fmt.Errorf("%w: AES-256-GCM key must be 32 bytes", ErrV2Crypto)
	}
	if err := validateOuterTuple(outer); err != nil {
		return zeroHeader, nil, err
	}
	if replay == nil {
		return zeroHeader, nil, ErrV2ReplayWindow
	}
	header, ciphertext, err := ParseV2Datagram(datagram, maxDatagram)
	if err != nil {
		return zeroHeader, nil, err
	}
	if header.PacketType != V2PacketData ||
		header.SessionToken != expectedToken ||
		header.KeyEpoch != expectedEpoch ||
		header.PayloadLength < V2AEADTagSize {
		return zeroHeader, nil, ErrV2Frame
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return zeroHeader, nil, fmt.Errorf("%w: create AES cipher: %v", ErrV2Crypto, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return zeroHeader, nil, fmt.Errorf("%w: create AES-GCM: %v", ErrV2Crypto, err)
	}
	nonce := v2Nonce(header.KeyEpoch, header.Sequence)
	aad := makeV2AAD(datagram[:V2HeaderSize], outer)
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return zeroHeader, nil, ErrV2Crypto
	}
	if !replay.AcceptAuthenticated(header.Sequence) {
		clear(plaintext)
		return zeroHeader, nil, ErrV2Replay
	}
	return header, plaintext, nil
}

// ReplayWindow tracks the most recent 1024 authenticated sequence numbers.
// AcceptAuthenticated MUST only be called after the packet's AEAD tag has verified.
type ReplayWindow struct {
	mu          sync.Mutex
	initialized bool
	highest     uint64
	bits        [V2ReplayWindowSize / 64]uint64
}

// AcceptAuthenticated atomically rejects duplicates and packets older than the window.
func (w *ReplayWindow) AcceptAuthenticated(sequence uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.initialized {
		w.initialized = true
		w.highest = sequence
		w.bits[0] = 1
		return true
	}
	if sequence > w.highest {
		delta := sequence - w.highest
		w.shift(delta)
		w.highest = sequence
		w.bits[0] |= 1
		return true
	}
	distance := w.highest - sequence
	if distance >= V2ReplayWindowSize {
		return false
	}
	word := distance / 64
	mask := uint64(1) << (distance % 64)
	if w.bits[word]&mask != 0 {
		return false
	}
	w.bits[word] |= mask
	return true
}

func (w *ReplayWindow) shift(delta uint64) {
	if delta >= V2ReplayWindowSize {
		w.bits = [V2ReplayWindowSize / 64]uint64{}
		return
	}
	wordShift := int(delta / 64)
	bitShift := uint(delta % 64)
	var shifted [V2ReplayWindowSize / 64]uint64
	for i := len(shifted) - 1; i >= wordShift; i-- {
		shifted[i] = w.bits[i-wordShift] << bitShift
		if bitShift != 0 && i-wordShift > 0 {
			shifted[i] |= w.bits[i-wordShift-1] >> (64 - bitShift)
		}
	}
	w.bits = shifted
}

func v2Nonce(epoch uint32, sequence uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], epoch)
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func makeV2AAD(header []byte, outer OuterTuple) []byte {
	aad := make([]byte, 0, V2HeaderSize+16+16+4)
	aad = append(aad, header...)
	source := outer.SourceIPv6.As16()
	destination := outer.DestinationIPv6.As16()
	aad = append(aad, source[:]...)
	aad = append(aad, destination[:]...)
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[:2], outer.SourcePort)
	binary.BigEndian.PutUint16(ports[2:], outer.DestinationPort)
	aad = append(aad, ports[:]...)
	return aad
}

func validateOuterTuple(outer OuterTuple) error {
	if !outer.SourceIPv6.Is6() || outer.SourceIPv6.Is4In6() ||
		!outer.DestinationIPv6.Is6() || outer.DestinationIPv6.Is4In6() ||
		outer.SourceIPv6.IsUnspecified() || outer.SourceIPv6.IsMulticast() ||
		outer.DestinationIPv6.IsUnspecified() || outer.DestinationIPv6.IsMulticast() ||
		outer.SourcePort == 0 || outer.DestinationPort == 0 {
		return ErrV2OuterTuple
	}
	return nil
}

// MarshalHopPlaintext serializes the fixed v2 encrypted hop plaintext layout.
func MarshalHopPlaintext(value HopPlaintext, maxInnerEnvelope uint32) ([]byte, error) {
	if allZero(value.PreviousHopIdentity[:]) ||
		!value.PreviousHopLocator.Is6() || value.PreviousHopLocator.Is4In6() ||
		value.PreviousHopLocator.IsUnspecified() || value.PreviousHopLocator.IsMulticast() ||
		value.PreviousHopLocator.IsLoopback() || len(value.InnerEnvelope) == 0 ||
		uint64(len(value.InnerEnvelope)) > uint64(^uint32(0)) {
		return nil, ErrV2HopPlaintext
	}
	if maxInnerEnvelope == 0 {
		maxInnerEnvelope = V2DefaultMaxDatagram
	}
	if uint64(len(value.InnerEnvelope)) > uint64(maxInnerEnvelope) {
		return nil, ErrV2InnerEnvelopeSize
	}
	out := make([]byte, v2HopPlaintextFixedSize+len(value.InnerEnvelope))
	out[0] = v2HopPlaintextKindIP
	binary.BigEndian.PutUint16(out[1:3], v2HopIdentitySize)
	copy(out[3:3+v2HopIdentitySize], value.PreviousHopIdentity[:])
	offset := 3 + v2HopIdentitySize
	binary.BigEndian.PutUint16(out[offset:offset+2], v2HopLocatorSize)
	offset += 2
	locator := value.PreviousHopLocator.As16()
	copy(out[offset:offset+v2HopLocatorSize], locator[:])
	offset += v2HopLocatorSize
	binary.BigEndian.PutUint32(out[offset:offset+4], uint32(len(value.InnerEnvelope)))
	offset += 4
	copy(out[offset:], value.InnerEnvelope)
	return out, nil
}

// ParseHopPlaintext strictly validates lengths and rejects trailing bytes.
func ParseHopPlaintext(raw []byte, maxInnerEnvelope uint32) (HopPlaintext, error) {
	var value HopPlaintext
	if len(raw) < v2HopPlaintextFixedSize || raw[0] != v2HopPlaintextKindIP {
		return value, ErrV2HopPlaintext
	}
	if binary.BigEndian.Uint16(raw[1:3]) != v2HopIdentitySize {
		return value, ErrV2HopPlaintext
	}
	copy(value.PreviousHopIdentity[:], raw[3:3+v2HopIdentitySize])
	if allZero(value.PreviousHopIdentity[:]) {
		return HopPlaintext{}, ErrV2HopPlaintext
	}
	offset := 3 + v2HopIdentitySize
	if binary.BigEndian.Uint16(raw[offset:offset+2]) != v2HopLocatorSize {
		return HopPlaintext{}, ErrV2HopPlaintext
	}
	offset += 2
	var locatorBytes [16]byte
	copy(locatorBytes[:], raw[offset:offset+16])
	value.PreviousHopLocator = netip.AddrFrom16(locatorBytes)
	if !value.PreviousHopLocator.Is6() || value.PreviousHopLocator.Is4In6() ||
		value.PreviousHopLocator.IsUnspecified() || value.PreviousHopLocator.IsMulticast() ||
		value.PreviousHopLocator.IsLoopback() {
		return HopPlaintext{}, ErrV2HopPlaintext
	}
	offset += 16
	innerLength := uint64(binary.BigEndian.Uint32(raw[offset : offset+4]))
	offset += 4
	if maxInnerEnvelope == 0 {
		maxInnerEnvelope = V2DefaultMaxDatagram
	}
	if innerLength == 0 || innerLength > uint64(maxInnerEnvelope) {
		return HopPlaintext{}, ErrV2InnerEnvelopeSize
	}
	if innerLength != uint64(len(raw)-offset) {
		return HopPlaintext{}, ErrV2HopPlaintext
	}
	value.InnerEnvelope = append([]byte(nil), raw[offset:]...)
	return value, nil
}
