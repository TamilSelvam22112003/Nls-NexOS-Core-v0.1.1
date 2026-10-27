package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Version is the only wire version supported by this implementation.
	Version uint8 = 1

	// HeaderSize is the fixed common NLS framing header size in bytes.
	HeaderSize = 8

	// MaxDatagramSize is the v1 NLS UDP payload ceiling for a 1500-byte
	// outer path MTU with IPv6 and UDP headers.
	MaxDatagramSize = 1452
	MaxBodySize     = MaxDatagramSize - HeaderSize
)

var (
	ErrMalformed        = errors.New("nls: malformed frame")
	ErrUnsupported      = errors.New("nls: unsupported version")
	ErrUnknownMessage   = errors.New("nls: unknown message type")
	ErrOversized        = errors.New("nls: datagram exceeds v1 limit")
	ErrReservedNonzero  = errors.New("nls: reserved bits must be zero")
	ErrInvalidFlags     = errors.New("nls: flags must be zero in v1")
)

// MessageType identifies a v1 NLS datagram.
type MessageType uint8

const (
	TypeM1Init   MessageType = 0x01
	TypeM1Cookie MessageType = 0x02
	TypeM2       MessageType = 0x03
	TypeM3       MessageType = 0x04
	TypeM4       MessageType = 0x05
	TypeData     MessageType = 0x10
	TypeRekeyInit MessageType = 0x11
	TypeRekeyAck  MessageType = 0x12
)

// Frame is a decoded common NLS frame. Body is copied by Parse, so it does
// not alias the input datagram.
type Frame struct {
	Type MessageType
	Body []byte
}

func knownType(t MessageType) bool {
	switch t {
	case TypeM1Init, TypeM1Cookie, TypeM2, TypeM3, TypeM4, TypeData, TypeRekeyInit, TypeRekeyAck:
		return true
	default:
		return false
	}
}

// Marshal encodes a Frame using the exact v1 common framing header:
// version:u8, type:u8, flags:u16=0, body_len:u16, reserved:u16=0.
// Message-specific validation belongs to the message-specific parser.
func (f Frame) Marshal() ([]byte, error) {
	if !knownType(f.Type) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownMessage, uint8(f.Type))
	}
	if len(f.Body) > MaxBodySize {
		return nil, ErrOversized
	}

	out := make([]byte, HeaderSize+len(f.Body))
	out[0] = Version
	out[1] = byte(f.Type)
	binary.BigEndian.PutUint16(out[2:4], 0)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(f.Body)))
	binary.BigEndian.PutUint16(out[6:8], 0)
	copy(out[HeaderSize:], f.Body)
	return out, nil
}

// Parse strictly decodes one complete v1 NLS datagram. It rejects unknown
// types, nonzero flags/reserved fields, inconsistent lengths, truncation,
// trailing bytes, and datagrams above the protocol's v1 size ceiling.
func Parse(datagram []byte) (Frame, error) {
	if len(datagram) > MaxDatagramSize {
		return Frame{}, ErrOversized
	}
	if len(datagram) < HeaderSize {
		return Frame{}, ErrMalformed
	}
	if datagram[0] != Version {
		return Frame{}, fmt.Errorf("%w: %d", ErrUnsupported, datagram[0])
	}

	t := MessageType(datagram[1])
	if !knownType(t) {
		return Frame{}, fmt.Errorf("%w: 0x%02x", ErrUnknownMessage, uint8(t))
	}
	if binary.BigEndian.Uint16(datagram[2:4]) != 0 {
		return Frame{}, ErrInvalidFlags
	}
	bodyLen := int(binary.BigEndian.Uint16(datagram[4:6]))
	if binary.BigEndian.Uint16(datagram[6:8]) != 0 {
		return Frame{}, ErrReservedNonzero
	}
	if bodyLen != len(datagram)-HeaderSize {
		return Frame{}, ErrMalformed
	}
	body := make([]byte, bodyLen)
	copy(body, datagram[HeaderSize:])
	return Frame{Type: t, Body: body}, nil
}
