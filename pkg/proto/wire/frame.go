package wire

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.1/pkg/proto"
)

const (
	TypeM1Init    byte = 0x01
	TypeM1Cookie  byte = 0x02
	TypeM2        byte = 0x03
	TypeM3        byte = 0x04
	TypeM4        byte = 0x05
	TypeData      byte = 0x10
	TypeRekeyInit byte = 0x11
	TypeRekeyAck  byte = 0x12
)

var (
	ErrMalformed           = errors.New("malformed NLS frame")
	ErrUnsupportedVersion  = errors.New("unsupported NLS version")
	ErrUnexpectedType      = errors.New("unexpected NLS message type")
	ErrNonCanonicalHeader  = errors.New("noncanonical NLS common header")
)

type Frame struct {
	Version byte
	Type    byte
	Body    []byte
}

// EncodeFrame encodes handshake framing: version, type, zero flags, body length, zero reserved.
func EncodeFrame(messageType byte, body []byte) ([]byte, error) {
	if len(body) > 65535 {
		return nil, fmt.Errorf("%w: body too large", ErrMalformed)
	}
	packet := make([]byte, proto.CommonHeaderLen+len(body))
	packet[0] = proto.WireVersion
	packet[1] = messageType
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(body)))
	copy(packet[proto.CommonHeaderLen:], body)
	return packet, nil
}

// ParseFrame rejects truncated data, nonzero flags/reserved fields, and trailing bytes.
func ParseFrame(packet []byte, expectedType byte) (Frame, error) {
	if len(packet) < proto.CommonHeaderLen {
		return Frame{}, fmt.Errorf("%w: truncated header", ErrMalformed)
	}
	if packet[0] != proto.WireVersion {
		return Frame{}, ErrUnsupportedVersion
	}
	if packet[2] != 0 || packet[3] != 0 || packet[6] != 0 || packet[7] != 0 {
		return Frame{}, ErrNonCanonicalHeader
	}
	bodyLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if len(packet) != proto.CommonHeaderLen+bodyLen {
		return Frame{}, fmt.Errorf("%w: body length mismatch or trailing bytes", ErrMalformed)
	}
	if expectedType != 0 && packet[1] != expectedType {
		return Frame{}, ErrUnexpectedType
	}
	body := append([]byte(nil), packet[proto.CommonHeaderLen:]...)
	return Frame{Version: packet[0], Type: packet[1], Body: body}, nil
}
