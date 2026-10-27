package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	V2ControlPrefixSize = 4
	v2ControlTLVHeaderSize = 6
	V2ControlInit uint8 = 0x01
	V2ControlRetry uint8 = 0x02
	V2ControlResp uint8 = 0x03
	V2ControlFinishI uint8 = 0x04
	V2ControlFinishR uint8 = 0x05
	V2ControlClose uint8 = 0x06
	V2ControlKeyUpdate uint8 = 0x07
)

var (
	ErrV2ControlPayload = errors.New("invalid NLS v2 control payload")
	ErrV2ControlTLV = errors.New("invalid NLS v2 control TLV")
	ErrV2ControlUnknownField = errors.New("unknown NLS v2 control field")
	ErrV2ControlReserved = errors.New("NLS v2 control reserved field is nonzero")
)

// V2ControlTLV is one canonical NLS v2 control type-length-value field.
type V2ControlTLV struct {
	Type  uint16
	Value []byte
}

// V2ControlMessage is a decoded control payload without the outer 44-byte NLS2 header.
// TLVs are preserved in wire order; values are copied during parsing.
type V2ControlMessage struct {
	Type uint8
	TLVs []V2ControlTLV
}

// MarshalV2ControlPayload serializes a control prefix and strictly ascending TLVs.
// maxPayload is an explicit local cap and must be nonzero. KEY_UPDATE is reserved and
// rejected until its cryptographic lifecycle and wire encoding are specified.
func MarshalV2ControlPayload(message V2ControlMessage, maxPayload uint32) ([]byte, error) {
	if maxPayload < V2ControlPrefixSize || !supportedV2ControlType(message.Type) || maxPayload == 0 {
		return nil, ErrV2ControlPayload
	}
	total := uint64(V2ControlPrefixSize)
	var previous uint16
	for i, tlv := range message.TLVs {
		if tlv.Type == 0 || (i > 0 && tlv.Type <= previous) {
			return nil, fmt.Errorf("%w: TLVs must have unique ascending types", ErrV2ControlTLV)
		}
		if uint64(len(tlv.Value)) > uint64(^uint32(0)) {
			return nil, ErrV2ControlTLV
		}
		total += uint64(v2ControlTLVHeaderSize) + uint64(len(tlv.Value))
		if total > uint64(maxPayload) {
			return nil, ErrV2ControlPayload
		}
		previous = tlv.Type
	}
	out := make([]byte, int(total))
	out[0] = message.Type
	// out[1] control_flags and out[2:4] reserved are canonical zero.
	offset := V2ControlPrefixSize
	for _, tlv := range message.TLVs {
		binary.BigEndian.PutUint16(out[offset:offset+2], tlv.Type)
		binary.BigEndian.PutUint32(out[offset+2:offset+6], uint32(len(tlv.Value)))
		copy(out[offset+v2ControlTLVHeaderSize:], tlv.Value)
		offset += v2ControlTLVHeaderSize + len(tlv.Value)
	}
	return out, nil
}

// ParseV2ControlPayload parses a bounded control payload using the per-message knownTLVTypes
// set. The control prefix and TLVs must be canonical and consume the entire input. Unknown
// fields are rejected because v2 defines no implicit non-critical extension allowance;
// callers must list every accepted type for that message.
func ParseV2ControlPayload(raw []byte, maxPayload uint32, knownTLVTypes map[uint16]struct{}) (V2ControlMessage, error) {
	var message V2ControlMessage
	if maxPayload < V2ControlPrefixSize || uint64(len(raw)) > uint64(maxPayload) || len(raw) < V2ControlPrefixSize {
		return message, ErrV2ControlPayload
	}
	if raw[1] != 0 || binary.BigEndian.Uint16(raw[2:4]) != 0 {
		return message, ErrV2ControlReserved
	}
	if !supportedV2ControlType(raw[0]) {
		return message, ErrV2ControlPayload
	}
	message.Type = raw[0]
	offset := V2ControlPrefixSize
	var previous uint16
	for offset < len(raw) {
		if len(raw)-offset < v2ControlTLVHeaderSize {
			return V2ControlMessage{}, ErrV2ControlTLV
		}
		tlvType := binary.BigEndian.Uint16(raw[offset : offset+2])
		tlvLength := uint64(binary.BigEndian.Uint32(raw[offset+2 : offset+6]))
		if tlvType == 0 || (offset > V2ControlPrefixSize && tlvType <= previous) {
			return V2ControlMessage{}, ErrV2ControlTLV
		}
		valueOffset := offset + v2ControlTLVHeaderSize
		remaining := uint64(len(raw) - valueOffset)
		if tlvLength > remaining {
			return V2ControlMessage{}, ErrV2ControlTLV
		}
		if _, known := knownTLVTypes[tlvType]; !known {
			return V2ControlMessage{}, fmt.Errorf("%w: 0x%04x", ErrV2ControlUnknownField, tlvType)
		}
		valueEnd := valueOffset + int(tlvLength)
		value := append([]byte(nil), raw[valueOffset:valueEnd]...)
		message.TLVs = append(message.TLVs, V2ControlTLV{Type: tlvType, Value: value})
		previous = tlvType
		offset = valueEnd
	}
	return message, nil
}

func supportedV2ControlType(controlType uint8) bool {
	return controlType >= V2ControlInit && controlType <= V2ControlClose
}
