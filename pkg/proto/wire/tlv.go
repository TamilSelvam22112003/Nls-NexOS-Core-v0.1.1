package wire

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	TLVCriticalBit uint16 = 0x8000
	TLVTypeMask    uint16 = 0x7fff
	TLVHeaderLen          = 6
)

type TLV struct {
	Type  uint16
	Value []byte
}

// EncodeTLVs requires strictly ascending types and rejects duplicates.
func EncodeTLVs(values []TLV) ([]byte, error) {
	total := 0
	var previous uint16
	for i, item := range values {
		if i > 0 && item.Type <= previous {
			return nil, fmt.Errorf("%w: TLVs must be sorted and unique", ErrMalformed)
		}
		if uint64(len(item.Value)) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: TLV value too large", ErrMalformed)
		}
		if total > math.MaxInt-TLVHeaderLen-len(item.Value) {
			return nil, fmt.Errorf("%w: TLV stream too large", ErrMalformed)
		}
		total += TLVHeaderLen + len(item.Value)
		previous = item.Type
	}
	out := make([]byte, total)
	offset := 0
	for _, item := range values {
		binary.BigEndian.PutUint16(out[offset:offset+2], item.Type)
		binary.BigEndian.PutUint32(out[offset+2:offset+6], uint32(len(item.Value)))
		copy(out[offset+TLVHeaderLen:], item.Value)
		offset += TLVHeaderLen + len(item.Value)
	}
	return out, nil
}

// ParseTLVs skips unknown noncritical types and rejects unknown critical types.
// knownTypes contains base type IDs with the critical bit cleared.
func ParseTLVs(data []byte, knownTypes map[uint16]struct{}) ([]TLV, error) {
	var out []TLV
	var previous uint16
	seenBase := make(map[uint16]struct{})
	for offset := 0; offset < len(data); {
		if len(data)-offset < TLVHeaderLen {
			return nil, fmt.Errorf("%w: truncated TLV header", ErrMalformed)
		}
		typ := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint32(data[offset+2 : offset+6])
		offset += TLVHeaderLen
		if len(out) > 0 && typ <= previous {
			return nil, fmt.Errorf("%w: TLVs must be sorted", ErrMalformed)
		}
		base := typ & TLVTypeMask
		if _, duplicate := seenBase[base]; duplicate {
			return nil, fmt.Errorf("%w: duplicate TLV base type", ErrMalformed)
		}
		if uint64(length) > uint64(len(data)-offset) {
			return nil, fmt.Errorf("%w: truncated TLV value", ErrMalformed)
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		previous = typ
		seenBase[base] = struct{}{}
		_, known := knownTypes[base]
		if !known && typ&TLVCriticalBit != 0 {
			return nil, fmt.Errorf("%w: unknown critical TLV 0x%04x", ErrMalformed, typ)
		}
		if known {
			out = append(out, TLV{Type: typ, Value: append([]byte(nil), value...)})
		}
	}
	return out, nil
}
