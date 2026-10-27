package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestV2ControlPayloadRoundTripCanonicalTLVs(t *testing.T) {
	message := V2ControlMessage{
		Type: V2ControlInit,
		TLVs: []V2ControlTLV{
			{Type: 0x8001, Value: []byte{1, 2, 3}},
			{Type: 0x8003, Value: []byte{4, 5}},
		},
	}
	raw, err := MarshalV2ControlPayload(message, 128)
	if err != nil {
		t.Fatal(err)
	}
	known := map[uint16]struct{}{0x8001: {}, 0x8003: {}}
	parsed, err := ParseV2ControlPayload(raw, 128, known)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Type != message.Type || len(parsed.TLVs) != len(message.TLVs) {
		t.Fatalf("unexpected parsed control: %+v", parsed)
	}
	for i := range message.TLVs {
		if parsed.TLVs[i].Type != message.TLVs[i].Type || !bytes.Equal(parsed.TLVs[i].Value, message.TLVs[i].Value) {
			t.Fatalf("TLV %d does not round-trip", i)
		}
	}
	parsed.TLVs[0].Value[0] ^= 0xff
	if message.TLVs[0].Value[0] == parsed.TLVs[0].Value[0] {
		t.Fatal("parser must copy TLV values rather than alias input state")
	}
}

func TestV2ControlPayloadRejectsMalformedRecords(t *testing.T) {
	known := map[uint16]struct{}{0x8001: {}, 0x8002: {}}
	base, err := MarshalV2ControlPayload(V2ControlMessage{
		Type: V2ControlInit,
		TLVs: []V2ControlTLV{{Type: 0x8001, Value: []byte{1}}, {Type: 0x8002, Value: []byte{2}}},
	}, 128)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw []byte
		max uint32
		known map[uint16]struct{}
		want error
	}{
		{name: "short prefix", raw: []byte{1, 0, 0}, max: 128, known: known, want: ErrV2ControlPayload},
		{name: "oversize", raw: base, max: uint32(len(base) - 1), known: known, want: ErrV2ControlPayload},
		{name: "nonzero flags", raw: mutateV2ControlByte(base, 1, 1), max: 128, known: known, want: ErrV2ControlReserved},
		{name: "nonzero reserved", raw: mutateV2ControlByte(base, 3, 1), max: 128, known: known, want: ErrV2ControlReserved},
		{name: "unknown control type", raw: mutateV2ControlByte(base, 0, V2ControlKeyUpdate), max: 128, known: known, want: ErrV2ControlPayload},
		{name: "truncated TLV header", raw: append(append([]byte(nil), base...), 0x80), max: 128, known: known, want: ErrV2ControlTLV},
		{name: "declared length exceeds bytes", raw: mutateV2ControlLength(base, 0xffffffff), max: 128, known: known, want: ErrV2ControlTLV},
		{name: "unknown critical field", raw: mutateV2ControlFirstType(base, 0x8fff), max: 128, known: known, want: ErrV2ControlUnknownField},
		{name: "unknown noncritical field", raw: mutateV2ControlFirstType(base, 0x0fff), max: 128, known: known, want: ErrV2ControlUnknownField},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseV2ControlPayload(tt.raw, tt.max, tt.known); !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestMarshalV2ControlPayloadRejectsUnsortedDuplicateAndReservedTypes(t *testing.T) {
	tests := []V2ControlMessage{
		{Type: V2ControlInit, TLVs: []V2ControlTLV{{Type: 0x8002}, {Type: 0x8001}}},
		{Type: V2ControlInit, TLVs: []V2ControlTLV{{Type: 0x8001}, {Type: 0x8001}}},
		{Type: V2ControlInit, TLVs: []V2ControlTLV{{Type: 0}}},
		{Type: V2ControlKeyUpdate},
	}
	for i, message := range tests {
		if _, err := MarshalV2ControlPayload(message, 128); err == nil {
			t.Fatalf("case %d should be rejected", i)
		}
	}
	if _, err := MarshalV2ControlPayload(V2ControlMessage{Type: V2ControlInit}, 3); !errors.Is(err, ErrV2ControlPayload) {
		t.Fatalf("undersized cap should be rejected, got %v", err)
	}
}

func mutateV2ControlByte(raw []byte, offset int, value byte) []byte {
	out := append([]byte(nil), raw...)
	out[offset] = value
	return out
}

func mutateV2ControlLength(raw []byte, value uint32) []byte {
	out := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(out[V2ControlPrefixSize+2:V2ControlPrefixSize+6], value)
	return out
}

func mutateV2ControlFirstType(raw []byte, value uint16) []byte {
	out := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(out[V2ControlPrefixSize:V2ControlPrefixSize+2], value)
	return out
}
