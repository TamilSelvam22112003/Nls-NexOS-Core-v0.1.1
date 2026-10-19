package wire

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	body := []byte{1, 2, 3}
	packet, err := EncodeFrame(TypeM2, body)
	if err != nil { t.Fatal(err) }
	if len(packet) != 11 { t.Fatalf("length = %d, want 11", len(packet)) }
	got, err := ParseFrame(packet, TypeM2)
	if err != nil { t.Fatal(err) }
	if got.Type != TypeM2 || string(got.Body) != string(body) { t.Fatalf("unexpected frame: %#v", got) }
}

func TestFrameRejectsInvalidInputs(t *testing.T) {
	packet, _ := EncodeFrame(TypeM2, []byte{1})
	cases := []struct{name string; mutate func([]byte) []byte; expected error}{
		{"short", func(b []byte) []byte { return b[:7] }, ErrMalformed},
		{"version", func(b []byte) []byte { b[0] = 2; return b }, ErrUnsupportedVersion},
		{"flags", func(b []byte) []byte { b[2] = 1; return b }, ErrNonCanonicalHeader},
		{"reserved", func(b []byte) []byte { b[7] = 1; return b }, ErrNonCanonicalHeader},
		{"length", func(b []byte) []byte { binary.BigEndian.PutUint16(b[4:6], 2); return b }, ErrMalformed},
		{"trailing", func(b []byte) []byte { return append(b, 0) }, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), packet...)
			_, err := ParseFrame(tc.mutate(b), 0)
			if !errors.Is(err, tc.expected) { t.Fatalf("error=%v, want %v", err, tc.expected) }
		})
	}
	if _, err := ParseFrame(packet, TypeM3); !errors.Is(err, ErrUnexpectedType) { t.Fatalf("expected type error, got %v", err) }
	if _, err := EncodeFrame(TypeM2, make([]byte, 65536)); !errors.Is(err, ErrMalformed) { t.Fatalf("expected oversized body error, got %v", err) }
}

func TestTLVRoundTripAndUnknownNoncriticalSkip(t *testing.T) {
	known := map[uint16]struct{}{1: {}, 2: {}}
	encoded, err := EncodeTLVs([]TLV{{Type: 1, Value: []byte("a")}, {Type: 2, Value: []byte("bc")}, {Type: 9, Value: []byte("skip")}})
	if err != nil { t.Fatal(err) }
	got, err := ParseTLVs(encoded, known)
	if err != nil { t.Fatal(err) }
	if len(got) != 2 || string(got[0].Value) != "a" || string(got[1].Value) != "bc" { t.Fatalf("unexpected TLVs: %#v", got) }
}

func TestTLVRejectsInvalidCorpus(t *testing.T) {
	known := map[uint16]struct{}{1: {}}
	unknownCritical, _ := EncodeTLVs([]TLV{{Type: TLVCriticalBit | 9, Value: []byte("x")}})
	unsorted, _ := EncodeTLVs([]TLV{{Type: 1, Value: nil}, {Type: 2, Value: nil}})
	duplicateCriticalBase := []byte{0,1,0,0,0,0,0x80,1,0,0,0,0}
	truncatedHeader := []byte{0,1,0}
	truncatedValue := []byte{0,1,0,0,0,2,0xff}
	duplicate, _ := EncodeTLVs([]TLV{{Type: 1, Value: nil}, {Type: 1, Value: nil}})
	for name, input := range map[string][]byte{
		"unknown critical": unknownCritical,
		"truncated header": truncatedHeader,
		"truncated value": truncatedValue,
		"duplicate": duplicate,
		"critical/base duplicate": duplicateCriticalBase,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTLVs(input, known); err == nil { t.Fatal("expected rejection") }
		})
	}
	if _, err := EncodeTLVs([]TLV{{Type: 2, Value: nil}, {Type: 1, Value: nil}}); err == nil { t.Fatal("expected unsorted encoder rejection") }
	// A well-formed unknown noncritical TLV is intentionally skipped.
	unknown, _ := EncodeTLVs([]TLV{{Type: 7, Value: []byte("ignored")}})
	if got, err := ParseTLVs(unknown, known); err != nil || len(got) != 0 { t.Fatalf("unknown noncritical: %#v, %v", got, err) }
	_ = unsorted
}
