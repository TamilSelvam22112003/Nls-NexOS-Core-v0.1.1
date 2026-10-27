package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	tests := []Frame{
		{Type: TypeM1Init, Body: make([]byte, 120)},
		{Type: TypeM1Cookie, Body: make([]byte, 52)},
		{Type: TypeM2, Body: make([]byte, 244)},
		{Type: TypeM3, Body: make([]byte, 178)},
		{Type: TypeM4, Body: make([]byte, 64)},
		{Type: TypeData, Body: []byte("ciphertext and tag")},
		{Type: TypeRekeyInit, Body: []byte("rekey init")},
		{Type: TypeRekeyAck, Body: []byte("rekey ack")},
	}
	for _, want := range tests {
		gotBytes, err := want.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%v): %v", want.Type, err)
		}
		got, err := Parse(gotBytes)
		if err != nil {
			t.Fatalf("Parse(%v): %v", want.Type, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Body, want.Body) {
			t.Fatalf("round trip mismatch: got %#v, want %#v", got, want)
		}
	}
}

func TestParseRejectsInvalidFrames(t *testing.T) {
	valid, err := (Frame{Type: TypeM1Init, Body: make([]byte, 120)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"short header", []byte{1, 1, 0}, ErrMalformed},
		{"unsupported version", func() []byte { b := append([]byte(nil), valid...); b[0] = 2; return b }(), ErrUnsupported},
		{"unknown type", func() []byte { b := append([]byte(nil), valid...); b[1] = 0x7f; return b }(), ErrUnknownMessage},
		{"nonzero flags", func() []byte { b := append([]byte(nil), valid...); b[3] = 1; return b }(), ErrInvalidFlags},
		{"nonzero reserved", func() []byte { b := append([]byte(nil), valid...); b[7] = 1; return b }(), ErrReservedNonzero},
		{"truncated body", valid[:len(valid)-1], ErrMalformed},
		{"trailing byte", append(append([]byte(nil), valid...), 0), ErrMalformed},
		{"oversized", make([]byte, MaxDatagramSize+1), ErrOversized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.data)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestMarshalRejectsUnknownAndOversized(t *testing.T) {
	if _, err := (Frame{Type: MessageType(0x7f)}).Marshal(); !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("unknown type error = %v", err)
	}
	if _, err := (Frame{Type: TypeData, Body: make([]byte, MaxBodySize+1)}).Marshal(); !errors.Is(err, ErrOversized) {
		t.Fatalf("oversized body error = %v", err)
	}
}

func TestParseCopiesBody(t *testing.T) {
	wire, err := (Frame{Type: TypeM1Cookie, Body: []byte{1, 2, 3}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire[HeaderSize] = 9
	if frame.Body[0] != 1 {
		t.Fatal("parsed body aliases input")
	}
}

func TestMarshalUsesBigEndianLengthAndZeroReserved(t *testing.T) {
	wire, err := (Frame{Type: TypeM1Cookie, Body: make([]byte, 258)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(wire[4:6]) != 258 || binary.BigEndian.Uint16(wire[2:4]) != 0 || binary.BigEndian.Uint16(wire[6:8]) != 0 {
		t.Fatal("invalid common header encoding")
	}
}

func FuzzParseNeverPanics(f *testing.F) {
	seed, _ := (Frame{Type: TypeM1Init, Body: make([]byte, 120)}).Marshal()
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{1, 0x10, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
