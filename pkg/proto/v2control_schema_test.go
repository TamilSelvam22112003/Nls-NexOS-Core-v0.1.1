package proto

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func validV2ControlMessageForTest(messageType uint8) V2ControlMessage {
	switch messageType {
	case V2ControlInit:
		suites := []byte{0, 1, 0, 1}
		return V2ControlMessage{Type: messageType, TLVs: []V2ControlTLV{
			{Type: 0x8001, Value: nonzeroBytesForTest(32, 1)},
			{Type: 0x8002, Value: nonzeroBytesForTest(32, 2)},
			{Type: 0x8003, Value: nonzeroBytesForTest(32, 3)},
			{Type: 0x8004, Value: nonzeroBytesForTest(32, 4)},
			{Type: 0x8005, Value: suites},
		}}
	case V2ControlRetry:
		return V2ControlMessage{Type: messageType, TLVs: []V2ControlTLV{{Type: 0x8006, Value: nonzeroBytesForTest(V2CookieSize, 5)}}}
	case V2ControlResp:
		return V2ControlMessage{Type: messageType, TLVs: []V2ControlTLV{
			{Type: 0x8001, Value: validV2CertificateChainForTest()},
			{Type: 0x8002, Value: validV2StatusTLVForTest()},
			{Type: 0x8003, Value: nonzeroBytesForTest(32, 6)},
			{Type: 0x8004, Value: nonzeroBytesForTest(32, 7)},
			{Type: 0x8005, Value: []byte{0, 1}},
			{Type: 0x8006, Value: validV2EndpointBindingForTest()},
			{Type: 0x8007, Value: nonzeroBytesForTest(64, 8)},
		}}
	case V2ControlFinishI:
		return V2ControlMessage{Type: messageType, TLVs: []V2ControlTLV{
			{Type: 0x8001, Value: validV2CertificateChainForTest()},
			{Type: 0x8002, Value: validV2StatusTLVForTest()},
			{Type: 0x8003, Value: nonzeroBytesForTest(32, 9)},
			{Type: 0x8004, Value: nonzeroBytesForTest(64, 10)},
		}}
	case V2ControlFinishR:
		lifetime := make([]byte, 4)
		binary.BigEndian.PutUint32(lifetime, 300)
		generation := make([]byte, 8)
		binary.BigEndian.PutUint64(generation, 7)
		return V2ControlMessage{Type: messageType, TLVs: []V2ControlTLV{
			{Type: 0x8001, Value: nonzeroBytesForTest(32, 11)},
			{Type: 0x8002, Value: nonzeroBytesForTest(16, 12)},
			{Type: 0x8003, Value: lifetime},
			{Type: 0x8004, Value: generation},
		}}
	case V2ControlClose:
		return V2ControlMessage{Type: messageType, TLVs: []V2ControlTLV{{Type: 0x8001, Value: []byte{0, 1}}}}
	default:
		return V2ControlMessage{Type: messageType}
	}
}

func nonzeroBytesForTest(length int, value byte) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func validV2CertificateChainForTest() []byte {
	// One length-prefixed synthetic DER byte-string; schema validation deliberately
	// does not parse X.509 or treat these bytes as authenticated certificate evidence.
	out := make([]byte, 4+4+3)
	binary.BigEndian.PutUint32(out[:4], 1)
	binary.BigEndian.PutUint32(out[4:8], 3)
	copy(out[8:], []byte{0x30, 0x01, 0x00})
	return out
}

func validV2StatusTLVForTest() []byte {
	out := make([]byte, 4+v2ControlStatusObjectBytes)
	binary.BigEndian.PutUint32(out[:4], v2ControlStatusObjectBytes)
	copy(out[4:8], []byte("N2ST"))
	out[8] = 1
	out[9] = 1
	binary.BigEndian.PutUint32(out[12:16], v2ControlStatusObjectBytes)
	return out
}

func validV2EndpointBindingForTest() []byte {
	out := make([]byte, 51)
	out[0] = 6
	copy(out[1:17], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10})
	binary.BigEndian.PutUint16(out[17:19], 4242)
	out[19] = 0x01
	return out
}

func TestValidateV2ControlMessageAcceptsCandidateSchemas(t *testing.T) {
	messages := []V2ControlMessage{
		validV2ControlMessageForTest(V2ControlInit),
		validV2ControlMessageForTest(V2ControlRetry),
		validV2ControlMessageForTest(V2ControlResp),
		validV2ControlMessageForTest(V2ControlFinishI),
		validV2ControlMessageForTest(V2ControlFinishR),
		validV2ControlMessageForTest(V2ControlClose),
	}
	names := []string{"INIT", "RETRY", "RESP", "FINISH_I", "FINISH_R", "CLOSE"}
	for i, message := range messages {
		t.Run(names[i], func(t *testing.T) {
			if err := ValidateV2ControlMessage(message); err != nil {
				t.Fatalf("valid message type 0x%02x rejected: %v", message.Type, err)
			}
		})
	}
}

func TestValidateV2ControlMessageRejectsFieldSetAndLengthDefects(t *testing.T) {
	tests := []struct {
		name    string
		message V2ControlMessage
	}{
		{name: "INIT missing field", message: V2ControlMessage{Type: V2ControlInit}},
		{name: "INIT unknown field", message: V2ControlMessage{Type: V2ControlInit, TLVs: []V2ControlTLV{{Type: 0x8fff}}}},
		{name: "RETRY cookie length", message: V2ControlMessage{Type: V2ControlRetry, TLVs: []V2ControlTLV{{Type: 0x8006, Value: []byte{1}}}}},
		{name: "RESP signature length", message: func() V2ControlMessage { m := validV2ControlMessageForTest(V2ControlResp); m.TLVs[6].Value = []byte{1}; return m }()},
		{name: "RESP unsupported suite", message: func() V2ControlMessage { m := validV2ControlMessageForTest(V2ControlResp); m.TLVs[4].Value = []byte{0, 2}; return m }()},
		{name: "RESP malformed certificate chain", message: func() V2ControlMessage { m := validV2ControlMessageForTest(V2ControlResp); m.TLVs[0].Value = []byte{0, 0, 0, 1, 0, 0, 0, 8, 1}; return m }()},
		{name: "RESP invalid endpoint", message: func() V2ControlMessage { m := validV2ControlMessageForTest(V2ControlResp); bad := validV2EndpointBindingForTest(); copy(bad[1:17], make([]byte, 16)); m.TLVs[5].Value = bad; return m }()},
		{name: "FINISH_I status length", message: func() V2ControlMessage { m := validV2ControlMessageForTest(V2ControlFinishI); m.TLVs[1].Value = []byte{1}; return m }()},
		{name: "FINISH_R zero token", message: func() V2ControlMessage { m := validV2ControlMessageForTest(V2ControlFinishR); m.TLVs[1].Value = make([]byte, 16); return m }()},
		{name: "CLOSE unknown reason", message: V2ControlMessage{Type: V2ControlClose, TLVs: []V2ControlTLV{{Type: 0x8001, Value: []byte{0, 99}}}}},
		{name: "reserved KEY_UPDATE", message: V2ControlMessage{Type: V2ControlKeyUpdate}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateV2ControlMessage(tt.message); !errors.Is(err, ErrV2ControlSchema) {
				t.Fatalf("expected schema rejection, got %v", err)
			}
		})
	}
}

func TestV2EndpointBindingUsesRoutableIPv6Address(t *testing.T) {
	for _, address := range []netip.Addr{
		netip.IPv6Unspecified(),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("ff02::1"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("::ffff:192.0.2.1"),
	} {
		binding := validV2EndpointBindingForTest()
		addressBytes := address.As16()
		copy(binding[1:17], addressBytes[:])
		if err := validateV2EndpointBinding(binding); err == nil {
			t.Fatalf("invalid endpoint address %s accepted", address)
		}
	}
}
