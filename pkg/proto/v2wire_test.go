package proto

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

func testOuterTuple() OuterTuple {
	return OuterTuple{
		SourceIPv6:      netip.MustParseAddr("2001:db8::1"),
		DestinationIPv6: netip.MustParseAddr("2001:db8::2"),
		SourcePort:      40000,
		DestinationPort: 4242,
	}
}

func testSessionToken() [16]byte {
	var token [16]byte
	token[0] = 1
	return token
}

func TestV2DataSealOpenAndReplay(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	token := testSessionToken()
	outer := testOuterTuple()
	plaintext := []byte("NLS v2 authenticated hop payload")
	header := V2Header{
		PacketType:   V2PacketData,
		SessionToken: token,
		KeyEpoch:     0,
		Sequence:     0,
	}
	datagram, err := SealV2Data(key, header, outer, plaintext, 1500)
	if err != nil {
		t.Fatal(err)
	}
	parsed, payload, err := ParseV2Datagram(datagram, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Sequence != 0 || parsed.KeyEpoch != 0 || parsed.PayloadLength != uint32(len(payload)) {
		t.Fatalf("unexpected parsed header: %+v", parsed)
	}

	var replay ReplayWindow
	gotHeader, gotPlaintext, err := OpenV2Data(key, datagram, outer, token, 0, &replay, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if gotHeader.Sequence != 0 || !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatal("decrypted DATA does not match input")
	}
	if _, _, err := OpenV2Data(key, datagram, outer, token, 0, &replay, 1500); !errors.Is(err, ErrV2Replay) {
		t.Fatalf("duplicate DATA should be rejected as replay, got %v", err)
	}
}

func TestV2DataAuthenticatesOuterTupleAndHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 32)
	token := testSessionToken()
	outer := testOuterTuple()
	datagram, err := SealV2Data(key, V2Header{PacketType: V2PacketData, SessionToken: token, KeyEpoch: 9, Sequence: 7}, outer, []byte("test"), 1500)
	if err != nil {
		t.Fatal(err)
	}

	wrongOuter := outer
	wrongOuter.SourceIPv6 = netip.MustParseAddr("2001:db8::9")
	var replayA ReplayWindow
	if _, _, err := OpenV2Data(key, datagram, wrongOuter, token, 9, &replayA, 1500); !errors.Is(err, ErrV2Crypto) {
		t.Fatalf("modified outer source must fail AEAD, got %v", err)
	}

	wrongToken := token
	wrongToken[1] = 7
	var replayB ReplayWindow
	if _, _, err := OpenV2Data(key, datagram, outer, wrongToken, 9, &replayB, 1500); !errors.Is(err, ErrV2Frame) {
		t.Fatalf("wrong session token must be rejected, got %v", err)
	}
	var replayC ReplayWindow
	if _, _, err := OpenV2Data(key, datagram, outer, token, 8, &replayC, 1500); !errors.Is(err, ErrV2Frame) {
		t.Fatalf("wrong key epoch must be rejected, got %v", err)
	}
}

func TestV2UnauthenticatedPacketDoesNotConsumeReplaySequence(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, 32)
	token := testSessionToken()
	outer := testOuterTuple()
	datagram, err := SealV2Data(key, V2Header{PacketType: V2PacketData, SessionToken: token, Sequence: 5}, outer, []byte("authenticated after retry"), 1500)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), datagram...)
	tampered[len(tampered)-1] ^= 1
	var replay ReplayWindow
	if _, _, err := OpenV2Data(key, tampered, outer, token, 0, &replay, 1500); !errors.Is(err, ErrV2Crypto) {
		t.Fatalf("tampered tag must fail authentication, got %v", err)
	}
	if _, _, err := OpenV2Data(key, datagram, outer, token, 0, &replay, 1500); err != nil {
		t.Fatalf("failed authentication must not commit replay state: %v", err)
	}
}

func TestParseV2DatagramRejectsLengthAndReservedFields(t *testing.T) {
	key := bytes.Repeat([]byte{0x17}, 32)
	token := testSessionToken()
	datagram, err := SealV2Data(key, V2Header{PacketType: V2PacketData, SessionToken: token}, testOuterTuple(), []byte("length"), 1500)
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(append([]byte(nil), datagram...), 0)
	if _, _, err := ParseV2Datagram(trailing, 1500); !errors.Is(err, ErrV2Frame) {
		t.Fatalf("trailing byte should fail exact length, got %v", err)
	}
	reserved := append([]byte(nil), datagram...)
	reserved[10] = 1
	if _, _, err := ParseV2Datagram(reserved, 1500); !errors.Is(err, ErrV2Frame) {
		t.Fatalf("nonzero reserved word should fail, got %v", err)
	}
	tooLarge := uint32(len(datagram) - 1)
	if _, _, err := ParseV2Datagram(datagram, tooLarge); !errors.Is(err, ErrV2Frame) {
		t.Fatalf("datagram above configured maximum should fail, got %v", err)
	}
}

func TestReplayWindowConcurrentMarkingAndWindowShift(t *testing.T) {
	var window ReplayWindow
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if window.AcceptAuthenticated(100) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("one sequence should be accepted once under concurrency, accepted=%d", accepted.Load())
	}
	if !window.AcceptAuthenticated(101) {
		t.Fatal("newer sequence should be accepted")
	}
	if !window.AcceptAuthenticated(99) {
		t.Fatal("in-window out-of-order sequence should be accepted")
	}
	if window.AcceptAuthenticated(99) {
		t.Fatal("duplicate out-of-order sequence should be rejected")
	}
	if !window.AcceptAuthenticated(2000) {
		t.Fatal("large forward jump should reset replay window")
	}
	if window.AcceptAuthenticated(100) {
		t.Fatal("sequence older than replay window should be rejected")
	}
}

func TestHopPlaintextRoundTripAndStrictLengths(t *testing.T) {
	identity := [32]byte{1, 2, 3}
	input := HopPlaintext{
		PreviousHopIdentity: identity,
		PreviousHopLocator:  LogicalLocatorForIdentity(identity),
		RouteToken:          [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1},
		InnerEnvelope:       []byte{0x4e, 0x32, 0x44, 0x45, 1, 2, 3, 4},
	}
	encoded, err := MarshalHopPlaintext(input, 1024)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseHopPlaintext(encoded, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PreviousHopIdentity != identity ||
		parsed.PreviousHopLocator != input.PreviousHopLocator ||
		parsed.RouteToken != input.RouteToken ||
		!bytes.Equal(parsed.InnerEnvelope, input.InnerEnvelope) {
		t.Fatalf("hop plaintext roundtrip mismatch: %+v", parsed)
	}

	trailing := append(append([]byte(nil), encoded...), 0)
	if _, err := ParseHopPlaintext(trailing, 1024); !errors.Is(err, ErrV2HopPlaintext) {
		t.Fatalf("trailing hop plaintext byte must fail, got %v", err)
	}

	wrongLocator := input
	wrongLocator.PreviousHopLocator = netip.MustParseAddr("fd00::1234")
	if _, err := MarshalHopPlaintext(wrongLocator, 1024); !errors.Is(err, ErrV2HopPlaintext) {
		t.Fatalf("locator not derived from authenticated identity must fail, got %v", err)
	}
	badIdentityLength := append([]byte(nil), encoded...)
	badIdentityLength[2] = 31
	if _, err := ParseHopPlaintext(badIdentityLength, 1024); !errors.Is(err, ErrV2HopPlaintext) {
		t.Fatalf("noncanonical identity length must fail, got %v", err)
	}
	badInnerLength := append([]byte(nil), encoded...)
	badInnerLength[71] = 0xff
	if _, err := ParseHopPlaintext(badInnerLength, 1024); err == nil {
		t.Fatal("incorrect inner envelope length must fail")
	}

	zeroRouteToken := input
	zeroRouteToken.RouteToken = [16]byte{}
	if _, err := MarshalHopPlaintext(zeroRouteToken, 1024); !errors.Is(err, ErrV2HopPlaintext) {
		t.Fatalf("zero route token must fail, got %v", err)
	}
	badRouteTokenLength := append([]byte(nil), encoded...)
	badRouteTokenLength[54] = 15
	if _, err := ParseHopPlaintext(badRouteTokenLength, 1024); !errors.Is(err, ErrV2HopPlaintext) {
		t.Fatalf("noncanonical route token length must fail, got %v", err)
	}
}
