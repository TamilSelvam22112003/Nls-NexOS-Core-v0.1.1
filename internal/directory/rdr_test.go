package directory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func testRDR(t *testing.T, router byte, endpoint string, port uint16, generation uint64) ([]byte, RDRFields, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("NLS Python reference fixture signing key " + string(rune(router))))
	key := ed25519.NewKeyFromSeed(seed[:])
	var fields RDRFields
	for i := range fields.RouterID { fields.RouterID[i] = router }
	ip := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	if endpoint == "2001:db8::2" { ip[15] = 2 } else { ip[15] = 1 }
	fields.EndpointIPv6 = ip
	fields.EndpointPort = port
	fields.CertificateSerial = uint64(router)
	fields.NotBeforeUnixMS = 1000
	fields.NotAfterUnixMS = 9999999
	fields.Status = StatusActive
	fields.Generation = generation
	for i := range fields.RecordNonce { fields.RecordNonce[i] = router }
	record, err := IssueRDR(key, fields)
	if err != nil { t.Fatal(err) }
	return record, fields, key
}

func TestRDRCanonical194ByteEncodingAndRoundTrip(t *testing.T) {
	record, want, _ := testRDR(t, 'R', "2001:db8::2", 40002, 9)
	if len(record) != 194 { t.Fatalf("record length=%d, want 194", len(record)) }
	if got := hex.EncodeToString(record[128:130]); got != "0000" { t.Fatalf("extensions_len=%s, want 0000", got) }
	got, err := VerifyRDR(record, 2000)
	if err != nil { t.Fatal(err) }
	if got != want { t.Fatalf("round-trip fields differ: got %#v want %#v", got, want) }
}

func TestRDRRejectsNonzeroExtensionsAndLegacyLength(t *testing.T) {
	record, _, _ := testRDR(t, 'R', "2001:db8::2", 40002, 9)
	nonzero := append([]byte(nil), record...)
	nonzero[129] = 1
	if _, err := VerifyRDR(nonzero, 2000); !errors.Is(err, ErrMalformedRDR) { t.Fatalf("nonzero extensions_len error=%v", err) }
	if _, err := VerifyRDR(append(append([]byte(nil), record...), make([]byte, 128)...), 2000); !errors.Is(err, ErrMalformedRDR) { t.Fatal("legacy-sized record accepted") }
}

func TestRDRRejectsTamperingAndExpiredRecords(t *testing.T) {
	record, _, _ := testRDR(t, 'R', "2001:db8::2", 40002, 9)
	tampered := append([]byte(nil), record...)
	tampered[54] ^= 1
	if _, err := VerifyRDR(tampered, 2000); !errors.Is(err, ErrBadSignature) { t.Fatalf("tamper error=%v", err) }
	if _, err := VerifyRDR(record, 10000000); !errors.Is(err, ErrNotCurrent) { t.Fatalf("expiry error=%v", err) }
}

func TestRegistryEnforcesGenerationEndpointUniquenessAndRevocation(t *testing.T) {
	registry := NewRegistry()
	first, fields, key := testRDR(t, 'A', "2001:db8::1", 40001, 1)
	if err := registry.Register(first, 2000); err != nil { t.Fatal(err) }
	got, err := registry.Lookup(fields.RouterID, 2000)
	if err != nil || len(got) != 194 { t.Fatalf("lookup len=%d err=%v", len(got), err) }
	got[4] ^= 1
	if _, err := registry.Lookup(fields.RouterID, 2000); err != nil { t.Fatalf("lookup copy mutated stored record: %v", err) }
	stale, _, _ := testRDR(t, 'A', "2001:db8::1", 40001, 1)
	if err := registry.Register(stale, 2000); !errors.Is(err, ErrStaleGeneration) { t.Fatalf("stale error=%v", err) }
	duplicate, _, _ := testRDR(t, 'B', "2001:db8::1", 40001, 1)
	if err := registry.Register(duplicate, 2000); !errors.Is(err, ErrDuplicateEndpoint) { t.Fatalf("duplicate endpoint error=%v", err) }
	fields.Generation = 2
	fields.RecordNonce[0]++
	updated, err := IssueRDR(key, fields)
	if err != nil { t.Fatal(err) }
	if err := registry.Register(updated, 2000); err != nil { t.Fatal(err) }
	fields.Status = StatusRevoked
	fields.Generation = 3
	revoked, err := IssueRDR(key, fields)
	if err != nil { t.Fatal(err) }
	if err := registry.Register(revoked, 2000); err != nil { t.Fatal(err) }
	if _, err := registry.Lookup(fields.RouterID, 2000); !errors.Is(err, ErrRouterInactive) { t.Fatalf("revoked lookup error=%v", err) }
}
