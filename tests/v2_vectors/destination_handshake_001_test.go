package v2_vectors

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type destinationHandshakeVector struct {
	FixedValidationTime int64             `json:"fixed_validation_time_unix_seconds"`
	InitiatorEphemeralPrivate string       `json:"initiator_ephemeral_x25519_private_hex"`
	ResponderEphemeralPrivate string       `json:"responder_ephemeral_x25519_private_hex"`
	RootCertificate string                 `json:"root_ca_certificate_der_hex"`
	DInitRecord string                     `json:"d_init_record_hex"`
	DRespRecord string                     `json:"d_resp_record_hex"`
	TranscriptHash string                  `json:"transcript_hash_hex"`
	SharedSecret string                    `json:"x25519_shared_secret_hex"`
	HKDFSalt string                        `json:"hkdf_salt_hex"`
	HKDFPRK string                         `json:"hkdf_prk_hex"`
	DerivedKeys map[string]string          `json:"derived_keys_hex"`
	FinishI finishVector                   `json:"finish_i"`
	FinishR finishVector                   `json:"finish_r"`
}

type finishVector struct {
	HeaderAAD string `json:"header_aad_hex"`
	Nonce string      `json:"nonce_hex"`
	Plaintext string  `json:"plaintext_hex"`
	Ciphertext string `json:"ciphertext_and_tag_hex"`
}

func loadDestinationHandshakeVector(t *testing.T) destinationHandshakeVector {
	t.Helper()
	raw, err := os.ReadFile("destination_handshake_001.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Provenance struct {
			FixedValidationTime int64 `json:"fixed_validation_time_unix_seconds"`
		} `json:"provenance"`
		TestOnlyInputs struct {
			InitiatorEphemeralPrivate string `json:"initiator_ephemeral_x25519_private_hex"`
			ResponderEphemeralPrivate string `json:"responder_ephemeral_x25519_private_hex"`
		} `json:"test_only_inputs"`
		RootCertificate string `json:"root_ca_certificate_der_hex"`
		DInitRecord string `json:"d_init_record_hex"`
		DRespRecord string `json:"d_resp_record_hex"`
		TranscriptHash string `json:"transcript_hash_hex"`
		SharedSecret string `json:"x25519_shared_secret_hex"`
		HKDFSalt string `json:"hkdf_salt_hex"`
		HKDFPRK string `json:"hkdf_prk_hex"`
		DerivedKeys map[string]string `json:"derived_keys_hex"`
		FinishI finishVector `json:"finish_i"`
		FinishR finishVector `json:"finish_r"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	return destinationHandshakeVector{
		FixedValidationTime: envelope.Provenance.FixedValidationTime,
		InitiatorEphemeralPrivate: envelope.TestOnlyInputs.InitiatorEphemeralPrivate,
		ResponderEphemeralPrivate: envelope.TestOnlyInputs.ResponderEphemeralPrivate,
		RootCertificate: envelope.RootCertificate,
		DInitRecord: envelope.DInitRecord,
		DRespRecord: envelope.DRespRecord,
		TranscriptHash: envelope.TranscriptHash,
		SharedSecret: envelope.SharedSecret,
		HKDFSalt: envelope.HKDFSalt,
		HKDFPRK: envelope.HKDFPRK,
		DerivedKeys: envelope.DerivedKeys,
		FinishI: envelope.FinishI,
		FinishR: envelope.FinishR,
	}
}

func parseE2EControlRecord(t *testing.T, record []byte, messageType byte, signatureType uint16) (map[uint16][]byte, []byte, []byte) {
	t.Helper()
	if len(record) < 4 || record[0] != messageType || record[1] != 0 || record[2] != 0 || record[3] != 0 {
		t.Fatal("invalid destination-control prefix")
	}
	fields := make(map[uint16][]byte)
	offset := 4
	var previous uint16
	var unsigned, signature []byte
	for offset < len(record) {
		start := offset
		if len(record)-offset < 6 {
			t.Fatal("truncated TLV header")
		}
		typ := binary.BigEndian.Uint16(record[offset : offset+2])
		length := uint64(binary.BigEndian.Uint32(record[offset+2 : offset+6]))
		offset += 6
		if typ <= previous {
			t.Fatal("TLVs are not strictly ascending")
		}
		if length > uint64(len(record)-offset) {
			t.Fatal("TLV length exceeds record")
		}
		if _, exists := fields[typ]; exists {
			t.Fatal("duplicate TLV")
		}
		value := record[offset : offset+int(length)]
		fields[typ] = value
		offset += int(length)
		previous = typ
		if typ == signatureType {
			if offset != len(record) {
				t.Fatal("signature TLV must be last")
			}
			unsigned = record[:start]
			signature = value
		}
	}
	if unsigned == nil || len(signature) != ed25519.SignatureSize {
		t.Fatal("missing or invalid signature TLV")
	}
	return fields, unsigned, signature
}

func parseSingleCertificateChain(t *testing.T, value []byte) *x509.Certificate {
	t.Helper()
	if len(value) < 8 || binary.BigEndian.Uint32(value[:4]) != 1 {
		t.Fatal("fixture must contain exactly one leaf certificate")
	}
	n := uint64(binary.BigEndian.Uint32(value[4:8]))
	if n != uint64(len(value)-8) {
		t.Fatal("certificate-chain length mismatch")
	}
	cert, err := x509.ParseCertificate(value[8:])
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return cert
}

func verifyN2STStatus(t *testing.T, object []byte, caKey ed25519.PublicKey, leaf *x509.Certificate, now uint64) uint64 {
	t.Helper()
	if len(object) != 304 {
		t.Fatalf("status object length = %d, want 304", len(object))
	}
	prefix, signature := object[:240], object[240:]
	if string(prefix[:4]) != "N2ST" || prefix[4] != 1 || prefix[5] != 1 ||
		binary.BigEndian.Uint16(prefix[6:8]) != 0 || binary.BigEndian.Uint32(prefix[8:12]) != 304 {
		t.Fatal("invalid N2ST header/status/length")
	}
	signed := append([]byte("NLS2-ROUTER-STATUS\x00"), prefix...)
	if !ed25519.Verify(caKey, signed, signature) {
		t.Fatal("Router-CA status signature failed")
	}
	identityFP := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	certFP := sha256.Sum256(leaf.Raw)
	if !bytes.Equal(prefix[12:44], identityFP[:]) || !bytes.Equal(prefix[44:76], certFP[:]) {
		t.Fatal("status object identity/certificate fingerprint mismatch")
	}
	if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 64 ||
		binary.BigEndian.Uint64(prefix[76:84]) != leaf.SerialNumber.Uint64() {
		t.Fatal("status object certificate serial mismatch")
	}
	generation := binary.BigEndian.Uint64(prefix[84:92])
	issued := binary.BigEndian.Uint64(prefix[92:100])
	expires := binary.BigEndian.Uint64(prefix[100:108])
	if generation == 0 || issued > now+30 || expires <= now-30 || expires <= issued || expires-issued > 300 {
		t.Fatal("status object freshness/generation invalid")
	}
	if prefix[108] < 1 || prefix[108] > 4 || prefix[109] != 0 || prefix[110] != 0 || prefix[111] != 0 {
		t.Fatal("invalid status endpoint count/reserved fields")
	}
	for _, b := range prefix[130:184] {
		if b != 0 {
			t.Fatal("unused endpoint slots must be zero")
		}
	}
	for _, b := range prefix[184:240] {
		if b != 0 {
			t.Fatal("status reserved suffix must be zero")
		}
	}
	return generation
}

func hkdfExpandSHA256(prk, info []byte, n int) []byte {
	var out, previous []byte
	for counter := byte(1); len(out) < n; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(previous)
		mac.Write(info)
		mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		out = append(out, previous...)
	}
	return out[:n]
}

func verifyFinishVector(t *testing.T, v finishVector, expectedType byte, sessionID, transcript []byte, generation uint64, lifetime *uint32, key []byte) {
	t.Helper()
	header := decodeHex(t, v.HeaderAAD)
	nonce := decodeHex(t, v.Nonce)
	ciphertext := decodeHex(t, v.Ciphertext)
	expectedPlaintext := decodeHex(t, v.Plaintext)
	if len(header) != 24 || header[0] != expectedType || header[1] != 0 ||
		binary.BigEndian.Uint16(header[2:4]) != 0 || !bytes.Equal(header[4:20], sessionID) ||
		int(binary.BigEndian.Uint32(header[20:24])) != len(ciphertext) || len(nonce) != 12 {
		t.Fatal("invalid destination FINISH header/nonce/length")
	}
	wantPlaintext := append(append([]byte(nil), transcript...), make([]byte, 8)...)
	binary.BigEndian.PutUint64(wantPlaintext[len(transcript):], generation)
	if lifetime != nil {
		wantPlaintext = append(wantPlaintext, byte(*lifetime>>24), byte(*lifetime>>16), byte(*lifetime>>8), byte(*lifetime))
	}
	if !bytes.Equal(expectedPlaintext, wantPlaintext) {
		t.Fatal("FINISH expected plaintext does not match transcript/status generation")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		t.Fatalf("valid FINISH record rejected: %v", err)
	}
	if !bytes.Equal(got, expectedPlaintext) {
		t.Fatal("FINISH plaintext mismatch")
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := gcm.Open(nil, nonce, tampered, header); err == nil {
		t.Fatal("tampered FINISH ciphertext/tag accepted")
	}
}

func TestDestinationEndpointHandshake001(t *testing.T) {
	v := loadDestinationHandshakeVector(t)
	dInit := decodeHex(t, v.DInitRecord)
	dResp := decodeHex(t, v.DRespRecord)
	rootDER := decodeHex(t, v.RootCertificate)
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root CA certificate: %v", err)
	}
	caKey, ok := root.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Router-CA key is not Ed25519")
	}
	initFields, initUnsigned, initSig := parseE2EControlRecord(t, dInit, 0x11, 0x8019)
	respFields, respUnsigned, respSig := parseE2EControlRecord(t, dResp, 0x12, 0x8028)
	if len(initFields) != 9 || len(respFields) != 8 {
		t.Fatal("unexpected D_INIT/D_RESP field count")
	}
	for _, typ := range []uint16{0x8011, 0x8012, 0x8013, 0x8014, 0x8015, 0x8016, 0x8017, 0x8018} {
		if _, ok := initFields[typ]; !ok { t.Fatalf("D_INIT missing TLV 0x%04x", typ) }
	}
	for _, typ := range []uint16{0x8021, 0x8022, 0x8023, 0x8024, 0x8025, 0x8026, 0x8027} {
		if _, ok := respFields[typ]; !ok { t.Fatalf("D_RESP missing TLV 0x%04x", typ) }
	}
	if !bytes.Equal(initFields[0x8011], respFields[0x8021]) || len(initFields[0x8011]) != 16 {
		t.Fatal("session ID mismatch")
	}
	if !bytes.Equal(initFields[0x8013], respFields[0x8022]) ||
		!bytes.Equal(initFields[0x8018], []byte{0, 1}) || !bytes.Equal(respFields[0x8027], []byte{0, 1}) {
		t.Fatal("peer identity or suite mismatch")
	}

	initCert := parseSingleCertificateChain(t, initFields[0x8014])
	respCert := parseSingleCertificateChain(t, respFields[0x8023])
	roots := x509.NewCertPool()
	roots.AddCert(root)
	now := time.Unix(v.FixedValidationTime, 0)
	for name, cert := range map[string]*x509.Certificate{"initiator": initCert, "responder": respCert} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("%s certificate path validation failed: %v", name, err)
		}
		if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
			t.Fatalf("%s identity key is not Ed25519", name)
		}
	}
	initPub := initCert.PublicKey.(ed25519.PublicKey)
	respPub := respCert.PublicKey.(ed25519.PublicKey)
	initSigInput := append([]byte("NLS2-E2E-HS-SIG\x00"), initUnsigned...)
	if !ed25519.Verify(initPub, initSigInput, initSig) {
		t.Fatal("D_INIT signature invalid")
	}
	var respSigInput bytes.Buffer
	respSigInput.WriteString("NLS2-E2E-HS-SIG\x00")
	dInitLength := make([]byte, 4)
	binary.BigEndian.PutUint32(dInitLength, uint32(len(dInit)))
	respSigInput.Write(dInitLength)
	respSigInput.Write(dInit)
	respUnsignedLength := make([]byte, 4)
	binary.BigEndian.PutUint32(respUnsignedLength, uint32(len(respUnsigned)))
	respSigInput.Write(respUnsignedLength)
	respSigInput.Write(respUnsigned)
	if !ed25519.Verify(respPub, respSigInput.Bytes(), respSig) {
		t.Fatal("D_RESP signature invalid")
	}

	initGen := verifyN2STStatus(t, initFields[0x8015], caKey, initCert, uint64(v.FixedValidationTime))
	respGen := verifyN2STStatus(t, respFields[0x8024], caKey, respCert, uint64(v.FixedValidationTime))
	if !bytes.Equal(initFields[0x8012], initFields[0x8015][12:44]) ||
		!bytes.Equal(respFields[0x8022], respFields[0x8024][12:44]) {
		t.Fatal("control identity differs from signed status identity")
	}

	transcriptInput := append([]byte("NLS2-E2E-TRANSCRIPT\x00"), make([]byte, 4)...)
	binary.BigEndian.PutUint32(transcriptInput[len("NLS2-E2E-TRANSCRIPT\x00"):], uint32(len(dInit)))
	transcriptInput = append(transcriptInput, dInit...)
	lenResp := make([]byte, 4)
	binary.BigEndian.PutUint32(lenResp, uint32(len(dResp)))
	transcriptInput = append(transcriptInput, lenResp...)
	transcriptInput = append(transcriptInput, dResp...)
	transcript := sha256.Sum256(transcriptInput)
	if !bytes.Equal(transcript[:], decodeHex(t, v.TranscriptHash)) {
		t.Fatal("transcript hash mismatch")
	}

	curve := ecdh.X25519()
	ephI, err := curve.NewPrivateKey(decodeHex(t, v.InitiatorEphemeralPrivate))
	if err != nil { t.Fatal(err) }
	ephR, err := curve.NewPrivateKey(decodeHex(t, v.ResponderEphemeralPrivate))
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(ephI.PublicKey().Bytes(), initFields[0x8017]) ||
		!bytes.Equal(ephR.PublicKey().Bytes(), respFields[0x8026]) {
		t.Fatal("ephemeral public key mismatch")
	}
	shared, err := ephI.ECDH(ephR.PublicKey())
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(shared, decodeHex(t, v.SharedSecret)) {
		t.Fatal("X25519 shared secret mismatch")
	}
	saltInput := append([]byte("NLS2-E2E-HS-SALT\x00"), initFields[0x8016]...)
	saltInput = append(saltInput, respFields[0x8025]...)
	saltInput = append(saltInput, transcript[:]...)
	salt := sha256.Sum256(saltInput)
	if !bytes.Equal(salt[:], decodeHex(t, v.HKDFSalt)) {
		t.Fatal("HKDF salt mismatch")
	}
	extract := hmac.New(sha256.New, salt[:])
	extract.Write(shared)
	prk := extract.Sum(nil)
	if !bytes.Equal(prk, decodeHex(t, v.HKDFPRK)) {
		t.Fatal("HKDF PRK mismatch")
	}
	keyIHandshake := hkdfExpandSHA256(prk, []byte("NLS2 E2E initiator-to-responder handshake key v1"), 32)
	keyRHandshake := hkdfExpandSHA256(prk, []byte("NLS2 E2E responder-to-initiator handshake key v1"), 32)
	keyIData := hkdfExpandSHA256(prk, []byte("NLS2 E2E initiator-to-responder data key v1"), 32)
	keyRData := hkdfExpandSHA256(prk, []byte("NLS2 E2E responder-to-initiator data key v1"), 32)
	for label, got := range map[string][]byte{
		"NLS2 E2E initiator-to-responder handshake key v1": keyIHandshake,
		"NLS2 E2E responder-to-initiator handshake key v1": keyRHandshake,
		"NLS2 E2E initiator-to-responder data key v1": keyIData,
		"NLS2 E2E responder-to-initiator data key v1": keyRData,
	} {
		if !bytes.Equal(got, decodeHex(t, v.DerivedKeys[label])) {
			t.Fatalf("derived key mismatch for %q", label)
		}
	}
	sessionID := initFields[0x8011]
	verifyFinishVector(t, v.FinishI, 0x13, sessionID, transcript[:], initGen, nil, keyIHandshake)
	lifetime := uint32(300)
	verifyFinishVector(t, v.FinishR, 0x14, sessionID, transcript[:], respGen, &lifetime, keyRHandshake)

	// Negative signature and status-tamper checks.
	badInitSig := append([]byte(nil), initSig...)
	badInitSig[0] ^= 1
	if ed25519.Verify(initPub, initSigInput, badInitSig) {
		t.Fatal("tampered D_INIT signature accepted")
	}
	badRespSig := append([]byte(nil), respSig...)
	badRespSig[0] ^= 1
	if ed25519.Verify(respPub, respSigInput.Bytes(), badRespSig) {
		t.Fatal("tampered D_RESP signature accepted")
	}
	badStatus := append([]byte(nil), initFields[0x8015]...)
	badStatus[len(badStatus)-1] ^= 1
	if ed25519.Verify(caKey, append([]byte("NLS2-ROUTER-STATUS\x00"), badStatus[:240]...), badStatus[240:]) {
		t.Fatal("tampered Router-CA status signature accepted")
	}
}
