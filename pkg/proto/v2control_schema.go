package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	v2TLVInitiatorRouterID uint16 = 0x8001
	v2TLVResponderRouterID uint16 = 0x8002
	v2TLVNonceI uint16 = 0x8003
	v2TLVEphemeralI uint16 = 0x8004
	v2TLVSuiteList uint16 = 0x8005
	v2TLVCookie uint16 = 0x8006

	v2TLVCertificateChain uint16 = 0x8001
	v2TLVStatusEvidence uint16 = 0x8002
	v2TLVNonceR uint16 = 0x8003
	v2TLVEphemeralR uint16 = 0x8004
	v2TLVSelectedSuite uint16 = 0x8005
	v2TLVEndpointBinding uint16 = 0x8006
	v2TLVSignature uint16 = 0x8007

	v2TLVTranscriptHash uint16 = 0x8001
	v2TLVSessionToken uint16 = 0x8002
	v2TLVSessionLifetime uint16 = 0x8003
	v2TLVStatusGeneration uint16 = 0x8004
	v2TLVCloseReason uint16 = 0x8001
	v2ControlSuiteX25519Ed25519AES256GCM uint16 = 0x0001
	v2ControlMaxCertificates = 8
	v2ControlMaxCertificateChainBytes = 16 * 1024
	v2ControlStatusObjectBytes = 304
)

var ErrV2ControlSchema = errors.New("invalid NLS v2 control message schema")

// ValidateV2ControlMessage validates message-specific required/optional TLVs and their
// exact structural lengths. It does not verify signatures, certificate paths, status
// signatures, transcript hashes, AEAD tags, or handshake state; those checks belong to
// the authenticated handshake state machine.
func ValidateV2ControlMessage(message V2ControlMessage) error {
	fields := make(map[uint16][]byte, len(message.TLVs))
	var prev uint16
	for i, tlv := range message.TLVs {
		if tlv.Type == 0 || (i > 0 && tlv.Type <= prev) {
			return fmt.Errorf("%w: TLVs must be unique and ascending", ErrV2ControlSchema)
		}
		fields[tlv.Type] = tlv.Value
		prev = tlv.Type
	}
	switch message.Type {
	case V2ControlInit:
		required := []uint16{0x8001, 0x8002, 0x8003, 0x8004, 0x8005}
		if !hasExactControlFields(fields, required, []uint16{0x8006}) {
			return fmt.Errorf("%w: INIT field set", ErrV2ControlSchema)
		}
		if len(fields[0x8001]) != 32 || len(fields[0x8002]) != 32 ||
			len(fields[0x8003]) != 32 || len(fields[0x8004]) != 32 {
			return fmt.Errorf("%w: INIT identity/nonce/key length", ErrV2ControlSchema)
		}
		if allZero(fields[0x8001]) || allZero(fields[0x8002]) ||
			allZero(fields[0x8003]) || allZero(fields[0x8004]) {
			return fmt.Errorf("%w: INIT zero identity/nonce/key", ErrV2ControlSchema)
		}
		if err := validateV2SuiteList(fields[0x8005]); err != nil {
			return err
		}
		if cookie, ok := fields[0x8006]; ok && len(cookie) != V2CookieSize {
			return fmt.Errorf("%w: INIT cookie must be exactly %d bytes", ErrV2ControlSchema, V2CookieSize)
		}
	case V2ControlRetry:
		if !hasExactControlFields(fields, []uint16{0x8006}, nil) || len(fields[0x8006]) != V2CookieSize {
			return fmt.Errorf("%w: RETRY requires one 40-byte cookie", ErrV2ControlSchema)
		}
	case V2ControlResp:
		if !hasExactControlFields(fields, []uint16{0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8006, 0x8007}, nil) {
			return fmt.Errorf("%w: RESP field set", ErrV2ControlSchema)
		}
		if err := validateV2CertificateChain(fields[0x8001]); err != nil {
			return err
		}
		if err := validateV2LengthPrefixedStatus(fields[0x8002]); err != nil {
			return err
		}
		if len(fields[0x8003]) != 32 || allZero(fields[0x8003]) ||
			len(fields[0x8004]) != 32 || allZero(fields[0x8004]) {
			return fmt.Errorf("%w: RESP nonce/ephemeral key length or value", ErrV2ControlSchema)
		}
		if len(fields[0x8005]) != 2 || binary.BigEndian.Uint16(fields[0x8005]) != v2ControlSuiteX25519Ed25519AES256GCM {
			return fmt.Errorf("%w: RESP selected suite", ErrV2ControlSchema)
		}
		if err := validateV2EndpointBinding(fields[0x8006]); err != nil {
			return err
		}
		if len(fields[0x8007]) != 64 {
			return fmt.Errorf("%w: RESP signature must be 64 bytes", ErrV2ControlSchema)
		}
	case V2ControlFinishI:
		if !hasExactControlFields(fields, []uint16{0x8001, 0x8002, 0x8003, 0x8004}, nil) {
			return fmt.Errorf("%w: FINISH_I field set", ErrV2ControlSchema)
		}
		if err := validateV2CertificateChain(fields[0x8001]); err != nil {
			return err
		}
		if err := validateV2LengthPrefixedStatus(fields[0x8002]); err != nil {
			return err
		}
		if len(fields[0x8003]) != 32 || len(fields[0x8004]) != 64 {
			return fmt.Errorf("%w: FINISH_I transcript hash/signature length", ErrV2ControlSchema)
		}
	case V2ControlFinishR:
		if !hasExactControlFields(fields, []uint16{0x8001, 0x8002, 0x8003, 0x8004}, nil) {
			return fmt.Errorf("%w: FINISH_R field set", ErrV2ControlSchema)
		}
		if len(fields[0x8001]) != 32 || len(fields[0x8002]) != 16 || allZero(fields[0x8002]) ||
			len(fields[0x8003]) != 4 || binary.BigEndian.Uint32(fields[0x8003]) == 0 ||
			len(fields[0x8004]) != 8 || binary.BigEndian.Uint64(fields[0x8004]) == 0 {
			return fmt.Errorf("%w: FINISH_R field length/value", ErrV2ControlSchema)
		}
	case V2ControlClose:
		if !hasExactControlFields(fields, []uint16{v2TLVCloseReason}, nil) || len(fields[v2TLVCloseReason]) != 2 {
			return fmt.Errorf("%w: CLOSE requires one uint16 reason", ErrV2ControlSchema)
		}
		reason := binary.BigEndian.Uint16(fields[v2TLVCloseReason])
		if reason < 1 || reason > 5 {
			return fmt.Errorf("%w: CLOSE reason is unknown", ErrV2ControlSchema)
		}
	default:
		return fmt.Errorf("%w: unsupported/reserved message type", ErrV2ControlSchema)
	}
	return nil
}

func hasExactControlFields(fields map[uint16][]byte, required, optional []uint16) bool {
	allowed := make(map[uint16]struct{}, len(required)+len(optional))
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return false
		}
		allowed[field] = struct{}{}
	}
	for _, field := range optional {
		allowed[field] = struct{}{}
	}
	for field := range fields {
		if _, ok := allowed[field]; !ok {
			return false
		}
	}
	return true
}

func validateV2SuiteList(value []byte) error {
	if len(value) < 4 {
		return fmt.Errorf("%w: suite_list is truncated", ErrV2ControlSchema)
	}
	count := int(binary.BigEndian.Uint16(value[:2]))
	if count == 0 || count > 16 || len(value) != 2+2*count {
		return fmt.Errorf("%w: suite_list count/length mismatch", ErrV2ControlSchema)
	}
	var previous uint16
	for i := 0; i < count; i++ {
		suite := binary.BigEndian.Uint16(value[2+i*2 : 4+i*2])
		if suite != v2ControlSuiteX25519Ed25519AES256GCM || (i > 0 && suite <= previous) {
			return fmt.Errorf("%w: unsupported or noncanonical suite_list", ErrV2ControlSchema)
		}
		previous = suite
	}
	return nil
}

func validateV2CertificateChain(value []byte) error {
	if len(value) < 8 || len(value) > v2ControlMaxCertificateChainBytes {
		return fmt.Errorf("%w: certificate chain size", ErrV2ControlSchema)
	}
	count := uint64(binary.BigEndian.Uint32(value[:4]))
	if count == 0 || count > v2ControlMaxCertificates {
		return fmt.Errorf("%w: certificate chain count", ErrV2ControlSchema)
	}
	offset := uint64(4)
	for i := uint64(0); i < count; i++ {
		if uint64(len(value))-offset < 4 {
			return fmt.Errorf("%w: truncated certificate length", ErrV2ControlSchema)
		}
		certLength := uint64(binary.BigEndian.Uint32(value[offset : offset+4]))
		offset += 4
		if certLength == 0 || certLength > uint64(v2ControlMaxCertificateChainBytes) || certLength > uint64(len(value))-offset {
			return fmt.Errorf("%w: invalid certificate length", ErrV2ControlSchema)
		}
		offset += certLength
	}
	if offset != uint64(len(value)) {
		return fmt.Errorf("%w: trailing certificate-chain bytes", ErrV2ControlSchema)
	}
	return nil
}

func validateV2LengthPrefixedStatus(value []byte) error {
	if len(value) < 4 {
		return fmt.Errorf("%w: status evidence length prefix is missing", ErrV2ControlSchema)
	}
	length := uint64(binary.BigEndian.Uint32(value[:4]))
	if length != v2ControlStatusObjectBytes || length != uint64(len(value)-4) {
		return fmt.Errorf("%w: status evidence must contain one exact 304-byte object", ErrV2ControlSchema)
	}
	status := value[4:]
	if len(status) != v2ControlStatusObjectBytes || string(status[:4]) != "N2ST" {
		return fmt.Errorf("%w: invalid N2ST status object framing", ErrV2ControlSchema)
	}
	return nil
}

func validateV2EndpointBinding(value []byte) error {
	// family(1) || IPv6(16) || UDP port(2) || identity fingerprint(32)
	if len(value) != 51 || value[0] != 6 || binary.BigEndian.Uint16(value[17:19]) == 0 ||
		allZero(value[19:51]) {
		return fmt.Errorf("%w: endpoint binding encoding", ErrV2ControlSchema)
	}
	return nil
}
