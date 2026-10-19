// Package ca implements durable, fail-closed local Router-CA initialization.
package ca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	stateFile = "ca-state.json"
	keyFile   = "ca-key.enc"
	formatV1  = 1
	argonTime = uint32(3)
	argonMemory = uint32(64 * 1024) // KiB (64 MiB)
	argonThreads = uint8(1)
	keyLen = uint32(32)
	maxTokenTTL = 10 * time.Minute
)

var (
	ErrNotInitialized = errors.New("CA is not initialized")
	ErrWrongPassphrase = errors.New("wrong passphrase or corrupt encrypted CA key")
	ErrNotReady = errors.New("CA state is not ready for enrollment")
)

type encryptedKey struct {
	Version int `json:"version"`
	KDF string `json:"kdf"`
	Time uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads uint8 `json:"threads"`
	Salt string `json:"salt"`
	Nonce string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type EnrollmentCredential struct {
	Name string `json:"name"`
	TokenSHA256 string `json:"token_sha256"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	EndpointIPv6 string `json:"endpoint_ipv6"`
	EndpointUDPPort uint16 `json:"endpoint_udp_port"`
	ExpiresAt time.Time `json:"expires_at"`
	Used bool `json:"used"`
}

type RouterRecord struct {
	RouterID string `json:"router_id"`
	Name string `json:"name"`
	PublicKey string `json:"public_key"`
	CertificateDER string `json:"certificate_der,omitempty"`
	CertificateSerial uint64 `json:"certificate_serial,omitempty"`
	LastControlEpoch uint64 `json:"last_control_epoch,omitempty"`
	RDR string `json:"rdr,omitempty"`
	EndpointIPv6 string `json:"endpoint_ipv6,omitempty"`
	EndpointUDPPort uint16 `json:"endpoint_udp_port,omitempty"`
	Status string `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RevocationRecord struct {
	RouterID string `json:"router_id"`
	Reason string `json:"reason"`
	Generation uint64 `json:"generation"`
	EffectiveAt time.Time `json:"effective_at"`
}

type Policy struct {
	Configured bool `json:"configured"`
	ProtectPrefixes []string `json:"protect_prefixes"`
	BypassPrefixes []string `json:"bypass_prefixes"`
}

type AccessControls struct {
	Configured bool `json:"configured"`
	AllowEnrollment bool `json:"allow_enrollment"`
	MaxActiveRouters int `json:"max_active_routers"`
}

type State struct {
	Version int `json:"version"`
	PolicyGeneration uint64 `json:"policy_generation"`
	RevocationGeneration uint64 `json:"revocation_generation"`
	ControlEpoch uint64 `json:"control_epoch"`
	CAID string `json:"ca_id"`
	PublicKey string `json:"public_key_ed25519"`
	TrustRegistry map[string]string `json:"trust_registry"`
	Routers map[string]RouterRecord `json:"routers"`
	Revocations map[string]RevocationRecord `json:"revocations"`
	Enrollment *EnrollmentCredential `json:"enrollment,omitempty"`
	EnrollmentCredentials map[string]EnrollmentCredential `json:"enrollment_credentials,omitempty"`
	Policy Policy `json:"policy"`
	Access AccessControls `json:"access_controls"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct { Dir string }

func (s Store) Init(passphrase string) error {
	if strings.TrimSpace(passphrase) == "" { return errors.New("passphrase must not be empty") }
	if err := os.MkdirAll(s.Dir, 0700); err != nil { return err }
	if err := os.Chmod(s.Dir, 0700); err != nil { return err }
	keyPath, statePath := s.path(keyFile), s.path(stateFile)
	if exists(keyPath) || exists(statePath) { return errors.New("CA already initialized or partial state exists; refusing to overwrite") }
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { return fmt.Errorf("generate CA identity: %w", err) }
	fp := sha256.Sum256(pub)
	now := time.Now().UTC()
	st := State{
		Version: formatV1, CAID: hex.EncodeToString(fp[:]),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		TrustRegistry: map[string]string{hex.EncodeToString(fp[:]): base64.StdEncoding.EncodeToString(pub)},
		Routers: map[string]RouterRecord{}, Revocations: map[string]RevocationRecord{}, EnrollmentCredentials: map[string]EnrollmentCredential{},
		Policy: Policy{ProtectPrefixes: []string{}, BypassPrefixes: []string{}},
		CreatedAt: now, UpdatedAt: now,
	}
	enc, err := encryptPrivateKey(priv, passphrase)
	if err != nil { return err }
	if err = writeJSONAtomic(keyPath, enc, 0600); err != nil { return fmt.Errorf("write encrypted CA key: %w", err) }
	if err = writeJSONAtomic(statePath, st, 0600); err != nil {
		_ = os.Remove(keyPath)
		return fmt.Errorf("write CA state: %w", err)
	}
	return nil
}

func (s Store) Status(passphrase string) (string, error) {
	st, _, err := s.load(passphrase)
	if err != nil { return "not ready: " + err.Error(), err }
	if err = validateState(st); err != nil { return "not ready: " + err.Error(), err }
	if !hasReadyCredential(st, time.Now().UTC()) {
		err = errors.New("no valid unused key-bound enrollment credential")
		return "not ready: " + err.Error(), err
	}
	if !st.Access.Configured || !st.Access.AllowEnrollment {
		err = errors.New("enrollment access controls are not enabled")
		return "not ready: " + err.Error(), err
	}
	if !st.Policy.Configured {
		err = errors.New("policy is not configured")
		return "not ready: " + err.Error(), err
	}
	return "ready for enrollment", nil
}

func (s Store) SetEnrollmentCredential(passphrase, name string, ttl time.Duration) (string, error) {
	return s.SetScopedEnrollmentCredential(passphrase, name, "", "", 0, ttl)
}

// SetScopedEnrollmentCredential binds a one-time token to the router public key and IPv6 UDP endpoint.
func (s Store) SetScopedEnrollmentCredential(passphrase, name, publicKeySHA256, endpointIPv6 string, port uint16, ttl time.Duration) (string, error) {
	unlock, err := s.lock(); if err != nil { return "", err }; defer unlock()
	if err := validateName(name); err != nil { return "", err }
	if ttl <= 0 || ttl > maxTokenTTL { return "", fmt.Errorf("TTL must be greater than zero and at most %s", maxTokenTTL) }
	if publicKeySHA256 != "" {
		if len(publicKeySHA256) != sha256.Size*2 { return "", errors.New("public-key SHA-256 must be 64 hexadecimal characters") }
		if _, err := hex.DecodeString(publicKeySHA256); err != nil { return "", errors.New("public-key SHA-256 must be hexadecimal") }
		addr, err := netip.ParseAddr(endpointIPv6)
		if err != nil || !addr.Is6() || addr.Is4In6() { return "", errors.New("endpoint must be a valid IPv6 address") }
		if port == 0 { return "", errors.New("UDP endpoint port must be 1..65535") }
	}
	st, _, err := s.load(passphrase)
	if err != nil { return "", err }
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil { return "", err }
	sum := sha256.Sum256(token)
	credential := EnrollmentCredential{Name:name, TokenSHA256:hex.EncodeToString(sum[:]), PublicKeySHA256:strings.ToLower(publicKeySHA256), EndpointIPv6:endpointIPv6, EndpointUDPPort:port, ExpiresAt:time.Now().UTC().Add(ttl), Used:false}
	if st.EnrollmentCredentials == nil { st.EnrollmentCredentials = map[string]EnrollmentCredential{} }
	st.EnrollmentCredentials[credential.TokenSHA256] = credential
	st.Enrollment = &credential
	st.UpdatedAt = time.Now().UTC()
	if err = validateState(st); err != nil { return "", err }
	if err = s.saveState(st); err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s Store) SetPolicy(passphrase string, protect, bypass []string) error {
	unlock, err := s.lock(); if err != nil { return err }; defer unlock()
	st, _, err := s.load(passphrase)
	if err != nil { return err }
	p, err := canonicalPrefixes(protect, bypass)
	if err != nil { return err }
	st.Policy = p
	st.PolicyGeneration++
	st.UpdatedAt = time.Now().UTC()
	if err = validateState(st); err != nil { return err }
	return s.saveState(st)
}

func (s Store) SetAccessControls(passphrase string, allow bool, maxRouters int) error {
	unlock, err := s.lock(); if err != nil { return err }; defer unlock()
	if maxRouters < 1 || maxRouters > 1_000_000 { return errors.New("max active routers must be in range 1..1000000") }
	st, _, err := s.load(passphrase)
	if err != nil { return err }
	st.Access = AccessControls{Configured:true, AllowEnrollment:allow, MaxActiveRouters:maxRouters}
	st.UpdatedAt = time.Now().UTC()
	if err = validateState(st); err != nil { return err }
	return s.saveState(st)
}

// LoadState validates encrypted-key/state binding before returning persistent state.
func (s Store) LoadState(passphrase string) (State, error) {
	st, _, err := s.load(passphrase)
	if err != nil { return State{}, err }
	if err = validateState(st); err != nil { return State{}, err }
	return st, nil
}

func (s Store) load(passphrase string) (State, ed25519.PrivateKey, error) {
	var st State
	var enc encryptedKey
	if strings.TrimSpace(passphrase) == "" { return st, nil, errors.New("passphrase must not be empty") }
	if err := s.checkPermissions(); err != nil { return st, nil, err }
	if err := readJSON(s.path(stateFile), &st); err != nil {
		if errors.Is(err, os.ErrNotExist) { return st, nil, ErrNotInitialized }
		return st, nil, fmt.Errorf("read CA state: %w", err)
	}
	if err := readJSON(s.path(keyFile), &enc); err != nil {
		return st, nil, fmt.Errorf("read encrypted CA key: %w", err)
	}
	raw, err := decryptPrivateKey(enc, passphrase)
	if err != nil { return st, nil, err }
	if len(raw) != ed25519.PrivateKeySize { return st, nil, ErrWrongPassphrase }
	priv := ed25519.PrivateKey(raw)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || base64.StdEncoding.EncodeToString(pub) != st.PublicKey { return st, nil, ErrWrongPassphrase }
	if err = validateState(st); err != nil { return st, nil, err }
	return st, priv, nil
}

func (s Store) checkPermissions() error {
	dirInfo, err := os.Lstat(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) { return ErrNotInitialized }
		return err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("CA state path must be a real directory")
	}
	if dirInfo.Mode().Perm()&0077 != 0 {
		return errors.New("CA state directory permissions must not allow group or other access")
	}
	for _, name := range []string{stateFile, keyFile} {
		info, statErr := os.Lstat(s.path(name))
		if statErr != nil { return statErr }
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a regular file", name)
		}
		if info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("%s permissions must not allow group or other access", name)
		}
	}
	return nil
}

func (s Store) saveState(st State) error {
	if err := validateState(st); err != nil { return err }
	return writeJSONAtomic(s.path(stateFile), st, 0600)
}

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

func validateState(st State) error {
	if st.Version != formatV1 { return errors.New("unsupported CA state version") }
	pub, err := base64.StdEncoding.DecodeString(st.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize { return errors.New("invalid CA public key") }
	fp := sha256.Sum256(pub)
	fingerprint := hex.EncodeToString(fp[:])
	if st.CAID != fingerprint { return errors.New("CA identity fingerprint mismatch") }
	if st.TrustRegistry == nil || st.Routers == nil || st.Revocations == nil { return errors.New("trust, router, and revocation registries must exist") }
	trusted, ok := st.TrustRegistry[fingerprint]
	if !ok || trusted != st.PublicKey { return errors.New("CA identity missing from trust registry") }
	for id, r := range st.Routers {
		if id == "" || r.RouterID != id || r.Name == "" { return errors.New("invalid router registry entry") }
		if r.Status != "ACTIVE" && r.Status != "REVOKED" && r.Status != "DISABLED" { return errors.New("invalid router status") }
	}
	for id, r := range st.Revocations {
		if id == "" || r.RouterID != id || r.Generation == 0 { return errors.New("invalid revocation entry") }
	}
	if st.Policy.Configured {
		if len(st.Policy.ProtectPrefixes)+len(st.Policy.BypassPrefixes) == 0 { return errors.New("configured policy has no prefixes") }
		if _, err := canonicalPrefixes(st.Policy.ProtectPrefixes, st.Policy.BypassPrefixes); err != nil { return fmt.Errorf("invalid policy: %w", err) }
	}
	if st.Access.Configured && (st.Access.MaxActiveRouters < 1 || st.Access.MaxActiveRouters > 1_000_000) { return errors.New("invalid access-control router limit") }
	if st.Enrollment != nil {
		if err := validateCredential(*st.Enrollment); err != nil { return err }
	}
	for hash, credential := range st.EnrollmentCredentials {
		if hash != credential.TokenSHA256 { return errors.New("enrollment credential key/hash mismatch") }
		if err := validateCredential(credential); err != nil { return err }
	}
	return nil
}

func validateCredential(credential EnrollmentCredential) error {
	if err := validateName(credential.Name); err != nil { return err }
	if len(credential.TokenSHA256) != sha256.Size*2 { return errors.New("invalid enrollment token hash") }
	if _, err := hex.DecodeString(credential.TokenSHA256); err != nil { return errors.New("invalid enrollment token hash") }
	if credential.ExpiresAt.IsZero() { return errors.New("invalid enrollment expiry") }
	if credential.PublicKeySHA256 != "" {
		if len(credential.PublicKeySHA256) != sha256.Size*2 { return errors.New("invalid enrollment public-key hash") }
		if _, err := hex.DecodeString(credential.PublicKeySHA256); err != nil { return errors.New("invalid enrollment public-key hash") }
		addr, err := netip.ParseAddr(credential.EndpointIPv6)
		if err != nil || !addr.Is6() || addr.Is4In6() || credential.EndpointUDPPort == 0 { return errors.New("invalid enrollment endpoint") }
	}
	return nil
}

func hasReadyCredential(st State, now time.Time) bool {
	for _, credential := range st.EnrollmentCredentials {
		if !credential.Used && credential.PublicKeySHA256 != "" && credential.EndpointIPv6 != "" && credential.EndpointUDPPort != 0 && now.Before(credential.ExpiresAt) { return true }
	}
	if st.Enrollment != nil {
		credential := st.Enrollment
		return !credential.Used && credential.PublicKeySHA256 != "" && credential.EndpointIPv6 != "" && credential.EndpointUDPPort != 0 && now.Before(credential.ExpiresAt)
	}
	return false
}

func canonicalPrefixes(protect, bypass []string) (Policy, error) {
	seen := map[string]string{}
	canon := func(values []string, action string) ([]string, error) {
		out := make([]string, 0, len(values))
		for _, raw := range values {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil { return nil, fmt.Errorf("invalid %s prefix %q: %w", action, raw, err) }
			p = p.Masked()
			key := p.String()
			if old, exists := seen[key]; exists { return nil, fmt.Errorf("prefix %s configured as both/again %s and %s", key, old, action) }
			seen[key] = action
			out = append(out, key)
		}
		sort.Strings(out)
		return out, nil
	}
	p, err := canon(protect, "PROTECT")
	if err != nil { return Policy{}, err }
	b, err := canon(bypass, "BYPASS")
	if err != nil { return Policy{}, err }
	for _, protectPrefix := range p {
		pp, _ := netip.ParsePrefix(protectPrefix)
		for _, bypassPrefix := range b {
			bp, _ := netip.ParsePrefix(bypassPrefix)
			if pp.Contains(bp.Addr()) || bp.Contains(pp.Addr()) {
				return Policy{}, fmt.Errorf("conflicting overlapping PROTECT/BYPASS prefixes %s and %s", pp, bp)
			}
		}
	}
	if len(p)+len(b) == 0 { return Policy{}, errors.New("at least one PROTECT or BYPASS prefix is required") }
	return Policy{Configured:true, ProtectPrefixes:p, BypassPrefixes:b}, nil
}

func validateName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 128 || strings.ContainsRune(name, 0) { return errors.New("name must be 1..128 bytes and contain no NUL") }
	return nil
}

func encryptPrivateKey(priv ed25519.PrivateKey, passphrase string) (encryptedKey, error) {
	var out encryptedKey
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil { return out, err }
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil { return out, err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return out, err }
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil { return out, err }
	ciphertext := gcm.Seal(nil, nonce, []byte(priv), []byte("NLS-CA-KEY-v1"))
	out = encryptedKey{Version:1, KDF:"argon2id", Time:argonTime, MemoryKiB:argonMemory, Threads:argonThreads,
		Salt:base64.StdEncoding.EncodeToString(salt), Nonce:base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:base64.StdEncoding.EncodeToString(ciphertext)}
	return out, nil
}

func decryptPrivateKey(enc encryptedKey, passphrase string) ([]byte, error) {
	if enc.Version != 1 || enc.KDF != "argon2id" || enc.Time == 0 || enc.MemoryKiB < 8*uint32(enc.Threads) || enc.MemoryKiB > 1024*1024 || enc.Time > 10 || enc.Threads == 0 || enc.Threads > 16 {
		return nil, errors.New("unsupported or unsafe encrypted-key parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(enc.Salt)
	if err != nil || len(salt) != 16 { return nil, ErrWrongPassphrase }
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil { return nil, ErrWrongPassphrase }
	ciphertext, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil { return nil, ErrWrongPassphrase }
	key := argon2.IDKey([]byte(passphrase), salt, enc.Time, enc.MemoryKiB, enc.Threads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil { return nil, ErrWrongPassphrase }
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() { return nil, ErrWrongPassphrase }
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte("NLS-CA-KEY-v1"))
	if err != nil { return nil, ErrWrongPassphrase }
	return plain, nil
}

func writeJSONAtomic(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil { return err }
	data = append(data, byte(10))
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".nls-tmp-*")
	if err != nil { return err }
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err != nil { _ = f.Close(); return err }
	if _, err = f.Write(data); err != nil { _ = f.Close(); return err }
	if err = f.Sync(); err != nil { _ = f.Close(); return err }
	if err = f.Close(); err != nil { return err }
	if err = os.Rename(tmp, path); err != nil { return err }
	d, err := os.Open(dir)
	if err == nil { _ = d.Sync(); _ = d.Close() }
	return nil
}

func readJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil { return err }
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 4<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(out); err != nil { return err }
	var extra any
	if err = dec.Decode(&extra); err != io.EOF { return errors.New("trailing data in state file") }
	return nil
}

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }
