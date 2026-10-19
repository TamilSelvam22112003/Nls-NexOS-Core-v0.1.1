package ca

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitCreatesProtectedIdentityAndRegistries(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	if err := s.Init("correct horse battery staple"); err != nil { t.Fatal(err) }
	for _, name := range []string{stateFile, keyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil { t.Fatal(err) }
		if info.Mode().Perm() != 0600 { t.Fatalf("%s permissions = %o, want 600", name, info.Mode().Perm()) }
	}
	info, err := os.Stat(dir)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0700 { t.Fatalf("directory permissions = %o, want 700", info.Mode().Perm()) }
	st, err := s.LoadState("correct horse battery staple")
	if err != nil { t.Fatal(err) }
	if st.CAID == "" || len(st.TrustRegistry) != 1 || st.Routers == nil || st.Revocations == nil {
		t.Fatalf("incomplete initialized state: %#v", st)
	}
	if _, err = s.Status("correct horse battery staple"); err == nil { t.Fatal("fresh initialization must not be ready for enrollment") }
	if err = s.Init("second passphrase"); err == nil { t.Fatal("Init must refuse to overwrite existing state") }
}

func TestRestartPersistenceAndReadyState(t *testing.T) {
	dir := t.TempDir()
	first := Store{Dir: dir}
	pass := "correct horse battery staple"
	if err := first.Init(pass); err != nil { t.Fatal(err) }
	token, err := first.SetScopedEnrollmentCredential(pass, "router-a", strings.Repeat("a", 64), "2001:db8::1", 51820, 10*time.Minute)
	if err != nil { t.Fatal(err) }
	if token == "" { t.Fatal("expected one-time token") }
	if err = first.SetPolicy(pass, []string{"10.0.0.0/8", "2001:db8:1::/48"}, []string{"192.0.2.0/24"}); err != nil { t.Fatal(err) }
	if err = first.SetAccessControls(pass, true, 500); err != nil { t.Fatal(err) }

	restarted := Store{Dir: dir}
	status, err := restarted.Status(pass)
	if err != nil { t.Fatalf("restart should preserve valid state: %v (%s)", err, status) }
	if status != "ready for enrollment" { t.Fatalf("status = %q", status) }
	st, err := restarted.LoadState(pass)
	if err != nil { t.Fatal(err) }
	if st.Enrollment == nil || st.Enrollment.Name != "router-a" || st.Enrollment.TokenSHA256 == token {
		t.Fatal("enrollment credential must persist by hash, never plaintext")
	}
	if !st.Policy.Configured || len(st.Policy.ProtectPrefixes) != 2 || len(st.Policy.BypassPrefixes) != 1 {
		t.Fatalf("policy not persisted: %#v", st.Policy)
	}
	if !st.Access.Configured || !st.Access.AllowEnrollment || st.Access.MaxActiveRouters != 500 {
		t.Fatalf("access controls not persisted: %#v", st.Access)
	}
	raw, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil { t.Fatal(err) }
	if strings.Contains(string(raw), token) { t.Fatal("plaintext enrollment token leaked into state file") }
}

func TestWrongPassphraseFailsClosed(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.Init("right passphrase"); err != nil { t.Fatal(err) }
	status, err := s.Status("wrong passphrase")
	if err == nil { t.Fatal("wrong passphrase must fail") }
	if !strings.HasPrefix(status, "not ready:") { t.Fatalf("status = %q", status) }
	if _, err = s.LoadState("wrong passphrase"); err == nil { t.Fatal("LoadState accepted wrong passphrase") }
}

func TestInvalidPolicyDoesNotPersist(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	pass := "passphrase"
	if err := s.Init(pass); err != nil { t.Fatal(err) }
	if err := s.SetPolicy(pass, []string{"10.0.0.0/8"}, []string{"10.0.0.0/8"}); err == nil {
		t.Fatal("conflicting policy should fail")
	}
	st, err := s.LoadState(pass)
	if err != nil { t.Fatal(err) }
	if st.Policy.Configured { t.Fatal("invalid policy persisted") }
}

func TestMalformedStateIsNotReady(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.Init("passphrase"); err != nil { t.Fatal(err) }
	p := filepath.Join(s.Dir, stateFile)
	b, err := os.ReadFile(p)
	if err != nil { t.Fatal(err) }
	var st map[string]any
	if err = json.Unmarshal(b, &st); err != nil { t.Fatal(err) }
	st["ca_id"] = "tampered"
	b, err = json.Marshal(st)
	if err != nil { t.Fatal(err) }
	if err = os.WriteFile(p, b, 0600); err != nil { t.Fatal(err) }
	if status, err := s.Status("passphrase"); err == nil || strings.HasPrefix(status, "ready") {
		t.Fatalf("tampered state accepted: %q, %v", status, err)
	}
}

func TestInsecurePermissionsPreventReadiness(t *testing.T) {
	dir := t.TempDir()
	store := Store{Dir: dir}
	if err := store.Init("passphrase"); err != nil { t.Fatal(err) }
	if err := os.Chmod(filepath.Join(dir, keyFile), 0644); err != nil { t.Fatal(err) }
	status, err := store.Status("passphrase")
	if err == nil || strings.HasPrefix(status, "ready") {
		t.Fatalf("insecure key permissions accepted: %q, %v", status, err)
	}
}
