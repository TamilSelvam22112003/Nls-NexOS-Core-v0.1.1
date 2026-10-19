package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"crypto/x509/pkix"
	"bytes"
	"encoding/pem"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPassphrase = "integration-test-ca-passphrase"

func readyStore(t *testing.T) Store {
	t.Helper()
	s:=Store{Dir:t.TempDir()}
	if err:=s.Init(testPassphrase);err!=nil{t.Fatal(err)}
	if err:=s.SetPolicy(testPassphrase,[]string{"10.0.0.0/8"},[]string{"192.0.2.0/24"});err!=nil{t.Fatal(err)}
	if err:=s.SetAccessControls(testPassphrase,true,20);err!=nil{t.Fatal(err)}
	return s
}

func makeCSR(t *testing.T,name string)(ed25519.PrivateKey,[]byte,string) {
	t.Helper()
	pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	csrDER,err:=x509.CreateCertificateRequest(rand.Reader,&x509.CertificateRequest{Subject:pkix.Name{CommonName:name}},priv)
	if err!=nil{t.Fatal(err)}
	sum:=sha256.Sum256(pub)
	return priv,csrDER,hex.EncodeToString(sum[:])
}

func enrollTestRouter(t *testing.T,s Store,name string,ttl time.Duration)(IssuedEnrollment,[]byte,string) {
	t.Helper()
	_,csr,keyHash:=makeCSR(t,name)
	token,err:=s.SetScopedEnrollmentCredential(testPassphrase,name,keyHash,"2001:db8::10",51820,ttl)
	if err!=nil{t.Fatal(err)}
	issued,err:=s.IssueEnrollment(testPassphrase,name,token,csr)
	if err!=nil{t.Fatal(err)}
	return issued,csr,token
}

func TestValidEnrollmentIssuesCertificateAndSignedRDR(t *testing.T) {
	s:=readyStore(t)
	issued,_,token:=enrollTestRouter(t,s,"router-a",10*time.Minute)
	if len(issued.CertificateDER)==0||len(issued.RDR)!=rdrSize||issued.RouterID==""||issued.Serial==0{t.Fatalf("incomplete issuance: %#v",issued)}
	rootPEM,err:=s.RootCertificatePEM(testPassphrase,"localhost");if err!=nil{t.Fatal(err)}
	block,pemErr:=pemDecode(rootPEM);if pemErr!=nil{t.Fatal(pemErr)}
	root,err:=x509.ParseCertificate(block);if err!=nil{t.Fatal(err)}
	cert,err:=x509.ParseCertificate(issued.CertificateDER);if err!=nil{t.Fatal(err)}
	roots:=x509.NewCertPool();roots.AddCert(root)
	if _,err=cert.Verify(x509.VerifyOptions{Roots:roots,KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}});err!=nil{t.Fatalf("router cert does not chain to CA: %v",err)}
	if cert.Subject.CommonName!="router-a"||cert.SerialNumber.Uint64()!=issued.Serial{t.Fatal("certificate identity/serial mismatch")}
	body,sig:=issued.RDR[:rdrBodySize],issued.RDR[rdrBodySize:]
	caPub:=root.PublicKey.(ed25519.PublicKey)
	if !ed25519.Verify(caPub,append([]byte("NLS-v1-RDR\x00"),body...),sig){t.Fatal("RDR signature invalid")}
	if binary.BigEndian.Uint64(body[72:80])!=issued.Serial||body[96]!=1||body[52]!=1||body[53]!=6{t.Fatal("RDR fields do not match certificate or protocol")}
	if string(body[128:258])!=string(make([]byte,130)){t.Fatal("RDR reserved extension is not zero")}
	st,err:=s.LoadState(testPassphrase);if err!=nil{t.Fatal(err)}
	record,ok:=st.Routers[issued.RouterID];if !ok||record.Status!="ACTIVE"||record.CertificateSerial!=issued.Serial{t.Fatal("router record not persisted")}
	if st.Enrollment==nil||!st.Enrollment.Used{t.Fatal("credential was not consumed")}
	if _,err=s.IssueEnrollment(testPassphrase,"router-a",token,[]byte("replay"));!errors.Is(err,ErrTokenReused){t.Fatalf("replay error = %v",err)}
}

func TestReplayedTokenRejected(t *testing.T) {
	s:=readyStore(t)
	_,_,token:=enrollTestRouter(t,s,"router-replay",time.Minute)
	_,csr,_:=makeCSR(t,"router-replay")
	_,err:=s.IssueEnrollment(testPassphrase,"router-replay",token,csr)
	if !errors.Is(err,ErrTokenReused){t.Fatalf("got %v, want ErrTokenReused",err)}
}

func TestExpiredTokenRejected(t *testing.T) {
	s:=readyStore(t)
	_,csr,keyHash:=makeCSR(t,"router-expired")
	token,err:=s.SetScopedEnrollmentCredential(testPassphrase,"router-expired",keyHash,"2001:db8::11",51821,time.Nanosecond)
	if err!=nil{t.Fatal(err)}
	time.Sleep(time.Millisecond)
	_,err=s.IssueEnrollment(testPassphrase,"router-expired",token,csr)
	if !errors.Is(err,ErrTokenExpired){t.Fatalf("got %v, want ErrTokenExpired",err)}
}

func TestWrongCSRKeyRejectedWithoutConsumingToken(t *testing.T) {
	s:=readyStore(t)
	_,csr,keyHash:=makeCSR(t,"router-keybind")
	token,err:=s.SetScopedEnrollmentCredential(testPassphrase,"router-keybind",keyHash,"2001:db8::12",51822,time.Minute)
	if err!=nil{t.Fatal(err)}
	_,otherCSR,_:=makeCSR(t,"router-keybind")
	if _,err=s.IssueEnrollment(testPassphrase,"router-keybind",token,otherCSR);!errors.Is(err,ErrBadCredential){t.Fatalf("got %v, want ErrBadCredential",err)}
	st,err:=s.LoadState(testPassphrase);if err!=nil{t.Fatal(err)}
	if st.Enrollment.Used{t.Fatal("bad CSR consumed token")}
	if len(csr)==0{t.Fatal("test CSR unexpectedly empty")}
}

func TestRevokedRouterRejectedOnControlAndRDRLookup(t *testing.T) {
	s:=readyStore(t)
	issued,_,_:=enrollTestRouter(t,s,"router-revoked",time.Minute)
	cert,err:=x509.ParseCertificate(issued.CertificateDER);if err!=nil{t.Fatal(err)}
	if _,err=s.AuthorizeControl(testPassphrase,cert);err!=nil{t.Fatalf("new router not authorized: %v",err)}
	if err=s.RevokeRouter(testPassphrase,issued.RouterID,"test revocation");err!=nil{t.Fatal(err)}
	if _,err=s.AuthorizeControl(testPassphrase,cert);!errors.Is(err,ErrRevoked){t.Fatalf("got %v, want ErrRevoked",err)}
	if _,status,err:=s.LookupRDR(testPassphrase,issued.RouterID);!errors.Is(err,ErrRevoked)||status!=2{t.Fatalf("lookup status=%d err=%v",status,err)}
	push,err:=s.RevocationPushValue(testPassphrase);if err!=nil{t.Fatal(err)}
	if len(push)<12+32||binary.BigEndian.Uint32(push[8:12])!=1{t.Fatalf("bad revocation push %x",push)}
	st,err:=s.LoadState(testPassphrase);if err!=nil{t.Fatal(err)}
	if st.Revocations[issued.RouterID].Generation==0{t.Fatal("revocation not persisted")}
}

func TestControlSnapshotsEncodeConfiguredPolicy(t *testing.T) {
	s:=readyStore(t)
	policy,err:=s.PolicySyncValue(testPassphrase);if err!=nil{t.Fatal(err)}
	if len(policy)<12||binary.BigEndian.Uint32(policy[8:12])!=2{t.Fatalf("policy sync invalid: %x",policy)}
	if policy[12]!=1&&policy[12]!=2{t.Fatal("invalid policy action")}
}

func TestCACertificateIsPersistentAndTLS13Compatible(t *testing.T) {
	s:=readyStore(t)
	_,rootPEM,err:=s.TLSCertificate(testPassphrase,"ca.test.example");if err!=nil{t.Fatal(err)}
	if _,_,err=s.TLSCertificate(testPassphrase,"ca.test.example");err!=nil{t.Fatal(err)}
	if _,_,err=s.TLSCertificate(testPassphrase,"other.test.example");err==nil{t.Fatal("hostname mismatch should fail closed")}
	if _,err=os.Stat(filepath.Join(s.Dir,"ca-cert.pem"));err!=nil{t.Fatal(err)}
	if len(rootPEM)==0{t.Fatal("root PEM missing")}
}

func TestMalformedEnrollmentCSRRejected(t *testing.T) {
	s:=readyStore(t)
	_,_,keyHash:=makeCSR(t,"router-malformed")
	token,err:=s.SetScopedEnrollmentCredential(testPassphrase,"router-malformed",keyHash,"2001:db8::13",51823,time.Minute)
	if err!=nil{t.Fatal(err)}
	if _,err=s.IssueEnrollment(testPassphrase,"router-malformed",token,[]byte("not a CSR"));!errors.Is(err,ErrBadSignature){t.Fatalf("got %v",err)}
}

func pemDecode(b []byte) ([]byte,error) {
	block,_:=pem.Decode(b)
	if block==nil{return nil,errors.New("missing PEM block")}
	return block.Bytes,nil
}

func TestCredentialTokenHashNotPersistedAsToken(t *testing.T) {
	s:=readyStore(t)
	_,_,token:=enrollTestRouter(t,s,"router-secret",time.Minute)
	raw,err:=os.ReadFile(filepath.Join(s.Dir,stateFile));if err!=nil{t.Fatal(err)}
	if bytes.Contains(raw,[]byte(token)){t.Fatal("token leaked to state")}
	if !bytes.Contains(raw,[]byte(base64.StdEncoding.EncodeToString([]byte("dummy")))) && len(raw)==0 {t.Fatal("state unexpectedly empty")}
}

func TestMultipleScopedCredentialsCanEnrollIndependentRouters(t *testing.T) {
	store := readyStore(t)
	_, csrA, hashA := makeCSR(t, "router-multi-a")
	_, csrB, hashB := makeCSR(t, "router-multi-b")
	tokenA, err := store.SetScopedEnrollmentCredential(testPassphrase, "router-multi-a", hashA, "2001:db8::21", 52001, time.Minute)
	if err != nil { t.Fatal(err) }
	tokenB, err := store.SetScopedEnrollmentCredential(testPassphrase, "router-multi-b", hashB, "2001:db8::22", 52002, time.Minute)
	if err != nil { t.Fatal(err) }
	a, err := store.IssueEnrollment(testPassphrase, "router-multi-a", tokenA, csrA)
	if err != nil { t.Fatal(err) }
	b, err := store.IssueEnrollment(testPassphrase, "router-multi-b", tokenB, csrB)
	if err != nil { t.Fatal(err) }
	state, err := store.LoadState(testPassphrase)
	if err != nil { t.Fatal(err) }
	if len(state.Routers) != 2 { t.Fatalf("router count=%d, want 2", len(state.Routers)) }
	if !state.EnrollmentCredentials[tokenHash(t,tokenA)].Used { t.Fatal("first credential not consumed") }
	if !state.EnrollmentCredentials[tokenHash(t,tokenB)].Used { t.Fatal("second credential not consumed") }
	if a.RouterID == b.RouterID { t.Fatal("router IDs collided") }
}

func tokenHash(t *testing.T, token string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil { t.Fatal(err) }
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
