package ca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	rdrBodySize = 258
	rdrSize = rdrBodySize + ed25519.SignatureSize
)

var (
	ErrBadCredential = errors.New("BAD_CREDENTIAL")
	ErrTokenExpired = errors.New("TOKEN_EXPIRED")
	ErrTokenReused = errors.New("TOKEN_REUSED")
	ErrBadSignature = errors.New("BAD_SIGNATURE")
	ErrRevoked = errors.New("REVOKED")
	ErrUnknownRouter = errors.New("UNKNOWN_ROUTER")
)

type IssuedEnrollment struct {
	RouterID string
	CertificateDER []byte
	RDR []byte
	Serial uint64
	NotBefore time.Time
	NotAfter time.Time
}

// IssueEnrollment validates the scoped token and CSR, then persists token consumption,
// certificate and signed RDR before returning any issuance material.
func (s Store) IssueEnrollment(passphrase, name, token string, csrDER []byte) (IssuedEnrollment, error) {
	var out IssuedEnrollment
	if len(csrDER) == 0 || len(csrDER) > 4096 || len(token) == 0 || len(token) > 512 {
		return out, ErrBadCredential
	}
	unlock, err := s.lock()
	if err != nil { return out, err }
	defer unlock()

	st, caKey, err := s.load(passphrase)
	if err != nil { return out, err }
	if st.Enrollment == nil || st.Enrollment.Name != name {
		return out, ErrBadCredential
	}
	cred := st.Enrollment
	rawToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil { return out, ErrBadCredential }
	tokenSum := sha256.Sum256(rawToken)
	if !equalHex(tokenSum[:], cred.TokenSHA256) { return out, ErrBadCredential }
	if cred.Used { return out, ErrTokenReused }
	if !time.Now().UTC().Before(cred.ExpiresAt) { return out, ErrTokenExpired }
	if !st.Access.Configured || !st.Access.AllowEnrollment || !st.Policy.Configured {
		return out, ErrBadCredential
	}
	if cred.PublicKeySHA256 == "" || cred.EndpointIPv6 == "" || cred.EndpointUDPPort == 0 {
		return out, ErrBadCredential
	}
	active := 0
	for _, router := range st.Routers { if router.Status == "ACTIVE" { active++ } }
	if active >= st.Access.MaxActiveRouters { return out, errors.New("POLICY_DENIED: active router limit reached") }

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || !bytes.Equal(csr.Raw, csrDER) || csr.CheckSignature() != nil {
		return out, ErrBadSignature
	}
	if csr.Subject.CommonName != name || strings.ContainsRune(csr.Subject.CommonName, 0) {
		return out, ErrBadCredential
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize { return out, ErrBadCredential }
	pubSum := sha256.Sum256(pub)
	if !equalHex(pubSum[:], cred.PublicKeySHA256) { return out, ErrBadCredential }

	rootDER, rootKey, err := s.rootCertificate(passphrase, "")
	if err != nil { return out, err }
	root, err := x509.ParseCertificate(rootDER)
	if err != nil { return out, err }
	serial, err := randomUint64()
	if err != nil { return out, err }
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.AddDate(1, 0, 0)
	leaf := &x509.Certificate{
		SerialNumber: new(big.Int).SetUint64(serial),
		Subject: csr.Subject,
		NotBefore: notBefore,
		NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA: false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, root, pub, rootKey)
	if err != nil { return out, err }

	var rid [16]byte
	if _, err = rand.Read(rid[:]); err != nil { return out, err }
	routerID := hex.EncodeToString(rid[:])
	endpoint, err := netip.ParseAddr(cred.EndpointIPv6)
	if err != nil || !endpoint.Is6() || endpoint.Is4In6() { return out, ErrBadCredential }
	body := make([]byte, rdrBodySize)
	body[0], body[1] = 1, 1
	binary.BigEndian.PutUint16(body[2:4], 0)
	copy(body[4:20], rid[:])
	copy(body[20:52], pub)
	body[52], body[53] = 1, 6
	endpointBytes := endpoint.As16()
	copy(body[54:70], endpointBytes[:])
	binary.BigEndian.PutUint16(body[70:72], cred.EndpointUDPPort)
	binary.BigEndian.PutUint64(body[72:80], serial)
	binary.BigEndian.PutUint64(body[80:88], uint64(notBefore.UnixMilli()))
	binary.BigEndian.PutUint64(body[88:96], uint64(notAfter.UnixMilli()))
	body[96] = 1
	binary.BigEndian.PutUint64(body[104:112], st.RevocationGeneration+1)
	if _, err = rand.Read(body[112:128]); err != nil { return out, err }
	rdr := signRDR(caKey, body)
	st.Enrollment.Used = true
	st.RevocationGeneration++
	st.ControlEpoch++
	now := time.Now().UTC()
	st.Routers[routerID] = RouterRecord{
		RouterID: routerID, Name: name, PublicKey: base64.StdEncoding.EncodeToString(pub),
		CertificateDER: base64.StdEncoding.EncodeToString(certDER), CertificateSerial: serial,
		RDR: base64.StdEncoding.EncodeToString(rdr), EndpointIPv6: cred.EndpointIPv6,
		EndpointUDPPort: cred.EndpointUDPPort, Status: "ACTIVE", UpdatedAt: now,
	}
	st.UpdatedAt = now
	if err = s.saveState(st); err != nil { return out, err }
	out = IssuedEnrollment{RouterID: routerID, CertificateDER: certDER, RDR: rdr, Serial: serial, NotBefore: notBefore, NotAfter: notAfter}
	return out, nil
}

func (s Store) SetScopedCredential(passphrase, name, publicKeySHA256, endpointIPv6 string, port uint16, ttl time.Duration) (string, error) {
	return s.SetScopedEnrollmentCredential(passphrase, name, publicKeySHA256, endpointIPv6, port, ttl)
}

func (s Store) RevokeRouter(passphrase, routerID, reason string) error {
	if reason == "" || len(reason) > 256 { return errors.New("revocation reason must be 1..256 bytes") }
	unlock, err := s.lock()
	if err != nil { return err }
	defer unlock()
	st, key, err := s.load(passphrase)
	if err != nil { return err }
	router, ok := st.Routers[routerID]
	if !ok { return ErrUnknownRouter }
	if router.Status == "REVOKED" { return nil }
	router.Status = "REVOKED"
	router.UpdatedAt = time.Now().UTC()
	st.RevocationGeneration++
	st.ControlEpoch++
	st.Routers[routerID] = router
	st.Revocations[routerID] = RevocationRecord{RouterID:routerID, Reason:reason, Generation:st.RevocationGeneration, EffectiveAt:time.Now().UTC()}
	if len(router.RDR) > 0 {
		rdr, decodeErr := base64.StdEncoding.DecodeString(router.RDR)
		if decodeErr != nil || len(rdr) != rdrSize { return errors.New("stored RDR is corrupt") }
		body := append([]byte(nil), rdr[:rdrBodySize]...)
		body[96] = 2
		binary.BigEndian.PutUint64(body[104:112], st.RevocationGeneration)
		router.RDR = base64.StdEncoding.EncodeToString(signRDR(key, body))
		st.Routers[routerID] = router
	}
	st.UpdatedAt = time.Now().UTC()
	return s.saveState(st)
}

func (s Store) RecordControlHeartbeat(passphrase, routerID string, epoch uint64) error {
	if epoch == 0 { return errors.New("invalid control epoch") }
	unlock, err := s.lock()
	if err != nil { return err }
	defer unlock()
	st, _, err := s.load(passphrase)
	if err != nil { return err }
	router, ok := st.Routers[routerID]
	if !ok { return ErrUnknownRouter }
	if router.Status != "ACTIVE" { return ErrRevoked }
	if epoch <= router.LastControlEpoch { return errors.New("stale control epoch") }
	router.LastControlEpoch = epoch
	router.UpdatedAt = time.Now().UTC()
	st.Routers[routerID] = router
	st.UpdatedAt = router.UpdatedAt
	return s.saveState(st)
}

func (s Store) LookupRDR(passphrase, routerID string) ([]byte, uint16, error) {
	st, _, err := s.load(passphrase)
	if err != nil { return nil, 3, err }
	router, ok := st.Routers[routerID]
	if !ok { return nil, 1, ErrUnknownRouter }
	if router.Status != "ACTIVE" { return nil, 2, ErrRevoked }
	rdr, err := base64.StdEncoding.DecodeString(router.RDR)
	if err != nil || len(rdr) != rdrSize { return nil, 3, errors.New("stored RDR invalid") }
	return rdr, 0, nil
}

func (s Store) AuthorizeControl(passphrase string, cert *x509.Certificate) (string, error) {
	if cert == nil { return "", ErrBadCredential }
	st, _, err := s.load(passphrase)
	if err != nil { return "", err }
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok { return "", ErrBadCredential }
	encoded := base64.StdEncoding.EncodeToString(pub)
	for id, router := range st.Routers {
		if router.CertificateSerial == uint64(cert.SerialNumber.Uint64()) && router.PublicKey == encoded {
			if router.Status != "ACTIVE" { return "", ErrRevoked }
			if _, revoked := st.Revocations[id]; revoked { return "", ErrRevoked }
			return id, nil
		}
	}
	return "", ErrUnknownRouter
}

func (s Store) PolicySyncValue(passphrase string) ([]byte, error) {
	st, _, err := s.load(passphrase)
	if err != nil { return nil, err }
	type entry struct { prefix netip.Prefix; action byte }
	entries := make([]entry, 0, len(st.Policy.ProtectPrefixes)+len(st.Policy.BypassPrefixes))
	for _, raw := range st.Policy.ProtectPrefixes { p, e := netip.ParsePrefix(raw); if e != nil { return nil, e }; entries=append(entries, entry{p,1}) }
	for _, raw := range st.Policy.BypassPrefixes { p, e := netip.ParsePrefix(raw); if e != nil { return nil, e }; entries=append(entries, entry{p,2}) }
	sort.Slice(entries, func(i,j int) bool { return entries[i].prefix.String() < entries[j].prefix.String() })
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[:8], st.PolicyGeneration)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(entries)))
	for _, e := range entries {
		p := e.prefix
		addr := p.Addr().AsSlice()
		family := byte(6); if p.Addr().Is4() { family=4 }
		buf=append(buf,e.action,family,byte(p.Bits()),0)
		buf=append(buf,addr...)
	}
	return buf,nil
}

func (s Store) RevocationPushValue(passphrase string) ([]byte, error) {
	st, _, err := s.load(passphrase)
	if err != nil { return nil, err }
	ids := make([]string,0,len(st.Routers))
	for id := range st.Routers { ids=append(ids,id) }
	sort.Strings(ids)
	if len(ids)>65536 { return nil, errors.New("revocation snapshot exceeds protocol limit") }
	buf:=make([]byte,12)
	binary.BigEndian.PutUint64(buf[:8],st.RevocationGeneration)
	binary.BigEndian.PutUint32(buf[8:12],uint32(len(ids)))
	for _,id:=range ids {
		raw,e:=hex.DecodeString(id); if e!=nil||len(raw)!=16{return nil,errors.New("invalid router ID in registry")}
		r:=st.Routers[id]
		status:=byte(1);if r.Status=="REVOKED"{status=2}else if r.Status=="DISABLED"{status=3}
		buf=append(buf,raw...)
		buf=append(buf,status,0,0,0,0,0,0,0)
		effective:=r.UpdatedAt
		if rev,ok:=st.Revocations[id];ok{effective=rev.EffectiveAt}
		ts:=make([]byte,8);binary.BigEndian.PutUint64(ts,uint64(effective.UnixMilli()))
		buf=append(buf,ts...)
	}
	return buf,nil
}

func (s Store) rootCertificate(passphrase, dnsName string) ([]byte, ed25519.PrivateKey, error) {
	st, key, err := s.load(passphrase)
	if err != nil { return nil, nil, err }
	path:=s.path("ca-cert.pem")
	if raw,readErr:=os.ReadFile(path);readErr==nil {
		block,_:=pem.Decode(raw);if block==nil||block.Type!="CERTIFICATE"{return nil,nil,errors.New("invalid CA certificate PEM")}
		cert,e:=x509.ParseCertificate(block.Bytes);if e!=nil{return nil,nil,e}
		pub:=key.Public().(ed25519.PublicKey)
		certPub,ok:=cert.PublicKey.(ed25519.PublicKey);if !ok||!bytes.Equal(certPub,pub){return nil,nil,errors.New("CA certificate key mismatch")}
		if dnsName!="" { if e=cert.VerifyHostname(dnsName);e!=nil{return nil,nil,fmt.Errorf("CA certificate hostname mismatch: %w",e)} }
		return cert.Raw,key,nil
	} else if !errors.Is(readErr,os.ErrNotExist){return nil,nil,readErr}
	if dnsName=="" { dnsName="localhost" }
	now:=st.CreatedAt
	if now.IsZero(){now=time.Now().UTC()}
	serialBytes:=sha256.Sum256([]byte(st.CAID))
	serial:=new(big.Int).SetBytes(serialBytes[:8]);serial.And(serial,new(big.Int).SetUint64(^uint64(0)>>1));if serial.Sign()==0{serial.SetInt64(1)}
	tmpl:=&x509.Certificate{SerialNumber:serial,Subject:pkixName("NLS Router-CA"),NotBefore:now.Add(-time.Minute),NotAfter:now.AddDate(10,0,0),
		KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature,
		ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid:true,IsCA:true,MaxPathLen:0,DNSNames:[]string{dnsName}}
	der,err:=x509.CreateCertificate(rand.Reader,tmpl,tmpl,key.Public(),key);if err!=nil{return nil,nil,err}
	pemBytes:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
	if err=writeBytesAtomic(path,pemBytes,0600);err!=nil{return nil,nil,err}
	return der,key,nil
}

func (s Store) TLSCertificate(passphrase, dnsName string) (tls.Certificate, []byte, error) {
	der,key,err:=s.rootCertificate(passphrase,dnsName);if err!=nil{return tls.Certificate{},nil,err}
	keyDER,err:=x509.MarshalPKCS8PrivateKey(key);if err!=nil{return tls.Certificate{},nil,err}
	certPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
	keyPEM:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER})
	pair,err:=tls.X509KeyPair(certPEM,keyPEM);if err!=nil{return tls.Certificate{},nil,err}
	return pair,certPEM,nil
}

func signRDR(key ed25519.PrivateKey, body []byte) []byte {
	message:=append([]byte("NLS-v1-RDR\x00"),body...)
	sig:=ed25519.Sign(key,message)
	return append(append([]byte(nil),body...),sig...)
}

func equalHex(value []byte, expected string) bool {
	decoded,err:=hex.DecodeString(expected)
	return err==nil&&len(decoded)==len(value)&&bytes.Equal(decoded,value)
}

func randomUint64() (uint64,error) {
	var b [8]byte
	if _,err:=rand.Read(b[:]);err!=nil{return 0,err}
	n:=binary.BigEndian.Uint64(b[:])&(^uint64(0)>>1)
	if n==0{n=1}
	return n,nil
}

func (s Store) lock() (func(),error) {
	if err:=os.MkdirAll(s.Dir,0700);err!=nil{return nil,err}
	f,err:=os.OpenFile(filepath.Join(s.Dir,".ca-state.lock"),os.O_CREATE|os.O_RDWR,0600)
	if err!=nil{return nil,err}
	if err=syscall.Flock(int(f.Fd()),syscall.LOCK_EX);err!=nil{_ = f.Close();return nil,err}
	return func(){_ = syscall.Flock(int(f.Fd()),syscall.LOCK_UN);_ = f.Close()},nil
}

func writeBytesAtomic(path string, data []byte, mode os.FileMode) error {
	dir:=filepath.Dir(path)
	f,err:=os.CreateTemp(dir,".nls-tmp-*");if err!=nil{return err}
	tmp:=f.Name();defer os.Remove(tmp)
	if err=f.Chmod(mode);err!=nil{_ = f.Close();return err}
	if _,err=f.Write(data);err!=nil{_ = f.Close();return err}
	if err=f.Sync();err!=nil{_ = f.Close();return err}
	if err=f.Close();err!=nil{return err}
	if err=os.Rename(tmp,path);err!=nil{return err}
	d,err:=os.Open(dir);if err==nil{_ = d.Sync();_ = d.Close()}
	return nil
}

// pkixName keeps the root certificate's subject construction centralized.
func pkixName(commonName string) pkix.Name {
	return pkix.Name{CommonName:commonName,Organization:[]string{"NLS"}}
}

func (s Store) RootCertificatePEM(passphrase, dnsName string) ([]byte,error) {
	_,key,err:=s.rootCertificate(passphrase,dnsName)
	if err!=nil{return nil,err}
	_ = key
	raw,err:=os.ReadFile(s.path("ca-cert.pem"))
	return raw,err
}
