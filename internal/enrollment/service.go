// Package enrollment implements the Router-CA TLS enrollment and mTLS control services.
package enrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.1/internal/ca"
	"golang.org/x/text/unicode/norm"
)

const (
	TLVHeartbeat uint16 = 0x0001
	TLVHeartbeatAck uint16 = 0x0002
	TLVEnrollmentRequest uint16 = 0x0010
	TLVEnrollmentResponse uint16 = 0x0011
	TLVPolicySync uint16 = 0x0020
	TLVPolicyAck uint16 = 0x0021
	TLVRevocationPush uint16 = 0x0030
	TLVDirectoryLookup uint16 = 0x0040
	TLVDirectoryResponse uint16 = 0x0041
	TLVError uint16 = 0x7fff
)

type Service struct {
	Store ca.Store
	Passphrase string
	TLSName string
}

func (s Service) ServeEnrollment(ctx context.Context, address string) error {
	cert, _, err := s.Store.TLSCertificate(s.Passphrase, s.TLSName)
	if err != nil { return err }
	ln, err := net.Listen("tcp", address)
	if err != nil { return err }
	defer ln.Close()
	go func(){ <-ctx.Done(); _ = ln.Close() }()
	cfg := &tls.Config{Certificates:[]tls.Certificate{cert}, MinVersion:tls.VersionTLS13, MaxVersion:tls.VersionTLS13}
	for {
		conn, e := ln.Accept()
		if e != nil {
			if ctx.Err()!=nil { return nil }
			return e
		}
		go s.handleEnrollment(tls.Server(conn,cfg))
	}
}

func (s Service) handleEnrollment(conn net.Conn) {
	defer conn.Close()
	tlsConn,ok:=conn.(*tls.Conn)
	if !ok { return }
	if err:=tlsConn.Handshake();err!=nil{return}
	_ = tlsConn.SetDeadline(deadline())
	typ,value,err:=readTLV(tlsConn, 6+6+128+512+4096)
	if err!=nil{return}
	if typ!=TLVEnrollmentRequest { _ = writeEnrollmentResponse(tlsConn,2,0x0001,nil,0);return }
	name,token,csr,err:=parseEnrollmentRequest(value)
	if err!=nil { _ = writeEnrollmentResponse(tlsConn,2,0x0001,nil,0);return }
	issued,err:=s.Store.IssueEnrollment(s.Passphrase,name,token,csr)
	if err!=nil { _ = writeEnrollmentResponse(tlsConn,2,errorCode(err),nil,0);return }
	if len(issued.CertificateDER)>8192 { _ = writeEnrollmentResponse(tlsConn,2,0x0016,nil,0);return }
	_ = writeEnrollmentResponse(tlsConn,1,0,issued.CertificateDER,issued.Serial)
}

func (s Service) ServeControl(ctx context.Context, address string) error {
	cert, rootPEM, err := s.Store.TLSCertificate(s.Passphrase,s.TLSName)
	if err!=nil{return err}
	roots:=x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM){return errors.New("failed to load Router-CA trust root")}
	ln,err:=net.Listen("tcp",address);if err!=nil{return err}
	defer ln.Close()
	go func(){<-ctx.Done();_ = ln.Close()}()
	cfg:=&tls.Config{Certificates:[]tls.Certificate{cert},ClientCAs:roots,ClientAuth:tls.RequireAndVerifyClientCert,MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13}
	for {
		conn,e:=ln.Accept()
		if e!=nil { if ctx.Err()!=nil{return nil};return e }
		go s.handleControl(tls.Server(conn,cfg))
	}
}

func (s Service) handleControl(conn net.Conn) {
	defer conn.Close()
	tlsConn,ok:=conn.(*tls.Conn);if !ok{return}
	if err:=tlsConn.Handshake();err!=nil{return}
	state:=tlsConn.ConnectionState()
	if len(state.PeerCertificates)==0{return}
	routerID,err:=s.Store.AuthorizeControl(s.Passphrase,state.PeerCertificates[0]);if err!=nil{return}
	for {
		_ = tlsConn.SetDeadline(deadline())
		typ,value,err:=readTLV(tlsConn, 1<<20)
		if err!=nil{return}
		switch typ {
		case TLVHeartbeat:
			if len(value)!=32{return}
			requestID:=binary.BigEndian.Uint64(value[:8])
			senderTime:=binary.BigEndian.Uint64(value[8:16])
			epoch:=binary.BigEndian.Uint64(value[16:24])
			lastRev:=binary.BigEndian.Uint64(value[24:32])
			if requestID==0||senderTime==0||epoch==0 { return }
			if err=s.Store.RecordControlHeartbeat(s.Passphrase,routerID,epoch);err!=nil{return}
			currentState,stateErr:=s.Store.LoadState(s.Passphrase)
			if stateErr!=nil||lastRev>currentState.RevocationGeneration{return}
			ack:=append([]byte(nil),value...)
			ack=appendU64(ack,uint64(nowMillis()))
			if err=writeTLV(tlsConn,TLVHeartbeatAck,ack);err!=nil{return}
			policy,e:=s.Store.PolicySyncValue(s.Passphrase);if e!=nil{return}
			if err=writeTLV(tlsConn,TLVPolicySync,policy);err!=nil{return}
			revocations,e:=s.Store.RevocationPushValue(s.Passphrase);if e!=nil{return}
			if err=writeTLV(tlsConn,TLVRevocationPush,revocations);err!=nil{return}
			policyGeneration:=binary.BigEndian.Uint64(policy[:8])
			revocationGeneration:=binary.BigEndian.Uint64(revocations[:8])
			for i,expected:=range []uint16{TLVPolicyAck,TLVPolicyAck} {
				ackType,ackValue,e:=readTLV(tlsConn,64);if e!=nil||ackType!=expected||len(ackValue)!=12{return}
				expectedGeneration:=policyGeneration
				if i==1{expectedGeneration=revocationGeneration}
				if binary.BigEndian.Uint64(ackValue[:8])!=expectedGeneration||binary.BigEndian.Uint16(ackValue[8:10])!=0||binary.BigEndian.Uint16(ackValue[10:12])!=0{return}
			}
		case TLVDirectoryLookup:
			if len(value)!=24{return}
			requestID:=binary.BigEndian.Uint64(value[:8])
			routerIDBytes:=value[8:24]
			id:=fmt.Sprintf("%x",routerIDBytes)
			rdr,status,e:=s.Store.LookupRDR(s.Passphrase,id)
			if e!=nil&&status==3{return}
			resp:=make([]byte,12)
			binary.BigEndian.PutUint64(resp[:8],requestID)
			binary.BigEndian.PutUint16(resp[8:10],status)
			if len(rdr)>65535{return}
			binary.BigEndian.PutUint16(resp[10:12],uint16(len(rdr)))
			resp=append(resp,rdr...)
			if writeTLV(tlsConn,TLVDirectoryResponse,resp)!=nil{return}
		default:
			return
		}
		// Re-check registry status after each request so revocation closes existing sessions.
		if _,err=s.Store.AuthorizeControl(s.Passphrase,state.PeerCertificates[0]);err!=nil{return}
		_ = routerID
	}
}

func parseEnrollmentRequest(value []byte)(string,string,[]byte,error) {
	if len(value)<6{return "","",nil,errors.New("truncated enrollment request")}
	if value[0]!=1{return "","",nil,errors.New("unsupported enrollment schema")}
	nameLen:=int(value[1]);tokenLen:=int(binary.BigEndian.Uint16(value[2:4]));csrLen:=int(binary.BigEndian.Uint16(value[4:6]))
	if nameLen<1||nameLen>128||tokenLen<1||tokenLen>512||csrLen<1||csrLen>4096{return "","",nil,errors.New("invalid enrollment field length")}
	if len(value)!=6+nameLen+tokenLen+csrLen{return "","",nil,errors.New("enrollment length mismatch")}
	nameBytes:=value[6:6+nameLen]
	if !utf8.Valid(nameBytes)||!norm.NFC.IsNormal(nameBytes)||strings.IndexByte(string(nameBytes),0)>=0{return "","",nil,errors.New("invalid router name")}
	tokenStart:=6+nameLen
	csrStart:=tokenStart+tokenLen
	return string(nameBytes),string(value[tokenStart:csrStart]),append([]byte(nil),value[csrStart:]...),nil
}

func writeEnrollmentResponse(w io.Writer,status byte,code uint16,cert []byte,serial uint64)error {
	value:=make([]byte,8)
	value[0],value[1]=1,status
	binary.BigEndian.PutUint16(value[2:4],code)
	binary.BigEndian.PutUint32(value[4:8],uint32(len(cert)))
	value=append(value,cert...)
	value=appendU64(value,serial)
	return writeTLV(w,TLVEnrollmentResponse,value)
}

func readTLV(r io.Reader,max int)(uint16,[]byte,error) {
	var header [6]byte
	if _,err:=io.ReadFull(r,header[:]);err!=nil{return 0,nil,err}
	n:=binary.BigEndian.Uint32(header[2:])
	if n>uint32(max){return 0,nil,errors.New("TLV exceeds limit")}
	value:=make([]byte,int(n))
	if _,err:=io.ReadFull(r,value);err!=nil{return 0,nil,err}
	return binary.BigEndian.Uint16(header[:2]),value,nil
}

func writeTLV(w io.Writer,typ uint16,value []byte)error {
	if len(value)>int(^uint32(0)){return errors.New("TLV too large")}
	header:=make([]byte,6)
	binary.BigEndian.PutUint16(header[:2],typ)
	binary.BigEndian.PutUint32(header[2:],uint32(len(value)))
	if err:=writeFull(w,header);err!=nil{return err}
	return writeFull(w,value)
}

func writeFull(w io.Writer,b []byte)error { for len(b)>0 { n,err:=w.Write(b);if err!=nil{return err};if n==0{return io.ErrShortWrite};b=b[n:] };return nil }
func errorCode(err error)uint16 {
	switch {
	case errors.Is(err,ca.ErrBadCredential):return 0x0003
	case errors.Is(err,ca.ErrTokenExpired):return 0x0004
	case errors.Is(err,ca.ErrTokenReused):return 0x0005
	case errors.Is(err,ca.ErrBadSignature):return 0x0007
	case errors.Is(err,ca.ErrRevoked):return 0x000b
	case errors.Is(err,ca.ErrUnknownRouter):return 0x000c
	default:return 0x0016
	}
}

func appendU64(b []byte,n uint64)[]byte { var v [8]byte;binary.BigEndian.PutUint64(v[:],n);return append(b,v[:]...) }
func nowMillis()int64{return timeNow().UnixMilli()}
var timeNow = func() time.Time { return time.Now() }
func deadline() time.Time { return timeNow().Add(15*time.Second) }
