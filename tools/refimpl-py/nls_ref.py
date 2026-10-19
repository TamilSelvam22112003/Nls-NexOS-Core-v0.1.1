"""Pure deterministic reference primitives for NLS v1-rc2.

No I/O is performed. The normative contract is docs/PROTOCOL.md.
EXPERIMENTAL: not independently cryptographically reviewed.
"""
from __future__ import annotations
import hashlib, hmac, ipaddress, struct
from dataclasses import dataclass, field
from typing import Mapping
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION=1; COMMON_HEADER_LEN=8; RDR_BODY_LEN=130; RDR_SIGNATURE_LEN=64; RDR_LEN=194
DATA_HEADER_LEN=32; GCM_TAG_LEN=16; MAX_INNER_MTU=1404
M1_INIT=1; M1_COOKIE=2; M2=3; M3=4; M4=5; DATA=0x10; REKEY_INIT=0x11; REKEY_ACK=0x12
RDR_CONTEXT=b"NLS-v1-RDR\x00"; M2_CONTEXT=b"NLS-v1-M2-SIG\x00"
M3_CONTEXT=b"NLS-v1-M3-SIG\x00"; M4_CONTEXT=b"NLS-v1-M4-FIN\x00"
SESSION_ID_CONTEXT=b"NLS-v1 session-id\x00"; ZERO_NONCE=b"\x00"*4+struct.pack(">Q",0)

def frame_header(message_type:int, body_len:int)->bytes:
    if not 0<=message_type<=255 or not 0<=body_len<=65535: raise ValueError("message type or body length out of range")
    return struct.pack(">BBHHH",VERSION,message_type,0,body_len,0)

def frame(message_type:int, body:bytes)->bytes:
    return frame_header(message_type,len(body))+body

def parse_frame(packet:bytes, expected_type:int|None=None)->tuple[int,bytes]:
    if len(packet)<8: raise ValueError("truncated common header")
    version,typ,flags,length,reserved=struct.unpack(">BBHHH",packet[:8])
    if version!=VERSION: raise ValueError("unsupported version")
    if flags or reserved: raise ValueError("nonzero common-header reserved field")
    if len(packet)!=8+length: raise ValueError("frame length mismatch or trailing bytes")
    if expected_type is not None and typ!=expected_type: raise ValueError("unexpected message type")
    return typ,packet[8:]

def _raw_public(key:Ed25519PrivateKey|X25519PrivateKey)->bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def rdr_body(signing_key:Ed25519PrivateKey, router_id:bytes, endpoint_ipv6:bytes|str,
             endpoint_port:int, certificate_serial:int, not_before_ms:int, not_after_ms:int,
             status:int, generation:int, record_nonce:bytes)->bytes:
    if len(router_id)!=16 or len(record_nonce)!=16: raise ValueError("router_id and record_nonce must be 16 bytes")
    ip=ipaddress.IPv6Address(endpoint_ipv6).packed
    if not 1<=endpoint_port<=65535: raise ValueError("invalid endpoint port")
    if status not in (1,2,3): raise ValueError("invalid router status")
    if not all(0<=v<2**64 for v in (certificate_serial,not_before_ms,not_after_ms,generation)): raise ValueError("u64 field out of range")
    body=(struct.pack(">BBH",1,1,0)+router_id+_raw_public(signing_key)+struct.pack(">BB",1,6)+ip
          +struct.pack(">HQQQB",endpoint_port,certificate_serial,not_before_ms,not_after_ms,status)
          +b"\x00"*7+struct.pack(">Q",generation)+record_nonce+struct.pack(">H",0))
    if len(body)!=RDR_BODY_LEN: raise AssertionError(f"RDR body is {len(body)} bytes")
    return body

def sign_rdr(signing_key:Ed25519PrivateKey, **fields)->bytes:
    body=rdr_body(signing_key=signing_key,**fields)
    return body+signing_key.sign(RDR_CONTEXT+body)

def verify_rdr(record:bytes, now_ms:int|None=None)->dict:
    if len(record)!=RDR_LEN: raise ValueError("RDR must be exactly 194 bytes")
    body,signature=record[:130],record[130:]
    version,alg,flags=struct.unpack(">BBH",body[:4])
    if version!=1 or alg!=1 or flags!=0: raise ValueError("unsupported or noncanonical RDR header")
    if body[52]!=1 or body[53]!=6: raise ValueError("RDR must contain exactly one IPv6 endpoint")
    if body[97:104]!=b"\x00"*7: raise ValueError("nonzero RDR reserved bytes")
    if struct.unpack(">H",body[128:130])[0]!=0: raise ValueError("RDR extensions_len must be zero in v1")
    port=struct.unpack(">H",body[70:72])[0]; before,after=struct.unpack(">QQ",body[80:96]); status=body[96]
    if port==0 or status not in (1,2,3) or after<=before: raise ValueError("invalid RDR endpoint, status, or validity")
    if now_ms is not None and not before<=now_ms<after: raise ValueError("RDR outside validity interval")
    public=Ed25519PublicKey.from_public_bytes(body[20:52])
    try: public.verify(signature,RDR_CONTEXT+body)
    except Exception as exc: raise ValueError("bad RDR signature") from exc
    return {"router_id":body[4:20],"public_key":body[20:52],"endpoint_ipv6":body[54:70],
            "endpoint_port":port,"certificate_serial":struct.unpack(">Q",body[72:80])[0],
            "not_before_ms":before,"not_after_ms":after,"status":status,
            "generation":struct.unpack(">Q",body[104:112])[0],"record_nonce":body[112:128],"record":record}

def _cookie_input(source_ipv6:bytes|str,source_port:int,destination_ipv6:bytes|str,destination_port:int,
                  initiator_router_id:bytes,destination_router_id:bytes,initiator_nonce:bytes,time_bucket:int)->bytes:
    src=ipaddress.IPv6Address(source_ipv6).packed; dst=ipaddress.IPv6Address(destination_ipv6).packed
    if len(initiator_router_id)!=16 or len(destination_router_id)!=16: raise ValueError("router IDs must be 16 bytes")
    if len(initiator_nonce)!=32: raise ValueError("initiator nonce must be 32 bytes")
    if not 1<=source_port<=65535 or not 1<=destination_port<=65535: raise ValueError("invalid UDP port")
    if not 0<=time_bucket<2**32: raise ValueError("time bucket out of range")
    return src+struct.pack(">H",source_port)+dst+struct.pack(">H",destination_port)+initiator_router_id+destination_router_id+initiator_nonce+struct.pack(">I",time_bucket)

def make_cookie(secret:bytes,**fields)->bytes:
    if len(secret)<32: raise ValueError("cookie secret must be at least 32 bytes")
    return hmac.new(secret,_cookie_input(**fields),hashlib.sha256).digest()[:16]

def verify_cookie(cookie:bytes,time_bucket:int,current_bucket:int,secrets_by_bucket:Mapping[int,bytes],**fields)->bool:
    if len(cookie)!=16 or time_bucket not in (current_bucket,current_bucket-1): return False
    secret=secrets_by_bucket.get(time_bucket)
    if secret is None or len(secret)<32: return False
    return hmac.compare_digest(cookie,make_cookie(secret,time_bucket=time_bucket,**fields))

def build_m1_init(initiator_nonce:bytes,initiator_router_id:bytes,destination_router_id:bytes,
                  ephemeral_public:bytes,cookie:bytes|None=None)->bytes:
    if len(initiator_nonce)!=32 or len(initiator_router_id)!=16 or len(destination_router_id)!=16 or len(ephemeral_public)!=32:
        raise ValueError("invalid M1 fixed field length")
    core=initiator_nonce+initiator_router_id+destination_router_id+ephemeral_public+struct.pack(">HH",1,0)
    if len(core)!=100: raise AssertionError("M1 fixed fields must occupy 100 bytes")
    if cookie is None: body=core+b"\x00"*20
    else:
        if len(cookie)!=16: raise ValueError("cookie must be 16 bytes")
        body=core+b"\x01"+cookie+b"\x00"*3
    return frame(M1_INIT,body)

def build_m1_cookie(initiator_nonce:bytes,cookie:bytes,time_bucket:int)->bytes:
    if len(initiator_nonce)!=32 or len(cookie)!=16 or not 0<=time_bucket<2**32: raise ValueError("invalid M1_COOKIE field")
    return frame(M1_COOKIE,initiator_nonce+cookie+struct.pack(">I",time_bucket))

def transcript_hash(*messages:bytes)->bytes: return hashlib.sha256(b"".join(messages)).digest()

def derive_keys(shared_secret:bytes,th0:bytes)->dict[str,bytes]:
    if len(shared_secret)!=32 or len(th0)!=32: raise ValueError("shared secret and TH0 must be 32 bytes")
    labels={"k_hs_i2r":b"NLS-v1 hs i2r","k_hs_r2i":b"NLS-v1 hs r2i",
            "k_finish_responder":b"NLS-v1 finish r","k_data_i2r":b"NLS-v1 data i2r",
            "k_data_r2i":b"NLS-v1 data r2i","salt_i2r":b"NLS-v1 nonce i2r","salt_r2i":b"NLS-v1 nonce r2i"}
    return {name:HKDF(algorithm=hashes.SHA256(),length=(4 if name.startswith("salt_") else 32),
                      salt=th0,info=label+th0).derive(shared_secret) for name,label in labels.items()}

def identity_plain(router_id:bytes,generation:int,rdr_hash:bytes,receiver_index:int)->bytes:
    if len(router_id)!=16 or len(rdr_hash)!=32 or not 0<=generation<2**64 or not 1<=receiver_index<2**32:
        raise ValueError("invalid identity field")
    out=router_id+struct.pack(">Q",generation)+rdr_hash+struct.pack(">I",receiver_index)+b"\x00"*4
    if len(out)!=64: raise AssertionError("identity plaintext must be 64 bytes")
    return out

def parse_identity(value:bytes)->dict:
    if len(value)!=64 or value[60:64]!=b"\x00"*4: raise ValueError("malformed encrypted identity plaintext")
    index=struct.unpack(">I",value[56:60])[0]
    if index==0: raise ValueError("zero receiver_index")
    return {"router_id":value[:16],"generation":struct.unpack(">Q",value[16:24])[0],"rdr_hash":value[24:56],"receiver_index":index}

def build_m2(responder_nonce:bytes,responder_ephemeral_public:bytes,prior_hash:bytes,identity:bytes,
             key_hs_r2i:bytes,signing_key:Ed25519PrivateKey)->bytes:
    if len(responder_nonce)!=32 or len(responder_ephemeral_public)!=32 or len(prior_hash)!=32 or len(identity)!=64 or len(key_hs_r2i)!=32:
        raise ValueError("invalid M2 field length")
    aad=frame_header(M2,244)+prior_hash
    encrypted=AESGCM(key_hs_r2i).encrypt(ZERO_NONCE,identity,aad)
    prefix=responder_nonce+responder_ephemeral_public+prior_hash+struct.pack(">H",80)+encrypted+struct.pack(">H",64)
    if len(prefix)!=180: raise AssertionError("M2 signed prefix must be 180 bytes")
    return frame(M2,prefix+signing_key.sign(M2_CONTEXT+hashlib.sha256(prior_hash+prefix).digest()))

def verify_m2(packet:bytes,signing_public:Ed25519PublicKey,key_hs_r2i:bytes)->dict:
    _,body=parse_frame(packet,M2)
    if len(body)!=244 or struct.unpack(">H",body[96:98])[0]!=80 or struct.unpack(">H",body[178:180])[0]!=64: raise ValueError("malformed M2 lengths")
    prior=body[64:96]
    try:
        signing_public.verify(body[180:244],M2_CONTEXT+hashlib.sha256(prior+body[:180]).digest())
        identity=AESGCM(key_hs_r2i).decrypt(ZERO_NONCE,body[98:178],packet[:8]+prior)
    except Exception as exc: raise ValueError("M2 signature or identity authentication failed") from exc
    return {"responder_nonce":body[:32],"ephemeral_public":body[32:64],"prior_hash":prior,"identity":parse_identity(identity)}

def build_m3(prior_hash:bytes,identity:bytes,key_hs_i2r:bytes,signing_key:Ed25519PrivateKey)->bytes:
    if len(prior_hash)!=32 or len(identity)!=64 or len(key_hs_i2r)!=32: raise ValueError("invalid M3 field length")
    aad=frame_header(M3,178)+prior_hash
    encrypted=AESGCM(key_hs_i2r).encrypt(ZERO_NONCE,identity,aad)
    prefix=prior_hash+struct.pack(">H",80)+encrypted
    if len(prefix)!=114: raise AssertionError("M3 signed prefix must be 114 bytes")
    return frame(M3,prefix+signing_key.sign(M3_CONTEXT+hashlib.sha256(prior_hash+prefix).digest()))

def verify_m3(packet:bytes,signing_public:Ed25519PublicKey,key_hs_i2r:bytes)->dict:
    _,body=parse_frame(packet,M3)
    if len(body)!=178 or struct.unpack(">H",body[32:34])[0]!=80: raise ValueError("malformed M3 lengths")
    prior=body[:32]
    try:
        signing_public.verify(body[114:178],M3_CONTEXT+hashlib.sha256(prior+body[:114]).digest())
        identity=AESGCM(key_hs_i2r).decrypt(ZERO_NONCE,body[34:114],packet[:8]+prior)
    except Exception as exc: raise ValueError("M3 signature or identity authentication failed") from exc
    return {"prior_hash":prior,"identity":parse_identity(identity)}

def build_m4(prior_hash:bytes,finish_key:bytes)->bytes:
    if len(prior_hash)!=32 or len(finish_key)!=32: raise ValueError("invalid M4 input")
    mac=hmac.new(finish_key,M4_CONTEXT+prior_hash,hashlib.sha256).digest()
    return frame(M4,prior_hash+mac)

def verify_m4(packet:bytes,expected_prior_hash:bytes,finish_key:bytes)->bool:
    _,body=parse_frame(packet,M4)
    if len(body)!=64 or len(expected_prior_hash)!=32 or len(finish_key)!=32: raise ValueError("malformed M4")
    expected=hmac.new(finish_key,M4_CONTEXT+expected_prior_hash,hashlib.sha256).digest()
    if not hmac.compare_digest(body[:32],expected_prior_hash) or not hmac.compare_digest(body[32:],expected): raise ValueError("M4 finish MAC or transcript mismatch")
    return True

@dataclass
class ReplayWindow:
    width:int=1024
    highest:int=0
    seen:set[int]=field(default_factory=set)
    def precheck(self,sequence:int)->None:
        if sequence<=0: raise ValueError("sequence zero is forbidden")
        if sequence in self.seen: raise ValueError("duplicate sequence")
        if self.highest and sequence<=self.highest-(self.width-1): raise ValueError("sequence too old")
    def commit(self,sequence:int)->None:
        self.precheck(sequence); self.seen.add(sequence); self.highest=max(self.highest,sequence)
        floor=max(1,self.highest-(self.width-1)); self.seen={n for n in self.seen if n>=floor}

def data_header(message_type:int,receiver_index:int,session_nonce_id:bytes,sequence:int)->bytes:
    if message_type not in (DATA,REKEY_INIT,REKEY_ACK): raise ValueError("invalid data-plane message type")
    if not 1<=receiver_index<2**32 or len(session_nonce_id)!=16: raise ValueError("invalid receiver index or session nonce ID")
    if not 1<=sequence<2**64: raise ValueError("invalid sequence")
    return struct.pack(">BBHI",VERSION,message_type,0,receiver_index)+session_nonce_id+struct.pack(">Q",sequence)

def seal_data(key:bytes,direction_salt:bytes,receiver_index:int,session_nonce_id:bytes,sequence:int,
              plaintext:bytes,message_type:int=DATA)->bytes:
    if len(key)!=32 or len(direction_salt)!=4: raise ValueError("invalid data key or direction salt")
    if len(plaintext)>MAX_INNER_MTU: raise ValueError("inner packet exceeds configured maximum MTU")
    header=data_header(message_type,receiver_index,session_nonce_id,sequence)
    return header+AESGCM(key).encrypt(direction_salt+struct.pack(">Q",sequence),plaintext,header)

def open_data(packet:bytes,key:bytes,direction_salt:bytes,expected_receiver_index:int|None=None,
              expected_session_nonce_id:bytes|None=None,replay_window:ReplayWindow|None=None)->tuple[dict,bytes]:
    if len(key)!=32 or len(direction_salt)!=4 or len(packet)<DATA_HEADER_LEN+GCM_TAG_LEN: raise ValueError("invalid data packet or key")
    header=packet[:DATA_HEADER_LEN]; version,typ,flags,index=struct.unpack(">BBHI",header[:8])
    session_id=header[8:24]; sequence=struct.unpack(">Q",header[24:32])[0]
    if version!=VERSION or flags!=0 or typ not in (DATA,REKEY_INIT,REKEY_ACK): raise ValueError("invalid data header")
    if index==0 or sequence==0: raise ValueError("zero receiver index or sequence")
    if expected_receiver_index is not None and index!=expected_receiver_index: raise ValueError("unexpected receiver index")
    if expected_session_nonce_id is not None and not hmac.compare_digest(session_id,expected_session_nonce_id): raise ValueError("unexpected session nonce ID")
    if replay_window is not None: replay_window.precheck(sequence)
    try: plaintext=AESGCM(key).decrypt(direction_salt+struct.pack(">Q",sequence),packet[DATA_HEADER_LEN:],header)
    except Exception as exc: raise ValueError("data packet authentication failed") from exc
    if len(plaintext)>MAX_INNER_MTU: raise ValueError("decrypted inner packet exceeds configured maximum MTU")
    if replay_window is not None: replay_window.commit(sequence)
    return {"type":typ,"receiver_index":index,"session_nonce_id":session_id,"sequence":sequence},plaintext

def deterministic_handshake_fixture()->dict:
    """Fixed keys/nonces produce reproducible RDRs, M1-M4 and data session identifiers."""
    initiator_sign=Ed25519PrivateKey.from_private_bytes(b"\x11"*32)
    responder_sign=Ed25519PrivateKey.from_private_bytes(b"\x22"*32)
    initiator_eph=X25519PrivateKey.from_private_bytes(bytes(range(1,33)))
    responder_eph=X25519PrivateKey.from_private_bytes(bytes(range(33,65)))
    iid,rid=b"I"*16,b"R"*16; ni,nr=bytes(range(32)),bytes(range(32,64))
    ri=sign_rdr(signing_key=initiator_sign,router_id=iid,endpoint_ipv6="2001:db8::1",endpoint_port=40001,
        certificate_serial=1,not_before_ms=1000,not_after_ms=9999999,status=1,generation=7,record_nonce=b"i"*16)
    rr=sign_rdr(signing_key=responder_sign,router_id=rid,endpoint_ipv6="2001:db8::2",endpoint_port=40002,
        certificate_serial=2,not_before_ms=1000,not_after_ms=9999999,status=1,generation=9,record_nonce=b"r"*16)
    initial=build_m1_init(ni,iid,rid,_raw_public(initiator_eph)); bucket=1000; secret=bytes(range(64))
    fields=dict(source_ipv6="2001:db8::1",source_port=40001,destination_ipv6="2001:db8::2",destination_port=40002,
        initiator_router_id=iid,destination_router_id=rid,initiator_nonce=ni,time_bucket=bucket)
    cookie=make_cookie(secret,**fields); cookie_msg=build_m1_cookie(ni,cookie,bucket)
    cookie_init=build_m1_init(ni,iid,rid,_raw_public(initiator_eph),cookie)
    th0=transcript_hash(initial,cookie_msg,cookie_init)
    shared=initiator_eph.exchange(X25519PublicKey.from_public_bytes(_raw_public(responder_eph)))
    keys=derive_keys(shared,th0)
    m2=build_m2(nr,_raw_public(responder_eph),th0,identity_plain(rid,9,hashlib.sha256(rr).digest(),0x10203040),keys["k_hs_r2i"],responder_sign)
    prior_m3=transcript_hash(initial,cookie_msg,cookie_init,m2)
    m3=build_m3(prior_m3,identity_plain(iid,7,hashlib.sha256(ri).digest(),0x50607080),keys["k_hs_i2r"],initiator_sign)
    prior_m4=transcript_hash(initial,cookie_msg,cookie_init,m2,m3)
    m4=build_m4(prior_m4,keys["k_finish_responder"])
    messages=(initial,cookie_msg,cookie_init,m2,m3,m4); th4=transcript_hash(*messages)
    return {"messages":messages,"keys":keys,"rdr_i":ri,"rdr_r":rr,"initiator_sign":initiator_sign,
        "responder_sign":responder_sign,"th0":th0,"th4":th4,
        "session_nonce_id":hashlib.sha256(SESSION_ID_CONTEXT+th4).digest()[:16],
        "cookie":cookie,"cookie_fields":fields,"cookie_secret":secret}
