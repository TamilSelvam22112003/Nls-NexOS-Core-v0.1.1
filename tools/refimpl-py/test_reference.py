import hashlib
import unittest
import nls_ref as nls

class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.fx=nls.deterministic_handshake_fixture()

    def test_rdr_size_signature_and_tamper(self):
        rdr=self.fx["rdr_r"]
        self.assertEqual(len(rdr),194)
        parsed=nls.verify_rdr(rdr,now_ms=2000)
        self.assertEqual(parsed["router_id"],b"R"*16)
        self.assertEqual(parsed["generation"],9)
        tampered=bytearray(rdr); tampered[54]^=1
        with self.assertRaises(ValueError): nls.verify_rdr(bytes(tampered))

    def test_rdr_rejects_nonzero_extensions(self):
        rdr=bytearray(self.fx["rdr_i"]); rdr[128:130]=b"\x00\x01"
        with self.assertRaisesRegex(ValueError,"extensions_len"): nls.verify_rdr(bytes(rdr))

    def test_cookie_current_previous_wrong_source_secret_and_bucket(self):
        fields=dict(self.fx["cookie_fields"]); current=fields.pop("time_bucket")
        cookie=self.fx["cookie"]; previous_secret=b"P"*32
        prev_fields=dict(fields,time_bucket=current-1)
        prev=nls.make_cookie(previous_secret,**prev_fields)
        secrets={current:self.fx["cookie_secret"],current-1:previous_secret}
        self.assertTrue(nls.verify_cookie(cookie,current,current,secrets,**fields))
        self.assertTrue(nls.verify_cookie(prev,current-1,current,secrets,**fields))
        self.assertFalse(nls.verify_cookie(cookie,current,current,secrets,**dict(fields,source_port=40003)))
        self.assertFalse(nls.verify_cookie(cookie,current,current,{current:b"X"*32},**fields))
        self.assertFalse(nls.verify_cookie(cookie,current-2,current,secrets,**fields))

    def test_full_fixed_handshake(self):
        msgs=self.fx["messages"]
        self.assertEqual([len(m) for m in msgs],[128,60,128,252,186,72])
        self.assertEqual(len(self.fx["keys"]["k_data_i2r"]),32)
        self.assertEqual(len(self.fx["keys"]["salt_i2r"]),4)
        m2=nls.verify_m2(msgs[3],self.fx["responder_sign"].public_key(),self.fx["keys"]["k_hs_r2i"])
        self.assertEqual(m2["identity"]["receiver_index"],0x10203040)
        m3=nls.verify_m3(msgs[4],self.fx["initiator_sign"].public_key(),self.fx["keys"]["k_hs_i2r"])
        self.assertEqual(m3["identity"]["receiver_index"],0x50607080)
        self.assertTrue(nls.verify_m4(msgs[5],nls.transcript_hash(*msgs[:5]),self.fx["keys"]["k_finish_responder"]))
        self.assertEqual(self.fx["session_nonce_id"],hashlib.sha256(nls.SESSION_ID_CONTEXT+self.fx["th4"]).digest()[:16])

    def test_data_round_trip_and_replay(self):
        key,salt=b"K"*32,b"S"*4; payload=bytes(i%251 for i in range(1404))
        packet=nls.seal_data(key,salt,0x50607080,self.fx["session_nonce_id"],1,payload)
        self.assertEqual(len(packet),1452)
        window=nls.ReplayWindow()
        header,opened=nls.open_data(packet,key,salt,0x50607080,self.fx["session_nonce_id"],window)
        self.assertEqual(opened,payload); self.assertEqual(header["sequence"],1)
        with self.assertRaisesRegex(ValueError,"duplicate"):
            nls.open_data(packet,key,salt,0x50607080,self.fx["session_nonce_id"],window)

    def test_tamper_does_not_commit_replay(self):
        key,salt=b"K"*32,b"S"*4
        packet=bytearray(nls.seal_data(key,salt,7,self.fx["session_nonce_id"],4,b"payload")); packet[-1]^=0x80
        window=nls.ReplayWindow()
        with self.assertRaisesRegex(ValueError,"authentication"):
            nls.open_data(bytes(packet),key,salt,7,self.fx["session_nonce_id"],window)
        self.assertEqual(window.highest,0); self.assertEqual(window.seen,set())

    def test_frame_rejects_trailing_bytes(self):
        message=nls.frame(nls.M1_COOKIE,b"x"*52)
        with self.assertRaisesRegex(ValueError,"length mismatch"): nls.parse_frame(message+b"\x00")

if __name__=="__main__": unittest.main()
