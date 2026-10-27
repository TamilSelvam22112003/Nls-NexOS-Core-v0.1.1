#!/usr/bin/env python3
"""Independent verification for adjacent_cookie_001.json."""
import hashlib
import hmac
import ipaddress
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

v = json.loads(Path(__file__).with_name("adjacent_cookie_001.json").read_text())
outer = v["outer_tuple"]
inp = v["test_only_inputs"]
expected = v["expected"]
secret = bytes.fromhex(inp["cookie_secret_hex"])
source = ipaddress.IPv6Address(outer["source_ipv6"]).packed
destination = ipaddress.IPv6Address(outer["destination_ipv6"]).packed
handshake_id = bytes.fromhex(inp["handshake_id_hex"])
nonce_i = bytes.fromhex(inp["nonce_i_hex"])
private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(inp["ephemeral_x25519_private_hex"]))
public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
assert public.hex() == inp["ephemeral_x25519_public_hex"]

def make_input(src=source, dst=destination, sport=outer["source_udp_port"],
               dport=outer["destination_udp_port"], hid=handshake_id, nonce=nonce_i,
               eph=public, bucket=inp["time_bucket"]):
    return (b"NLS2-COOKIE\x00" + src + dst + struct.pack(">HH", sport, dport) +
            hid + nonce + eph + struct.pack(">Q", bucket))

raw = make_input()
assert raw.hex() == expected["mac_input_hex"]
mac = hmac.new(secret, raw, hashlib.sha256).digest()
cookie = struct.pack(">Q", inp["time_bucket"]) + mac
assert mac.hex() == expected["mac_hex"]
assert cookie.hex() == expected["cookie_hex"] and len(cookie) == expected["cookie_length_bytes"] == 40

mutations = [
    make_input(src=source[:-1] + bytes([source[-1] ^ 1])),
    make_input(dst=destination[:-1] + bytes([destination[-1] ^ 1])),
    make_input(sport=outer["source_udp_port"] + 1),
    make_input(dport=outer["destination_udp_port"] + 1),
    make_input(hid=bytes([handshake_id[0] ^ 1]) + handshake_id[1:]),
    make_input(nonce=bytes([nonce_i[0] ^ 1]) + nonce_i[1:]),
    make_input(eph=bytes([public[0] ^ 1]) + public[1:]),
    make_input(bucket=inp["time_bucket"] + 1),
]
assert all(not hmac.compare_digest(hmac.new(secret, item, hashlib.sha256).digest(), mac) for item in mutations)
changed_secret = bytes([secret[0] ^ 1]) + secret[1:]
assert not hmac.compare_digest(hmac.new(changed_secret, raw, hashlib.sha256).digest(), mac)
print("adjacent_cookie_001: PASS (Python cryptography + stdlib; positive and binding-negative cases)")
