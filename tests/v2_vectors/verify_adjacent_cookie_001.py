#!/usr/bin/env python3
"""Independent stdlib/cryptography verification for adjacent_cookie_001.json."""
import hashlib
import hmac
import ipaddress
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

v=json.loads(Path(__file__).with_name("adjacent_cookie_001.json").read_text())
outer=v["outer_tuple"]; inp=v["test_only_inputs"]; expected=v["expected"]
priv=x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(inp["ephemeral_x25519_private_hex"]))
pub=priv.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
assert pub.hex()==inp["ephemeral_x25519_public_hex"]
raw=(b"NLS2-COOKIE\x00"+ipaddress.IPv6Address(outer["source_ipv6"]).packed+
     ipaddress.IPv6Address(outer["destination_ipv6"]).packed+
     struct.pack(">HH",outer["source_udp_port"],outer["destination_udp_port"])+
     bytes.fromhex(inp["handshake_id_hex"])+bytes.fromhex(inp["nonce_i_hex"])+pub+
     struct.pack(">Q",inp["time_bucket"]))
assert raw.hex()==expected["mac_input_hex"]
mac=hmac.new(bytes.fromhex(inp["cookie_secret_hex"]),raw,hashlib.sha256).digest()
cookie=struct.pack(">Q",inp["time_bucket"])+mac
assert mac.hex()==expected["mac_hex"]
assert cookie.hex()==expected["cookie_hex"] and len(cookie)==expected["cookie_length_bytes"]==40
print("adjacent_cookie_001: PASS (Python cryptography + stdlib)")
