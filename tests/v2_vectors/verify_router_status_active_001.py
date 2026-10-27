#!/usr/bin/env python3
"""Rebuild and verify router_status_active_001.json. TEST KEYS ONLY."""
import hashlib
import ipaddress
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 2**32:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", n)

def enc(value):
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1-value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(enc(x) for x in value)
    if isinstance(value, dict):
        pairs = [(enc(k), enc(v)) for k, v in value.items()]
        pairs.sort(key=lambda p: (len(p[0]), p[0]))
        return head(5, len(pairs)) + b"".join(k+v for k, v in pairs)
    raise TypeError(type(value))

def hx(s):
    return bytes.fromhex(s)

def build():
    fixture_path = Path(__file__).with_name("router_status_active_001.json")
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    seed = hx(fixture["issuer_private_seed_hex_test_only"])
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = hashlib.sha256(public_der).digest()
    router_id = hx(fixture["router_id_hex"])
    address = ipaddress.IPv6Address(fixture["authorized_endpoint"]["ipv6"]).packed
    endpoint = {1: 6, 2: address, 3: fixture["authorized_endpoint"]["udp_port"], 4: router_id}
    payload_obj = {
        1: 1, 2: router_id, 3: hx(fixture["certificate_serial_hex"]),
        4: hx(fixture["certificate_fingerprint_hex"]), 5: 1,
        6: fixture["status_generation"], 7: fixture["issued_at"],
        8: fixture["expires_at"], 9: [endpoint],
        10: fixture["authorized_endpoint"]["role_ids"], 11: kid,
        12: fixture["revocation_generation"], 13: fixture["policy_id"].encode("ascii")
    }
    payload = enc(payload_obj)
    external_aad = hx(fixture["external_aad_hex"])
    protected = enc({1: -8, 4: kid})
    sig_structure = enc(["Signature1", protected, external_aad, payload])
    signature = key.sign(sig_structure)
    cose = b"\xd2" + enc([protected, {}, payload, signature])
    actual = {
        "issuer_public_spki_der_hex": public_der.hex(),
        "issuer_key_id_hex": kid.hex(),
        "protected_header_hex": protected.hex(),
        "payload_cbor_hex": payload.hex(),
        "sig_structure_cbor_hex": sig_structure.hex(),
        "signature_hex": signature.hex(),
        "cose_sign1_tagged_cbor_hex": cose.hex()
    }
    for name, value in actual.items():
        if fixture[name] != value:
            raise SystemExit(f"mismatch: {name}")
    key.public_key().verify(signature, sig_structure)
    print("PASS router_status_active_001: deterministic CBOR and COSE_Sign1 match fixture")
    print("WARNING: fixture uses synthetic test-only signing material")

if __name__ == "__main__":
    build()
