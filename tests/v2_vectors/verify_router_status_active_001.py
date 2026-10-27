#!/usr/bin/env python3
"""Rebuild and verify the fixed-width Router-CA status vector. TEST KEYS ONLY."""
import hashlib
import ipaddress
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def hx(value):
    return bytes.fromhex(value)

def build():
    fixture = json.loads(Path(__file__).with_name("router_status_active_001.json").read_text(encoding="utf-8"))
    key = Ed25519PrivateKey.from_private_bytes(hx(fixture["issuer_private_seed_hex_test_only"]))
    public_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    identity_spki = hx(fixture["router_identity_spki_der_hex"])
    router_id = hashlib.sha256(identity_spki).digest()
    if router_id.hex() != fixture["router_identity_fingerprint_hex"]:
        raise SystemExit("router identity fingerprint mismatch")
    cert_fp = hx(fixture["certificate_fingerprint_hex"])
    prefix = bytearray(b"N2ST")
    prefix += bytes([1, 1]) + b"\x00\x00" + struct.pack(">I", 304)
    prefix += router_id + cert_fp
    prefix += struct.pack(">Q", fixture["certificate_serial_u64"])
    prefix += struct.pack(">Q", fixture["status_generation"])
    prefix += struct.pack(">Q", fixture["issued_at_unix_seconds"])
    prefix += struct.pack(">Q", fixture["expires_at_unix_seconds"])
    prefix += bytes([1, 0, 0, 0])
    prefix += ipaddress.IPv6Address(fixture["endpoint_ipv6"]).packed
    prefix += struct.pack(">H", fixture["endpoint_udp_port"])
    prefix += bytes(18 * 3) + bytes(56)
    if len(prefix) != 240:
        raise SystemExit(f"wrong prefix size: {len(prefix)}")
    signed = b"NLS2-ROUTER-STATUS\x00" + bytes(prefix)
    signature = key.sign(signed)
    obj = bytes(prefix) + signature
    actual = {
        "issuer_public_spki_der_hex": public_der.hex(),
        "signature_input_hex": signed.hex(),
        "status_prefix_240_hex": bytes(prefix).hex(),
        "signature_hex": signature.hex(),
        "status_object_304_hex": obj.hex()
    }
    for name, value in actual.items():
        if fixture[name] != value:
            raise SystemExit(f"mismatch: {name}")
    key.public_key().verify(signature, signed)
    print("PASS router_status_active_001: 240-byte prefix and Ed25519 signature match fixture")
    print("WARNING: synthetic test-only signing material; X.509 validation is not tested")

if __name__ == "__main__":
    build()
