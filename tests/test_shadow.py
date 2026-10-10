"""Unit tests for Active Directory msDS-KeyCredentialLink Binary Parser."""

import hashlib
import io
import json
import os
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.shadow import (
    ShadowCredentialDecodeError,
    format_shadow_report_terminal,
    parse_cng_public_key,
    parse_filetime_to_iso,
    parse_guid_bytes,
    parse_key_credential_link,
)


def build_synthetic_shadow_blob(
    version: int = 0x00000200,
    key_type: str = "RSA",
    usage: int = 0x01,
    source: int = 0x00,
    mismatch_key_id: bool = False,
) -> bytes:
    """Construct authentic msDS-KeyCredentialLink binary blob per [MS-ADTS] 2.2.20."""
    blob = bytearray()
    blob.extend(struct.pack("<I", version))

    # 1. KeyMaterial
    if key_type == "RSA":
        # BCRYPT_RSAKEY_BLOB: Magic (RSA1), BitLen (2048), cbPublicExp (3), cbModulus (256), cbPrime1 (0), cbPrime2 (0)
        cng_hdr = struct.pack("<4sIIIII", b"RSA1", 2048, 3, 256, 0, 0)
        pub_exp = b"\x01\x00\x01"  # 65537
        modulus = b"\xbb" * 256
        km_bytes = cng_hdr + pub_exp + modulus
    else:
        # BCRYPT_ECCKEY_BLOB: Magic (ECK1), cbKey (32)
        cng_hdr = struct.pack("<4sI", b"ECK1", 32)
        x_coord = b"\x11" * 32
        y_coord = b"\x22" * 32
        km_bytes = cng_hdr + x_coord + y_coord

    # Entry 0x03: KEY_MATERIAL
    blob.extend(struct.pack("<HB", len(km_bytes), 0x03))
    blob.extend(km_bytes)

    # Entry 0x01: KEY_ID (SHA-256)
    if mismatch_key_id:
        kid = b"\x00" * 32
    else:
        kid = hashlib.sha256(km_bytes).digest()
    blob.extend(struct.pack("<HB", len(kid), 0x01))
    blob.extend(kid)

    # Entry 0x04: KEY_USAGE
    blob.extend(struct.pack("<HB", 1, 0x04))
    blob.append(usage)

    # Entry 0x05: KEY_SOURCE
    blob.extend(struct.pack("<HB", 1, 0x05))
    blob.append(source)

    # Entry 0x06: DEVICE_ID (GUID)
    dev_guid = bytes.fromhex("11223344556677889900aabbccddeeff")
    blob.extend(struct.pack("<HB", 16, 0x06))
    blob.extend(dev_guid)

    # Entry 0x07: CUSTOM_KEY_INFORMATION (Version 1, Attestation flag 0x01)
    custom_info = bytes([0x01, 0x01])
    blob.extend(struct.pack("<HB", len(custom_info), 0x07))
    blob.extend(custom_info)

    # Entry 0x09: KEY_CREATION_TIME (FILETIME for 2026-05-15T12:00:00Z)
    ft_creation = 133918032000000000
    blob.extend(struct.pack("<HB", 8, 0x09))
    blob.extend(struct.pack("<Q", ft_creation))

    return bytes(blob)


class TestShadowCredentialParser(unittest.TestCase):
    def test_parse_version_2_rsa(self):
        blob = build_synthetic_shadow_blob(version=0x00000200, key_type="RSA", usage=0x01, source=0x00)
        report = parse_key_credential_link(blob)

        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["version_str"], "2.0")
        self.assertEqual(report["key_usage"], "NGC")
        self.assertEqual(report["key_source"], "AD")
        self.assertEqual(report["device_id"], "44332211-6655-8877-9900-aabbccddeeff")
        self.assertTrue(report["integrity_valid"])
        self.assertEqual(len(report["integrity_issues"]), 0)

        km = report["key_material"]
        self.assertIsNotNone(km)
        self.assertEqual(km["key_type"], "RSA")
        self.assertEqual(km["bit_length"], 2048)
        self.assertEqual(km["public_exponent"], 65537)
        self.assertEqual(km["modulus_length"], 256)

        self.assertIsNotNone(report["creation_time"])
        self.assertTrue(report["creation_time"].startswith("2025-"))

    def test_parse_version_1_ecc(self):
        blob = build_synthetic_shadow_blob(version=0x00000100, key_type="ECC", usage=0x02, source=0x01)
        report = parse_key_credential_link(blob)

        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["version_str"], "1.0")
        self.assertEqual(report["key_usage"], "FIDO")
        self.assertEqual(report["key_source"], "AzureAD")
        self.assertTrue(report["integrity_valid"])

        km = report["key_material"]
        self.assertIsNotNone(km)
        self.assertEqual(km["key_type"], "ECC")
        self.assertEqual(km["algorithm"], "ECDSA")
        self.assertEqual(km["curve"], "P-256")
        self.assertEqual(km["coordinate_length"], 32)

    def test_parse_dn_binary_format(self):
        blob = build_synthetic_shadow_blob()
        hex_data = blob.hex()
        target_dn = "CN=tanuki-app,CN=Users,DC=lab,DC=local"
        dn_binary_str = f"B:{len(hex_data)}:{hex_data}:{target_dn}"

        report = parse_key_credential_link(dn_binary_str)
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["target_dn"], target_dn)
        self.assertEqual(report["raw_length"], len(blob))

    def test_integrity_mismatch_warning(self):
        blob = build_synthetic_shadow_blob(mismatch_key_id=True)
        report = parse_key_credential_link(blob)

        self.assertFalse(report["integrity_valid"])
        self.assertIn("KeyID does not match SHA-256 of KeyMaterial", report["integrity_issues"])

    def test_safe_filetime_pre_1970(self):
        self.assertIsNone(parse_filetime_to_iso(0))
        self.assertIsNone(parse_filetime_to_iso(-100))
        # Valid timestamp prior to 1970 (e.g. year 1800) does not crash
        res = parse_filetime_to_iso(627984000000000)
        self.assertIsNotNone(res)
        self.assertTrue(res.startswith("1603-") or res.startswith("1602-"))

    def test_corrupted_and_truncated_blobs(self):
        with self.assertRaises(ShadowCredentialDecodeError):
            parse_key_credential_link(b"\x00\x00")

        # Unsupported version 0x00000300
        with self.assertRaises(ShadowCredentialDecodeError):
            parse_key_credential_link(struct.pack("<I", 0x00000300))

        # Entry length exceeds buffer bounds
        corrupt = struct.pack("<IHB", 0x00000200, 500, 0x01) + b"\xaa" * 10
        with self.assertRaises(ShadowCredentialDecodeError):
            parse_key_credential_link(corrupt)

    def test_terminal_format(self):
        blob = build_synthetic_shadow_blob()
        report = parse_key_credential_link(blob)
        formatted = format_shadow_report_terminal(report)

        self.assertIn("Active Directory Shadow Credential", formatted)
        self.assertIn("Structure Version", formatted)
        self.assertIn("Public Key Type", formatted)
        self.assertIn("Device ID", formatted)

    def test_cli_integration(self):
        from tanuki.cli import main

        blob = build_synthetic_shadow_blob()
        hex_input = blob.hex()

        # Test terminal output
        stdout_capture = io.StringIO()
        with patch("sys.stdout", stdout_capture):
            exit_code = main(["shadow", hex_input])
        self.assertEqual(exit_code, 0)
        self.assertIn("Active Directory Shadow Credential", stdout_capture.getvalue())

        # Test JSON output
        json_capture = io.StringIO()
        with patch("sys.stdout", json_capture):
            exit_code = main(["shadow", hex_input, "--json"])
        self.assertEqual(exit_code, 0)
        parsed = json.loads(json_capture.getvalue())
        self.assertEqual(parsed["status"], "SUCCESS")
        self.assertEqual(parsed["version_str"], "2.0")


if __name__ == "__main__":
    unittest.main()
