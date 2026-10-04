import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from kcm_parser import scan_for_ccache_blobs, try_parse_default_principal


class TestKCMParser(unittest.TestCase):
    def test_scan_for_ccache_blobs_basic(self):
        fake_db = bytearray(b"RANDOM_LDB_RECORDS_DATA_PADDING")

        valid_ccache = bytearray(b"\x05\x04")
        valid_ccache += struct.pack(">H", 12)
        valid_ccache += b"A" * 50

        fake_db += valid_ccache
        fake_db += b"MORE_PADDING_DATA"

        blobs = scan_for_ccache_blobs(bytes(fake_db))
        self.assertGreaterEqual(len(blobs), 1)
        first = blobs[0]
        self.assertEqual(first["header_len"], 12)
        self.assertTrue(first["data"].startswith(b"\x05\x04"))

    def test_scan_with_principal_extraction(self):
        blob = bytearray(b"\x05\x04")
        blob += struct.pack(">H", 0)  # header_len = 0
        blob += struct.pack(">I", 1)  # name_type
        blob += struct.pack(">I", 1)  # num_components
        realm = b"CORP.LOCAL"
        blob += struct.pack(">I", len(realm)) + realm
        comp = b"admin"
        blob += struct.pack(">I", len(comp)) + comp

        blobs = scan_for_ccache_blobs(bytes(blob))
        self.assertEqual(len(blobs), 1)
        self.assertEqual(blobs[0]["default_principal"], "admin@CORP.LOCAL")

    def test_rejects_empty_realm_principal(self):
        blob = bytearray(b"\x05\x04")
        blob += struct.pack(">H", 0)
        blob += struct.pack(">I", 1)
        blob += struct.pack(">I", 1)
        blob += struct.pack(">I", 0)  # realm_len = 0
        blobs = scan_for_ccache_blobs(bytes(blob))
        self.assertEqual(len(blobs), 1)
        self.assertIsNone(blobs[0]["default_principal"])

    def test_cli_json_mode(self):
        blob = bytearray(b"\x05\x04")
        blob += struct.pack(">H", 0)
        blob += struct.pack(">I", 1)
        blob += struct.pack(">I", 1)
        realm = b"CORP.LOCAL"
        blob += struct.pack(">I", len(realm)) + realm
        comp = b"svc_backup"
        blob += struct.pack(">I", len(comp)) + comp

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldb") as tf:
            tf.write(blob)
            tf_path = tf.name

        try:
            script_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "scripts", "kcm_parser.py")
            )
            res = subprocess.run(
                [sys.executable, script_path, "-f", tf_path, "--json"],
                capture_output=True,
                text=True,
                check=True,
            )
            data = json.loads(res.stdout)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["default_principal"], "svc_backup@CORP.LOCAL")
            self.assertEqual(data[0]["header_len"], 0)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_missing_file_error(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "kcm_parser.py")
        )
        res = subprocess.run(
            [sys.executable, script_path, "-f", "non_existent_file.ldb"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 3)
        self.assertIn("File not found", res.stderr)
        self.assertIn("[RESOURCE MISSING]", res.stderr)

    def test_missing_file_json_mode(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "kcm_parser.py")
        )
        res = subprocess.run(
            [sys.executable, script_path, "-f", "non_existent_file.ldb", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 3)
        data = json.loads(res.stdout)
        self.assertEqual(data.get("status"), "ERROR")
        self.assertEqual(data.get("reason_code"), "MISSING_RESOURCE")
        self.assertEqual(data.get("category"), "RESOURCE_MISSING")
        self.assertEqual(data.get("exit_code"), 3)


if __name__ == "__main__":
    unittest.main()
