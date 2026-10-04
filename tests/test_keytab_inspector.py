import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from keytab_inspector import parse_keytab_stream, ENCTYPE_MAP


def make_entry_bytes(realm: bytes, components: list, key_data: bytes, keytype: int = 18, vno8: int = 1, vno32: int = 1):
    entry_buf = io.BytesIO()
    entry_buf.write(struct.pack(">h", len(components)))
    entry_buf.write(struct.pack(">h", len(realm)) + realm)
    for comp in components:
        entry_buf.write(struct.pack(">h", len(comp)) + comp)
    entry_buf.write(struct.pack(">I", 1))  # name_type
    entry_buf.write(struct.pack(">I", 1700000000))  # timestamp
    entry_buf.write(struct.pack(">B", vno8))
    entry_buf.write(struct.pack(">h", keytype))
    entry_buf.write(struct.pack(">H", len(key_data)) + key_data)
    entry_buf.write(struct.pack(">I", vno32))
    return entry_buf.getvalue()


class TestKeytabInspector(unittest.TestCase):
    def test_parse_valid_synthetic_keytab(self):
        stream = io.BytesIO()
        stream.write(b"\x05\x02")

        realm = b"CORP.LOCAL"
        components = [b"HOST", b"server01.corp.local"]
        key_data = b"\xaa" * 32
        entry_bytes = make_entry_bytes(realm, components, key_data, keytype=18, vno8=3, vno32=3)

        stream.write(struct.pack(">i", len(entry_bytes)))
        stream.write(entry_bytes)

        stream.seek(0)
        entries = parse_keytab_stream(stream)

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["principal"], "HOST/server01.corp.local@CORP.LOCAL")
        self.assertEqual(entry["realm"], "CORP.LOCAL")
        self.assertEqual(entry["keytype"], 18)
        self.assertEqual(entry["enctype_name"], "aes256-cts-hmac-sha1-96")
        self.assertEqual(entry["vno"], 3)
        self.assertEqual(entry["key_len"], 32)
        self.assertEqual(entry["key_hex"], ("aa" * 32))

    def test_invalid_header_raises_error(self):
        stream = io.BytesIO(b"\x01\x02badheader")
        with self.assertRaises(ValueError):
            parse_keytab_stream(stream)

    def test_skip_deleted_negative_size_entry(self):
        stream = io.BytesIO()
        stream.write(b"\x05\x02")
        # Deleted hole of 8 bytes with non-zero residual data
        stream.write(struct.pack(">i", -8))
        stream.write(b"\x12\x34\x56\x78\x9a\xbc\xde\xf0")

        # Valid entry following the deleted hole
        valid_entry = make_entry_bytes(b"CORP.LOCAL", [b"krbtgt", b"CORP.LOCAL"], b"\xbb" * 32)
        stream.write(struct.pack(">i", len(valid_entry)))
        stream.write(valid_entry)

        stream.seek(0)
        entries = parse_keytab_stream(stream)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["principal"], "krbtgt/CORP.LOCAL@CORP.LOCAL")

    def test_32bit_kvno_override(self):
        stream = io.BytesIO()
        stream.write(b"\x05\x02")
        valid_entry = make_entry_bytes(b"CORP.LOCAL", [b"HTTP", b"app.corp.local"], b"\x11" * 16, keytype=17, vno8=5, vno32=500)
        stream.write(struct.pack(">i", len(valid_entry)))
        stream.write(valid_entry)

        stream.seek(0)
        entries = parse_keytab_stream(stream)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["vno"], 500)
        self.assertEqual(entries[0]["enctype_name"], "aes128-cts-hmac-sha1-96")

    def test_empty_components_principal(self):
        stream = io.BytesIO()
        stream.write(b"\x05\x02")
        valid_entry = make_entry_bytes(b"CORP.LOCAL", [], b"\xcc" * 32)
        stream.write(struct.pack(">i", len(valid_entry)))
        stream.write(valid_entry)

        stream.seek(0)
        entries = parse_keytab_stream(stream)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["principal"], "@CORP.LOCAL")
        self.assertEqual(entries[0]["components"], [])

    def test_excessive_components_raises_value_error(self):
        stream = io.BytesIO()
        stream.write(b"\x05\x02")
        entry_buf = io.BytesIO()
        entry_buf.write(struct.pack(">h", 999))  # 999 > 256 MAX_COMPONENTS
        entry_buf.write(struct.pack(">h", 4) + b"CORP")
        entry_bytes = entry_buf.getvalue()
        stream.write(struct.pack(">i", len(entry_bytes)))
        stream.write(entry_bytes)

        stream.seek(0)
        with self.assertRaises(ValueError):
            parse_keytab_stream(stream)

    def test_malformed_truncated_entry_raises_value_error(self):
        stream = io.BytesIO()
        stream.write(b"\x05\x02")
        # Says entry is 40 bytes, but only provides 10 bytes
        stream.write(struct.pack(">i", 40))
        stream.write(b"\x00" * 10)

        stream.seek(0)
        with self.assertRaises(ValueError):
            parse_keytab_stream(stream)

    def test_cli_missing_file_semantic_exit(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "keytab_inspector.py")
        )
        res = subprocess.run(
            [sys.executable, script_path, "nonexistent.keytab"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 3)
        self.assertIn("[RESOURCE MISSING]", res.stderr)

    def test_cli_missing_file_json(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "keytab_inspector.py")
        )
        res = subprocess.run(
            [sys.executable, script_path, "nonexistent.keytab", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 3)
        data = json.loads(res.stdout)
        self.assertEqual(data.get("status"), "ERROR")
        self.assertEqual(data.get("reason_code"), "MISSING_KEYTAB")
        self.assertEqual(data.get("exit_code"), 3)

    def test_cli_empty_file_json(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "keytab_inspector.py")
        )
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            empty_path = tf.name

        try:
            res = subprocess.run(
                [sys.executable, script_path, empty_path, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 4)
            data = json.loads(res.stdout)
            self.assertEqual(data.get("status"), "ERROR")
            self.assertEqual(data.get("reason_code"), "EMPTY_KEYTAB")
            self.assertEqual(data.get("exit_code"), 4)
        finally:
            if os.path.exists(empty_path):
                os.unlink(empty_path)

    def test_cli_corrupt_file_json(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "keytab_inspector.py")
        )
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(b"not_a_valid_keytab_bytes")
            corrupt_path = tf.name

        try:
            res = subprocess.run(
                [sys.executable, script_path, corrupt_path, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 4)
            data = json.loads(res.stdout)
            self.assertEqual(data.get("status"), "ERROR")
            self.assertEqual(data.get("reason_code"), "CORRUPT_KEYTAB")
            self.assertEqual(data.get("exit_code"), 4)
        finally:
            if os.path.exists(corrupt_path):
                os.unlink(corrupt_path)

    def test_cli_valid_synthetic_keytab_json(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "keytab_inspector.py")
        )
        stream = io.BytesIO()
        stream.write(b"\x05\x02")
        realm = b"CORP.LOCAL"
        components = [b"HOST", b"server01.corp.local"]
        key_data = b"\xaa" * 32
        entry_bytes = make_entry_bytes(realm, components, key_data, keytype=18, vno8=3, vno32=3)
        stream.write(struct.pack(">i", len(entry_bytes)))
        stream.write(entry_bytes)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(stream.getvalue())
            valid_path = tf.name

        try:
            res = subprocess.run(
                [sys.executable, script_path, valid_path, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["principal"], "HOST/server01.corp.local@CORP.LOCAL")
            self.assertEqual(data[0]["vno"], 3)
        finally:
            if os.path.exists(valid_path):
                os.unlink(valid_path)


if __name__ == "__main__":
    unittest.main()
