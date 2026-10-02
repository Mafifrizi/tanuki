import io
import struct
import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from keytab_inspector import parse_keytab_stream, ENCTYPE_MAP


class TestKeytabInspector(unittest.TestCase):
    def test_parse_valid_synthetic_keytab(self):
        stream = io.BytesIO()
        stream.write(b"\x05\x02")

        realm = b"CORP.LOCAL"
        comp1 = b"HOST"
        comp2 = b"server01.corp.local"
        key_data = b"\xaa" * 32

        entry_buf = io.BytesIO()
        entry_buf.write(struct.pack(">h", 2))
        entry_buf.write(struct.pack(">h", len(realm)) + realm)
        entry_buf.write(struct.pack(">h", len(comp1)) + comp1)
        entry_buf.write(struct.pack(">h", len(comp2)) + comp2)
        entry_buf.write(struct.pack(">I", 1))
        entry_buf.write(struct.pack(">I", 1700000000))
        entry_buf.write(struct.pack(">B", 3))
        entry_buf.write(struct.pack(">h", 18))
        entry_buf.write(struct.pack(">H", len(key_data)) + key_data)
        entry_buf.write(struct.pack(">I", 3))

        entry_bytes = entry_buf.getvalue()
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


if __name__ == "__main__":
    unittest.main()
