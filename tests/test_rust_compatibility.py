import json
import os
import struct
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from keytab_inspector import parse_keytab_stream
from kcm_parser import scan_for_ccache_blobs


class TestRustCompatibility(unittest.TestCase):
    def test_cargo_toml_files_exist(self):
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        root_cargo = os.path.join(root_dir, "Cargo.toml")
        cli_cargo = os.path.join(root_dir, "crates", "tanuki-cli", "Cargo.toml")

        self.assertTrue(os.path.isfile(root_cargo), "Root Cargo.toml must exist")
        self.assertTrue(os.path.isfile(cli_cargo), "Crates Cargo.toml must exist")

        with open(cli_cargo, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn('name = "tanuki-cli"', content)
            self.assertIn('name = "tanuki"', content)

    def test_forbid_unsafe_code(self):
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        lib_rs = os.path.join(root_dir, "crates", "tanuki-cli", "src", "lib.rs")
        self.assertTrue(os.path.isfile(lib_rs))
        with open(lib_rs, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("#![forbid(unsafe_code)]", content)

    def test_binary_contract_equivalence(self):
        entry_data = bytearray()
        realm = b"CORP.LOCAL"
        comp1 = b"HOST"
        comp2 = b"server01.corp.local"
        key = b"\xaa" * 32

        entry_data += struct.pack(">h", 2)
        entry_data += struct.pack(">h", len(realm)) + realm
        entry_data += struct.pack(">h", len(comp1)) + comp1
        entry_data += struct.pack(">h", len(comp2)) + comp2
        entry_data += struct.pack(">I", 1)  # name_type
        entry_data += struct.pack(">I", 1700000000)  # timestamp
        entry_data += struct.pack(">B", 3)  # vno8
        entry_data += struct.pack(">h", 18)  # keytype (aes256-cts-hmac-sha1-96)
        entry_data += struct.pack(">H", len(key)) + key
        entry_data += struct.pack(">I", 3)  # vno32

        full_stream = bytearray(b"\x05\x02")
        full_stream += struct.pack(">i", len(entry_data))
        full_stream += entry_data

        import io
        py_entries = parse_keytab_stream(io.BytesIO(full_stream))
        self.assertEqual(len(py_entries), 1)
        self.assertEqual(py_entries[0]["principal"], "HOST/server01.corp.local@CORP.LOCAL")
        self.assertEqual(py_entries[0]["enctype_name"], "aes256-cts-hmac-sha1-96")
        self.assertEqual(py_entries[0]["vno"], 3)
        self.assertEqual(py_entries[0]["key_len"], 32)


if __name__ == "__main__":
    unittest.main()
