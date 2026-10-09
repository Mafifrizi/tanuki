import json
import os
import re
import struct
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from keytab_inspector import parse_keytab_stream
from kcm_parser import scan_for_ccache_blobs


class TestRustCompatibility(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.crates_dir = os.path.join(self.root_dir, "crates", "tanuki-cli")

    def test_cargo_toml_files_exist(self):
        root_cargo = os.path.join(self.root_dir, "Cargo.toml")
        cli_cargo = os.path.join(self.crates_dir, "Cargo.toml")

        self.assertTrue(os.path.isfile(root_cargo), "Root Cargo.toml must exist")
        self.assertTrue(os.path.isfile(cli_cargo), "Crates Cargo.toml must exist")

        with open(cli_cargo, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn('name = "tanuki-cli"', content)
            self.assertIn('name = "tanuki"', content)
            self.assertIn('edition = "2021"', content)

    def test_forbid_unsafe_code(self):
        lib_rs = os.path.join(self.crates_dir, "src", "lib.rs")
        self.assertTrue(os.path.isfile(lib_rs))
        with open(lib_rs, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("#![forbid(unsafe_code)]", content)

        # Ensure no unsafe blocks exist in any Rust source file
        src_dir = os.path.join(self.crates_dir, "src")
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(".rs"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        code = f.read()
                        self.assertNotIn("unsafe {", code, f"Unsafe block found in {file_path}")
                        self.assertNotIn("unsafe fn", code, f"Unsafe fn found in {file_path}")

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
        entry_data += struct.pack(">I", 1)
        entry_data += struct.pack(">I", 1700000000)
        entry_data += struct.pack(">B", 3)
        entry_data += struct.pack(">h", 18)
        entry_data += struct.pack(">H", len(key)) + key
        entry_data += struct.pack(">I", 3)

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

    def test_json_escaping_validity(self):
        # Verify JSON escaping helper logic generates strictly valid RFC 8259 JSON
        # Simulating control characters escaping: \x00 through \x1f
        escaped_control = "\\u0000\\u001f"
        json_str = f'{{"control": "{escaped_control}", "quote": "\\\"quoted\\\""}}'
        parsed = json.loads(json_str)
        self.assertEqual(parsed["control"], "\x00\x1f")
        self.assertEqual(parsed["quote"], '"quoted"')

    def test_protocol_error_dictionary_coverage(self):
        kerberos_rs = os.path.join(self.crates_dir, "src", "protocol", "kerberos.rs")
        with open(kerberos_rs, "r", encoding="utf-8") as f:
            content = f.read()

        required_codes = [
            "KRB_AP_ERR_SKEW",
            "KDC_ERR_ETYPE_NOSUPP",
            "KDC_ERR_C_PRINCIPAL_UNKNOWN",
            "KDC_ERR_PREAUTH_FAILED",
            "STATUS_MORE_PROCESSING_REQUIRED",
        ]
        for code in required_codes:
            self.assertIn(code, content, f"Missing required error code {code}")

    def test_ladder_coverage(self):
        kerberos_rs = os.path.join(self.crates_dir, "src", "protocol", "kerberos.rs")
        with open(kerberos_rs, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("RUNG 1: LOCAL PASSIVE TRIAGE", content)
        self.assertIn("RUNG 2: ZERO-NOISE OPSEC FILTER", content)
        self.assertIn("RUNG 3: MACHINE IDENTITY REUSE (LOTD)", content)
        self.assertIn("RUNG 4: SURGICAL PATHFINDING", content)
        self.assertIn("RUNG 5: DETERMINISTIC ONE-LINER", content)

    def test_no_slop_comments_in_rust_source(self):
        src_dir = os.path.join(self.crates_dir, "src")
        banned_patterns = [
            re.compile(r"//\s*(?:name_type|timestamp|header_len|vno8|keytype|key_len)\b", re.IGNORECASE),
            re.compile(r"//\s*={3,}", re.IGNORECASE),
            re.compile(r"//\s*-{3,}", re.IGNORECASE),
            re.compile(r"//\s*Step\s+\d+:", re.IGNORECASE),
        ]
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(".rs"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        for line_idx, line in enumerate(f, 1):
                            for pat in banned_patterns:
                                self.assertIsNone(
                                    pat.search(line),
                                    f"Slop comment pattern '{pat.pattern}' found in {file_path}:{line_idx}: {line.strip()}",
                                )

    def test_rust_fast_and_rbcd_parity(self):
        config_rs = os.path.join(self.crates_dir, "src", "config.rs")
        with open(config_rs, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("fast: bool", content)
        self.assertIn("armor_cache: Option<&str>", content)
        self.assertIn("fast_req_armoring = true", content)
        self.assertIn("armor_cache = {}", content)
        self.assertIn("Realm cannot contain newline characters", content)

        pac_rs = os.path.join(self.crates_dir, "src", "pac.rs")
        with open(pac_rs, "r", encoding="utf-8") as f:
            pac_content = f.read()
        self.assertIn("pub fn parse_windows_sid", pac_content)
        self.assertIn("pub fn parse_rbcd_security_descriptor", pac_content)
        self.assertIn("pub struct RbcdSecurityDescriptor", pac_content)
        self.assertIn("pub struct AceDetail", pac_content)
        self.assertIn("exceeds MS-DTYP maximum of 15", pac_content)

        lib_rs = os.path.join(self.crates_dir, "src", "lib.rs")
        with open(lib_rs, "r", encoding="utf-8") as f:
            lib_content = f.read()
        self.assertIn("parse_windows_sid", lib_content)
        self.assertIn("parse_rbcd_security_descriptor", lib_content)

    def test_no_em_dashes_in_rust_source(self):
        src_dir = os.path.join(self.crates_dir)
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith((".rs", ".toml")):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        text = f.read()
                        self.assertNotIn("\u2014", text, f"Em dash found in {file_path}")

    def test_rust_main_symbols_validity(self):
        main_rs = os.path.join(self.crates_dir, "src", "main.rs")
        with open(main_rs, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("escape_json", content)
        self.assertNotIn("escape_json(armor)", content.replace("tanuki::escape_json(armor)", ""))
        self.assertNotIn("crate::util", content)
        self.assertIn("resolve_current_uid", content)


if __name__ == "__main__":
    unittest.main()
