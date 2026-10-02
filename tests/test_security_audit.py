import io
import os
import struct
import tempfile
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from keytab_inspector import parse_keytab_stream, MAX_COMPONENTS
from kcm_parser import scan_for_ccache_blobs, save_recovered_ticket


class TestSecurityAudit(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.scripts_dir = os.path.join(self.root_dir, "scripts")
        self.crates_dir = os.path.join(self.root_dir, "crates", "tanuki-cli")

    def test_zero_shell_execution_in_python_scripts(self):
        """Audit that Python scripts use zero subprocess/os.system for protocol parsing."""
        dangerous_calls = [
            "os.system",
            "os.popen",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            "eval(",
            "exec(",
        ]
        for script_name in ["keytab_inspector.py", "kcm_parser.py"]:
            script_path = os.path.join(self.scripts_dir, script_name)
            with open(script_path, "r", encoding="utf-8") as f:
                code = f.read()
                for dangerous in dangerous_calls:
                    self.assertNotIn(
                        dangerous,
                        code,
                        f"Found dangerous call '{dangerous}' in {script_name}. Protocol parsers must be pure stdlib without shell spawning."
                    )

    def test_rust_memory_safety_forbid_unsafe(self):
        """Audit that Rust crate enforces #![forbid(unsafe_code)] with zero unsafe blocks."""
        lib_rs = os.path.join(self.crates_dir, "src", "lib.rs")
        with open(lib_rs, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("#![forbid(unsafe_code)]", content)

        for root, _, files in os.walk(os.path.join(self.crates_dir, "src")):
            for f in files:
                if f.endswith(".rs"):
                    f_path = os.path.join(root, f)
                    with open(f_path, "r", encoding="utf-8") as rf:
                        rs_code = rf.read()
                        self.assertNotIn("unsafe ", rs_code, f"Unsafe code detected in {f_path}")

    def test_fuzz_malformed_keytab_inputs(self):
        """Fuzz testing malformed binary streams against Keytab inspector to verify no unhandled crashes."""
        malformed_inputs = [
            b"",
            b"\x00",
            b"\x05",
            b"\x05\x01",  # Invalid version
            b"\x05\x02",  # Header only, no entries
            b"\x05\x02\x00\x00\x00\x10",  # Truncated entry size
            b"\x05\x02" + struct.pack(">i", 1000) + b"\x00" * 10,  # Declared 1000 bytes, only 10 provided
            b"\x05\x02" + struct.pack(">i", -100) + b"\x00" * 10,  # Deleted entry declared 100 bytes, only 10 provided
            b"\x05\x02" + struct.pack(">i", 10) + struct.pack(">h", -1),  # Negative component count
            b"\x05\x02" + struct.pack(">i", 10) + struct.pack(">h", 500),  # Excessive component count (>256)
            b"\x05\x02" + struct.pack(">i", 10) + struct.pack(">h", 1) + struct.pack(">H", 5000),  # Realm length exceeds entry
        ]

        for idx, bad_data in enumerate(malformed_inputs):
            stream = io.BytesIO(bad_data)
            try:
                entries = parse_keytab_stream(stream)
                # If it doesn't raise, entries must be empty list or valid
                self.assertIsInstance(entries, list)
            except ValueError:
                # Expected clean validation failure
                pass
            except Exception as exc:
                self.fail(f"Input #{idx} raised unexpected exception {type(exc)}: {exc}")

    def test_fuzz_malformed_ccache_inputs(self):
        """Fuzz testing malformed binary streams against KCM parser to verify robustness."""
        malformed_streams = [
            b"",
            b"\x05\x04",
            b"\x05\x04\x00",
            b"\x05\x04\xff\xff",  # Giant header_len exceeding buffer
            b"\x05\x04\x00\x00" + b"\xff" * 5,  # Short principal payload
            b"\x05\x04\x00\x00" + struct.pack(">III", 1, 999, 10),  # 999 components (>16 max)
            b"\x05\x04\x00\x00" + struct.pack(">III", 1, 1, 999),  # 999 realm length (>256 max)
        ]

        for idx, bad_stream in enumerate(malformed_streams):
            try:
                blobs = scan_for_ccache_blobs(bad_stream)
                self.assertIsInstance(blobs, list)
            except Exception as exc:
                self.fail(f"CCACHE input #{idx} raised unexpected exception {type(exc)}: {exc}")

    def test_secure_file_permissions_on_recovered_tickets(self):
        """Verify recovered tickets are saved with 0o600 permissions where supported."""
        with tempfile.TemporaryDirectory() as td:
            out_file = os.path.join(td, "test_recovered.ccache")
            save_recovered_ticket(out_file, b"\x05\x04TESTTICKET")
            self.assertTrue(os.path.exists(out_file))

            # On Unix-like / POSIX systems, verify mode & 0o777 == 0o600
            if hasattr(os, "stat") and os.name != "nt":
                mode = os.stat(out_file).st_mode & 0o777
                self.assertEqual(mode, 0o600, f"Expected 0600 file permissions, got {oct(mode)}")


if __name__ == "__main__":
    unittest.main()
