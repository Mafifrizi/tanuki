import io
import os
import struct
import tempfile
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from keytab_inspector import parse_keytab_stream, MAX_COMPONENTS
from kcm_parser import scan_for_ccache_blobs, save_recovered_ticket
from tanuki.adcs import (
    parse_x509_der,
    parse_oid_bytes,
    encode_oid_to_der_bytes,
    AdcsScannerError,
    OID_CLIENT_AUTH,
)
from tanuki.telemetry import (
    format_telemetry_terminal,
    format_telemetry_inline,
)
from tanuki.shadow import (
    parse_key_credential_link,
    ShadowCredentialDecodeError,
)
from tanuki.auth import acquire_tgt
from tanuki.doctor import parse_ccache_stream
from tanuki.purge import shred_file
from tanuki.pac import parse_pac_bytes, PacDecodeError
from tests.test_doctor import make_ccache_bytes


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
        paths_to_audit = [
            os.path.join(self.scripts_dir, "keytab_inspector.py"),
            os.path.join(self.scripts_dir, "kcm_parser.py"),
            os.path.join(self.root_dir, "tanuki", "keytab.py"),
            os.path.join(self.root_dir, "tanuki", "kcm.py"),
            os.path.join(self.root_dir, "tanuki", "protocol.py"),
        ]
        for script_path in paths_to_audit:
            with open(script_path, "r", encoding="utf-8") as f:
                code = f.read()
                for dangerous in dangerous_calls:
                    self.assertNotIn(
                        dangerous,
                        code,
                        f"Found dangerous call '{dangerous}' in {script_path}. Protocol parsers must be pure stdlib without shell spawning."
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

    def test_x509_der_binary_oid_detection(self):
        """Verify parse_x509_der detects Client Auth OID in binary ASN.1 DER format."""
        der_oid = encode_oid_to_der_bytes(OID_CLIENT_AUTH)
        self.assertTrue(len(der_oid) > 2)
        tbs_body = b"\x30\x14" + b"\x00" * 8 + der_oid
        tbs_seq = bytes([0x30, len(tbs_body)]) + tbs_body
        cert_seq = bytes([0x30, len(tbs_seq)]) + tbs_seq

        res = parse_x509_der(cert_seq)
        self.assertTrue(res["has_client_auth"])
        self.assertIn(OID_CLIENT_AUTH, res["ekus"])

    def test_truncated_oid_raises_error(self):
        """Verify parse_oid_bytes raises AdcsScannerError when VLQ bytes are truncated."""
        truncated_oid = bytes([0x2B, 0x86])
        with self.assertRaises(AdcsScannerError):
            parse_oid_bytes(truncated_oid)

    def test_telemetry_missing_keys(self):
        """Verify telemetry formatters safely handle missing priority, logsource, or title."""
        partial_telemetry = {
            "sigma": [{"description": "Missing title and logsource"}],
            "falco": [{"description": "Missing rule and priority"}],
        }
        term_out = format_telemetry_terminal(partial_telemetry)
        self.assertIn("Unknown Title", term_out)
        self.assertIn("Unknown Rule", term_out)

        inline_out = format_telemetry_inline(partial_telemetry)
        self.assertIn("Unknown", inline_out)

    def test_shadow_malformed_dn_binary(self):
        """Verify parse_key_credential_link raises ShadowCredentialDecodeError on invalid DN-Binary."""
        malformed_strings = [
            "B:not_an_int:aabb:CN=Target",
            "B:4:zzzz:CN=Target",
        ]
        for bad_str in malformed_strings:
            with self.assertRaises(ShadowCredentialDecodeError):
                parse_key_credential_link(bad_str)

    def test_auth_rejects_symlink_ccache(self):
        """Verify acquire_tgt rejects symlink ccache destinations."""
        with tempfile.TemporaryDirectory() as td:
            real_file = os.path.join(td, "real.ccache")
            with open(real_file, "wb") as f:
                f.write(b"data")
            link_file = os.path.join(td, "link.ccache")
            try:
                os.symlink(real_file, link_file)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks not supported on this platform/privilege level")

            dummy_keytab = os.path.join(td, "test.keytab")
            with open(dummy_keytab, "wb") as f:
                f.write(b"\x05\x02\x00\x00\x00\x00")

            res = acquire_tgt(
                keytab_path=dummy_keytab,
                principal="user@REALM",
                ccache_path=link_file,
            )
            self.assertEqual(res.get("status"), "ERROR")
            self.assertEqual(res.get("reason_code"), "SYMLINK_REJECTED")

    def test_doctor_ccache_unbounded_addr_count(self):
        """Verify parse_ccache_stream safely bounds large addr_count and ad_count to prevent DoS."""
        # 1. Valid first ticket followed by malformed second ticket with giant addr_count
        valid_bytes = make_ccache_bytes(
            default_principal="user@CORP.LOCAL",
            tickets=[{
                "client": "user@CORP.LOCAL",
                "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                "endtime": 2000000000,
            }],
        )
        buf = io.BytesIO(valid_bytes)
        buf.seek(0, io.SEEK_END)
        client_b = struct.pack(">III", 1, 1, 4) + b"CORP" + struct.pack(">I", 4) + b"user"
        server_b = struct.pack(">III", 1, 1, 4) + b"CORP" + struct.pack(">I", 4) + b"krbt"
        key_b = struct.pack(">HI", 18, 32) + b"\x00" * 32
        times_b = struct.pack(">IIII", 1000, 1000, 2000, 2000)
        flags_b = b"\x00" + struct.pack(">I", 0x40000000)
        giant_addr_b = struct.pack(">I", 50000)
        buf.write(client_b + server_b + key_b + times_b + flags_b + giant_addr_b)
        buf.seek(0)

        # Must return the valid first ticket without hanging on the second ticket
        ticket = parse_ccache_stream(buf)
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket["default_principal"], "user@CORP.LOCAL")

        # 2. Standalone stream with giant addr_count on first ticket terminates safely
        standalone_corrupt = io.BytesIO(valid_bytes[:20] + giant_addr_b)
        res_corrupt = parse_ccache_stream(standalone_corrupt)
        self.assertIsNone(res_corrupt)

    def test_purge_empty_file_zero_passes(self):
        """Verify shred_file on a 0-byte file reports passes: 0 instead of claiming passes performed."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf_path = tf.name
        try:
            self.assertEqual(os.path.getsize(tf_path), 0)
            res = shred_file(tf_path, passes=2)
            self.assertEqual(res["status"], "SHREDDED")
            self.assertEqual(res["bytes_shredded"], 0)
            self.assertEqual(res["passes"], 0)
        finally:
            if os.path.exists(tf_path):
                os.unlink(tf_path)

    def test_pac_buffer_header_overlap(self):
        """Verify parse_pac_bytes rejects buffer offsets overlapping the PAC header."""
        c_buffers = 1
        version = 0
        buf_type = 1
        cb_size = 10
        offset = 10
        raw_pac = struct.pack("<IIIIQ", c_buffers, version, buf_type, cb_size, offset) + b"\x00" * 30
        with self.assertRaises(PacDecodeError) as ctx:
            parse_pac_bytes(raw_pac)
        self.assertIn("overlaps header", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
