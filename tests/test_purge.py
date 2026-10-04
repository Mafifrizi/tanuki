"""Unit tests for Cryptographic Zero-Trace Forensic Purge Engine (tanuki purge)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.purge import PurgeReport, run_purge, shred_file, zeroize_buffer


class TestZeroTracePurge(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.tmp_dir.name, "sensitive.ccache")
        with open(self.test_file, "wb") as f:
            f.write(b"\x05\x04SensitiveCredentialDataHere12345")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_shred_file_removes_and_overwrites(self):
        self.assertTrue(os.path.exists(self.test_file))
        result = shred_file(self.test_file, passes=2)
        self.assertEqual(result["status"], "SHREDDED")
        self.assertGreater(result["bytes_shredded"], 0)
        self.assertFalse(os.path.exists(self.test_file))

    def test_shred_nonexistent_file(self):
        result = shred_file("/nonexistent/file/path/here.ccache")
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["bytes_shredded"], 0)

    def test_zeroize_buffer(self):
        secret = bytearray(b"MasterKerberosSessionKey0987654321")
        self.assertTrue(any(b != 0 for b in secret))
        zeroize_buffer(secret)
        self.assertTrue(all(b == 0 for b in secret))

    def test_run_purge_target_and_env(self):
        # Set dummy Kerberos environment variables
        os.environ["KRB5CCNAME"] = f"FILE:{self.test_file}"
        os.environ["KRB5_CONFIG"] = "/tmp/dummy_krb5.conf"

        try:
            report = run_purge(target_paths=[self.test_file])
            self.assertEqual(report.status, "SUCCESS")
            self.assertFalse(os.path.exists(self.test_file))
            # Verify environment was sanitized
            self.assertNotIn("KRB5CCNAME", os.environ)
            self.assertNotIn("KRB5_CONFIG", os.environ)
            self.assertIn("KRB5CCNAME", report.cleared_env)
            self.assertIn("KRB5_CONFIG", report.cleared_env)
        finally:
            os.environ.pop("KRB5CCNAME", None)
            os.environ.pop("KRB5_CONFIG", None)

    def test_format_terminal_and_json(self):
        report = run_purge(target_paths=[self.test_file])
        term_text = report.format_terminal()
        self.assertIn("TANUKI FORENSIC ZERO-TRACE PURGE", term_text)
        self.assertIn("NIST SP 800-88 Compliant", term_text)

        json_str = report.to_json()
        self.assertIn('"status": "SUCCESS"', json_str)
        self.assertIn('"memory_zeroed": true', json_str)


if __name__ == "__main__":
    unittest.main()
