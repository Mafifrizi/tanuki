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

    def test_shred_symlink_does_not_destroy_target(self):
        # Security test for CWE-59: ensure symlink unlinking never overwrites the target file.
        target_file = os.path.join(self.tmp_dir.name, "victim_file.txt")
        with open(target_file, "w") as f:
            f.write("SENSITIVE_TARGET_DATA")

        link_file = os.path.join(self.tmp_dir.name, "symlink_pointer")
        try:
            os.symlink(target_file, link_file)
        except OSError:
            # Skip if symlink creation is not permitted on this platform
            return

        res = shred_file(link_file)
        self.assertEqual(res["status"], "SHREDDED")
        self.assertFalse(os.path.exists(link_file))
        # Ensure target file was NOT overwritten or truncated
        self.assertTrue(os.path.exists(target_file))
        with open(target_file, "r") as f:
            self.assertEqual(f.read(), "SENSITIVE_TARGET_DATA")

    def test_shred_directory_returns_error(self):
        sub_dir = os.path.join(self.tmp_dir.name, "sub_directory")
        os.makedirs(sub_dir, exist_ok=True)
        res = shred_file(sub_dir)
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("Target is a directory", res.get("error", ""))
        self.assertTrue(os.path.exists(sub_dir))

    def test_run_purge_all_extracts_env_ccache_and_config(self):
        custom_cc = os.path.join(self.tmp_dir.name, "active_custom.ccache")
        with open(custom_cc, "wb") as f:
            f.write(b"CUSTOM_TICKET_CONTENT")

        custom_cfg = os.path.join(self.tmp_dir.name, "active_custom.conf")
        with open(custom_cfg, "w") as f:
            f.write("[libdefaults]\n")

        os.environ["KRB5CCNAME"] = f"FILE:{custom_cc}"
        os.environ["KRB5_CONFIG"] = custom_cfg

        try:
            report = run_purge(purge_all=True)
            self.assertEqual(report.status, "SUCCESS")
            self.assertFalse(os.path.exists(custom_cc))
            self.assertFalse(os.path.exists(custom_cfg))
        finally:
            os.environ.pop("KRB5CCNAME", None)
            os.environ.pop("KRB5_CONFIG", None)


class TestPurgeCLIIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.sample_ccache = os.path.join(self.tmp_dir.name, "cli_test.ccache")
        with open(self.sample_ccache, "wb") as f:
            f.write(b"CLI_CCACHE_CONTENT_HERE")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def run_cli(self, args):
        import subprocess
        cmd = [sys.executable, "-m", "tanuki"] + args
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_purge_missing_target_exits_code_3(self):
        import json
        code, out, err = self.run_cli(["purge", "--target", "nonexistent_target_123.ccache", "--json"])
        self.assertEqual(code, 3)
        data = json.loads(out)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["exit_code"], 3)
        self.assertEqual(data["reason_code"], "MISSING_TARGET_FILE")
        self.assertEqual(data["category"], "RESOURCE_MISSING")

    def test_cli_purge_bare_without_all_exits_code_1(self):
        import json
        code, out, err = self.run_cli(["purge", "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["exit_code"], 1)
        self.assertEqual(data["reason_code"], "MISSING_ARGUMENT")
        self.assertEqual(data["category"], "USAGE_ERROR")

    def test_cli_purge_directory_target_exits_code_1(self):
        import json
        code, out, err = self.run_cli(["purge", "--target", self.tmp_dir.name, "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["exit_code"], 1)
        self.assertEqual(data["reason_code"], "INVALID_TARGET_DIRECTORY")
        self.assertEqual(data["category"], "USAGE_ERROR")

    def test_cli_purge_target_success_exits_code_0(self):
        self.assertTrue(os.path.exists(self.sample_ccache))
        code, out, err = self.run_cli(["purge", "--target", self.sample_ccache])
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.sample_ccache))
        self.assertIn("OVERALL PURGE STATUS: SUCCESS", out)


if __name__ == "__main__":
    unittest.main()
