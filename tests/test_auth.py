"""Comprehensive Unit Tests for Tanuki Unprivileged Auth Engine and Ctypes Bridge."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import tanuki
from tanuki.auth import acquire_tgt, acquire_tgt_via_ctypes, find_krb5_library
from tests.e2e.fixtures import build_synthetic_keytab


class TestAuthEngine(unittest.TestCase):
    """Unit tests for acquire_tgt, ctypes binding, and kinit fallback behavior."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_acquire_tgt_missing_keytab(self):
        non_existent = os.path.join(self.temp_dir.name, "absent.keytab")
        res = acquire_tgt(non_existent, principal="user@CORP.LOCAL")
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason_code"], "MISSING_KEYTAB")
        self.assertEqual(res["category"], "RESOURCE_MISSING")

    def test_acquire_tgt_corrupt_keytab(self):
        bad_kt = os.path.join(self.temp_dir.name, "corrupt.keytab")
        with open(bad_kt, "wb") as f:
            f.write(b"\x00\x00corrupt")
        res = acquire_tgt(bad_kt)
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason_code"], "CORRUPT_KEYTAB")

    def test_acquire_tgt_missing_principal_empty_keytab(self):
        empty_kt = os.path.join(self.temp_dir.name, "empty.keytab")
        with open(empty_kt, "wb") as f:
            f.write(b"\x05\x02")
        res = acquire_tgt(empty_kt)
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason_code"], "MISSING_PRINCIPAL")

    def test_acquire_tgt_infers_principal_from_keytab(self):
        kt_bytes = build_synthetic_keytab(realm="CORP.LOCAL", principal_comps=["svc_web", "app.corp.local"])
        kt_path = os.path.join(self.temp_dir.name, "valid.keytab")
        with open(kt_path, "wb") as f:
            f.write(kt_bytes)

        with patch("shutil.which", return_value="/usr/bin/kinit"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            res = acquire_tgt(kt_path)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["method"], "kinit")
            self.assertEqual(res["principal"], "svc_web/app.corp.local@CORP.LOCAL")
            self.assertIn("KRB5CCNAME=", res["export_command"])

    def test_acquire_tgt_with_mock_kinit_success(self):
        kt_bytes = build_synthetic_keytab(realm="CORP.LOCAL", principal_comps=["user1"])
        kt_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(kt_path, "wb") as f:
            f.write(kt_bytes)

        cc_path = os.path.join(self.temp_dir.name, "krb5cc_out")
        with patch("shutil.which", return_value="/usr/bin/kinit"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            res = acquire_tgt(kt_path, principal="user1@CORP.LOCAL", ccache_path=cc_path)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["method"], "kinit")
            self.assertEqual(res["ccache"], os.path.abspath(cc_path))

    def test_acquire_tgt_fallback_when_kinit_absent(self):
        kt_bytes = build_synthetic_keytab(realm="CORP.LOCAL", principal_comps=["user1"])
        kt_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(kt_path, "wb") as f:
            f.write(kt_bytes)

        with patch("shutil.which", return_value=None), \
             patch("tanuki.auth.acquire_tgt_via_ctypes") as mock_ctypes:
            mock_ctypes.return_value = {
                "status": "SUCCESS",
                "method": "ctypes",
                "principal": "user1@CORP.LOCAL",
                "keytab": kt_path,
                "ccache": "/tmp/krb5cc_test",
                "export_command": "export KRB5CCNAME=/tmp/krb5cc_test",
            }
            res = acquire_tgt(kt_path, principal="user1@CORP.LOCAL")
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["method"], "ctypes")
            mock_ctypes.assert_called_once()

    def test_acquire_tgt_no_backend_available(self):
        kt_bytes = build_synthetic_keytab(realm="CORP.LOCAL", principal_comps=["user1"])
        kt_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(kt_path, "wb") as f:
            f.write(kt_bytes)

        with patch("shutil.which", return_value=None), \
             patch("tanuki.auth.find_krb5_library", return_value=None):
            res = acquire_tgt(kt_path, principal="user1@CORP.LOCAL")
            self.assertEqual(res["status"], "ERROR")
            self.assertEqual(res["reason_code"], "NO_AUTHENTICATION_BACKEND")
            self.assertIn("recommendation", res)

    def test_acquire_tgt_via_ctypes_library_not_found(self):
        res = acquire_tgt_via_ctypes(
            keytab_path="/etc/krb5.keytab",
            principal="user@CORP.LOCAL",
            ccache_path="/tmp/cc",
            lib_path="/nonexistent/libkrb5.so.999",
        )
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason_code"], "LIBRARY_LOAD_FAILED")

    def test_acquire_tgt_via_ctypes_mock_success(self):
        mock_lib = MagicMock()
        mock_lib.krb5_init_context.return_value = 0
        mock_lib.krb5_parse_name.return_value = 0
        mock_lib.krb5_kt_resolve.return_value = 0
        mock_lib.krb5_cc_resolve.return_value = 0
        mock_lib.krb5_cc_initialize.return_value = 0
        mock_lib.krb5_get_init_creds_keytab.return_value = 0
        mock_lib.krb5_cc_store_cred.return_value = 0

        with patch("ctypes.CDLL", return_value=mock_lib):
            res = acquire_tgt_via_ctypes(
                keytab_path="/path/test.keytab",
                principal="admin@CORP.LOCAL",
                ccache_path="/path/test.ccache",
                lib_path="mock_libkrb5.so.3",
            )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["method"], "ctypes")
            self.assertEqual(res["principal"], "admin@CORP.LOCAL")

    def test_acquire_tgt_with_krb5_conf(self):
        kt_bytes = build_synthetic_keytab(realm="CORP.LOCAL", principal_comps=["user1"])
        kt_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(kt_path, "wb") as f:
            f.write(kt_bytes)

        conf_path = os.path.join(self.temp_dir.name, "custom_krb5.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n    default_realm = CORP.LOCAL\n")

        with patch("shutil.which", return_value="/usr/bin/kinit"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            res = acquire_tgt(kt_path, principal="user1@CORP.LOCAL", krb5_conf=conf_path)
            self.assertEqual(res["status"], "SUCCESS")
            # Verify KRB5_CONFIG was passed in environment
            _, kwargs = mock_run.call_args
            self.assertEqual(kwargs["env"]["KRB5_CONFIG"], os.path.abspath(conf_path))

    def test_acquire_tgt_kinit_failed_and_ctypes_missing(self):
        kt_bytes = build_synthetic_keytab(realm="CORP.LOCAL", principal_comps=["user1"])
        kt_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(kt_path, "wb") as f:
            f.write(kt_bytes)

        with patch("shutil.which", return_value="/usr/bin/kinit"), \
             patch("subprocess.run") as mock_run, \
             patch("tanuki.auth.find_krb5_library", return_value=None):
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="kinit: Clock skew too great while getting initial credentials")
            res = acquire_tgt(kt_path, principal="user1@CORP.LOCAL")
            self.assertEqual(res["status"], "ERROR")
            self.assertEqual(res["reason_code"], "AUTH_FAILED")
            self.assertIn("Clock skew too great", res["message"])


class TestAuthCLI(unittest.TestCase):
    """CLI and subprocess integration tests for tanuki auth."""

    def run_cli(self, args):
        cmd = [sys.executable, "-m", "tanuki", "auth"] + args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_auth_missing_keytab_arg(self):
        proc = self.run_cli([])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Keytab path required", proc.stderr)

    def test_cli_auth_missing_keytab_json(self):
        proc = self.run_cli(["--json"])
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["reason_code"], "MISSING_ARGUMENT")

    def test_cli_auth_nonexistent_keytab(self):
        proc = self.run_cli(["--keytab", "nonexistent_keytab_123.keytab"])
        self.assertNotEqual(proc.returncode, 0)

    def test_cli_auth_nonexistent_keytab_json(self):
        proc = self.run_cli(["--keytab", "nonexistent_keytab_123.keytab", "--json"])
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["reason_code"], "MISSING_KEYTAB")

    def test_cli_auth_with_krb5_conf_forwarded(self):
        proc = self.run_cli(["--keytab", "nonexistent.keytab", "--krb5-conf", "/tmp/fake.conf", "--json"])
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["reason_code"], "MISSING_KEYTAB")


if __name__ == "__main__":
    unittest.main()
