"""Unit Tests for Tanuki Kerberos Service Ticket (TGS) Acquisition Engine."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import tanuki
from tanuki.auth import acquire_tgs, acquire_tgs_via_ctypes
from tests.e2e.fixtures import build_synthetic_keytab


class TestTgsEngine(unittest.TestCase):
    """Unit tests for acquire_tgs, kvno invocation, and error handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_acquire_tgs_missing_spn(self):
        res = acquire_tgs(spn="")
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason_code"], "MISSING_SPN")
        self.assertEqual(res["category"], "USAGE_ERROR")

    def test_acquire_tgs_missing_ccache(self):
        non_existent_cc = os.path.join(self.temp_dir.name, "missing.ccache")
        res = acquire_tgs(
            spn="HTTP/srv01.lab.local@LAB.LOCAL",
            ccache_path=non_existent_cc,
        )
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason_code"], "MISSING_CCACHE")
        self.assertEqual(res["category"], "RESOURCE_MISSING")

    def test_acquire_tgs_with_mock_kvno_success(self):
        cc_path = os.path.join(self.temp_dir.name, "krb5cc_valid")
        with open(cc_path, "wb") as f:
            f.write(b"\x05\x04synthetic_ccache_bytes")

        with patch("shutil.which", return_value="/usr/bin/kvno"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="HTTP/srv01.lab.local@LAB.LOCAL: kvno = 9\n",
                stderr="",
            )
            res = acquire_tgs(
                spn="HTTP/srv01.lab.local@LAB.LOCAL",
                ccache_path=cc_path,
                principal="user@LAB.LOCAL",
            )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["method"], "kvno")
            self.assertEqual(res["kvno"], 9)
            self.assertEqual(res["spn"], "HTTP/srv01.lab.local@LAB.LOCAL")
            self.assertEqual(res["proof_of_access"], "VERIFIED_MUTUAL_AUTH")
            self.assertEqual(res["telemetry"]["event_id"], 4769)
            self.assertIn("export KRB5CCNAME=", res["export_command"])

    def test_acquire_tgs_with_keytab_pre_tgt(self):
        kt_bytes = build_synthetic_keytab(realm="LAB.LOCAL", principal_comps=["tanuki-nhi"])
        kt_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(kt_path, "wb") as f:
            f.write(kt_bytes)

        cc_path = os.path.join(self.temp_dir.name, "krb5cc_target")

        with patch("tanuki.auth.acquire_tgt") as mock_tgt, \
             patch("shutil.which", return_value="/usr/bin/kvno"), \
             patch("subprocess.run") as mock_run:
            mock_tgt.return_value = {
                "status": "SUCCESS",
                "method": "kinit",
                "principal": "tanuki-nhi@LAB.LOCAL",
                "keytab": kt_path,
                "ccache": cc_path,
                "export_command": f"export KRB5CCNAME={cc_path}",
            }
            # Create cc_path so acquire_tgs sees it
            with open(cc_path, "wb") as f:
                f.write(b"\x05\x04")

            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="cifs/dc01.lab.local@LAB.LOCAL: kvno = 5\n",
                stderr="",
            )
            res = acquire_tgs(
                spn="cifs/dc01.lab.local@LAB.LOCAL",
                keytab_path=kt_path,
                ccache_path=cc_path,
            )
            self.assertEqual(res["status"], "SUCCESS")
            mock_tgt.assert_called_once()
            self.assertEqual(res["kvno"], 5)

    def test_acquire_tgs_kdc_port_88_unreachable(self):
        cc_path = os.path.join(self.temp_dir.name, "krb5cc_test")
        with open(cc_path, "wb") as f:
            f.write(b"\x05\x04")

        with patch("tanuki.ldap.probe_tcp_port", return_value=(False, "Connection timed out")):
            res = acquire_tgs(
                spn="HTTP/srv01.lab.local@LAB.LOCAL",
                ccache_path=cc_path,
                kdc="192.168.56.254",
            )
            self.assertEqual(res["status"], "ERROR")
            self.assertEqual(res["reason_code"], "KDC_UNREACHABLE")
            self.assertIn("192.168.56.254", res["message"])


class TestTgsCLI(unittest.TestCase):
    """CLI tests for tanuki tgs and tanuki auth --spn."""

    def test_cli_tgs_missing_spn(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tanuki", "tgs"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Target SPN required", proc.stderr + proc.stdout)

    def test_cli_tgs_missing_spn_json(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tanuki", "tgs", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["reason_code"], "MISSING_ARGUMENT")

    def test_cli_auth_with_spn_delegates_to_tgs(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "tanuki",
                "auth",
                "--spn",
                "HTTP/test.lab.local@LAB.LOCAL",
                "--ccache",
                "/nonexistent/ccache/path",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["reason_code"], "MISSING_CCACHE")


if __name__ == "__main__":
    unittest.main()
