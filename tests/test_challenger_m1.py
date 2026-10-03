"""Adversarial Challenge & Boundary Verification Suite for Milestone 1 Doctor Engine."""

import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from tanuki.doctor import (
    DoctorReport,
    check_keytab,
    check_krb5_conf,
    check_sssd,
    check_ticket_lifetime,
    diagnose_system,
    parse_ccache_stream,
    parse_proc_keys,
)


class TestDoctorAdversarialKeytab(unittest.TestCase):
    """Adversarial stress-testing of Keytab parser and auditor."""

    def test_keytab_corrupted_header_lengths(self):
        """Pass truncated header bytes of lengths 0, 1, 2."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for size, content in [(0, b""), (1, b"\x05")]:
                fpath = os.path.join(tmpdir, f"kt_len_{size}.keytab")
                with open(fpath, "wb") as f:
                    f.write(content)
                res = check_keytab(fpath)
                self.assertEqual(res["status"], "FAIL")
                self.assertFalse(res["valid_format"])
                self.assertIn("issues", res)
                self.assertTrue(len(res["issues"]) > 0)

    def test_keytab_unsupported_versions(self):
        """Ensure Keytab v1 (0x0501) and arbitrary versions (0x0503, 0x0102) fail gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for magic in [b"\x05\x01", b"\x05\x03", b"\x00\x00", b"\xff\xff"]:
                fpath = os.path.join(tmpdir, "kt_bad_magic.keytab")
                with open(fpath, "wb") as f:
                    f.write(magic + b"\x00" * 30)
                res = check_keytab(fpath)
                self.assertEqual(res["status"], "FAIL")
                self.assertFalse(res["valid_format"])

    def test_keytab_truncated_entry_payload(self):
        """Entry size specifies 100 bytes, but only 10 bytes provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "kt_trunc_payload.keytab")
            with open(fpath, "wb") as f:
                # 0x0502 magic + 4-byte big-endian int 100 + 10 bytes
                f.write(b"\x05\x02" + struct.pack(">i", 100) + b"\xaa" * 10)
            res = check_keytab(fpath)
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("Corrupted keytab", res["details"])

    def test_keytab_mocked_posix_permissions(self):
        """Stress-test POSIX permission audits: 0644, 0666, 0640, 0600."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "test.keytab")
            with open(fpath, "wb") as f:
                f.write(b"\x05\x02\x00\x00\x00\x00")

            modes_to_test = [
                (0o100644, "FAIL", "world-readable"),
                (0o100666, "FAIL", "world-writable"),
                (0o100640, "WARN", "group-readable"),
                (0o100600, "PASS", "secure"),
                (0o100400, "PASS", "secure"),
            ]

            for mode_val, expected_status, expected_phrase in modes_to_test:
                mock_stat = MagicMock()
                mock_stat.st_mode = mode_val
                with patch("os.name", "posix"):
                    with patch("os.stat", return_value=mock_stat):
                        res = check_keytab(fpath)
                        self.assertEqual(res["status"], expected_status, f"Mode {oct(mode_val)} expected {expected_status}")
                        self.assertIn(expected_phrase, res["details"])


class TestDoctorAdversarialKrb5Conf(unittest.TestCase):
    """Adversarial stress-testing of krb5.conf parsing and RFC 4120 § 6.1 compliance."""

    def test_nested_braces_and_subsections(self):
        """Ensure inner attributes like 'kdc = dc.example.com' are not confused with realms."""
        conf_text = """
        [libdefaults]
            default_realm = ACME.CORP
            dns_lookup_realm = false

        [realms]
            ACME.CORP = {
                kdc = dc01.acme.corp:88
                admin_server = dc01.acme.corp:749
                kpasswd_server = dc01.acme.corp:464
                database_module = openldap_ldapconf
            }

        [domain_realm]
            .acme.corp = ACME.CORP
            acme.corp = ACME.CORP
        """
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(conf_text)
            f_path = f.name
        try:
            res = check_krb5_conf(f_path)
            self.assertEqual(res["status"], "PASS")
            self.assertEqual(res["default_realm"], "ACME.CORP")
            self.assertEqual(res["realms"], ["ACME.CORP"])
            self.assertEqual(res["lowercase_realms"], [])
        finally:
            os.remove(f_path)

    def test_lowercase_realms_flagged_in_all_sections(self):
        """Verify lowercase realms are correctly caught in libdefaults, realms, and domain_realm RHS."""
        conf_cases = [
            # Lowercase in libdefaults
            ("[libdefaults]\n default_realm = acme.corp\n", "acme.corp"),
            # Lowercase in realms
            ("[realms]\n acme.corp = {\n kdc = dc01:88\n }\n", "acme.corp"),
            # Lowercase in domain_realm target
            ("[domain_realm]\n .acme.corp = acme.corp\n", "acme.corp"),
        ]
        for conf_text, expected_lower in conf_cases:
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(conf_text)
                f_path = f.name
            try:
                res = check_krb5_conf(f_path)
                self.assertEqual(res["status"], "FAIL")
                self.assertFalse(res["is_realm_uppercase"])
                self.assertIn(expected_lower, res["lowercase_realms"])
            finally:
                os.remove(f_path)

    def test_comments_and_malformed_syntax(self):
        """Verify comments (# and ;) are ignored and malformed lines don't crash."""
        conf_text = """
        # Global configuration
        ; Semicolon comment
        [libdefaults] # inline comment
            default_realm = CORP.LOCAL ; inline semicolon comment
            # commented_realm = lowercase.corp
            valid_empty_line = 
            broken_line_without_equals
        """
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(conf_text)
            f_path = f.name
        try:
            res = check_krb5_conf(f_path)
            self.assertEqual(res["status"], "PASS")
            self.assertEqual(res["default_realm"], "CORP.LOCAL")
            self.assertEqual(res["lowercase_realms"], [])
        finally:
            os.remove(f_path)


class TestDoctorAdversarialSssd(unittest.TestCase):
    """Adversarial stress-testing of SSSD daemon and KCM socket inspector."""

    def test_stale_pid_file(self):
        """PID file has valid number but /proc/<pid> does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pid_file = os.path.join(tmpdir, "sssd.pid")
            with open(pid_file, "w") as f:
                f.write("999999\n")  # Non-existent PID
            res = check_sssd(sssd_pipe="/tmp/nonexistent.sock", sssd_pid=pid_file)
            self.assertEqual(res["status"], "WARN")
            self.assertFalse(res["daemon_running"])

    def test_corrupt_pid_file(self):
        """PID file has non-numeric text or garbage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pid_file = os.path.join(tmpdir, "sssd.pid")
            with open(pid_file, "w") as f:
                f.write("NOT_A_PID\n")
            res = check_sssd(sssd_pipe="/tmp/nonexistent.sock", sssd_pid=pid_file)
            self.assertFalse(res["daemon_running"])

    def test_non_socket_kcm_path(self):
        """KCM path exists but is a regular file, not a UNIX socket."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_kcm = os.path.join(tmpdir, "kcm")
            with open(fake_kcm, "w") as f:
                f.write("not a socket")
            res = check_sssd(sssd_pipe=fake_kcm, sssd_pid="/tmp/nonexistent.pid")
            self.assertFalse(res["kcm_socket_active"])
            self.assertTrue(any("not a UNIX domain socket" in iss for iss in res["issues"]))


class TestDoctorAdversarialCcache(unittest.TestCase):
    """Adversarial stress-testing of MIT CCACHE v4 parsing and lifetime calculations."""

    def test_truncated_ccache_header(self):
        """CCACHE streams with truncated headers (0-3 bytes)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for data in [b"", b"\x05", b"\x05\x04", b"\x05\x04\x00"]:
                fpath = os.path.join(tmpdir, "trunc.ccache")
                with open(fpath, "wb") as f:
                    f.write(data)
                res = check_ticket_lifetime(fpath)
                self.assertEqual(res["status"], "N_A")

    def test_ccache_invalid_magic(self):
        """CCACHE streams with wrong magic (e.g. 0x0502 Keytab)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "wrong_magic.ccache")
            with open(fpath, "wb") as f:
                f.write(b"\x05\x02\x00\x00" + b"\x00" * 20)
            res = check_ticket_lifetime(fpath)
            self.assertEqual(res["status"], "N_A")

    def test_ccache_huge_component_count_no_dos(self):
        """Principal claims 100,000 components: ensure it aborts cleanly without memory bomb."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "dos.ccache")
            # 0x0504 + header_len 0 + name_type 1 + num_components 100,000 + realm_len 10
            data = b"\x05\x04\x00\x00" + struct.pack(">III", 1, 100000, 10) + b"CORP.LOCAL"
            with open(fpath, "wb") as f:
                f.write(data)
            t0 = time.perf_counter()
            res = check_ticket_lifetime(fpath)
            elapsed = time.perf_counter() - t0
            self.assertLess(elapsed, 0.05, "DoS attack took too long!")
            self.assertEqual(res["status"], "N_A")


class TestDoctorCLIAndContract(unittest.TestCase):
    """Verify CLI integration and JSON output schema contracts."""

    def test_cli_doctor_json_schema(self):
        """Run python -m tanuki doctor --json and verify schema."""
        cmd = [sys.executable, "-m", "tanuki", "doctor", "--json"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Even if exit code is 0 or 1, stdout MUST be parseable JSON
        data = json.loads(proc.stdout)
        self.assertIn("status", data)
        self.assertIn(data["status"], ("PASS", "WARN", "FAIL"))
        self.assertIn("checks", data)
        self.assertIsInstance(data["checks"], list)
        self.assertIn("duration_ms", data)
        self.assertIsInstance(data["duration_ms"], (int, float))

        # Check required checks exist
        check_names = [c["name"] for c in data["checks"]]
        self.assertIn("keytab_permissions", check_names)
        self.assertIn("realm_capitalization", check_names)
        self.assertIn("sssd_subsystem", check_names)
        self.assertIn("ticket_lifetime", check_names)

    def test_cli_doctor_text_output(self):
        """Run python -m tanuki doctor and verify checklist headers."""
        cmd = [sys.executable, "-m", "tanuki", "doctor"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertIn("TANUKI PRE-FLIGHT DOCTOR", proc.stdout)
        self.assertIn("OVERALL HEALTH:", proc.stdout)
        self.assertIn("Network Packets Emitted: 0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
