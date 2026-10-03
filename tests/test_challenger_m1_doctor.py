"""Empirical boundary and stress test suite for Milestone 1 Doctor Engine."""

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
)


def make_synthetic_keytab(entries: list, magic: bytes = b"\x05\x02") -> bytes:
    """Build synthetic keytab binary stream."""
    buf = io.BytesIO()
    buf.write(magic)
    for entry in entries:
        realm = entry.get("realm", "CORP.LOCAL").encode("utf-8")
        comps = [c.encode("utf-8") for c in entry.get("comps", ["host", "server01.corp.local"])]
        keytype = entry.get("keytype", 18)
        kvno = entry.get("kvno", 1)
        key_data = entry.get("key", b"\x11" * 32)
        timestamp = entry.get("timestamp", 1700000000)

        ebuf = io.BytesIO()
        ebuf.write(struct.pack(">h", len(comps)))
        ebuf.write(struct.pack(">h", len(realm)) + realm)
        for c in comps:
            ebuf.write(struct.pack(">h", len(c)) + c)

        ebuf.write(struct.pack(">I", 1))
        ebuf.write(struct.pack(">I", timestamp))
        ebuf.write(struct.pack(">B", kvno if kvno < 256 else 0))
        ebuf.write(struct.pack(">h", keytype))
        ebuf.write(struct.pack(">H", len(key_data)) + key_data)
        ebuf.write(struct.pack(">I", kvno))

        raw = ebuf.getvalue()
        buf.write(struct.pack(">i", len(raw)))
        buf.write(raw)

    return buf.getvalue()


class TestKrb5ConfBoundaries(unittest.TestCase):
    """Empirical boundary tests for /etc/krb5.conf parsing."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_conf(self, content: str) -> str:
        conf_path = os.path.join(self.temp_dir.name, "test_krb5.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)
        return conf_path

    def test_comments_and_inline_semicolons(self):
        """Verify comments (# and ;) are stripped without corrupting values or depth."""
        content = """
        # Whole line hash comment
        ; Whole line semicolon comment
        # default_realm = deceptive.lowercase.realm
        ; [realms]
        ; lowercase.realm = { kdc = 127.0.0.1 }

        [libdefaults]
            default_realm = CORP.LOCAL # inline hash with lowercase chars
            ticket_lifetime = 24h ; inline semicolon comment
            dns_lookup_realm = false # comment with closing brace }
            dns_lookup_kdc = true ; comment with opening brace {

        [realms]
            CORP.LOCAL = {
                # inner hash comment { with unclosed brace
                ; inner semicolon comment } with extra close brace
                kdc = kdc.corp.local ; inline kdc comment
                admin_server = kdc.corp.local # inline admin comment
            } # comment on closing brace
        """
        conf_path = self._write_conf(content)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["default_realm"], "CORP.LOCAL")
        self.assertEqual(res["realms"], ["CORP.LOCAL"])
        self.assertEqual(res["lowercase_realms"], [])

    def test_empty_sections_handling(self):
        """Verify empty sections and empty files produce graceful WARN status."""
        # 1. 0-byte file
        conf_empty = self._write_conf("")
        res_empty = check_krb5_conf(conf_empty)
        self.assertEqual(res_empty["status"], "WARN")
        self.assertIn("No realm definitions discovered", res_empty["details"])

        # 2. Whitespace and comments only
        conf_ws = self._write_conf("   \n\t\n# Just comments\n; More comments\n")
        res_ws = check_krb5_conf(conf_ws)
        self.assertEqual(res_ws["status"], "WARN")

        # 3. Explicit empty sections
        conf_sections = self._write_conf("""
        [libdefaults]

        [realms]

        [domain_realm]

        [capaths]

        [appdefaults]
        """)
        res_sections = check_krb5_conf(conf_sections)
        self.assertEqual(res_sections["status"], "WARN")
        self.assertIn("No realm definitions discovered", res_sections["details"])

    def test_lowercase_realm_in_libdefaults(self):
        """Verify lowercase default_realm in [libdefaults] is flagged as FAIL."""
        conf_path = self._write_conf("""
        [libdefaults]
            default_realm = corp.local
        """)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["is_realm_uppercase"])
        self.assertIn("corp.local", res["lowercase_realms"])
        self.assertIn("Lowercase realm detected", res["details"])
        self.assertIsNotNone(res["recommendation"])

    def test_lowercase_realm_in_realms(self):
        """Verify lowercase realm definition in [realms] is flagged as FAIL."""
        conf_path = self._write_conf("""
        [libdefaults]
            default_realm = CORP.LOCAL

        [realms]
            bad.realm.local = {
                kdc = kdc.bad.realm.local
            }
        """)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["is_realm_uppercase"])
        self.assertIn("bad.realm.local", res["lowercase_realms"])

    def test_lowercase_realm_in_both_libdefaults_and_realms(self):
        """Verify lowercase detection when present in both [libdefaults] and [realms]."""
        conf_path = self._write_conf("""
        [libdefaults]
            default_realm = corp.local

        [realms]
            corp.local = {
                kdc = 127.0.0.1
            }
        """)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("corp.local", res["lowercase_realms"])
        self.assertGreaterEqual(len(res["issues"]), 2)

    def test_domain_realm_lhs_vs_rhs_capitalization(self):
        """Verify [domain_realm] LHS domain is lowercase-safe while RHS realm is validated."""
        # Valid: lowercase domain LHS, uppercase realm RHS
        valid_conf = self._write_conf("""
        [domain_realm]
            .corp.local = CORP.LOCAL
            corp.local = CORP.LOCAL
        """)
        res_valid = check_krb5_conf(valid_conf)
        self.assertEqual(res_valid["status"], "PASS")
        self.assertEqual(res_valid["lowercase_realms"], [])

        # Invalid: lowercase realm RHS
        invalid_conf = self._write_conf("""
        [domain_realm]
            .corp.local = corp.local
        """)
        res_invalid = check_krb5_conf(invalid_conf)
        self.assertEqual(res_invalid["status"], "FAIL")
        self.assertIn("corp.local", res_invalid["lowercase_realms"])

    def test_nested_braces_in_realms(self):
        """Verify complex multi-level nested braces do not corrupt realm name extraction."""
        conf_path = self._write_conf("""
        [realms]
            CORP.LOCAL = {
                kdc = kdc.corp.local
                admin_server = kdc.corp.local
                auth_to_local = {
                    RULE:[1:$1@$0](.*@CORP.LOCAL)s/@CORP.LOCAL//
                    RULE:[2:$1@$0](.*@CORP.LOCAL)s/@CORP.LOCAL//
                    DEFAULT
                }
                pkinit_anchors = {
                    FILE:/etc/ssl/certs/ca.pem
                }
                nested_subblock = {
                    level2 = {
                        level3 = {
                            key = value
                        }
                    }
                }
            }
            SECONDARY.CORP = {
                kdc = sec-kdc.corp.local
            }
        """)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["realms"], ["CORP.LOCAL", "SECONDARY.CORP"])
        self.assertEqual(res["lowercase_realms"], [])

    def test_nested_braces_followed_by_lowercase_realm(self):
        """Verify lowercase realm following nested brace structure is still caught."""
        conf_path = self._write_conf("""
        [realms]
            CORP.LOCAL = {
                kdc = kdc.corp.local
                auth_to_local = {
                    sub = value
                }
            }
            bad.realm = {
                kdc = 127.0.0.1
            }
        """)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("bad.realm", res["lowercase_realms"])
        self.assertIn("CORP.LOCAL", res["realms"])

    def test_single_line_realm_definitions(self):
        """Verify single-line realm definitions with inline braces."""
        conf_path = self._write_conf("""
        [realms]
            FIRST.LOCAL = { kdc = 127.0.0.1 }
            SECOND.LOCAL = { kdc = 127.0.0.2 }
        """)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["realms"], ["FIRST.LOCAL", "SECOND.LOCAL"])

    def test_krb5_conf_windows_crlf_endings(self):
        """Verify Windows CRLF line endings parse identically without trailing carriage returns."""
        content = "[libdefaults]\r\n    default_realm = CORP.LOCAL\r\n[realms]\r\n    CORP.LOCAL = {\r\n        kdc = 127.0.0.1\r\n    }\r\n"
        conf_path = self._write_conf(content)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["default_realm"], "CORP.LOCAL")
        self.assertEqual(res["realms"], ["CORP.LOCAL"])

    def test_krb5_conf_extra_closing_braces(self):
        """Verify extra unmatched closing braces saturate to 0 without throwing."""
        content = """
        [realms]
            CORP.LOCAL = {
                kdc = 127.0.0.1
            }
            }
            }
            SECOND.LOCAL = {
                kdc = 127.0.0.2
            }
        """
        conf_path = self._write_conf(content)
        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["realms"], ["CORP.LOCAL", "SECOND.LOCAL"])



class TestKeytabPermissionsBoundaries(unittest.TestCase):
    """Empirical boundary tests for keytab permissions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.valid_keytab_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(self.valid_keytab_path, "wb") as f:
            f.write(make_synthetic_keytab([
                {"realm": "CORP.LOCAL", "comps": ["host"], "keytype": 18, "kvno": 1}
            ]))

    def tearDown(self):
        self.temp_dir.cleanup()

    def _test_mode_with_posix_mock(self, mode_int: int):
        """Helper to evaluate POSIX mode logic deterministically regardless of host OS."""
        mock_stat = MagicMock()
        mock_stat.st_mode = stat.S_IFREG | mode_int

        with patch("os.name", "posix"):
            with patch("os.stat", return_value=mock_stat):
                return check_keytab(self.valid_keytab_path)

    def test_permission_0600_secure(self):
        """Verify 0600 mode produces PASS and is_secure_permissions=True."""
        res = self._test_mode_with_posix_mock(0o600)
        self.assertEqual(res["status"], "PASS")
        self.assertTrue(res["is_secure_permissions"])
        self.assertEqual(res["permissions"], "0600")
        self.assertIn("secure", res["details"])
        self.assertIsNone(res["recommendation"])

    def test_permission_0400_secure_readonly(self):
        """Verify 0400 (read-only by owner) produces PASS and is_secure_permissions=True."""
        res = self._test_mode_with_posix_mock(0o400)
        self.assertEqual(res["status"], "PASS")
        self.assertTrue(res["is_secure_permissions"])
        self.assertEqual(res["permissions"], "0400")
        self.assertIn("secure", res["details"])

    def test_permission_0644_world_readable_fails(self):
        """Verify 0644 (world-readable) produces FAIL and recommendation chmod 0600."""
        res = self._test_mode_with_posix_mock(0o644)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["is_secure_permissions"])
        self.assertEqual(res["permissions"], "0644")
        self.assertIn("world-readable", res["details"])
        self.assertIn("chmod 0600", res["recommendation"])

    def test_permission_0666_world_writable_fails(self):
        """Verify 0666 (world-writable) produces FAIL and recommendation chmod 0600."""
        res = self._test_mode_with_posix_mock(0o666)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["is_secure_permissions"])
        self.assertEqual(res["permissions"], "0666")
        self.assertIn("world-writable", res["details"])
        self.assertIn("chmod 0600", res["recommendation"])

    def test_permission_0777_world_accessible_fails(self):
        """Verify 0777 produces FAIL and is_secure_permissions=False."""
        res = self._test_mode_with_posix_mock(0o777)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["is_secure_permissions"])
        self.assertEqual(res["permissions"], "0777")
        self.assertIn("world-writable", res["details"])
        self.assertIn("chmod 0600", res["recommendation"])

    def test_permission_0640_group_readable_warns(self):
        """Verify 0640 (group-readable) produces WARN status."""
        res = self._test_mode_with_posix_mock(0o640)
        self.assertEqual(res["status"], "WARN")
        self.assertFalse(res["is_secure_permissions"])
        self.assertEqual(res["permissions"], "0640")
        self.assertIn("group-readable", res["details"])

    def test_nonexistent_keytab_path(self):
        """Verify non-existent keytab path returns N_A status."""
        nonexistent = os.path.join(self.temp_dir.name, "does_not_exist.keytab")
        res = check_keytab(nonexistent)
        self.assertEqual(res["status"], "N_A")
        self.assertFalse(res["exists"])
        self.assertFalse(res["readable"])
        self.assertIn("not found", res["details"])
        self.assertIsNotNone(res["recommendation"])

    def test_failure_recommendations_always_provided(self):
        """Verify failing checks always include actionable remediation recommendations."""
        res_kt = self._test_mode_with_posix_mock(0o644)
        self.assertEqual(res_kt["status"], "FAIL")
        self.assertIsNotNone(res_kt["recommendation"])
        self.assertIn("chmod 0600", res_kt["recommendation"])



class TestDoctorJsonStrictValidation(unittest.TestCase):
    """Empirical strict validation of --json output schema."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _validate_schema(self, data: dict):
        """Strictly validate schema compliance against Doctor Engine contract."""
        self.assertIsInstance(data, dict)
        self.assertIn("status", data)
        self.assertIn(data["status"], ["PASS", "WARN", "FAIL"])
        self.assertIn("timestamp", data)
        self.assertIsInstance(data["timestamp"], str)
        self.assertIn("duration_ms", data)
        self.assertIsInstance(data["duration_ms"], (int, float))
        self.assertIn("execution_time_ms", data)
        self.assertIsInstance(data["execution_time_ms"], (int, float))

        self.assertIn("summary", data)
        summary = data["summary"]
        self.assertIsInstance(summary, dict)
        self.assertIn("passed", summary)
        self.assertIn("warnings", summary)
        self.assertIn("failures", summary)
        self.assertIsInstance(summary["passed"], int)
        self.assertIsInstance(summary["warnings"], int)
        self.assertIsInstance(summary["failures"], int)

        self.assertIn("checks", data)
        checks = data["checks"]
        self.assertIsInstance(checks, list)
        self.assertEqual(len(checks), 4)

        expected_names = [
            "keytab_permissions",
            "realm_capitalization",
            "sssd_subsystem",
            "ticket_lifetime",
        ]
        actual_names = [c["name"] for c in checks]
        self.assertEqual(actual_names, expected_names)

        for c in checks:
            self.assertIn("name", c)
            self.assertIn("status", c)
            self.assertIn(c["status"], ["PASS", "WARN", "FAIL", "N_A", "EXPIRED"])
            self.assertIn("details", c)
            self.assertIsInstance(c["details"], str)
            self.assertIn("recommendation", c)
            self.assertTrue(c["recommendation"] is None or isinstance(c["recommendation"], str))

        # Check ticket_lifetime specific fields
        ticket_chk = next(c for c in checks if c["name"] == "ticket_lifetime")
        self.assertIn("remaining_seconds", ticket_chk)
        self.assertIsInstance(ticket_chk["remaining_seconds"], int)

    def test_json_loads_on_direct_engine_reports(self):
        """Verify json.loads parses to_json() across all status outcomes."""
        # 1. Default (unconfigured host)
        rep1 = diagnose_system()
        data1 = json.loads(rep1.to_json())
        self._validate_schema(data1)

        # 2. Failing keytab
        bad_kt = os.path.join(self.temp_dir.name, "bad.keytab")
        with open(bad_kt, "wb") as f:
            f.write(b"garbage_magic")
        rep2 = diagnose_system(keytab_path=bad_kt)
        self.assertEqual(rep2.status, "FAIL")
        data2 = json.loads(rep2.to_json())
        self._validate_schema(data2)

    def test_cli_doctor_json_stdout_strict_parsing(self):
        """Invoke python -m tanuki doctor --json and strictly parse stdout."""
        cmd = [sys.executable, "-m", "tanuki", "doctor", "--json"]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        # Even if exit code is 1 (on host with FAIL status), stdout MUST be strictly valid JSON
        self.assertTrue(len(proc.stdout.strip()) > 0)
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"CLI stdout was not valid JSON: {exc}\nSTDOUT:\n{proc.stdout}")

        self._validate_schema(parsed)

    def test_cli_doctor_json_with_explicit_options(self):
        """Invoke python -m tanuki doctor with specific file arguments and --json."""
        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n    default_realm = CORP.LOCAL\n")

        kt_path = os.path.join(self.temp_dir.name, "krb5.keytab")
        with open(kt_path, "wb") as f:
            f.write(make_synthetic_keytab([
                {"realm": "CORP.LOCAL", "comps": ["host"], "keytype": 18}
            ]))

        cmd = [
            sys.executable,
            "-m",
            "tanuki",
            "doctor",
            "--json",
            "--keytab",
            kt_path,
            "--krb5-conf",
            conf_path,
        ]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        self.assertTrue(len(proc.stdout.strip()) > 0)
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"CLI stdout with options was not valid JSON: {exc}\nSTDOUT:\n{proc.stdout}")

        self._validate_schema(parsed)
        # Verify krb5.conf was checked and passed
        realm_chk = next(c for c in parsed["checks"] if c["name"] == "realm_capitalization")
        self.assertEqual(realm_chk["status"], "PASS")
        self.assertEqual(realm_chk["default_realm"], "CORP.LOCAL")


if __name__ == "__main__":
    unittest.main()

