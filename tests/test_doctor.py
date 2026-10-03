"""Comprehensive Unit Tests for Tanuki Pre-Flight Doctor Engine."""

import io
import json
import os
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

import tanuki
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


def make_keytab_bytes(
    entries: list,
    magic: bytes = b"\x05\x02",
) -> bytes:
    """Build synthetic keytab stream with specified entries."""
    buf = io.BytesIO()
    buf.write(magic)

    for entry in entries:
        realm = entry.get("realm", "CORP.LOCAL").encode("utf-8")
        comps = [c.encode("utf-8") for c in entry.get("comps", ["host", "server01.corp.local"])]
        keytype = entry.get("keytype", 18)
        kvno = entry.get("kvno", 1)
        key_data = entry.get("key", b"\x33" * 32)
        timestamp = entry.get("timestamp", 1700000000)

        ebuf = io.BytesIO()
        ebuf.write(struct.pack(">h", len(comps)))
        ebuf.write(struct.pack(">h", len(realm)) + realm)
        for c in comps:
            ebuf.write(struct.pack(">h", len(c)) + c)

        ebuf.write(struct.pack(">I", 1))  # name_type
        ebuf.write(struct.pack(">I", timestamp))
        ebuf.write(struct.pack(">B", kvno if kvno < 256 else 0))
        ebuf.write(struct.pack(">h", keytype))
        ebuf.write(struct.pack(">H", len(key_data)) + key_data)
        ebuf.write(struct.pack(">I", kvno))

        raw = ebuf.getvalue()
        buf.write(struct.pack(">i", len(raw)))
        buf.write(raw)

    return buf.getvalue()


def make_ccache_bytes(
    default_principal: str = "user1@CORP.LOCAL",
    tickets: list = None,
    header_tags: bytes = b"",
) -> bytes:
    """Build synthetic MIT CCACHE v4 stream."""
    buf = io.BytesIO()
    buf.write(b"\x05\x04")
    buf.write(struct.pack(">H", len(header_tags)))
    buf.write(header_tags)

    def write_princ(p_str: str) -> None:
        parts = p_str.split("@")
        comps = parts[0].split("/") if parts[0] else []
        realm = parts[1] if len(parts) > 1 else ""
        buf.write(struct.pack(">I", 1))  # name_type
        buf.write(struct.pack(">I", len(comps)))
        r_bytes = realm.encode("utf-8")
        buf.write(struct.pack(">I", len(r_bytes)) + r_bytes)
        for c in comps:
            c_bytes = c.encode("utf-8")
            buf.write(struct.pack(">I", len(c_bytes)) + c_bytes)

    write_princ(default_principal)

    if tickets:
        for t in tickets:
            write_princ(t.get("client", default_principal))
            write_princ(t.get("server", "krbtgt/CORP.LOCAL@CORP.LOCAL"))

            enctype = t.get("enctype", 18)
            key = t.get("key", b"\x44" * 32)
            buf.write(struct.pack(">HI", enctype, len(key)) + key)

            authtime = t.get("authtime", 1700000000)
            starttime = t.get("starttime", 1700000000)
            endtime = t.get("endtime", 1700036000)
            renew_till = t.get("renew_till", 1700086400)
            buf.write(struct.pack(">IIII", authtime, starttime, endtime, renew_till))

            buf.write(struct.pack(">B", 0))  # is_skey
            buf.write(struct.pack(">I", 0x40e00000))  # ticket_flags
            buf.write(struct.pack(">I", 0))  # addresses count
            buf.write(struct.pack(">I", 0))  # authdata count

            ticket_data = b"\x30\x82\x01\x00" + b"\x00" * 16
            buf.write(struct.pack(">I", len(ticket_data)) + ticket_data)
            buf.write(struct.pack(">I", 0))  # second_ticket

    return buf.getvalue()


class TestDoctorKeytabCheck(unittest.TestCase):
    """Unit tests for keytab format and permissions checks."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_keytab_returns_n_a(self):
        missing = os.path.join(self.temp_dir.name, "missing.keytab")
        res = check_keytab(missing)
        self.assertEqual(res["status"], "N_A")
        self.assertFalse(res["exists"])
        self.assertIn("not found", res["details"])
        self.assertIsNotNone(res["recommendation"])

    def test_empty_keytab_fails(self):
        empty_kt = os.path.join(self.temp_dir.name, "empty.keytab")
        with open(empty_kt, "wb") as f:
            pass
        res = check_keytab(empty_kt)
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(res["exists"])
        self.assertIn("empty", res["details"])

    def test_truncated_header_fails(self):
        trunc_kt = os.path.join(self.temp_dir.name, "trunc.keytab")
        with open(trunc_kt, "wb") as f:
            f.write(b"\x05")
        res = check_keytab(trunc_kt)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("< 2 bytes", res["details"])

    def test_deprecated_v1_fails(self):
        v1_kt = os.path.join(self.temp_dir.name, "v1.keytab")
        with open(v1_kt, "wb") as f:
            f.write(b"\x05\x01\x00\x00")
        res = check_keytab(v1_kt)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("Deprecated Keytab v1", res["details"])

    def test_invalid_magic_fails(self):
        bad_kt = os.path.join(self.temp_dir.name, "bad.keytab")
        with open(bad_kt, "wb") as f:
            f.write(b"\x00\x00\x00\x00")
        res = check_keytab(bad_kt)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("Invalid keytab magic", res["details"])

    def test_valid_keytab_aes256(self):
        valid_kt = os.path.join(self.temp_dir.name, "valid.keytab")
        data = make_keytab_bytes([
            {"realm": "CORP.LOCAL", "comps": ["host", "srv.corp.local"], "keytype": 18, "kvno": 2}
        ])
        with open(valid_kt, "wb") as f:
            f.write(data)

        res = check_keytab(valid_kt)
        self.assertTrue(res["valid_format"])
        self.assertEqual(res["format_version"], 2)
        self.assertEqual(res["entry_count"], 1)
        self.assertIn("aes256-cts-hmac-sha1-96", res["encryption_types"])
        self.assertFalse(res["has_weak_enctypes"])

    def test_weak_enctypes_flagged_with_warning(self):
        weak_kt = os.path.join(self.temp_dir.name, "weak.keytab")
        data = make_keytab_bytes([
            {"realm": "CORP.LOCAL", "comps": ["user"], "keytype": 23, "kvno": 1},
            {"realm": "CORP.LOCAL", "comps": ["user"], "keytype": 1, "kvno": 1},
        ])
        with open(weak_kt, "wb") as f:
            f.write(data)
        if os.name != "nt":
            os.chmod(weak_kt, 0o600)

        res = check_keytab(weak_kt)
        self.assertTrue(res["has_weak_enctypes"])
        self.assertEqual(res["status"], "WARN")
        self.assertTrue(any("weak" in iss.lower() for iss in res["issues"]))

    def test_corrupted_keytab_entry_fails(self):
        corrupt_kt = os.path.join(self.temp_dir.name, "corrupt.keytab")
        with open(corrupt_kt, "wb") as f:
            f.write(b"\x05\x02\x00\x00\x00\x20truncated_entry_data")
        res = check_keytab(corrupt_kt)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("Corrupted keytab", res["details"])

    def test_posix_permissions_security(self):
        kt_path = os.path.join(self.temp_dir.name, "perm.keytab")
        with open(kt_path, "wb") as f:
            f.write(make_keytab_bytes([{"realm": "CORP.LOCAL", "comps": ["host"], "keytype": 18}]))

        if os.name != "nt":
            # Test 0600 (secure)
            os.chmod(kt_path, 0o600)
            res = check_keytab(kt_path)
            self.assertEqual(res["status"], "PASS")
            self.assertTrue(res["is_secure_permissions"])
            self.assertEqual(res["permissions"], "0600")

            # Test 0644 (world-readable)
            os.chmod(kt_path, 0o644)
            res = check_keytab(kt_path)
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["is_secure_permissions"])
            self.assertIn("world-readable", res["details"])
            self.assertIn("chmod 0600", res["recommendation"])

            # Test 0666 (world-writable)
            os.chmod(kt_path, 0o666)
            res = check_keytab(kt_path)
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["is_secure_permissions"])
            self.assertIn("insecure", res["details"])

            # Test 0640 (group-readable)
            os.chmod(kt_path, 0o640)
            res = check_keytab(kt_path)
            self.assertEqual(res["status"], "WARN")
            self.assertIn("group-readable", res["details"])
        else:
            res = check_keytab(kt_path)
            self.assertIn("Windows", res["permissions"])


class TestDoctorKrb5ConfCheck(unittest.TestCase):
    """Unit tests for krb5.conf parsing and realm capitalization."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_krb5_conf_returns_n_a(self):
        missing = os.path.join(self.temp_dir.name, "missing.conf")
        res = check_krb5_conf(missing)
        self.assertEqual(res["status"], "N_A")
        self.assertFalse(res["exists"])
        self.assertIn("not found", res["details"])

    def test_uppercase_realm_passes(self):
        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        content = """
        [libdefaults]
            default_realm = CORP.LOCAL
            dns_lookup_realm = false

        [realms]
            CORP.LOCAL = {
                kdc = kdc.corp.local
                admin_server = kdc.corp.local
            }

        [domain_realm]
            .corp.local = CORP.LOCAL
            corp.local = CORP.LOCAL
        """
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)

        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "PASS")
        self.assertTrue(res["is_realm_uppercase"])
        self.assertEqual(res["default_realm"], "CORP.LOCAL")
        self.assertEqual(res["lowercase_realms"], [])

    def test_lowercase_default_realm_fails(self):
        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        content = """
        [libdefaults]
            default_realm = corp.local
        """
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)

        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["is_realm_uppercase"])
        self.assertIn("corp.local", res["lowercase_realms"])
        self.assertIn("Lowercase realm detected", res["details"])
        self.assertIsNotNone(res["recommendation"])

    def test_lowercase_in_domain_realm_rhs_fails(self):
        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        content = """
        [libdefaults]
            default_realm = CORP.LOCAL

        [domain_realm]
            .corp.local = corp.local
        """
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)

        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("corp.local", res["lowercase_realms"])

    def test_domain_realm_lhs_lowercase_not_flagged(self):
        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        content = """
        [domain_realm]
            .subdomain.corp.local = CORP.LOCAL
        """
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)

        res = check_krb5_conf(conf_path)
        self.assertNotIn(".subdomain.corp.local", res["lowercase_realms"])
        self.assertEqual(len(res["lowercase_realms"]), 0)

    def test_inline_comments_and_semicolons_ignored(self):
        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        content = """
        # Global configuration
        [libdefaults]
            default_realm = CORP.LOCAL ; inline comment with lowercase chars
            ticket_lifetime = 24h # another comment
        """
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)

        res = check_krb5_conf(conf_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["default_realm"], "CORP.LOCAL")
        self.assertEqual(res["lowercase_realms"], [])


class TestDoctorSssdCheck(unittest.TestCase):
    """Unit tests for SSSD daemon and KCM socket audit."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_inactive_daemon_and_missing_socket(self):
        fake_sock = os.path.join(self.temp_dir.name, "kcm.sock")
        fake_pid = os.path.join(self.temp_dir.name, "sssd.pid")
        res = check_sssd(fake_sock, fake_pid)
        self.assertEqual(res["status"], "WARN")
        self.assertFalse(res["daemon_running"])
        self.assertFalse(res["kcm_socket_active"])
        self.assertIn("inactive", res["details"].lower())

    def test_running_daemon_detected(self):
        fake_sock = os.path.join(self.temp_dir.name, "kcm.sock")
        fake_pid = os.path.join(self.temp_dir.name, "sssd.pid")
        my_pid = os.getpid()
        with open(fake_pid, "w") as f:
            f.write(str(my_pid))

        orig_exists = os.path.exists
        def mock_exists(p):
            if f"/proc/{my_pid}" in str(p):
                return True
            return orig_exists(p)

        with patch("os.path.exists", side_effect=mock_exists):
            res = check_sssd(fake_sock, fake_pid)
            self.assertTrue(res["daemon_running"])
            self.assertEqual(res["pid"], my_pid)
            self.assertFalse(res["kcm_socket_active"])
            self.assertEqual(res["status"], "WARN")

    def test_stale_pid_file_handled(self):
        fake_sock = os.path.join(self.temp_dir.name, "kcm.sock")
        fake_pid = os.path.join(self.temp_dir.name, "sssd.pid")
        with open(fake_pid, "w") as f:
            f.write("999999999")  # Unlikely PID

        res = check_sssd(fake_sock, fake_pid)
        self.assertFalse(res["daemon_running"])
        self.assertTrue(any("stale" in iss.lower() for iss in res["issues"]))


class TestDoctorTicketLifetimeCheck(unittest.TestCase):
    """Unit tests for MIT CCACHE parsing and ticket lifetime calculations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_active_ticket_lifetime_calculation(self):
        now = int(time.time())
        endtime = now + 7200  # 2 hours
        data = make_ccache_bytes(
            default_principal="admin@CORP.LOCAL",
            tickets=[{
                "client": "admin@CORP.LOCAL",
                "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                "authtime": now - 3600,
                "starttime": now - 3600,
                "endtime": endtime,
                "renew_till": now + 86400,
            }]
        )
        cc_path = os.path.join(self.temp_dir.name, "krb5cc_active")
        with open(cc_path, "wb") as f:
            f.write(data)

        res = check_ticket_lifetime(cc_path)
        self.assertEqual(res["status"], "PASS")
        self.assertFalse(res["is_expired"])
        self.assertGreater(res["remaining_seconds"], 7000)
        self.assertIn("h", res["remaining_human"])
        self.assertEqual(res["default_principal"], "admin@CORP.LOCAL")
        self.assertEqual(res["service_principal"], "krbtgt/CORP.LOCAL@CORP.LOCAL")

    def test_expired_ticket_detection(self):
        now = int(time.time())
        endtime = now - 600  # expired 10m ago
        data = make_ccache_bytes(
            default_principal="user@CORP.LOCAL",
            tickets=[{
                "client": "user@CORP.LOCAL",
                "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                "authtime": now - 3600,
                "starttime": now - 3600,
                "endtime": endtime,
            }]
        )
        cc_path = os.path.join(self.temp_dir.name, "krb5cc_expired")
        with open(cc_path, "wb") as f:
            f.write(data)

        res = check_ticket_lifetime(cc_path)
        self.assertEqual(res["status"], "EXPIRED")
        self.assertTrue(res["is_expired"])
        self.assertLessEqual(res["remaining_seconds"], 0)
        self.assertEqual(res["remaining_human"], "Expired")
        self.assertIsNotNone(res["recommendation"])

    def test_expiring_soon_triggers_warning(self):
        now = int(time.time())
        endtime = now + 900  # 15 minutes (< 1800s threshold)
        data = make_ccache_bytes(
            default_principal="svc@CORP.LOCAL",
            tickets=[{
                "client": "svc@CORP.LOCAL",
                "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                "endtime": endtime,
            }]
        )
        cc_path = os.path.join(self.temp_dir.name, "krb5cc_soon")
        with open(cc_path, "wb") as f:
            f.write(data)

        res = check_ticket_lifetime(cc_path)
        self.assertEqual(res["status"], "WARN")
        self.assertFalse(res["is_expired"])
        self.assertIn("Expiring soon", res["details"])
        self.assertIn("kinit -R", res["recommendation"])

    def test_multiple_tickets_selects_tgt(self):
        now = int(time.time())
        data = make_ccache_bytes(
            default_principal="admin@CORP.LOCAL",
            tickets=[
                {
                    "client": "admin@CORP.LOCAL",
                    "server": "cifs/file01.corp.local@CORP.LOCAL",
                    "endtime": now + 3600,
                },
                {
                    "client": "admin@CORP.LOCAL",
                    "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                    "endtime": now + 28800,
                },
            ]
        )
        cc_path = os.path.join(self.temp_dir.name, "krb5cc_multi")
        with open(cc_path, "wb") as f:
            f.write(data)

        res = check_ticket_lifetime(cc_path)
        self.assertEqual(res["service_principal"], "krbtgt/CORP.LOCAL@CORP.LOCAL")
        self.assertGreater(res["remaining_seconds"], 20000)

    def test_corrupted_truncated_ccache_handled_gracefully(self):
        bad_streams = [
            b"",
            b"\x05\x04",
            b"\x05\x04\x00\x10truncated",
            b"\x05\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04CORP",
        ]
        for stream_bytes in bad_streams:
            parsed = parse_ccache_stream(io.BytesIO(stream_bytes))
            # Must return None or empty ticket dict, never crash
            self.assertTrue(parsed is None or isinstance(parsed, dict))


class TestDoctorOrchestratorAndPerformance(unittest.TestCase):
    """Unit tests for diagnose_system orchestrator, sub-5ms latency, and report output."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_diagnose_system_clean_pass(self):
        kt_path = os.path.join(self.temp_dir.name, "krb5.keytab")
        with open(kt_path, "wb") as f:
            f.write(make_keytab_bytes([{"realm": "CORP.LOCAL", "comps": ["host"], "keytype": 18}]))
        if os.name != "nt":
            os.chmod(kt_path, 0o600)

        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n    default_realm = CORP.LOCAL\n")

        cc_path = os.path.join(self.temp_dir.name, "krb5cc")
        now = int(time.time())
        with open(cc_path, "wb") as f:
            f.write(make_ccache_bytes(
                default_principal="admin@CORP.LOCAL",
                tickets=[{"endtime": now + 36000}]
            ))

        report = diagnose_system(
            keytab_path=kt_path,
            krb5_conf_path=conf_path,
            ccache_path=cc_path,
        )

        self.assertIsInstance(report, DoctorReport)
        self.assertEqual(len(report.checks), 5)
        self.assertIn("status", report.to_dict())
        self.assertIn("summary", report.to_dict())
        self.assertIn("timestamp", report.to_dict())
        self.assertIn("duration_ms", report.to_dict())

    def test_deterministic_latency_sub_5ms(self):
        """Verify doctor engine executes deterministically in < 5ms."""
        kt_path = os.path.join(self.temp_dir.name, "krb5.keytab")
        with open(kt_path, "wb") as f:
            f.write(make_keytab_bytes([{"realm": "CORP.LOCAL", "comps": ["host"], "keytype": 18}]))
        if os.name != "nt":
            os.chmod(kt_path, 0o600)

        conf_path = os.path.join(self.temp_dir.name, "krb5.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n    default_realm = CORP.LOCAL\n")

        # Warm up
        _ = diagnose_system(keytab_path=kt_path, krb5_conf_path=conf_path)

        # Measure 5 runs
        durations = []
        for _ in range(5):
            rep = diagnose_system(keytab_path=kt_path, krb5_conf_path=conf_path)
            durations.append(rep.duration_ms)

        avg_ms = sum(durations) / len(durations)
        self.assertLess(avg_ms, 5.0, f"Average doctor execution time {avg_ms:.2f}ms exceeded 5.0ms threshold")

    def test_json_serialization_validity(self):
        report = diagnose_system()
        json_str = report.to_json()
        parsed = json.loads(json_str)

        self.assertIn(parsed["status"], ["PASS", "WARN", "FAIL"])
        self.assertIn("summary", parsed)
        self.assertIn("passed", parsed["summary"])
        self.assertIn("warnings", parsed["summary"])
        self.assertIn("failures", parsed["summary"])
        self.assertIsInstance(parsed["checks"], list)
        self.assertEqual(len(parsed["checks"]), 5)

        names = [c["name"] for c in parsed["checks"]]
        self.assertEqual(
            names,
            ["keytab_permissions", "realm_capitalization", "sssd_subsystem", "ticket_lifetime", "host_tooling"]
        )

    def test_format_checklist_contains_headers_and_summary(self):
        report = diagnose_system()
        text = report.format_checklist()
        self.assertIn("TANUKI PRE-FLIGHT DOCTOR", text)
        self.assertIn("OVERALL HEALTH:", text)
        self.assertIn("Execution Time:", text)
        self.assertIn("Network Packets Emitted: 0", text)


if __name__ == "__main__":
    unittest.main()
