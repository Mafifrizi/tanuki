"""Comprehensive Unit Tests for Tanuki Unprivileged Config Generator and Host Tooling Probes."""

import json
import os
import subprocess
import struct
import sys
import tempfile
import unittest

import tanuki
from tanuki.config import generate_krb5_conf, write_krb5_conf_file
from tanuki.doctor import check_host_tools, check_krb5_conf, diagnose_system


class TestKrb5ConfigGenerator(unittest.TestCase):
    """Unit tests for generate_krb5_conf and write_krb5_conf_file."""

    def test_generate_krb5_conf_uppercase_and_zero_dns(self):
        conf = generate_krb5_conf("corp.local", "192.168.56.106")
        self.assertIn("default_realm = CORP.LOCAL", conf)
        self.assertIn("dns_lookup_realm = false", conf)
        self.assertIn("dns_lookup_kdc = false", conf)
        self.assertIn("kdc = 192.168.56.106", conf)
        self.assertIn("admin_server = 192.168.56.106", conf)
        self.assertIn(".corp.local = CORP.LOCAL", conf)
        self.assertIn("corp.local = CORP.LOCAL", conf)

    def test_generate_krb5_conf_custom_admin_server(self):
        conf = generate_krb5_conf("CORP.LOCAL", "192.168.56.106", admin_server="192.168.56.107")
        self.assertIn("kdc = 192.168.56.106", conf)
        self.assertIn("admin_server = 192.168.56.107", conf)

    def test_generate_krb5_conf_empty_inputs_raise_value_error(self):
        with self.assertRaises(ValueError):
            generate_krb5_conf("", "192.168.56.106")
        with self.assertRaises(ValueError):
            generate_krb5_conf("CORP.LOCAL", "")

    def test_write_krb5_conf_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "subdir", "custom.conf")
            res = write_krb5_conf_file(target, "DOMAIN.COM", "10.0.0.1")
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["realm"], "DOMAIN.COM")
            self.assertTrue(os.path.isfile(target))
            self.assertIn("export KRB5_CONFIG=", res["export_command"])

    def test_generate_krb5_conf_hardening_clockskew_and_multiple_kdcs(self):
        conf = generate_krb5_conf(
            "corp.local",
            ["kdc1.corp.local", "kdc2.corp.local"],
            clockskew=300,
            enforce_aes=True,
        )
        self.assertIn("udp_preference_limit = 0", conf)
        self.assertIn("rdns = false", conf)
        self.assertIn("clockskew = 300", conf)
        self.assertIn("default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96", conf)
        self.assertIn("permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96", conf)
        self.assertIn("kdc = kdc1.corp.local", conf)
        self.assertIn("kdc = kdc2.corp.local", conf)


class TestHostToolingProbe(unittest.TestCase):
    """Unit tests for check_host_tools availability and recommendations."""

    def test_check_host_tools_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_kinit = os.path.join(tmpdir, "kinit.exe" if os.name == "nt" else "kinit")
            with open(mock_kinit, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            if os.name != "nt":
                os.chmod(mock_kinit, 0o755)

            res = check_host_tools(search_path=tmpdir)
            self.assertEqual(res["status"], "PASS")
            self.assertTrue(res["kinit_present"])
            self.assertIsNotNone(res["kinit_path"])
            self.assertIn("kinit", res["details"])

    def test_check_host_tools_absent(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            res = check_host_tools(search_path=empty_dir)
            self.assertEqual(res["status"], "WARN")
            self.assertFalse(res["kinit_present"])
            self.assertIsNone(res["kinit_path"])
            self.assertIn("not found on PATH", res["details"])
            self.assertIsNotNone(res["recommendation"])


class TestKrb5ConfigPrecedence(unittest.TestCase):
    """Unit tests for KRB5_CONFIG environment variable precedence."""

    def test_check_krb5_conf_honors_env_var(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            conf_path = os.path.join(tmpdir, "local_krb5.conf")
            with open(conf_path, "w", encoding="utf-8") as f:
                f.write("[libdefaults]\n    default_realm = ENVREALM.LOCAL\n")

            old_env = os.environ.get("KRB5_CONFIG")
            try:
                os.environ["KRB5_CONFIG"] = conf_path
                res = check_krb5_conf()
                self.assertEqual(res["status"], "PASS")
                self.assertEqual(res["default_realm"], "ENVREALM.LOCAL")
                self.assertEqual(res["source"], "KRB5_CONFIG")
            finally:
                if old_env is not None:
                    os.environ["KRB5_CONFIG"] = old_env
                else:
                    os.environ.pop("KRB5_CONFIG", None)


class TestConfigCLIIntegration(unittest.TestCase):
    """Subprocess and CLI tests for tanuki config subcommand."""

    def test_cli_config_stdout(self):
        cmd = [
            sys.executable,
            "-m",
            "tanuki",
            "config",
            "--realm",
            "corp.local",
            "--kdc",
            "192.168.56.106",
            "--stdout",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("default_realm = CORP.LOCAL", proc.stdout)
        self.assertIn("kdc = 192.168.56.106", proc.stdout)

    def test_cli_config_clock_skew_and_enforce_aes(self):
        cmd = [
            sys.executable,
            "-m",
            "tanuki",
            "config",
            "--realm",
            "corp.local",
            "--kdc",
            "192.168.56.106",
            "--clock-skew",
            "300",
            "--enforce-aes",
            "--stdout",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("clockskew = 300", proc.stdout)
        self.assertIn("permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96", proc.stdout)

    def test_cli_config_multiple_kdcs(self):
        cmd = [
            sys.executable,
            "-m",
            "tanuki",
            "config",
            "--realm",
            "corp.local",
            "--kdc",
            "10.0.0.1",
            "--kdc",
            "10.0.0.2",
            "--stdout",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("kdc = 10.0.0.1", proc.stdout)
        self.assertIn("kdc = 10.0.0.2", proc.stdout)

    def test_cli_config_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_path = os.path.join(tmpdir, "test.conf")
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--realm",
                "CORP.LOCAL",
                "--kdc",
                "192.168.56.106",
                "-o",
                target_path,
                "--json",
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 0)
            data = json.loads(proc.stdout)
            self.assertEqual(data["status"], "SUCCESS")
            self.assertEqual(data["realm"], "CORP.LOCAL")
            self.assertEqual(data["kdc"], "192.168.56.106")
            self.assertTrue(os.path.isfile(target_path))

    def test_cli_config_missing_arguments(self):
        cmd_no_realm = [sys.executable, "-m", "tanuki", "config", "--kdc", "192.168.56.106"]
        proc1 = subprocess.run(cmd_no_realm, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc1.returncode, 1)

        cmd_no_kdc = [sys.executable, "-m", "tanuki", "config", "--realm", "CORP.LOCAL"]
        proc2 = subprocess.run(cmd_no_kdc, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc2.returncode, 1)

    def test_cli_config_keytab_inference_success(self):
        from tests.e2e.fixtures import build_synthetic_keytab
        kt_bytes = build_synthetic_keytab(realm="INFERRED.CORP.LOCAL")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(kt_bytes)
            kt_path = tf.name

        try:
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--keytab",
                kt_path,
                "--kdc",
                "192.168.56.106",
                "--stdout",
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("default_realm = INFERRED.CORP.LOCAL", proc.stdout)
            self.assertIn("kdc = 192.168.56.106", proc.stdout)
        finally:
            if os.path.exists(kt_path):
                os.unlink(kt_path)

    def test_cli_config_keytab_inference_json(self):
        from tests.e2e.fixtures import build_synthetic_keytab
        kt_bytes = build_synthetic_keytab(realm="inferred.corp.local")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(kt_bytes)
            kt_path = tf.name

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "inferred.conf")
            try:
                cmd = [
                    sys.executable,
                    "-m",
                    "tanuki",
                    "config",
                    "--keytab",
                    kt_path,
                    "--kdc",
                    "192.168.56.106",
                    "-o",
                    out_file,
                    "--json",
                ]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(proc.returncode, 0)
                data = json.loads(proc.stdout)
                self.assertEqual(data["status"], "SUCCESS")
                self.assertEqual(data["realm"], "INFERRED.CORP.LOCAL")
                self.assertTrue(os.path.isfile(out_file))
            finally:
                if os.path.exists(kt_path):
                    os.unlink(kt_path)

    def test_cli_config_keytab_missing_file(self):
        cmd = [
            sys.executable,
            "-m",
            "tanuki",
            "config",
            "--keytab",
            "/nonexistent/file/path/does_not_exist.keytab",
            "--kdc",
            "192.168.56.106",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 3)

    def test_cli_config_keytab_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            empty_path = tf.name

        try:
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--keytab",
                empty_path,
                "--kdc",
                "192.168.56.106",
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 4)
        finally:
            if os.path.exists(empty_path):
                os.unlink(empty_path)

    def test_cli_config_keytab_corrupt_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(b"not_a_valid_keytab_file")
            corrupt_path = tf.name

        try:
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--keytab",
                corrupt_path,
                "--kdc",
                "192.168.56.106",
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 4)
        finally:
            if os.path.exists(corrupt_path):
                os.unlink(corrupt_path)

    def test_cli_config_realm_precedence_over_keytab(self):
        from tests.e2e.fixtures import build_synthetic_keytab
        kt_bytes = build_synthetic_keytab(realm="INFERRED.CORP.LOCAL")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(kt_bytes)
            kt_path = tf.name

        try:
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--realm",
                "EXPLICIT.CORP.LOCAL",
                "--keytab",
                kt_path,
                "--kdc",
                "192.168.56.106",
                "--stdout",
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("default_realm = EXPLICIT.CORP.LOCAL", proc.stdout)
            self.assertNotIn("INFERRED.CORP.LOCAL", proc.stdout)
        finally:
            if os.path.exists(kt_path):
                os.unlink(kt_path)

    def test_cli_config_keytab_zero_entries(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(b"\x05\x02")
            kt_path = tf.name

        try:
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--keytab",
                kt_path,
                "--kdc",
                "192.168.56.106",
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 4)
        finally:
            if os.path.exists(kt_path):
                os.unlink(kt_path)

    def test_cli_config_keytab_multi_realm_first_selected(self):
        from tests.e2e.fixtures import build_multi_entry_keytab
        entries = [
            {"realm": "FIRST.CORP.LOCAL", "principal_comps": ["HOST", "srv1.first.corp.local"]},
            {"realm": "SECOND.CORP.LOCAL", "principal_comps": ["HOST", "srv2.second.corp.local"]},
        ]
        kt_bytes = build_multi_entry_keytab(entries)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(kt_bytes)
            kt_path = tf.name

        try:
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--keytab",
                kt_path,
                "--kdc",
                "192.168.56.106",
                "--stdout",
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("default_realm = FIRST.CORP.LOCAL", proc.stdout)
        finally:
            if os.path.exists(kt_path):
                os.unlink(kt_path)

    def test_cli_config_missing_kdc_with_keytab(self):
        from tests.e2e.fixtures import build_synthetic_keytab
        kt_bytes = build_synthetic_keytab(realm="INFERRED.CORP.LOCAL")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(kt_bytes)
            kt_path = tf.name

        try:
            cmd = [
                sys.executable,
                "-m",
                "tanuki",
                "config",
                "--keytab",
                kt_path,
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 1)
        finally:
            if os.path.exists(kt_path):
                os.unlink(kt_path)

    def test_dns_srv_packet_building_and_parsing(self):
        from tanuki.config import build_dns_srv_query, parse_srv_response
        query = build_dns_srv_query("_kerberos._tcp.corp.local", tx_id=0x1234)
        self.assertTrue(len(query) > 12)
        self.assertEqual(query[:2], b"\x12\x34")
        self.assertIn(b"_kerberos", query)
        self.assertIn(b"_tcp", query)
        self.assertIn(b"corp", query)

        # Build synthetic DNS response with SRV record
        # Header (12 bytes): ID 0x1234, Flags 0x8180 (response, no error), QDCOUNT 1, ANCOUNT 1, NSCOUNT 0, ARCOUNT 0
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        # Question echo: _kerberos._tcp.corp.local (same length as in query)
        q_echo = query[12:]
        # Answer RR:
        # Name pointer to offset 12 (0xC00C), Type 33 (SRV), Class 1, TTL 300, RDLength 18
        # SRV RDATA: priority 0, weight 100, port 88, target dc01.corp.local (\x04dc01\xc0\x1a)
        target_name = b"\x04dc01\x04corp\x05local\x00"
        srv_rdata = struct.pack(">HHH", 0, 100, 88) + target_name
        ans_rr = struct.pack(">HHIH", 0xC00C, 33, 1, 300) + struct.pack(">H", len(srv_rdata)) + srv_rdata
        synthetic_resp = header + q_echo + ans_rr

        records = parse_srv_response(synthetic_resp)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0][0], 0)  # Priority
        self.assertEqual(records[0][1], 100)  # Weight
        self.assertEqual(records[0][2], 88)  # Port
        self.assertEqual(records[0][3], "dc01.corp.local")

    def test_discover_dc_via_srv_mocked(self):
        from tanuki.config import discover_dc_via_srv
        from unittest.mock import patch
        with patch("tanuki.config.query_dns_srv", return_value=[(0, 100, 88, "dc01.corp.local")]):
            dc = discover_dc_via_srv("CORP.LOCAL")
            self.assertEqual(dc, ("dc01.corp.local", 88))

    def test_build_dns_srv_query_random_txid(self):
        from tanuki.config import build_dns_srv_query
        q1 = build_dns_srv_query("_kerberos._tcp.corp.local")
        self.assertTrue(len(q1) > 12)
        q2 = build_dns_srv_query("_kerberos._tcp.corp.local")
        self.assertTrue(len(q2) > 12)
        tx1 = int.from_bytes(q1[:2], "big")
        tx2 = int.from_bytes(q2[:2], "big")
        self.assertGreaterEqual(tx1, 0)
        self.assertLessEqual(tx1, 65535)
        self.assertGreaterEqual(tx2, 0)
        self.assertLessEqual(tx2, 65535)


if __name__ == "__main__":
    unittest.main()
