"""Comprehensive Unit Tests for Tanuki Unprivileged Config Generator and Host Tooling Probes."""

import json
import os
import subprocess
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


if __name__ == "__main__":
    unittest.main()
