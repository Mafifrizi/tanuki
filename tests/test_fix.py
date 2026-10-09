"""Unit tests for Idempotent Closed-Loop Self-Healing Engine (tanuki fix)."""

import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.fix import FixReport, run_fix


class TestSelfHealingFix(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.kt_path = os.path.join(self.tmp_dir.name, "test.keytab")
        self.conf_path = os.path.join(self.tmp_dir.name, "krb5.conf")

        # Create dummy keytab with relaxed permissions
        with open(self.kt_path, "wb") as f:
            f.write(b"\x05\x02\x00\x00\x00\x00")
        try:
            os.chmod(self.kt_path, 0o666)
        except Exception:
            pass

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_dry_run_does_not_alter_files(self):
        rep = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=True,
        )
        self.assertTrue(rep.dry_run)
        d = rep.to_dict()
        self.assertIn("proposed_count", d)
        # Verify krb5.conf was not created on disk
        self.assertFalse(os.path.exists(self.conf_path))

    def test_live_fix_creates_config_and_preserves_backup(self):
        # First write initial config
        with open(self.conf_path, "w", encoding="utf-8") as f:
            f.write("# Initial config\n")

        rep = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=False,
        )
        self.assertEqual(rep.status, "SUCCESS")
        # Check backup was created
        bak_file = self.conf_path + ".bak"
        self.assertTrue(os.path.exists(bak_file))
        with open(bak_file, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "# Initial config\n")

        # Verify new config content
        with open(self.conf_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("CORP.LOCAL", content)
            self.assertIn("udp_preference_limit = 0", content)

    def test_idempotent_consecutive_runs(self):
        # Run 1: Applies changes
        rep1 = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=False,
        )
        self.assertEqual(rep1.status, "SUCCESS")

        # Run 2: Confirms idempotency
        rep2 = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=False,
        )
        self.assertEqual(rep2.status, "SUCCESS")
        # Config generation should be skipped because it is already optimal
        config_action = [a for a in rep2.actions if a.get("action") == "krb5_config"]
        if config_action:
            self.assertEqual(config_action[0].get("status"), "IDEMPOTENT_SKIPPED")

    def test_format_terminal_output(self):
        rep = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=True,
        )
        term_text = rep.format_terminal()
        self.assertIn("TANUKI CLOSED-LOOP SELF-HEALING", term_text)
        self.assertIn("DRY RUN", term_text)

    def test_json_serialization(self):
        rep = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=True,
        )
        json_str = rep.to_json()
        self.assertIn('"status": "SUCCESS"', json_str)
        self.assertIn('"dry_run": true', json_str)

    def test_clock_drift_and_remediation_math(self):
        from tanuki.protocol import (
            calculate_clock_drift,
            calculate_remediated_clockskew,
            parse_krb_error_stime,
        )
        sample = b"\x30\x11\x18\x0f20261007120000Z"
        t = parse_krb_error_stime(sample)
        self.assertIsNotNone(t)
        # Drift with fixed local_time: t + 350
        drift = calculate_clock_drift(t, local_time=float(t + 350))
        self.assertEqual(drift, 350)
        remediated = calculate_remediated_clockskew(drift, padding=60)
        self.assertEqual(remediated, 410)

    def test_run_fix_with_krb_error_synthesizes_clockskew(self):
        from tanuki.protocol import parse_krb_error_stime
        import time

        # Generate a KRB-ERROR stime 500 seconds in the future
        future_time = int(time.time()) + 500
        gm = time.gmtime(future_time)
        time_str = f"{gm.tm_year:04d}{gm.tm_mon:02d}{gm.tm_mday:02d}{gm.tm_hour:02d}{gm.tm_min:02d}{gm.tm_sec:02d}Z"
        asn1_bytes = b"\x30\x11\x18\x0f" + time_str.encode("ascii")

        rep = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=False,
            krb_error=asn1_bytes,
        )
        self.assertEqual(rep.status, "SUCCESS")
        with open(self.conf_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("clockskew =", content)
            # Find the clockskew value written
            for line in content.splitlines():
                if "clockskew" in line:
                    val = int(line.split("=")[1].strip())
                    # Should be approx 500 + 60 = 560 (tolerance 540-580)
                    self.assertTrue(540 <= val <= 580, f"Expected clockskew ~560, got {val}")

    def test_parse_krb_error_stime_fractional_and_iso(self):
        from tanuki.protocol import parse_krb_error_stime
        # 1. Fractional GeneralizedTime (.000Z)
        sample_frac = b"\x30\x15\x18\x1320261007120000.000Z"
        t_frac = parse_krb_error_stime(sample_frac)
        self.assertIsNotNone(t_frac)

        # 2. ISO text format
        sample_iso = "Clock skew too great at 2026-10-07 12:00:00 UTC"
        t_iso = parse_krb_error_stime(sample_iso)
        self.assertIsNotNone(t_iso)
        self.assertEqual(t_frac, t_iso)

    def test_run_fix_with_krb_error_file_path(self):
        err_file = os.path.join(self.tmp_dir.name, "krb_error.bin")
        with open(err_file, "wb") as f:
            f.write(b"\x30\x11\x18\x0f20261007120000Z")

        rep = run_fix(
            keytab_path=self.kt_path,
            realm="CORP.LOCAL",
            kdc="192.168.56.106",
            krb5_conf=self.conf_path,
            dry_run=False,
            krb_error=err_file,
        )
        self.assertEqual(rep.status, "SUCCESS")
        with open(self.conf_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("clockskew =", content)

    def test_parse_krb_error_stime_symlink_ignored(self):
        from tanuki.protocol import parse_krb_error_stime
        if not hasattr(os, "symlink"):
            return
        err_file = os.path.join(self.tmp_dir.name, "valid_krb_err.bin")
        with open(err_file, "wb") as f:
            f.write(b"\x30\x11\x18\x0f20261007120000Z")
        sym_file = os.path.join(self.tmp_dir.name, "sym_krb_err.bin")
        try:
            os.symlink(err_file, sym_file)
        except OSError:
            return
        try:
            res = parse_krb_error_stime(sym_file)
            self.assertIsNone(res)
        finally:
            if os.path.exists(sym_file):
                try:
                    os.unlink(sym_file)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()

