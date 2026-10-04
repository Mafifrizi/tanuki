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


if __name__ == "__main__":
    unittest.main()
