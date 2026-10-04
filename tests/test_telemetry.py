"""Comprehensive Unit Tests for Dual-Use Detection Telemetry (Milestone 2)."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tanuki.protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution
from tanuki.telemetry import (
    ERROR_TELEMETRY,
    EVENT_DESCRIPTIONS,
    LADDER_TELEMETRY,
    OPERATIONAL_REMEDIATIONS,
    format_telemetry_inline,
    format_telemetry_terminal,
)


class TestErrorTelemetryData(unittest.TestCase):
    """Verify detection telemetry structure and content for all 11 Kerberos errors."""

    def test_all_ten_errors_present_and_enriched(self):
        self.assertEqual(len(ERROR_DICTIONARY), 11)
        for item in ERROR_DICTIONARY:
            self.assertIn("code", item)
            self.assertIn("tactical_cmd", item, f"Missing tactical_cmd in {item['code']}")
            self.assertTrue(len(item["tactical_cmd"]) > 0)
            self.assertIn("telemetry", item, f"Missing telemetry in {item['code']}")

    def test_telemetry_block_schema(self):
        for item in ERROR_DICTIONARY:
            code = item["code"]
            telem = item["telemetry"]
            self.assertIsInstance(telem, dict, f"Telemetry not a dict for {code}")
            for key in ["auditd", "event_ids", "sigma", "falco"]:
                self.assertIn(key, telem, f"Missing '{key}' in telemetry for {code}")

            audit_rules = telem["auditd"]
            self.assertIsInstance(audit_rules, list, f"auditd not a list for {code}")
            self.assertGreater(len(audit_rules), 0, f"auditd empty for {code}")
            for rule in audit_rules:
                self.assertTrue(
                    rule.startswith("-w ") or rule.startswith("-a "),
                    f"Invalid auditd rule syntax for {code}: {rule}",
                )

            event_ids = telem["event_ids"]
            self.assertIsInstance(event_ids, list, f"event_ids not a list for {code}")
            self.assertGreater(len(event_ids), 0, f"event_ids empty for {code}")
            for eid in event_ids:
                self.assertIsInstance(eid, int)
                self.assertGreater(eid, 0)
                self.assertLess(eid, 100000)

            sigma_rules = telem["sigma"]
            self.assertIsInstance(sigma_rules, list, f"sigma not a list for {code}")
            self.assertGreater(len(sigma_rules), 0, f"sigma empty for {code}")
            for sig in sigma_rules:
                self.assertIn("title", sig)
                self.assertTrue(len(sig["title"]) > 0)
                self.assertIn("status", sig)
                self.assertIn(sig["status"], ["stable", "experimental", "testing"])
                self.assertIn("logsource", sig)
                self.assertTrue(len(sig["logsource"]) > 0)
                self.assertIn("tags", sig)
                self.assertIsInstance(sig["tags"], list)
                self.assertGreater(len(sig["tags"]), 0)

            falco_rules = telem["falco"]
            self.assertIsInstance(falco_rules, list, f"falco not a list for {code}")
            self.assertGreater(len(falco_rules), 0, f"falco empty for {code}")
            for fal in falco_rules:
                self.assertIn("rule", fal)
                self.assertTrue(len(fal["rule"]) > 0)
                self.assertIn("priority", fal)
                self.assertIn(
                    fal["priority"],
                    ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"],
                )
                self.assertIn("condition", fal)
                self.assertTrue(len(fal["condition"]) > 0)
                self.assertIn("output", fal)
                self.assertTrue(len(fal["output"]) > 0)

    def test_clock_skew_telemetry_coupling(self):
        item = find_error_resolution("KRB_AP_ERR_SKEW")
        self.assertIsNotNone(item)
        self.assertEqual(item["event_id"], 37)
        self.assertTrue("chronyc" in item["tactical_cmd"] or "ntpdate" in item["tactical_cmd"])

        telem = item["telemetry"]
        self.assertTrue(any("adjtimex" in r or "clock_settime" in r for r in telem["auditd"]))
        self.assertIn(4768, telem["event_ids"])
        self.assertIn(4771, telem["event_ids"])

    def test_etype_nosupp_telemetry_coupling(self):
        item = find_error_resolution("KDC_ERR_ETYPE_NOSUPP")
        self.assertIsNotNone(item)
        self.assertEqual(item["event_id"], 14)
        telem = item["telemetry"]
        self.assertTrue(any("/etc/krb5.conf" in r for r in telem["auditd"]))
        self.assertIn(4768, telem["event_ids"])
        self.assertIn(4769, telem["event_ids"])
        self.assertTrue(any("RC4" in s["title"] for s in telem["sigma"]))

    def test_preauth_failed_telemetry_coupling(self):
        item = find_error_resolution("KDC_ERR_PREAUTH_FAILED")
        self.assertIsNotNone(item)
        self.assertEqual(item["event_id"], 24)
        telem = item["telemetry"]
        self.assertTrue(any("/etc/krb5.keytab" in r for r in telem["auditd"]))
        self.assertIn(4771, telem["event_ids"])
        self.assertIn(4625, telem["event_ids"])

    def test_c_principal_unknown_telemetry_coupling(self):
        item = find_error_resolution("KDC_ERR_C_PRINCIPAL_UNKNOWN")
        self.assertIsNotNone(item)
        self.assertEqual(item["event_id"], 6)
        telem = item["telemetry"]
        self.assertTrue(any("/etc/krb5.keytab" in r for r in telem["auditd"]))
        self.assertIn(4768, telem["event_ids"])
        self.assertIn(4771, telem["event_ids"])

    def test_status_more_processing_required_telemetry_coupling(self):
        item = find_error_resolution("STATUS_MORE_PROCESSING_REQUIRED")
        self.assertIsNotNone(item)
        self.assertIsNone(item["event_id"])
        telem = item["telemetry"]
        self.assertTrue(any("krb5cc_" in r or "kcm" in r for r in telem["auditd"]))
        self.assertIn(4624, telem["event_ids"])
        self.assertIn(4625, telem["event_ids"])

    def test_badkeyver_telemetry_coupling(self):
        item = find_error_resolution("KRB_AP_ERR_BADKEYVER")
        self.assertIsNotNone(item)
        self.assertEqual(item["event_id"], 44)
        telem = item["telemetry"]
        self.assertIn(4769, telem["event_ids"])
        self.assertTrue(any("/etc/krb5.keytab" in r for r in telem["auditd"]))
        self.assertTrue(any("Key Version" in s["title"] for s in telem["sigma"]))
        self.assertTrue(any("Keytab" in f["rule"] for f in telem["falco"]))


class TestDecisionLadderTelemetry(unittest.TestCase):
    """Verify telemetry enrichment for the 5-Rung Tactical Decision Ladder."""

    def test_all_five_rungs_enriched(self):
        self.assertEqual(len(DECISION_LADDER), 5)
        for rung in DECISION_LADDER:
            self.assertIn("rung", rung)
            self.assertIn("title", rung)
            self.assertIn("description", rung)
            self.assertIn("telemetry", rung)
            telem = rung["telemetry"]
            self.assertIn("auditd", telem)
            self.assertIn("event_ids", telem)
            self.assertIn("sigma", telem)
            self.assertIn("falco", telem)
            self.assertGreater(len(telem["auditd"]), 0)
            self.assertGreater(len(telem["event_ids"]), 0)

    def test_rung1_keytab_audit_rule(self):
        rung1 = DECISION_LADDER[0]
        self.assertEqual(rung1["rung"], 1)
        audit_rules = rung1["telemetry"]["auditd"]
        self.assertTrue(any("-w /etc/krb5.keytab" in r for r in audit_rules))
        self.assertIn(4624, rung1["telemetry"]["event_ids"])

    def test_rung5_structural_tags_and_telemetry(self):
        rung5 = DECISION_LADDER[4]
        self.assertEqual(rung5["rung"], 5)
        desc = rung5["description"]
        self.assertIn("[TARGET]", desc)
        self.assertIn("[PREREQUISITE]", desc)
        self.assertIn("[TACTICAL CMD]", desc)
        self.assertIn("[TACTICAL COMMAND]", desc)
        self.assertIn("[BLUE TELEMETRY]", desc)
        self.assertIn("[EXPECTED ARTIFACT]", desc)
        self.assertIn("[OPSEC RATIONALE]", desc)


class TestOperationalRemediationsTelemetry(unittest.TestCase):
    """Verify auxiliary operational remediations dictionary."""

    def test_all_operational_remediations_exist(self):
        required_keys = [
            "keytab_machine_extraction",
            "sssd_kcm_stream_access",
            "pass_the_ticket",
            "delegation_triage",
            "shadow_credentials",
            "rbcd",
        ]
        for key in required_keys:
            self.assertIn(key, OPERATIONAL_REMEDIATIONS)
            item = OPERATIONAL_REMEDIATIONS[key]
            self.assertIn("title", item)
            self.assertIn("tactical_cmd", item)
            self.assertIn("telemetry", item)
            telem = item["telemetry"]
            self.assertIn("auditd", telem)
            self.assertIn("event_ids", telem)
            self.assertIn("sigma", telem)
            self.assertIn("falco", telem)


class TestTelemetryFormatters(unittest.TestCase):
    """Verify terminal and inline string formatters."""

    def test_format_telemetry_terminal(self):
        sample = ERROR_TELEMETRY["KRB_AP_ERR_SKEW"]["telemetry"]
        text = format_telemetry_terminal(sample)
        self.assertIn("[BLUE TELEMETRY]", text)
        self.assertIn("Auditd Rules:", text)
        self.assertIn("Windows Event IDs:", text)
        self.assertIn("Sigma Rules:", text)
        self.assertIn("Falco Signatures:", text)
        self.assertIn("4768 (Kerberos TGT Request)", text)
        self.assertIn("4771 (Kerberos Pre-authentication Failed)", text)

    def test_format_telemetry_inline(self):
        sample = ERROR_TELEMETRY["KRB_AP_ERR_SKEW"]["telemetry"]
        inline = format_telemetry_inline(sample)
        self.assertIn("Auditd:", inline)
        self.assertIn("Event IDs: 4768, 4771", inline)
        self.assertIn("Sigma: System Time Modification Detected", inline)
        self.assertIn("Falco: System Time Modification", inline)


class TestCLITelemetryExecution(unittest.TestCase):
    """Verify CLI terminal output and --json export via subprocess execution."""

    def run_cli(self, args: list) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "tanuki"] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        )

    def test_triage_terminal_output_displays_blue_telemetry(self):
        res = self.run_cli(["triage", "KRB_AP_ERR_SKEW"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("Found matching error: KRB_AP_ERR_SKEW", res.stdout)
        self.assertIn("Event ID: 37", res.stdout)
        self.assertIn("Root Cause:", res.stdout)
        self.assertIn("[TACTICAL CMD]", res.stdout)
        self.assertIn("[BLUE TELEMETRY]", res.stdout)
        self.assertIn("Auditd Rules:", res.stdout)
        self.assertIn("Windows Event IDs:", res.stdout)

    def test_triage_single_json_has_telemetry_block(self):
        res = self.run_cli(["triage", "KRB_AP_ERR_SKEW", "--json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["code"], "KRB_AP_ERR_SKEW")
        self.assertIn("tactical_cmd", data)
        self.assertIn("telemetry", data)
        telem = data["telemetry"]
        self.assertIn("auditd", telem)
        self.assertIn("event_ids", telem)
        self.assertIn("sigma", telem)
        self.assertIn("falco", telem)

    def test_triage_full_dictionary_terminal_output(self):
        res = self.run_cli(["triage"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("KERBEROS & SSSD ERROR RESOLUTION DICTIONARY", res.stdout)
        self.assertIn("[TACTICAL CMD]:", res.stdout)
        self.assertIn("[BLUE TELEMETRY]:", res.stdout)

    def test_triage_full_dictionary_json_has_telemetry(self):
        res = self.run_cli(["triage", "--json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertGreaterEqual(len(data), 10)
        for item in data:
            self.assertIn("telemetry", item)
            self.assertIn("auditd", item["telemetry"])
            self.assertIn("event_ids", item["telemetry"])

    def test_ladder_terminal_output_displays_blue_telemetry(self):
        res = self.run_cli(["ladder"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("TANUKI 5-RUNG TACTICAL DECISION LADDER", res.stdout)
        self.assertIn("[BLUE TELEMETRY]", res.stdout)
        self.assertIn("[TACTICAL CMD] -> [BLUE TELEMETRY]", res.stdout)

    def test_ladder_json_has_telemetry_blocks(self):
        res = self.run_cli(["ladder", "--json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(len(data), 5)
        for rung in data:
            self.assertIn("telemetry", rung)
            self.assertIn("auditd", rung["telemetry"])
            self.assertIn("event_ids", rung["telemetry"])


class TestRustParityAndIntegrity(unittest.TestCase):
    """Verify Rust CLI protocol files maintain parity and strict safety constraints."""

    def setUp(self):
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.crates_dir = os.path.join(self.root_dir, "crates", "tanuki-cli")

    def test_telemetry_rs_exists_and_forbid_unsafe(self):
        telem_rs = os.path.join(self.crates_dir, "src", "protocol", "telemetry.rs")
        self.assertTrue(os.path.isfile(telem_rs))
        with open(telem_rs, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("pub struct TelemetryData", content)
        self.assertIn("pub struct SigmaRuleRef", content)
        self.assertIn("pub struct FalcoRuleRef", content)
        self.assertIn("pub const TELEMETRY_KRB_AP_ERR_SKEW", content)
        self.assertNotIn("unsafe", content)

    def test_kerberos_rs_has_telemetry_data(self):
        kerberos_rs = os.path.join(self.crates_dir, "src", "protocol", "kerberos.rs")
        with open(kerberos_rs, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("pub tactical_cmd: &'static str", content)
        self.assertIn("pub telemetry: TelemetryData", content)
        self.assertIn("TELEMETRY_KRB_AP_ERR_SKEW", content)
        self.assertIn("TELEMETRY_LADDER_RUNG_1", content)
        self.assertNotIn("unsafe", content)

    def test_zero_em_dashes_in_source(self):
        py_files = [
            os.path.join(self.root_dir, "tanuki", "telemetry.py"),
            os.path.join(self.root_dir, "tanuki", "protocol.py"),
            os.path.join(self.root_dir, "tanuki", "cli.py"),
        ]
        rust_files = [
            os.path.join(self.crates_dir, "src", "protocol", "telemetry.rs"),
            os.path.join(self.crates_dir, "src", "protocol", "kerberos.rs"),
            os.path.join(self.crates_dir, "src", "main.rs"),
        ]
        for fpath in py_files + rust_files:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("—", content, f"Em dash found in {fpath}")


if __name__ == "__main__":
    unittest.main()
