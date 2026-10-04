"""Adversarial Challenge Unit Tests for Milestone 2 (Dual-Use Detection Telemetry)."""

import json
import os
import subprocess
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tanuki.protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution
from tanuki.telemetry import (
    ERROR_TELEMETRY,
    EVENT_DESCRIPTIONS,
    LADDER_TELEMETRY,
    OPERATIONAL_REMEDIATIONS,
    format_telemetry_inline,
    format_telemetry_terminal,
)

ALL_10_ERROR_CODES = [
    "KRB_AP_ERR_SKEW",
    "KDC_ERR_ETYPE_NOSUPP",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "KDC_ERR_PREAUTH_FAILED",
    "STATUS_MORE_PROCESSING_REQUIRED",
    "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_KEY_EXPIRED",
    "KDC_ERR_NAME_EXP",
    "KDC_ERR_PADATA_TYPE_NOSUPP",
]


class TestChallengerM2TerminalTriage(unittest.TestCase):
    """Assert terminal triage displays [TACTICAL CMD] and [BLUE TELEMETRY] for all 10 error codes."""

    def run_cli(self, args):
        cmd = [sys.executable, "-m", "tanuki"] + args
        return subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)

    def test_all_10_error_codes_have_required_terminal_sections(self):
        for code in ALL_10_ERROR_CODES:
            res = self.run_cli(["triage", code])
            self.assertEqual(res.returncode, 0, f"Error {code} failed: {res.stderr}")
            self.assertIn("[TACTICAL CMD]", res.stdout, f"Missing [TACTICAL CMD] in {code}")
            self.assertIn("[BLUE TELEMETRY]", res.stdout, f"Missing [BLUE TELEMETRY] in {code}")
            self.assertIn("Auditd Rules:", res.stdout, f"Missing Auditd Rules in {code}")
            self.assertIn("Windows Event IDs:", res.stdout, f"Missing Windows Event IDs in {code}")
            self.assertIn("Sigma Rules:", res.stdout, f"Missing Sigma Rules in {code}")
            self.assertIn("Falco Signatures:", res.stdout, f"Missing Falco Signatures in {code}")


class TestChallengerM2JsonSchema(unittest.TestCase):
    """Assert JSON output validity and telemetry block schema across all 10 error codes and ladder."""

    def run_cli(self, args):
        cmd = [sys.executable, "-m", "tanuki"] + args
        return subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)

    def test_all_10_error_codes_json_schema(self):
        for code in ALL_10_ERROR_CODES:
            res = self.run_cli(["triage", code, "--json"])
            self.assertEqual(res.returncode, 0, f"Error {code} failed: {res.stderr}")
            data = json.loads(res.stdout)
            self.assertEqual(data["code"], code)
            self.assertIn("tactical_cmd", data)
            self.assertIn("telemetry", data)
            telem = data["telemetry"]
            for field in ["auditd", "event_ids", "sigma", "falco"]:
                self.assertIn(field, telem, f"Missing {field} in {code}")
                self.assertIsInstance(telem[field], list)
                self.assertGreater(len(telem[field]), 0, f"Empty {field} in {code}")

    def test_ladder_json_schema(self):
        res = self.run_cli(["ladder", "--json"])
        self.assertEqual(res.returncode, 0, f"Ladder JSON failed: {res.stderr}")
        rungs = json.loads(res.stdout)
        self.assertEqual(len(rungs), 5)
        for idx, rung in enumerate(rungs, 1):
            self.assertEqual(rung["rung"], idx)
            self.assertIn("telemetry", rung)
            telem = rung["telemetry"]
            for field in ["auditd", "event_ids", "sigma", "falco"]:
                self.assertIn(field, telem, f"Missing {field} in rung {idx}")
                self.assertIsInstance(telem[field], list)
                self.assertGreater(len(telem[field]), 0)


class TestChallengerM2AdversarialInputs(unittest.TestCase):
    """Test adversarial query inputs, event ID resolution, case insensitivity, and invalid queries."""

    def run_cli(self, args):
        cmd = [sys.executable, "-m", "tanuki"] + args
        return subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)

    def test_windows_event_id_queries(self):
        mappings = {
            "37": "KRB_AP_ERR_SKEW",
            "14": "KDC_ERR_ETYPE_NOSUPP",
            "6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
            "24": "KDC_ERR_PREAUTH_FAILED",
            "7": "KDC_ERR_S_PRINCIPAL_UNKNOWN",
            "18": "KDC_ERR_CLIENT_REVOKED",
            "23": "KDC_ERR_KEY_EXPIRED",
            "12": "KDC_ERR_NAME_EXP",
            "16": "KDC_ERR_PADATA_TYPE_NOSUPP",
        }
        for eid, expected_code in mappings.items():
            res = self.run_cli(["triage", eid])
            self.assertEqual(res.returncode, 0)
            self.assertIn(f"Found matching error: {expected_code}", res.stdout)
            self.assertIn("[TACTICAL CMD]", res.stdout)
            self.assertIn("[BLUE TELEMETRY]", res.stdout)

    def test_case_insensitivity_and_partial_queries(self):
        cases = [
            ("krb_ap_err_skew", "KRB_AP_ERR_SKEW"),
            ("kdc_err_etype_nosupp", "KDC_ERR_ETYPE_NOSUPP"),
            ("skew", "KRB_AP_ERR_SKEW"),
            ("etype", "KDC_ERR_ETYPE_NOSUPP"),
        ]
        for query, expected in cases:
            res = self.run_cli(["triage", query])
            self.assertEqual(res.returncode, 0)
            self.assertIn(f"Found matching error: {expected}", res.stdout)

    def test_invalid_query_error_handling(self):
        res = self.run_cli(["triage", "INVALID_ERR_CODE_DOES_NOT_EXIST"])
        self.assertEqual(res.returncode, 3)

        res_json = self.run_cli(["triage", "INVALID_ERR_CODE_DOES_NOT_EXIST", "--json"])
        self.assertEqual(res_json.returncode, 3)
        data = json.loads(res_json.stdout)
        self.assertEqual(data.get("status"), "ERROR")
        self.assertEqual(data.get("reason_code"), "UNKNOWN_ERROR_CODE")
        self.assertEqual(data.get("exit_code"), 3)


if __name__ == "__main__":
    unittest.main()
