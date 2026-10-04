"""Adversarial SIEM/EDR Telemetry & Rule Verification Suite (Challenger 2 for Milestone 2).

This suite performs adversarial validation of Milestone 2:
1. Auditd rule syntax validity across all error codes, ladder rungs, and operational remediations.
   (Verifies -w and -a syntax, permission flags, valid syscalls, and filter keys).
2. Windows Active Directory Security Event ID validity (integer types, valid ranges, official mappings).
3. Sigma rule identifiers and Falco syscall signatures mapping accuracy and field integrity.
4. Rung 5 decision ladder standard format verification:
   [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE].
5. Rust vs Python dual-engine parity and antislop compliance (zero em dashes, forbidden unsafe code).
"""

import json
import os
import re
import subprocess
import sys
import unittest
from typing import Any, Dict, List, Tuple

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

VALID_FALCO_PRIORITIES = {
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG",
}

VALID_SIGMA_STATUSES = {"stable", "experimental", "testing"}
VALID_SIGMA_LOGSOURCES = {"linux:auditd", "windows:security"}


def run_tanuki(args: List[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "tanuki"] + args
    return subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)


class TestAdversarialAuditdRules(unittest.TestCase):
    """Stress-test and parse every Auditd rule for syntax correctness."""

    def _validate_auditd_rule(self, rule: str, context: str):
        self.assertIsInstance(rule, str, f"Rule not a string in {context}")
        self.assertTrue(len(rule.strip()) > 0, f"Empty rule in {context}")

        tokens = rule.strip().split()
        first = tokens[0]
        self.assertIn(first, ["-w", "-a"], f"Rule must start with -w or -a in {context}: '{rule}'")

        if first == "-w":
            # Syntax: -w <path> -p <r|w|x|a> [-k <key>]
            self.assertGreaterEqual(len(tokens), 4, f"Watch rule too short in {context}: '{rule}'")
            path = tokens[1]
            self.assertTrue(path.startswith("/"), f"Watch path must be absolute in {context}: '{path}'")

            self.assertIn("-p", tokens, f"Watch rule missing -p in {context}: '{rule}'")
            p_idx = tokens.index("-p")
            self.assertLess(p_idx + 1, len(tokens), f"Missing permission flags after -p in {context}: '{rule}'")
            perms = tokens[p_idx + 1]
            for char in perms:
                self.assertIn(char, "rwxa", f"Invalid permission flag '{char}' in {context}: '{rule}'")

            if "-k" in tokens:
                k_idx = tokens.index("-k")
                self.assertLess(k_idx + 1, len(tokens), f"Missing key name after -k in {context}: '{rule}'")
                key = tokens[k_idx + 1]
                self.assertTrue(re.match(r"^[a-zA-Z0-9_\-]+$", key), f"Invalid key identifier '{key}' in {context}")

        elif first == "-a":
            # Syntax: -a <action,list> [-F ...] -S <syscalls> [-k <key>]
            action_list = tokens[1]
            valid_actions = {"always,exit", "exit,always", "never,exit", "exit,never", "never,task"}
            self.assertIn(action_list, valid_actions, f"Invalid action,list '{action_list}' in {context}")

            self.assertIn("-S", tokens, f"Syscall rule missing -S in {context}: '{rule}'")
            s_idx = tokens.index("-S")
            self.assertLess(s_idx + 1, len(tokens), f"Missing syscall list after -S in {context}: '{rule}'")
            syscalls = tokens[s_idx + 1].split(",")
            known_syscalls = {
                "adjtimex", "settimeofday", "clock_settime",
                "open", "openat", "execve", "read", "write"
            }
            for sc in syscalls:
                self.assertIn(sc, known_syscalls, f"Unknown/unexpected syscall '{sc}' in {context}: '{rule}'")

            if "-k" in tokens:
                k_idx = tokens.index("-k")
                self.assertLess(k_idx + 1, len(tokens), f"Missing key name after -k in {context}: '{rule}'")
                key = tokens[k_idx + 1]
                self.assertTrue(re.match(r"^[a-zA-Z0-9_\-]+$", key), f"Invalid key identifier '{key}' in {context}")

    def test_auditd_rules_in_all_error_codes(self):
        for code, data in ERROR_TELEMETRY.items():
            telem = data.get("telemetry", {})
            rules = telem.get("auditd", [])
            self.assertGreater(len(rules), 0, f"No auditd rules for {code}")
            for rule in rules:
                self._validate_auditd_rule(rule, f"error {code}")

    def test_auditd_rules_in_all_ladder_rungs(self):
        for rung_num, telem in LADDER_TELEMETRY.items():
            rules = telem.get("auditd", [])
            self.assertGreater(len(rules), 0, f"No auditd rules for rung {rung_num}")
            for rule in rules:
                self._validate_auditd_rule(rule, f"rung {rung_num}")

    def test_auditd_rules_in_operational_remediations(self):
        for key, data in OPERATIONAL_REMEDIATIONS.items():
            telem = data.get("telemetry", {})
            rules = telem.get("auditd", [])
            self.assertGreater(len(rules), 0, f"No auditd rules for remediation {key}")
            for rule in rules:
                self._validate_auditd_rule(rule, f"remediation {key}")


class TestAdversarialEventIds(unittest.TestCase):
    """Stress-test and validate Active Directory Security Event IDs."""

    # Recognized Windows Security / Active Directory / Kerberos Event IDs
    CANONICAL_AD_EVENT_IDS = {
        4624,  # Successful Logon
        4625,  # Failed Logon
        4662,  # Operation Performed on Object
        4672,  # Special Privileges Assigned
        4738,  # User Account Modified
        4740,  # User Account Locked Out
        4768,  # Kerberos TGT Request (AS-REQ)
        4769,  # Kerberos Service Ticket Request (TGS-REQ)
        4771,  # Kerberos Pre-authentication Failed
        4886,  # AD CS Certificate Request Received
        4887,  # AD CS Certificate Issued
        5136,  # Directory Service Object Modified (msDS-KeyCredentialLink, etc.)
    }

    def _validate_event_ids(self, eids: List[Any], context: str):
        self.assertIsInstance(eids, list, f"Event IDs not a list in {context}")
        self.assertGreater(len(eids), 0, f"Event IDs empty in {context}")
        for eid in eids:
            self.assertIsInstance(eid, int, f"Event ID {eid} is not an int in {context}")
            self.assertIn(eid, self.CANONICAL_AD_EVENT_IDS, f"Unknown/Non-AD Event ID {eid} in {context}")
            self.assertIn(eid, EVENT_DESCRIPTIONS, f"Missing description for Event ID {eid} in EVENT_DESCRIPTIONS")

    def test_event_ids_in_all_error_codes(self):
        for code, data in ERROR_TELEMETRY.items():
            telem = data.get("telemetry", {})
            eids = telem.get("event_ids", [])
            self._validate_event_ids(eids, f"error {code}")

    def test_event_ids_in_ladder_rungs(self):
        for rung_num, telem in LADDER_TELEMETRY.items():
            eids = telem.get("event_ids", [])
            self._validate_event_ids(eids, f"rung {rung_num}")

    def test_event_ids_in_operational_remediations(self):
        for key, data in OPERATIONAL_REMEDIATIONS.items():
            telem = data.get("telemetry", {})
            eids = telem.get("event_ids", [])
            self._validate_event_ids(eids, f"remediation {key}")

    def test_event_descriptions_integrity(self):
        for eid, desc in EVENT_DESCRIPTIONS.items():
            self.assertIsInstance(eid, int)
            self.assertIn(eid, self.CANONICAL_AD_EVENT_IDS)
            self.assertTrue(len(desc) > 0)


class TestAdversarialSigmaAndFalcoRules(unittest.TestCase):
    """Stress-test Sigma rule identifiers and Falco syscall signatures."""

    def test_sigma_rules_schema_and_taxonomy(self):
        all_scopes = []
        for code, data in ERROR_TELEMETRY.items():
            all_scopes.append((f"error {code}", data["telemetry"].get("sigma", [])))
        for rung_num, telem in LADDER_TELEMETRY.items():
            all_scopes.append((f"rung {rung_num}", telem.get("sigma", [])))
        for key, data in OPERATIONAL_REMEDIATIONS.items():
            all_scopes.append((f"remediation {key}", data["telemetry"].get("sigma", [])))

        for context, sigmas in all_scopes:
            self.assertGreater(len(sigmas), 0, f"No sigma rules in {context}")
            for sig in sigmas:
                self.assertIn("title", sig, f"Missing title in {context}")
                self.assertTrue(len(sig["title"]) > 5, f"Title too short in {context}")

                self.assertIn("status", sig, f"Missing status in {context}")
                self.assertIn(sig["status"], VALID_SIGMA_STATUSES, f"Invalid status in {context}")

                self.assertIn("logsource", sig, f"Missing logsource in {context}")
                self.assertIn(sig["logsource"], VALID_SIGMA_LOGSOURCES, f"Invalid logsource in {context}")

                self.assertIn("tags", sig, f"Missing tags in {context}")
                self.assertIsInstance(sig["tags"], list, f"Tags not a list in {context}")
                self.assertGreater(len(sig["tags"]), 0, f"Empty tags in {context}")

                for tag in sig["tags"]:
                    self.assertTrue(tag.startswith("attack."), f"Tag must start with 'attack.' in {context}: {tag}")
                    t_val = tag[len("attack."):]
                    is_technique = bool(re.match(r"^t\d+(\.\d+)?$", t_val))
                    is_tactic = t_val in {
                        "initial_access", "execution", "persistence",
                        "privilege_escalation", "defense_evasion", "credential_access",
                        "discovery", "lateral_movement", "collection",
                        "command_and_control", "exfiltration", "impact", "reconnaissance"
                    }
                    self.assertTrue(
                        is_technique or is_tactic,
                        f"Tag '{tag}' not a recognized MITRE tactic or technique in {context}"
                    )

    def test_falco_signatures_schema_and_conditions(self):
        all_scopes = []
        for code, data in ERROR_TELEMETRY.items():
            all_scopes.append((f"error {code}", data["telemetry"].get("falco", [])))
        for rung_num, telem in LADDER_TELEMETRY.items():
            all_scopes.append((f"rung {rung_num}", telem.get("falco", [])))
        for key, data in OPERATIONAL_REMEDIATIONS.items():
            all_scopes.append((f"remediation {key}", data["telemetry"].get("falco", [])))

        for context, falcos in all_scopes:
            self.assertGreater(len(falcos), 0, f"No falco rules in {context}")
            for fal in falcos:
                self.assertIn("rule", fal, f"Missing rule in {context}")
                self.assertTrue(len(fal["rule"]) > 3, f"Rule name too short in {context}")

                self.assertIn("priority", fal, f"Missing priority in {context}")
                self.assertIn(fal["priority"], VALID_FALCO_PRIORITIES, f"Invalid priority in {context}")

                self.assertIn("condition", fal, f"Missing condition in {context}")
                cond = fal["condition"]
                self.assertTrue(len(cond) > 5, f"Condition too short in {context}")

                # Ensure condition references relevant Falco primitives
                valid_primitives = ["evt.type", "fd.name", "proc.name", "proc.cmdline", "open_read", "open_write", "fd.rport", "connect", "sendto"]
                has_primitive = any(p in cond for p in valid_primitives)
                self.assertTrue(has_primitive, f"Falco condition lacks recognizable primitives in {context}: '{cond}'")

                self.assertIn("output", fal, f"Missing output in {context}")
                self.assertTrue(len(fal["output"]) > 5, f"Output too short in {context}")


class TestAdversarialRung5LadderFormat(unittest.TestCase):
    """Verify Rung 5 decision ladder standard output format:
    [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE].
    """

    EXPECTED_STANDARD = (
        "[TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]"
    )

    REQUIRED_SEQUENCE = [
        "[TARGET]",
        "[PREREQUISITE]",
        "[TACTICAL CMD]",
        "[BLUE TELEMETRY]",
        "[EXPECTED ARTIFACT]",
        "[OPSEC RATIONALE]",
    ]

    def test_ladder_terminal_command_standard_line(self):
        res = run_tanuki(["ladder"])
        self.assertEqual(res.returncode, 0, f"tanuki ladder failed: {res.stderr}")
        stdout = res.stdout

        self.assertIn(self.EXPECTED_STANDARD, stdout, f"Expected standard string missing from terminal ladder output")

        # Extract the Command Output Standard block
        std_idx = stdout.find("Command Output Standard:")
        self.assertNotEqual(std_idx, -1, "Missing 'Command Output Standard:' header")
        std_section = stdout[std_idx:]

        # Verify ordering of tags specifically within the Command Output Standard line
        last_idx = -1
        for tag in self.REQUIRED_SEQUENCE:
            idx = std_section.find(tag)
            self.assertNotEqual(idx, -1, f"Missing tag '{tag}' in Command Output Standard line")
            self.assertGreater(idx, last_idx, f"Tag '{tag}' appeared out of order in Command Output Standard line")
            last_idx = idx

    def test_rung5_description_contains_required_tags_and_order(self):
        rung5 = DECISION_LADDER[4]
        self.assertEqual(rung5["rung"], 5)
        desc = rung5["description"]

        last_idx = -1
        for tag in self.REQUIRED_SEQUENCE:
            idx = desc.find(tag)
            self.assertNotEqual(idx, -1, f"Missing tag '{tag}' in Rung 5 description")
            self.assertGreater(idx, last_idx, f"Tag '{tag}' out of order in Rung 5 description")
            last_idx = idx

    def test_rung5_json_output_fidelity(self):
        res = run_tanuki(["ladder", "--json"])
        self.assertEqual(res.returncode, 0, f"tanuki ladder --json failed: {res.stderr}")
        rungs = json.loads(res.stdout)
        self.assertEqual(len(rungs), 5)
        rung5 = rungs[4]
        self.assertEqual(rung5["rung"], 5)
        self.assertIn("telemetry", rung5)
        telem = rung5["telemetry"]
        self.assertIn("auditd", telem)
        self.assertIn("event_ids", telem)
        self.assertIn("sigma", telem)
        self.assertIn("falco", telem)


class TestRustParityAndAntislop(unittest.TestCase):
    """Audit Rust crate parity, absence of unsafe blocks, and zero em dashes."""

    def test_rust_telemetry_source_safety(self):
        crates_dir = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli")
        src_dir = os.path.join(crates_dir, "src")
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(".rs"):
                    fpath = os.path.join(root, file)
                    with open(fpath, "r", encoding="utf-8") as f:
                        code = f.read()
                    self.assertNotIn("unsafe {", code, f"Unsafe block in {fpath}")
                    self.assertNotIn("unsafe fn", code, f"Unsafe function in {fpath}")

    def test_rust_ladder_format_parity(self):
        main_rs = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "main.rs")
        with open(main_rs, "r", encoding="utf-8") as f:
            content = f.read()
        expected = "[TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]"
        self.assertIn(expected, content, "Rust main.rs missing Rung 5 standard format string")

    def test_zero_em_dashes_across_all_sources(self):
        targets = [
            os.path.join(PROJECT_ROOT, "tanuki", "telemetry.py"),
            os.path.join(PROJECT_ROOT, "tanuki", "protocol.py"),
            os.path.join(PROJECT_ROOT, "tanuki", "cli.py"),
            os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "protocol", "telemetry.rs"),
            os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "protocol", "kerberos.rs"),
            os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "main.rs"),
        ]
        for t in targets:
            if os.path.isfile(t):
                with open(t, "r", encoding="utf-8") as f:
                    txt = f.read()
                self.assertNotIn("—", txt, f"Banned em dash found in {t}")


class TestAdversarialQueryFuzzing(unittest.TestCase):
    """Stress-test CLI error lookup against adversarial query fuzzing."""

    def test_adversarial_fuzz_queries_terminal(self):
        # In-process test for embedded null characters which cannot be passed to Windows CreateProcess
        self.assertIsNone(find_error_resolution("\x00\x00\x00"))

        fuzz_inputs = [
            "'; DROP TABLE krb5; --",
            "$(cat /etc/passwd)",
            "`whoami`",
            "../../../../etc/shadow",
            "SELECT * FROM users",
            "<script>alert(1)</script>",
            "\n\r\t",
            "   ",
            "NaN",
            "undefined",
            "null",
            "KRB_AP_ERR_SKEW' OR '1'='1",
            "A" * 500,
        ]
        for query in fuzz_inputs:
            res = run_tanuki(["triage", query])
            # None of these should crash with unhandled python traceback
            self.assertNotIn("Traceback (most recent call last):", res.stderr, f"Traceback on fuzz '{query}'")
            self.assertEqual(res.returncode, 3, f"Expected non-zero exit code 3 on unknown fuzz query '{query}'")

    def test_adversarial_fuzz_queries_json(self):
        fuzz_inputs = [
            "'; DROP TABLE krb5; --",
            "$(cat /etc/passwd)",
            "`whoami`",
            "../../../../etc/shadow",
            "NaN",
            "undefined",
            "A" * 500,
        ]
        for query in fuzz_inputs:
            res = run_tanuki(["triage", query, "--json"])
            self.assertNotIn("Traceback (most recent call last):", res.stderr, f"Traceback on json fuzz '{query}'")
            self.assertEqual(res.returncode, 3)
            data = json.loads(res.stdout)
            self.assertEqual(data.get("reason_code"), "UNKNOWN_ERROR_CODE", f"Expected 'UNKNOWN_ERROR_CODE' on fuzz query '{query}'")
            self.assertEqual(data.get("exit_code"), 3)


class TestRustTelemetryConstantsParity(unittest.TestCase):
    """Verify Rust telemetry constants and event descriptions match Python definitions."""

    def test_all_rust_telemetry_constants_exist_and_match(self):
        telem_rs_path = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "protocol", "telemetry.rs")
        with open(telem_rs_path, "r", encoding="utf-8") as f:
            rs_content = f.read()

        for code in ALL_10_ERROR_CODES:
            var_name = f"TELEMETRY_{code}"
            self.assertIn(var_name, rs_content, f"Missing {var_name} in Rust telemetry.rs")

        for rung_num in range(1, 6):
            var_name = f"TELEMETRY_LADDER_RUNG_{rung_num}"
            self.assertIn(var_name, rs_content, f"Missing {var_name} in Rust telemetry.rs")

        # Verify get_event_description mappings in Rust match Python EVENT_DESCRIPTIONS
        for eid, desc in EVENT_DESCRIPTIONS.items():
            self.assertIn(str(eid), rs_content, f"Missing event ID {eid} in Rust telemetry.rs")
            self.assertIn(f'"{desc}"', rs_content, f"Missing event description '{desc}' in Rust telemetry.rs")


def run_all_adversarial_checks() -> bool:
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite.addTests(loader.loadTestsFromTestCase(TestAdversarialAuditdRules))
    suite.addTests(loader.loadTestsFromTestCase(TestAdversarialEventIds))
    suite.addTests(loader.loadTestsFromTestCase(TestAdversarialSigmaAndFalcoRules))
    suite.addTests(loader.loadTestsFromTestCase(TestAdversarialRung5LadderFormat))
    suite.addTests(loader.loadTestsFromTestCase(TestRustParityAndAntislop))
    suite.addTests(loader.loadTestsFromTestCase(TestAdversarialQueryFuzzing))
    suite.addTests(loader.loadTestsFromTestCase(TestRustTelemetryConstantsParity))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_adversarial_checks()
    sys.exit(0 if success else 1)
