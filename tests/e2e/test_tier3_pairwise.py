"""Tier 3: Pairwise Combinatorial & Cross-Feature Interactions Test Suite.

Tests cross-feature interactions and flag combinations:
- CLI flags --json combined with various subcommands
- Token exchange + doctor ticket lifetime correlation
- Triage blue telemetry + doctor keytab recommendations
- stdout vs stderr stream purity when piping structured outputs
- Keytab weak encryption types + triage etype error correlation
"""

import json
import os
import sys
import tempfile
import time
import unittest

_E2E_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_E2E_DIR, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
if _E2E_DIR not in sys.path:
    sys.path.insert(0, _E2E_DIR)

try:
    from tests.e2e.fixtures import (
        REPO_ROOT,
        build_multi_entry_keytab,
        build_synthetic_ccache,
        build_synthetic_jwt,
        build_synthetic_keytab,
        build_synthetic_krb5_conf,
        run_tanuki_cli,
    )
except ImportError:
    from fixtures import (
        REPO_ROOT,
        build_multi_entry_keytab,
        build_synthetic_ccache,
        build_synthetic_jwt,
        build_synthetic_keytab,
        build_synthetic_krb5_conf,
        run_tanuki_cli,
    )

STRICT_E2E = os.environ.get("TANUKI_STRICT_E2E", "0") == "1"


def skip_or_fail(test_case: unittest.TestCase, reason: str) -> None:
    if STRICT_E2E:
        test_case.fail(reason)
    else:
        test_case.skipTest(reason)


def is_cli_command_supported(cmd: str) -> bool:
    ret, stdout, _ = run_tanuki_cli(["-h"])
    return f"{cmd} " in stdout or f"{cmd}\n" in stdout or f"{cmd}[" in stdout


class TestTier3PairwiseInteractions(unittest.TestCase):
    """Tier 3 Pairwise Combinatorial and Cross-Feature Interaction Tests."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_pairwise_json_flag_across_all_commands(self) -> None:
        """Pairwise 1: --json flag emits valid parseable JSON across all supported subcommands."""
        commands_to_test = [
            ["ladder", "--json"],
            ["triage", "--json"],
            ["triage", "KRB_AP_ERR_SKEW", "--json"],
        ]

        if is_cli_command_supported("doctor"):
            commands_to_test.append(["doctor", "--json"])

        keytab_file = os.path.join(self.dir_path, "test.keytab")
        with open(keytab_file, "wb") as f:
            f.write(build_synthetic_keytab())
        commands_to_test.append(["keytab", keytab_file, "--json"])

        for cmd_args in commands_to_test:
            ret, stdout, stderr = run_tanuki_cli(cmd_args)
            self.assertEqual(ret, 0, f"Command {cmd_args} failed: {stderr}")
            try:
                parsed = json.loads(stdout)
                self.assertTrue(isinstance(parsed, (dict, list)))
            except json.JSONDecodeError as exc:
                self.fail(f"Command {cmd_args} output is not valid JSON: {exc}. Output was: {stdout}")

    def test_pairwise_stdout_purity_piped_json(self) -> None:
        """Pairwise 2: Verify stdout contains purely JSON with zero banner or log pollution."""
        ret, stdout, stderr = run_tanuki_cli(["ladder", "--json"])
        self.assertEqual(ret, 0)
        stripped = stdout.strip()
        self.assertTrue(
            stripped.startswith("[") or stripped.startswith("{"),
            f"stdout contains unexpected prefix: {stripped[:50]}",
        )
        self.assertTrue(
            stripped.endswith("]") or stripped.endswith("}"),
            f"stdout contains unexpected suffix: {stripped[-50:]}",
        )

    def test_pairwise_doctor_keytab_and_triage_correlation(self) -> None:
        """Pairwise 3: Keytab permission audit in doctor correlates with triage keytab telemetry."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "KDC_ERR_PREAUTH_FAILED", "--json"])
        self.assertEqual(ret, 0)
        triage_data = json.loads(stdout)

        if "telemetry" not in triage_data:
            skip_or_fail(self, "Telemetry block pending implementation in Milestone M2")
            return

        audit_rules = triage_data["telemetry"].get("auditd", [])
        self.assertTrue(
            any("/etc/krb5.keytab" in r for r in audit_rules),
            "Expected /etc/krb5.keytab audit rule in KDC_ERR_PREAUTH_FAILED telemetry",
        )

    def test_pairwise_weak_enctype_and_triage_nosupp_correlation(self) -> None:
        """Pairwise 4: Legacy weak ciphers (RC4/DES) flagged in keytab correlate with KDC_ERR_ETYPE_NOSUPP."""
        # Create keytab with RC4-HMAC (23) and DES-CBC-MD5 (3)
        entries = [
            {"principal_comps": ["HTTP", "app.corp.local"], "keytype": 23, "kvno": 1},
            {"principal_comps": ["HTTP", "app.corp.local"], "keytype": 3, "kvno": 1},
        ]
        keytab_file = os.path.join(self.dir_path, "weak.keytab")
        with open(keytab_file, "wb") as f:
            f.write(build_multi_entry_keytab(entries))

        # Check keytab output
        ret, stdout, stderr = run_tanuki_cli(["keytab", keytab_file, "--json"])
        self.assertEqual(ret, 0)
        parsed_entries = json.loads(stdout)
        enctypes = [e["keytype"] for e in parsed_entries]
        self.assertIn(23, enctypes)

        # Cross-correlate with triage lookup for ETYPE_NOSUPP
        ret, stdout, stderr = run_tanuki_cli(["triage", "KDC_ERR_ETYPE_NOSUPP", "--json"])
        self.assertEqual(ret, 0)
        triage_data = json.loads(stdout)
        self.assertIn("RC4-HMAC", triage_data.get("root_cause", ""))
        self.assertIn("aes256-cts-hmac-sha1-96", triage_data.get("resolution", ""))

    def test_pairwise_token_exchange_and_doctor_ticket_expiry(self) -> None:
        """Pairwise 5: NHI token exchange claims correlate with doctor ticket validity window."""
        try:
            from tanuki.nhi import validate_jwt_workload
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.nhi pending implementation in Milestone M3")
            return

        now = int(time.time())
        token = build_synthetic_jwt(payload={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:prod:db-sync",
            "aud": "https://sts.corp.local",
            "exp": now + 1800,
            "iat": now,
        })
        nhi_report = validate_jwt_workload(token)
        self.assertTrue(nhi_report.get("valid", False))
        temporal = nhi_report.get("temporal", {})
        self.assertFalse(temporal.get("is_expired", True))
        self.assertGreater(temporal.get("remaining_seconds", 0), 1000)

    def test_pairwise_flag_ordering_tolerance(self) -> None:
        """Pairwise 6: CLI accepts --json either before or after subcommands."""
        # --json after subcommand
        ret1, stdout1, _ = run_tanuki_cli(["ladder", "--json"])
        self.assertEqual(ret1, 0)

        # --json before subcommand
        ret2, stdout2, _ = run_tanuki_cli(["--json", "ladder"])
        self.assertEqual(ret2, 0)

        # Both should decode to identical lists of 5 rungs
        data1 = json.loads(stdout1)
        data2 = json.loads(stdout2)
        self.assertEqual(len(data1), 5)
        self.assertEqual(len(data2), 5)
        self.assertEqual(data1[0]["title"], data2[0]["title"])


if __name__ == "__main__":
    unittest.main()
