"""Tier 1: Category-Partition Feature Coverage Test Suite.

Tests CLI entry points:
- tanuki doctor [--json]
- tanuki triage <ERROR> [--json]
- tanuki ladder [--json]
- tanuki token [--json]
- tanuki nhi [--json]
and core engine interface contracts.
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
    """Either skip or fail depending on strict E2E mode."""
    if STRICT_E2E:
        test_case.fail(reason)
    else:
        test_case.skipTest(reason)


def is_cli_command_supported(cmd: str) -> bool:
    """Check if a subcommand is registered in tanuki CLI."""
    ret, stdout, _ = run_tanuki_cli(["-h"])
    return f"{cmd} " in stdout or f"{cmd}\n" in stdout or f"{cmd}[" in stdout


class TestTier1DoctorFeatures(unittest.TestCase):
    """Tier 1 tests for Feature: tanuki doctor (Pre-flight Diagnostic Engine)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _check_doctor_cli_supported(self) -> None:
        if not is_cli_command_supported("doctor"):
            skip_or_fail(self, "Command 'tanuki doctor' pending implementation in Milestone M1")

    def test_doctor_cli_default_clean_pass(self) -> None:
        """Category 1.1: Execution on healthy synthetic environment returns PASS/HEALTHY."""
        self._check_doctor_cli_supported()
        kt_path = os.path.join(self.dir_path, "krb5.keytab")
        with open(kt_path, "wb") as f:
            f.write(build_synthetic_keytab())
        conf_path = os.path.join(self.dir_path, "krb5.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(build_synthetic_krb5_conf(default_realm="CORP.LOCAL"))
        cc_path = os.path.join(self.dir_path, "krb5cc")
        now = int(time.time())
        creds = [{"authtime": now - 300, "starttime": now - 300, "endtime": now + 28800}]
        with open(cc_path, "wb") as f:
            f.write(build_synthetic_ccache(creds=creds))

        ret, stdout, stderr = run_tanuki_cli([
            "doctor",
            "--keytab", kt_path,
            "--krb5-conf", conf_path,
        ])
        self.assertEqual(ret, 0, f"Doctor CLI clean pass failed: {stderr}")
        self.assertIn("TANUKI PRE-FLIGHT DOCTOR", stdout)
        self.assertIn("OVERALL HEALTH:", stdout)

    def test_doctor_cli_json_schema(self) -> None:
        """Category 1.2: --json outputs valid JSON conforming to DoctorReport schema."""
        self._check_doctor_cli_supported()
        ret, stdout, stderr = run_tanuki_cli(["doctor", "--json"])
        self.assertEqual(ret, 0, f"Doctor --json failed with exit code {ret}: {stderr}")
        data = json.loads(stdout)
        self.assertIn("status", data)
        self.assertIn(data["status"], ["PASS", "WARN", "FAIL", "HEALTHY", "DEGRADED", "CRITICAL"])
        self.assertIn("checks", data)
        checks = data["checks"]
        self.assertIsInstance(checks, list)
        check_names = [c.get("name") for c in checks]
        for expected_name in ["keytab_permissions", "realm_capitalization", "sssd_subsystem", "ticket_lifetime"]:
            self.assertIn(expected_name, check_names, f"Missing check '{expected_name}' in doctor report")

    def test_doctor_insecure_keytab_permissions(self) -> None:
        """Category 1.3: Insecure keytab permissions (0644/0666) are flagged."""
        self._check_doctor_cli_supported()
        keytab_path = os.path.join(self.dir_path, "krb5.keytab")
        with open(keytab_path, "wb") as f:
            f.write(build_synthetic_keytab())
        os.chmod(keytab_path, 0o666)

        try:
            from tanuki.doctor import diagnose_system
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.doctor.diagnose_system pending implementation in Milestone M1")
            return

        report = diagnose_system(keytab_path=keytab_path)
        checks_dict = {c["name"]: c for c in report.checks}
        kt_check = checks_dict.get("keytab_permissions", {})
        if os.name != "nt":
            self.assertIn(kt_check.get("status"), ["WARN", "FAIL"])
            issues = " ".join(kt_check.get("issues", []))
            self.assertTrue("insecure" in issues.lower() or "permission" in issues.lower())
        else:
            self.assertTrue("permissions" in kt_check or "status" in kt_check)

    def test_doctor_lowercase_realm_flagged(self) -> None:
        """Category 1.4: Lowercase realm definitions in krb5.conf are detected."""
        conf_path = os.path.join(self.dir_path, "krb5.conf")
        content = build_synthetic_krb5_conf(default_realm="corp.local")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)

        try:
            from tanuki.doctor import diagnose_system
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.doctor.diagnose_system pending implementation in Milestone M1")
            return

        report = diagnose_system(krb5_conf_path=conf_path)
        checks_dict = {c["name"]: c for c in report.checks}
        conf_check = checks_dict.get("realm_capitalization", {})
        self.assertIn(conf_check.get("status"), ["WARN", "FAIL"])
        self.assertFalse(conf_check.get("is_realm_uppercase", True))

    def test_doctor_expired_ticket_flagged(self) -> None:
        """Category 1.5: Expired CCACHE tickets are identified with status EXPIRED."""
        ccache_path = os.path.join(self.dir_path, "krb5cc_test")
        past_epoch = int(time.time()) - 3600
        creds = [{"authtime": past_epoch - 3600, "starttime": past_epoch - 3600, "endtime": past_epoch}]
        with open(ccache_path, "wb") as f:
            f.write(build_synthetic_ccache(creds=creds))

        try:
            from tanuki.doctor import diagnose_system
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.doctor.diagnose_system pending implementation in Milestone M1")
            return

        try:
            report = diagnose_system(ccache_path=ccache_path)
        except TypeError as exc:
            self.fail(
                f"IMPLEMENTATION BUG ESCALATION (Worker M1): tanuki.doctor._read_principal crashed with '{exc}'. "
                "Line 480 compares 'len_b < 4' where len_b is bytes; should be 'len(len_b) < 4'."
            )
            return

        checks_dict = {c["name"]: c for c in report.checks}
        ticket_check = checks_dict.get("ticket_lifetime", {})
        self.assertIn(ticket_check.get("status"), ["EXPIRED", "WARN", "FAIL"])
        self.assertTrue(ticket_check.get("is_expired", False) or ticket_check.get("remaining_seconds", 0) <= 0)

    def test_doctor_sssd_kcm_socket_audit(self) -> None:
        """Category 1.6: SSSD KCM socket presence is verified."""
        fake_socket = os.path.join(self.dir_path, "nonexistent.sock")
        try:
            from tanuki.doctor import diagnose_system
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.doctor.diagnose_system pending implementation in Milestone M1")
            return

        report = diagnose_system(sssd_pipe=fake_socket)
        checks_dict = {c["name"]: c for c in report.checks}
        sssd_check = checks_dict.get("sssd_subsystem", {})
        self.assertFalse(sssd_check.get("kcm_socket_active", True))


class TestTier1TriageFeatures(unittest.TestCase):
    """Tier 1 tests for Feature: tanuki triage (Resolution & Detection Telemetry)."""

    def test_triage_cli_by_error_code(self) -> None:
        """Category 2.1: Single lookup by Kerberos error code renders root cause and resolution."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "KRB_AP_ERR_SKEW"])
        self.assertEqual(ret, 0, f"triage error lookup failed: {stderr}")
        self.assertIn("KRB_AP_ERR_SKEW", stdout)
        self.assertIn("Root Cause", stdout)

    def test_triage_cli_by_event_id(self) -> None:
        """Category 2.2: Single lookup by Event ID returns matching error."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "37", "--json"])
        self.assertEqual(ret, 0, f"triage event_id lookup failed: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data.get("code"), "KRB_AP_ERR_SKEW")
        self.assertEqual(data.get("event_id"), 37)

    def test_triage_cli_full_dictionary(self) -> None:
        """Category 2.3: Full dictionary view lists all known errors."""
        ret, stdout, stderr = run_tanuki_cli(["triage"])
        self.assertEqual(ret, 0, f"triage full dictionary failed: {stderr}")
        self.assertIn("KRB_AP_ERR_SKEW", stdout)
        self.assertIn("KDC_ERR_ETYPE_NOSUPP", stdout)
        self.assertIn("KDC_ERR_PREAUTH_FAILED", stdout)

    def test_triage_cli_full_dictionary_json(self) -> None:
        """Category 2.4: Full dictionary --json returns array of error objects."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "--json"])
        self.assertEqual(ret, 0, f"triage --json failed: {stderr}")
        data = json.loads(stdout)
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 10)
        codes = [item.get("code") for item in data]
        self.assertIn("KRB_AP_ERR_SKEW", codes)
        self.assertIn("KDC_ERR_C_PRINCIPAL_UNKNOWN", codes)

    def test_triage_case_insensitive_lookup(self) -> None:
        """Category 2.5: Lookup is case-insensitive."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "krb_ap_err_skew", "--json"])
        self.assertEqual(ret, 0, f"case-insensitive lookup failed: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data.get("code"), "KRB_AP_ERR_SKEW")

    def test_triage_telemetry_schema(self) -> None:
        """Category 2.6: Telemetry block contains auditd, event_ids, sigma, falco."""
        ret, stdout, stderr = run_tanuki_cli(["triage", "KRB_AP_ERR_SKEW", "--json"])
        self.assertEqual(ret, 0)
        data = json.loads(stdout)
        if "telemetry" not in data:
            skip_or_fail(self, "Telemetry block pending implementation in Milestone M2")
            return

        telemetry = data["telemetry"]
        self.assertIn("auditd", telemetry)
        self.assertIn("event_ids", telemetry)
        self.assertIn("sigma", telemetry)
        self.assertIn("falco", telemetry)
        self.assertIsInstance(telemetry["auditd"], list)
        self.assertIsInstance(telemetry["event_ids"], list)


class TestTier1LadderFeatures(unittest.TestCase):
    """Tier 1 tests for Feature: tanuki ladder (5-Rung Tactical Decision Ladder)."""

    def test_ladder_cli_terminal_output(self) -> None:
        """Category 3.1: tanuki ladder displays 5 rungs with tactical progression."""
        ret, stdout, stderr = run_tanuki_cli(["ladder"])
        self.assertEqual(ret, 0, f"ladder failed: {stderr}")
        self.assertIn("RUNG 1", stdout)
        self.assertIn("RUNG 2", stdout)
        self.assertIn("RUNG 3", stdout)
        self.assertIn("RUNG 4", stdout)
        self.assertIn("RUNG 5", stdout)

    def test_ladder_cli_json_output(self) -> None:
        """Category 3.2: tanuki ladder --json outputs list of 5 rungs."""
        ret, stdout, stderr = run_tanuki_cli(["ladder", "--json"])
        self.assertEqual(ret, 0, f"ladder --json failed: {stderr}")
        data = json.loads(stdout)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 5)
        for idx, rung in enumerate(data, 1):
            self.assertEqual(rung.get("rung"), idx)
            self.assertIn("title", rung)
            self.assertIn("description", rung)

    def test_ladder_all_rungs_present(self) -> None:
        """Category 3.3: Verifies titles match specification."""
        from tanuki.protocol import DECISION_LADDER
        self.assertEqual(len(DECISION_LADDER), 5)
        titles = [r["title"] for r in DECISION_LADDER]
        self.assertTrue(any("LOCAL PASSIVE TRIAGE" in t for t in titles))
        self.assertTrue(any("ZERO-NOISE OPSEC" in t for t in titles))
        self.assertTrue(any("MACHINE IDENTITY REUSE" in t for t in titles))
        self.assertTrue(any("SURGICAL PATHFINDING" in t for t in titles))
        self.assertTrue(any("DETERMINISTIC ONE-LINER" in t for t in titles))

    def test_ladder_rung5_format_validation(self) -> None:
        """Category 3.4: Rung 5 adheres to required output tags."""
        from tanuki.protocol import DECISION_LADDER
        rung5 = DECISION_LADDER[4]
        desc = rung5["description"]
        self.assertIn("[TARGET]", desc)
        self.assertIn("[PREREQUISITE]", desc)
        self.assertIn("[OPSEC RATIONALE]", desc)

    def test_ladder_telemetry_schema(self) -> None:
        """Category 3.5: Verifies telemetry field on decision ladder rungs."""
        from tanuki.protocol import DECISION_LADDER
        rung1 = DECISION_LADDER[0]
        if "telemetry" not in rung1:
            skip_or_fail(self, "Ladder telemetry blocks pending implementation in Milestone M2")
            return
        telemetry = rung1["telemetry"]
        self.assertIn("auditd", telemetry)
        self.assertIn("event_ids", telemetry)
        self.assertIn("sigma", telemetry)
        self.assertIn("falco", telemetry)


class TestTier1TokenFeatures(unittest.TestCase):
    """Tier 1 tests for Feature: tanuki token (Workload Identity Validator)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _check_token_cli_supported(self) -> None:
        if not is_cli_command_supported("token"):
            skip_or_fail(self, "Command 'tanuki token' pending implementation in Milestone M3")

    def test_token_cli_valid_k8s_workload(self) -> None:
        """Category 4.1: Valid Kubernetes ServiceAccount token reports VALID."""
        self._check_token_cli_supported()
        token = build_synthetic_jwt()
        ret, stdout, stderr = run_tanuki_cli(["token", token])
        self.assertEqual(ret, 0, f"Valid token failed: {stderr}")
        self.assertIn("WORKLOAD IDENTITY VALIDATOR", stdout)
        self.assertTrue("VALID" in stdout or "SAFE" in stdout)

    def test_token_cli_json_output(self) -> None:
        """Category 4.2: tanuki token <token> --json produces valid JSON report."""
        self._check_token_cli_supported()
        token = build_synthetic_jwt()
        ret, stdout, stderr = run_tanuki_cli(["token", token, "--json"])
        self.assertEqual(ret, 0, f"Token --json failed: {stderr}")
        data = json.loads(stdout)
        self.assertTrue(data.get("valid", False))
        self.assertIn("claims", data)
        self.assertEqual(data["claims"].get("sub"), "system:serviceaccount:production:payment-processor")

    def test_token_cli_expired_jwt(self) -> None:
        """Category 4.3: Expired JWT is detected and marked invalid/expired."""
        self._check_token_cli_supported()
        past = int(time.time()) - 7200
        token = build_synthetic_jwt(payload={"sub": "user1", "exp": past, "iat": past - 3600})
        ret, stdout, stderr = run_tanuki_cli(["token", token, "--json"])
        data = json.loads(stdout)
        self.assertFalse(data.get("valid", True))
        temporal = data.get("temporal", {})
        self.assertTrue(temporal.get("is_expired", False) or temporal.get("remaining_seconds", 0) <= 0)

    def test_token_cli_wildcard_audience_warning(self) -> None:
        """Category 4.4: Wildcard audience ('*') triggers security risk warning."""
        self._check_token_cli_supported()
        now = int(time.time())
        token = build_synthetic_jwt(payload={"sub": "user1", "aud": "*", "exp": now + 3600})
        ret, stdout, stderr = run_tanuki_cli(["token", token, "--json"])
        data = json.loads(stdout)
        eval_sec = data.get("security_evaluation", {})
        self.assertTrue(eval_sec.get("has_wildcard_audience", False))

    def test_token_cli_broad_subject_warning(self) -> None:
        """Category 4.5: Wildcard namespace in subject triggers broad scope warning."""
        self._check_token_cli_supported()
        now = int(time.time())
        token = build_synthetic_jwt(
            payload={"sub": "system:serviceaccount:*:admin", "aud": "https://sts.corp.local", "exp": now + 3600}
        )
        ret, stdout, stderr = run_tanuki_cli(["token", token, "--json"])
        data = json.loads(stdout)
        eval_sec = data.get("security_evaluation", {})
        self.assertTrue(eval_sec.get("has_broad_subject_scope", False))

    def test_token_cli_file_option(self) -> None:
        """Category 4.6: Token loaded via -f/--file option."""
        self._check_token_cli_supported()
        token = build_synthetic_jwt()
        token_path = os.path.join(self.temp_dir.name, "token.jwt")
        with open(token_path, "w", encoding="utf-8") as f:
            f.write(token)
        ret, stdout, stderr = run_tanuki_cli(["token", "-f", token_path, "--json"])
        self.assertEqual(ret, 0, f"Token file option failed: {stderr}")
        data = json.loads(stdout)
        self.assertTrue(data.get("valid", False))


class TestTier1NhiFeatures(unittest.TestCase):
    """Tier 1 tests for Feature: tanuki nhi (NHI Subcommand & RFC 8693 Exchange)."""

    def _check_nhi_cli_supported(self) -> None:
        if not is_cli_command_supported("nhi"):
            skip_or_fail(self, "Command 'tanuki nhi' pending implementation in Milestone M3")

    def test_nhi_inspect_token_cli(self) -> None:
        """Category 5.1: tanuki nhi inspect <token> parses workload token."""
        self._check_nhi_cli_supported()
        token = build_synthetic_jwt()
        ret, stdout, stderr = run_tanuki_cli(["nhi", "inspect", token])
        self.assertEqual(ret, 0, f"nhi inspect failed: {stderr}")
        self.assertIn("WORKLOAD IDENTITY VALIDATOR", stdout)

    def test_nhi_inspect_token_json(self) -> None:
        """Category 5.2: tanuki nhi inspect <token> --json produces JSON report."""
        self._check_nhi_cli_supported()
        token = build_synthetic_jwt()
        ret, stdout, stderr = run_tanuki_cli(["nhi", "inspect", token, "--json"])
        self.assertEqual(ret, 0, f"nhi inspect --json failed: {stderr}")
        data = json.loads(stdout)
        self.assertTrue(data.get("valid", False))
        self.assertIn("claims", data)

    def test_nhi_exchange_valid_rfc8693(self) -> None:
        """Category 5.3: RFC 8693 token exchange with valid parameters passes validation."""
        try:
            from tanuki.nhi import validate_token_exchange
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.nhi.validate_token_exchange pending implementation in Milestone M3")
            return

        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": build_synthetic_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "https://sts.corp.local",
        }
        report = validate_token_exchange(params)
        self.assertTrue(report.get("valid", False))

    def test_nhi_exchange_unsupported_grant(self) -> None:
        """Category 5.4: RFC 8693 token exchange rejects unsupported grant_type."""
        try:
            from tanuki.nhi import validate_token_exchange
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.nhi.validate_token_exchange pending implementation in Milestone M3")
            return

        params = {
            "grant_type": "authorization_code",
            "subject_token": build_synthetic_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        report = validate_token_exchange(params)
        self.assertFalse(report.get("valid", True))
        self.assertEqual(report.get("error"), "unsupported_grant_type")

    def test_nhi_exchange_missing_subject_token(self) -> None:
        """Category 5.5: RFC 8693 token exchange rejects missing subject_token."""
        try:
            from tanuki.nhi import validate_token_exchange
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.nhi.validate_token_exchange pending implementation in Milestone M3")
            return

        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        report = validate_token_exchange(params)
        self.assertFalse(report.get("valid", True))
        self.assertEqual(report.get("error"), "invalid_request")


if __name__ == "__main__":
    unittest.main()
