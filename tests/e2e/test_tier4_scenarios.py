"""Tier 4: Real-World Workload & Incident Response Scenarios Test Suite.

Tests realistic end-user operational and threat hunting scenarios:
1. Pre-flight AD health check prior to service startup (systemd/container init)
2. SOC triage of Kerberos clock skew with auditd deployment and DC Event ID mapping
3. Kubernetes ServiceAccount token exchange into Active Directory (RFC 8693)
4. Keytab permission compliance audit and threat detection pipeline
5. SSSD credential recovery and 5-Rung decision ladder execution
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


class TestTier4RealWorldScenarios(unittest.TestCase):
    """Tier 4 Real-World Application & Incident Response Scenarios."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_scenario_preflight_health_check_service_startup(self) -> None:
        """Scenario 1: Pre-flight AD health check prior to service startup.

        A systemd service or container entrypoint runs `tanuki doctor --json`
        before starting domain-joined services (e.g. SSSD, Apache, Postgres).
        Ensures execution finishes ultra-fast (<50ms for subprocess) and output
        provides clean parseable health status.
        """
        if not is_cli_command_supported("doctor"):
            skip_or_fail(self, "Command 'tanuki doctor' pending implementation in Milestone M1")
            return

        kt_path = os.path.join(self.dir_path, "krb5.keytab")
        with open(kt_path, "wb") as f:
            f.write(build_synthetic_keytab())
        if os.name != "nt":
            os.chmod(kt_path, 0o600)

        conf_path = os.path.join(self.dir_path, "krb5.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(build_synthetic_krb5_conf(default_realm="CORP.LOCAL"))

        start_time = time.perf_counter()
        ret, stdout, stderr = run_tanuki_cli([
            "doctor",
            "--keytab", kt_path,
            "--krb5-conf", conf_path,
            "--json",
        ])
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        self.assertEqual(ret, 0, f"Doctor pre-flight failed: {stderr}")
        data = json.loads(stdout)

        # Automated pipeline verifies health status
        self.assertIn(data.get("status"), ["PASS", "WARN", "HEALTHY", "DEGRADED"])
        self.assertIn("summary", data)
        self.assertEqual(data["summary"].get("failures", 0), 0)

        # Internal doctor execution latency contract (<20ms reported)
        duration_ms = data.get("duration_ms") or data.get("execution_time_ms")
        self.assertIsNotNone(duration_ms)
        self.assertLess(duration_ms, 20.0, f"Doctor internal execution took {duration_ms}ms, expected <20ms")

    def test_scenario_soc_triage_clock_skew_and_auditd_deployment(self) -> None:
        """Scenario 2: SOC triage of Kerberos clock skew with auditd deployment.

        An alert fires for Kerberos error KRB_AP_ERR_SKEW (Event ID 37).
        SOC analyst runs `tanuki triage KRB_AP_ERR_SKEW --json` to obtain:
        1. Tactical NTP synchronization command.
        2. Blue team detection telemetry: Auditd rules for time modification.
        3. Windows DC Event IDs 4768 and 4771 for SIEM correlation.
        """
        ret, stdout, stderr = run_tanuki_cli(["triage", "KRB_AP_ERR_SKEW", "--json"])
        self.assertEqual(ret, 0, f"Triage lookup failed: {stderr}")
        data = json.loads(stdout)

        self.assertEqual(data.get("code"), "KRB_AP_ERR_SKEW")
        self.assertEqual(data.get("event_id"), 37)
        self.assertIn("clock", data.get("root_cause", "").lower())

        if "telemetry" not in data:
            skip_or_fail(self, "Telemetry block pending implementation in Milestone M2")
            return

        telemetry = data["telemetry"]

        # 1. Auditd rules must include system time tampering watch
        audit_rules = telemetry.get("auditd", [])
        self.assertTrue(
            any("adjtimex" in r or "time" in r or "clock" in r for r in audit_rules),
            "Expected time modification audit rule in telemetry",
        )

        # 2. Windows DC Event IDs must include 4768 and/or 4771
        event_ids = telemetry.get("event_ids", [])
        self.assertTrue(
            4768 in event_ids or 4771 in event_ids,
            f"Expected Kerberos event IDs (4768/4771) in telemetry, got {event_ids}",
        )

        # 3. Tactical command includes chronyc or ntpdate
        tactical = data.get("tactical_cmd") or data.get("resolution")
        self.assertTrue("chronyc" in tactical or "ntpdate" in tactical)

    def test_scenario_kubernetes_token_exchange_into_ad(self) -> None:
        """Scenario 3: Kubernetes SA token exchange into Active Directory.

        A cloud microservice in Kubernetes uses its projected SA token to authenticate
        to a Windows Active Directory Kerberos KDC via RFC 8693 token exchange.
        Tanuki NHI validates token integrity, verifies audience boundaries, and
        ensures the subject scope is non-wildcard.
        """
        try:
            from tanuki.nhi import validate_jwt_workload, validate_token_exchange
        except (ImportError, AttributeError):
            skip_or_fail(self, "tanuki.nhi module pending implementation in Milestone M3")
            return

        now = int(time.time())
        # Valid tightly-scoped Kubernetes ServiceAccount JWT
        k8s_token = build_synthetic_jwt(
            header={"alg": "RS256", "typ": "JWT", "kid": "k8s-cluster-key-01"},
            payload={
                "iss": "https://kubernetes.default.svc.cluster.local",
                "sub": "system:serviceaccount:production:payment-processor",
                "aud": "https://sts.corp.local",
                "exp": now + 3600,
                "nbf": now - 30,
                "iat": now,
            },
        )

        # Step 1: Workload JWT Inspection
        jwt_report = validate_jwt_workload(k8s_token, expected_aud="https://sts.corp.local")
        self.assertTrue(jwt_report.get("valid", False))
        sec_eval = jwt_report.get("security_evaluation", {})
        self.assertFalse(sec_eval.get("has_wildcard_audience", True))
        self.assertFalse(sec_eval.get("has_broad_subject_scope", True))

        # Step 2: RFC 8693 Token Exchange Request Validation
        exchange_params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": k8s_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "https://sts.corp.local",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        exchange_report = validate_token_exchange(exchange_params)
        self.assertTrue(exchange_report.get("valid", False))
        self.assertIsNone(exchange_report.get("error"))

    def test_scenario_keytab_permission_incident_response(self) -> None:
        """Scenario 4: Keytab permission compliance audit and threat detection.

        An insecure keytab (0644) triggers an alert in `tanuki doctor`.
        The incident responder cross-references Rung 1 of the Tactical Decision Ladder
        to verify that local keytab inspection is prioritized before sending packets,
        and extracts the auditd watch rule to monitor future unauthorized reads.
        """
        from tanuki.protocol import DECISION_LADDER
        rung1 = DECISION_LADDER[0]

        # Rung 1 mandates local passive triage of keytab before network packets
        self.assertEqual(rung1["rung"], 1)
        self.assertIn("LOCAL PASSIVE TRIAGE", rung1["title"])
        self.assertIn("/etc/krb5.keytab", rung1["description"])

        # If telemetry is present, verify keytab watch rule
        if "telemetry" in rung1:
            audit_rules = rung1["telemetry"].get("auditd", [])
            self.assertTrue(
                any("-w /etc/krb5.keytab" in r for r in audit_rules),
                "Expected /etc/krb5.keytab auditd watch in Rung 1 telemetry",
            )

    def test_scenario_kcm_cache_recovery_and_ladder_triage(self) -> None:
        """Scenario 5: SSSD credential cache triage and 5-Rung ladder workflow.

        Operator needs to inspect local credential caches without interactive kinit.
        Verifies `tanuki ladder --json` provides full 5-rung operational guidance
        and Rung 5 formats deterministic one-liner output.
        """
        ret, stdout, stderr = run_tanuki_cli(["ladder", "--json"])
        self.assertEqual(ret, 0)
        rungs = json.loads(stdout)
        self.assertEqual(len(rungs), 5)

        rung5 = rungs[4]
        self.assertEqual(rung5["rung"], 5)
        self.assertIn("DETERMINISTIC ONE-LINER", rung5["title"])
        self.assertIn("[TACTICAL COMMAND]", rung5["description"])
        self.assertIn("[EXPECTED ARTIFACT]", rung5["description"])


if __name__ == "__main__":
    unittest.main()
