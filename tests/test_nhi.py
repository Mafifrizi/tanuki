"""Comprehensive Unit Tests for NHI and RFC 8693 Token Validation."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tanuki.nhi import (
    b64url_decode,
    decode_jwt_segment,
    detect_identity_type,
    format_exchange_report_terminal,
    format_token_report_terminal,
    parse_workload_jwt,
    validate_jwt_workload,
    validate_token_exchange,
    JwtValidationReport,
    TokenValidationReport,
)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def build_test_jwt(header=None, payload=None, sig=b"test_signature_bytes_1234") -> str:
    if header is None:
        header = {"alg": "RS256", "typ": "JWT", "kid": "key-2026"}
    if payload is None:
        now = int(time.time())
        payload = {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:production:payment-processor",
            "aud": "https://sts.corp.local",
            "exp": now + 3600,
            "nbf": now - 30,
            "iat": now,
        }
    h_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"{b64url_encode(h_bytes)}.{b64url_encode(p_bytes)}.{b64url_encode(sig)}"


class TestBase64UrlAndJwtParsing(unittest.TestCase):
    def test_b64url_decode_valid_padding_variants(self):
        # 1 byte -> 2 base64 chars (mod 2)
        self.assertEqual(b64url_decode("AQ"), b"\x01")
        # 2 bytes -> 3 base64 chars (mod 3)
        self.assertEqual(b64url_decode("AQI"), b"\x01\x02")
        # 3 bytes -> 4 base64 chars (mod 0)
        self.assertEqual(b64url_decode("AQID"), b"\x01\x02\x03")

    def test_b64url_decode_urlsafe_characters(self):
        # '-' is 62 (0x3e), '_' is 63 (0x3f)
        data = b"\xfb\xff\xfe"
        encoded = b64url_encode(data)
        self.assertTrue("-" in encoded or "_" in encoded)
        self.assertEqual(b64url_decode(encoded), data)

    def test_b64url_decode_modulo_1_raises_error(self):
        with self.assertRaises(ValueError):
            b64url_decode("A")
        with self.assertRaises(ValueError):
            b64url_decode("AAAAA")

    def test_decode_jwt_segment_valid_json(self):
        obj = {"key": "value", "num": 42}
        encoded = b64url_encode(json.dumps(obj).encode("utf-8"))
        decoded = decode_jwt_segment(encoded)
        self.assertEqual(decoded, obj)

    def test_decode_jwt_segment_non_dict_json_raises_error(self):
        encoded = b64url_encode(b"[1, 2, 3]")
        with self.assertRaises(ValueError):
            decode_jwt_segment(encoded)

    def test_parse_workload_jwt_valid_three_parts(self):
        token = build_test_jwt()
        parsed = parse_workload_jwt(token)
        self.assertIn("header", parsed)
        self.assertIn("payload", parsed)
        self.assertIn("signature_raw", parsed)
        self.assertEqual(parsed["header"]["alg"], "RS256")
        self.assertEqual(parsed["payload"]["sub"], "system:serviceaccount:production:payment-processor")

    def test_parse_workload_jwt_invalid_segment_count(self):
        with self.assertRaises(ValueError):
            parse_workload_jwt("header.payload")
        with self.assertRaises(ValueError):
            parse_workload_jwt("header.payload.signature.extra")
        with self.assertRaises(ValueError):
            parse_workload_jwt("")


class TestIdentityTypeDetection(unittest.TestCase):
    def test_kubernetes_service_account(self):
        claims = {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:kube-system:coredns",
        }
        self.assertEqual(detect_identity_type(claims), "Kubernetes ServiceAccount Token")

    def test_github_actions_oidc(self):
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:owner/repo:ref:refs/heads/main",
        }
        self.assertEqual(detect_identity_type(claims), "GitHub Actions OIDC Token")

    def test_spiffe_svid(self):
        claims = {
            "iss": "spiffe://example.org",
            "sub": "spiffe://example.org/ns/prod/sa/app",
        }
        self.assertEqual(detect_identity_type(claims), "SPIFFE SVID")

    def test_aws_iam_workload(self):
        claims = {
            "iss": "https://rolesanywhere.amazonaws.com",
            "sub": "arn:aws:iam::123456789012:role/WorkloadRole",
        }
        self.assertEqual(detect_identity_type(claims), "AWS IAM Workload Identity")

    def test_generic_workload(self):
        claims = {"iss": "https://auth.company.com", "sub": "user_id_123"}
        self.assertEqual(detect_identity_type(claims), "Workload Identity Token")


class TestWorkloadJwtValidation(unittest.TestCase):
    def test_valid_token_clean_pass(self):
        token = build_test_jwt()
        report = validate_jwt_workload(token, expected_aud="https://sts.corp.local")
        self.assertTrue(report.get("valid"))
        self.assertEqual(report.get("identity_type"), "Kubernetes ServiceAccount Token")
        temporal = report.get("temporal", {})
        self.assertFalse(temporal.get("is_expired"))
        self.assertGreater(temporal.get("remaining_seconds", 0), 3000)
        self.assertTrue(temporal.get("is_ephemeral"))
        eval_sec = report.get("security_evaluation", {})
        self.assertFalse(eval_sec.get("has_wildcard_audience"))
        self.assertFalse(eval_sec.get("has_broad_subject_scope"))
        self.assertFalse(eval_sec.get("insecure_algorithm"))
        self.assertEqual(eval_sec.get("risk_level"), "LOW")

    def test_expired_token_detected(self):
        past = int(time.time()) - 1000
        token = build_test_jwt(payload={"sub": "worker", "exp": past, "iat": past - 3600})
        report = validate_jwt_workload(token)
        self.assertFalse(report.get("valid"))
        temporal = report.get("temporal", {})
        self.assertTrue(temporal.get("is_expired"))
        self.assertEqual(temporal.get("remaining_human"), "Expired")

    def test_missing_exp_claim(self):
        token = build_test_jwt(payload={"sub": "worker", "aud": "https://target.com"})
        report = validate_jwt_workload(token)
        self.assertFalse(report.get("valid"))
        temporal = report.get("temporal", {})
        self.assertIsNone(temporal.get("is_expired"))
        self.assertEqual(temporal.get("remaining_human"), "No Expiration")

    def test_token_not_yet_valid_nbf(self):
        future = int(time.time()) + 600
        token = build_test_jwt(payload={"sub": "worker", "aud": "https://target.com", "exp": future + 3600, "nbf": future})
        report = validate_jwt_workload(token)
        self.assertFalse(report.get("valid"))
        self.assertTrue(any("TOKEN_NOT_YET_VALID" in w for w in report.get("security_warnings", [])))

    def test_excessive_lifetime_not_ephemeral(self):
        now = int(time.time())
        token = build_test_jwt(payload={"sub": "worker", "aud": "https://target.com", "exp": now + 100000, "iat": now})
        report = validate_jwt_workload(token)
        temporal = report.get("temporal", {})
        self.assertFalse(temporal.get("is_ephemeral"))
        self.assertTrue(any("EXCESSIVE_LIFETIME" in w for w in report.get("security_warnings", [])))

    def test_wildcard_audience_policy(self):
        now = int(time.time())
        # aud == "*"
        token1 = build_test_jwt(payload={"sub": "worker", "aud": "*", "exp": now + 3600})
        rep1 = validate_jwt_workload(token1)
        self.assertTrue(rep1.get("security_evaluation", {}).get("has_wildcard_audience"))

        # aud in list with "*"
        token2 = build_test_jwt(payload={"sub": "worker", "aud": ["serviceA", "*"], "exp": now + 3600})
        rep2 = validate_jwt_workload(token2)
        self.assertTrue(rep2.get("security_evaluation", {}).get("has_wildcard_audience"))

        # missing aud
        token3 = build_test_jwt(payload={"sub": "worker", "exp": now + 3600})
        rep3 = validate_jwt_workload(token3)
        self.assertTrue(rep3.get("security_evaluation", {}).get("has_wildcard_audience"))

    def test_expected_audience_mismatch(self):
        now = int(time.time())
        token = build_test_jwt(payload={"sub": "worker", "aud": "https://sts.corp.local", "exp": now + 3600})
        rep = validate_jwt_workload(token, expected_aud="https://other.corp.local")
        self.assertFalse(rep.get("valid"))
        self.assertTrue(any("AUDIENCE_MISMATCH" in w for w in rep.get("security_warnings", [])))

    def test_broad_subject_patterns(self):
        now = int(time.time())
        # K8s wildcard namespace
        k8s_token = build_test_jwt(payload={"sub": "system:serviceaccount:*:admin", "aud": "target", "exp": now + 3600})
        rep_k8s = validate_jwt_workload(k8s_token)
        self.assertTrue(rep_k8s.get("security_evaluation", {}).get("has_broad_subject_scope"))

        # GitHub wildcard repo
        gh_token = build_test_jwt(payload={"sub": "repo:org/*:ref:refs/heads/main", "aud": "target", "exp": now + 3600})
        rep_gh = validate_jwt_workload(gh_token)
        self.assertTrue(rep_gh.get("security_evaluation", {}).get("has_broad_subject_scope"))

        # SPIFFE wildcard
        spiffe_token = build_test_jwt(payload={"sub": "spiffe://domain.com/*", "aud": "target", "exp": now + 3600})
        rep_spiffe = validate_jwt_workload(spiffe_token)
        self.assertTrue(rep_spiffe.get("security_evaluation", {}).get("has_broad_subject_scope"))

    def test_insecure_algorithm_none(self):
        token = build_test_jwt(header={"alg": "none", "typ": "JWT"})
        rep = validate_jwt_workload(token)
        eval_sec = rep.get("security_evaluation", {})
        self.assertTrue(eval_sec.get("insecure_algorithm"))
        self.assertIn(eval_sec.get("risk_level"), ["HIGH", "CRITICAL"])

    def test_symmetric_algorithm_warning(self):
        token = build_test_jwt(header={"alg": "HS256", "typ": "JWT"})
        rep = validate_jwt_workload(token)
        self.assertTrue(any("SYMMETRIC_ALGORITHM" in w for w in rep.get("security_warnings", [])))


class TestRfc8693TokenExchange(unittest.TestCase):
    def test_valid_token_exchange_request(self):
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": build_test_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "https://sts.corp.local",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        report = validate_token_exchange(params)
        self.assertTrue(report.get("valid"))
        self.assertTrue(report.get("exchange_valid"))
        self.assertIsNone(report.get("error"))
        self.assertIn("subject_token_report", report)

    def test_unsupported_grant_type(self):
        params = {
            "grant_type": "client_credentials",
            "subject_token": build_test_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        report = validate_token_exchange(params)
        self.assertFalse(report.get("valid"))
        self.assertEqual(report.get("error"), "unsupported_grant_type")

    def test_missing_grant_type(self):
        params = {
            "subject_token": build_test_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        report = validate_token_exchange(params)
        self.assertFalse(report.get("valid"))
        self.assertEqual(report.get("error"), "invalid_request")

    def test_missing_subject_token(self):
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        report = validate_token_exchange(params)
        self.assertFalse(report.get("valid"))
        self.assertEqual(report.get("error"), "invalid_request")

    def test_unsupported_subject_token_type(self):
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": build_test_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:unknown",
        }
        report = validate_token_exchange(params)
        self.assertFalse(report.get("valid"))
        self.assertEqual(report.get("error"), "invalid_request")

    def test_wildcard_audience_warning_in_exchange(self):
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": build_test_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "*",
        }
        report = validate_token_exchange(params)
        warnings = report.get("security_warnings", [])
        self.assertTrue(any("wildcard" in w.lower() for w in warnings))

    def test_expired_subject_token_returns_invalid_grant(self):
        past = int(time.time()) - 3600
        expired_token = build_test_jwt(payload={"sub": "worker", "exp": past, "iat": past - 1800})
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": expired_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        report = validate_token_exchange(params)
        self.assertFalse(report.get("valid"))
        self.assertEqual(report.get("error"), "invalid_grant")


class TestTerminalFormatting(unittest.TestCase):
    def test_format_token_report_terminal(self):
        token = build_test_jwt()
        report = validate_jwt_workload(token)
        output = format_token_report_terminal(report)
        self.assertIn("TANUKI WORKLOAD IDENTITY VALIDATOR", output)
        self.assertIn("Kubernetes ServiceAccount Token", output)
        self.assertIn("OVERALL ASSESSMENT", output)

    def test_format_exchange_report_terminal(self):
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": build_test_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        report = validate_token_exchange(params)
        output = format_exchange_report_terminal(report)
        self.assertIn("TOKEN EXCHANGE VALIDATION REPORT", output)
        self.assertIn("VALID", output)


class TestCliIntegration(unittest.TestCase):
    def run_cli(self, args, stdin_data=None):
        cmd = [sys.executable, "-m", "tanuki"] + args
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        env = os.environ.copy()
        env["PYTHONPATH"] = root
        proc = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True, cwd=root)
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_token_command_valid(self):
        token = build_test_jwt()
        ret, stdout, stderr = self.run_cli(["token", token])
        self.assertEqual(ret, 0)
        self.assertIn("WORKLOAD IDENTITY VALIDATOR", stdout)

    def test_cli_token_command_json(self):
        token = build_test_jwt()
        ret, stdout, stderr = self.run_cli(["token", token, "--json"])
        self.assertEqual(ret, 0)
        data = json.loads(stdout)
        self.assertTrue(data.get("valid"))
        self.assertIn("claims", data)

    def test_cli_token_from_file(self):
        token = build_test_jwt()
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jwt") as tf:
            tf.write(token)
            tf_path = tf.name

        try:
            ret, stdout, stderr = self.run_cli(["token", "-f", tf_path, "--json"])
            self.assertEqual(ret, 0)
            data = json.loads(stdout)
            self.assertTrue(data.get("valid"))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_cli_nhi_inspect_subcommand(self):
        token = build_test_jwt()
        ret, stdout, stderr = self.run_cli(["nhi", "inspect", token])
        self.assertEqual(ret, 0)
        self.assertIn("WORKLOAD IDENTITY VALIDATOR", stdout)

    def test_cli_nhi_scan_subcommand(self):
        ret, stdout, stderr = self.run_cli(["nhi", "scan", "--json"])
        self.assertEqual(ret, 0)
        data = json.loads(stdout)
        self.assertIn("discovered_tokens", data)


if __name__ == "__main__":
    unittest.main()
