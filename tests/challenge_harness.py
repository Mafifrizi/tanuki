"""Empirical Challenge Harness for Milestone 3 (NHI Token Validator RFC 8693).

Written by Challenger 1 to empirically stress-test and verify:
1. CLI subcommands 'tanuki token' and 'tanuki nhi' in both text and --json modes.
2. Token input via direct argument, -f/--file, and stdin pipe.
3. RFC 8693 token exchange parameter errors (unsupported_grant_type, invalid_request, invalid_grant).
4. JSON output schema conformance against PROJECT.md specification.
5. Edge cases: corrupt tokens, padding variations, oversized payloads, unicode, algorithm none.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)

from tanuki.nhi import (
    RFC8693_TOKEN_EXCHANGE_GRANT,
    SUPPORTED_TOKEN_TYPES,
    b64url_decode,
    decode_jwt_segment,
    detect_identity_type,
    parse_workload_jwt,
    validate_jwt_workload,
    validate_token_exchange,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def create_jwt(header: dict = None, claims: dict = None, sig: bytes = b"sig123") -> str:
    if header is None:
        header = {"alg": "RS256", "typ": "JWT", "kid": "k1"}
    if claims is None:
        now = int(time.time())
        claims = {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:default:my-app",
            "aud": "https://sts.corp.local",
            "exp": now + 3600,
            "iat": now,
            "nbf": now - 10,
        }
    h_str = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    c_str = b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    s_str = b64url(sig)
    return f"{h_str}.{c_str}.{s_str}"


def run_cli(args: list, stdin_data: str = None) -> tuple:
    cmd = [sys.executable, "-m", "tanuki"] + args
    if stdin_data is not None:
        proc = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            input=stdin_data,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=5,
        )
    else:
        proc = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=5,
        )
    return proc.returncode, proc.stdout, proc.stderr


class TestCliSubcommandsAndModes(unittest.TestCase):
    """Challenge 1: CLI subcommands in text and --json modes."""

    def test_token_plain_text_valid(self):
        jwt = create_jwt()
        code, out, err = run_cli(["token", jwt])
        self.assertEqual(code, 0, f"CLI error: {err}")
        self.assertIn("TANUKI WORKLOAD IDENTITY VALIDATOR", out)
        self.assertIn("OVERALL ASSESSMENT: VALID & SECURE", out)
        self.assertIn("Kubernetes ServiceAccount Token", out)

    def test_token_json_valid(self):
        jwt = create_jwt()
        code, out, err = run_cli(["token", jwt, "--json"])
        self.assertEqual(code, 0, f"CLI error: {err}")
        parsed = json.loads(out)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["header"]["alg"], "RS256")
        self.assertEqual(parsed["claims"]["aud"], "https://sts.corp.local")
        self.assertEqual(parsed["security_evaluation"]["risk_level"], "LOW")
        self.assertTrue(isinstance(parsed["security_warnings"], list))

    def test_nhi_inspect_plain_text(self):
        jwt = create_jwt()
        code, out, err = run_cli(["nhi", "inspect", jwt])
        self.assertEqual(code, 0, f"CLI error: {err}")
        self.assertIn("TANUKI WORKLOAD IDENTITY VALIDATOR", out)
        self.assertIn("OVERALL ASSESSMENT: VALID & SECURE", out)

    def test_nhi_inspect_json(self):
        jwt = create_jwt()
        code, out, err = run_cli(["nhi", "inspect", jwt, "--json"])
        self.assertEqual(code, 0, f"CLI error: {err}")
        parsed = json.loads(out)
        self.assertTrue(parsed["valid"])
        self.assertIn("identity_type", parsed)

    def test_nhi_scan_plain_text(self):
        code, out, err = run_cli(["nhi", "scan"])
        self.assertEqual(code, 0, f"CLI error: {err}")
        self.assertIn("TANUKI NHI PASSIVE TOKEN SCANNER", out)

    def test_nhi_scan_json(self):
        code, out, err = run_cli(["nhi", "scan", "--json"])
        self.assertEqual(code, 0, f"CLI error: {err}")
        parsed = json.loads(out)
        self.assertIn("discovered_tokens", parsed)
        self.assertTrue(isinstance(parsed["discovered_tokens"], list))


class TestTokenInputMethods(unittest.TestCase):
    """Challenge 2: Token input via argument, -f/--file, and stdin pipe."""

    def setUp(self):
        self.jwt = create_jwt()
        self.temp_file = tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8")
        self.temp_file.write(self.jwt)
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_input_via_positional_arg(self):
        code, out, err = run_cli(["token", self.jwt, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["valid"])

    def test_input_via_f_flag(self):
        code, out, err = run_cli(["token", "-f", self.temp_file.name, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["valid"])

    def test_input_via_file_long_flag(self):
        code, out, err = run_cli(["token", "--file", self.temp_file.name, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["valid"])

    def test_input_via_stdin_pipe_token(self):
        code, out, err = run_cli(["token", "--json"], stdin_data=self.jwt)
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["valid"])

    def test_input_via_stdin_pipe_nhi_inspect(self):
        code, out, err = run_cli(["nhi", "inspect", "--json"], stdin_data=self.jwt)
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["valid"])

    def test_missing_input_exits_with_code_1(self):
        code, out, err = run_cli(["token"])
        self.assertEqual(code, 1)
        self.assertIn("No token provided", err)

    def test_nonexistent_file_exits_with_code_1(self):
        code, out, err = run_cli(["token", "-f", "non_existent_token_file_xyz.jwt"])
        self.assertEqual(code, 1)
        self.assertIn("Token file not found", err)

    def test_empty_file_exits_with_code_1(self):
        empty_tmp = tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8")
        empty_tmp.close()
        try:
            code, out, err = run_cli(["token", "-f", empty_tmp.name])
            self.assertEqual(code, 1)
            self.assertIn("No token provided", err)
        finally:
            if os.path.exists(empty_tmp.name):
                os.remove(empty_tmp.name)


class TestRfc8693TokenExchangeErrors(unittest.TestCase):
    """Challenge 3: RFC 8693 parameter validation & error responses."""

    def setUp(self):
        self.jwt = create_jwt()
        now = int(time.time())
        self.expired_jwt = create_jwt(claims={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:prod:expired-worker",
            "aud": "https://sts.corp.local",
            "exp": now - 300,
            "iat": now - 3600,
        })

    def test_unsupported_grant_type_returns_proper_error(self):
        # RFC 8693 Section 2.2.2: unsupported_grant_type
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", "client_credentials",
            "--subject-token", self.jwt,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertFalse(report["exchange_valid"])
        self.assertEqual(report["error"], "unsupported_grant_type")
        self.assertIn("Unsupported grant_type", report["error_description"])

    def test_missing_grant_type_returns_invalid_request(self):
        # Missing grant_type must fail with invalid_request
        code, out, err = run_cli([
            "nhi", "exchange",
            "--subject-token", self.jwt,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertEqual(report["error"], "invalid_request")
        self.assertIn("grant_type", report["error_description"])

    def test_missing_subject_token_returns_invalid_request(self):
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertEqual(report["error"], "invalid_request")
        self.assertIn("subject_token", report["error_description"])

    def test_missing_subject_token_type_returns_invalid_request(self):
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", self.jwt,
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertEqual(report["error"], "invalid_request")
        self.assertIn("subject_token_type", report["error_description"])

    def test_unsupported_subject_token_type_returns_invalid_request(self):
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", self.jwt,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:unsupported_format",
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertEqual(report["error"], "invalid_request")
        self.assertIn("Unsupported subject_token_type", report["error_description"])

    def test_unsupported_requested_token_type_returns_invalid_request(self):
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", self.jwt,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--requested-token-type", "urn:ietf:params:oauth:token-type:bogus",
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertEqual(report["error"], "invalid_request")
        self.assertIn("Unsupported requested_token_type", report["error_description"])

    def test_expired_subject_token_returns_invalid_grant(self):
        # RFC 8693 Section 2.2.2: invalid_grant
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", self.expired_jwt,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertEqual(report["error"], "invalid_grant")
        self.assertIn("expired", report["error_description"])

    def test_malformed_jwt_subject_token_returns_invalid_request(self):
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", "not-a-jwt.part2",
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--json",
        ])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["valid"])
        self.assertEqual(report["error"], "invalid_request")
        self.assertIn("Failed to parse subject_token JWT", report["error_description"])


class TestSchemaConformanceAgainstProjectMd(unittest.TestCase):
    """Challenge 4: Schema verification against PROJECT.md interface contract."""

    def test_token_exchange_schema_keys(self):
        # Valid token exchange request
        jwt = create_jwt()
        code, out, err = run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", jwt,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--audience", "https://kerberos.ad.corp.local",
            "--json",
        ])
        self.assertEqual(code, 0)
        report = json.loads(out)

        # Expected top-level keys in PROJECT.md:
        # valid, exchange_valid, error, error_description, parameters, security_warnings, subject_token_report
        self.assertIn("valid", report)
        self.assertIn("exchange_valid", report)
        self.assertIn("error", report)
        self.assertIn("security_warnings", report)
        self.assertTrue(isinstance(report["valid"], bool))
        self.assertTrue(isinstance(report["exchange_valid"], bool))
        self.assertTrue(isinstance(report["security_warnings"], list))

        # Check subject_token_report sub-schema
        sub_rep = report.get("subject_token_report")
        self.assertIsNotNone(sub_rep)
        self.assertIn("header", sub_rep)
        self.assertIn("claims", sub_rep)
        self.assertIn("temporal", sub_rep)
        self.assertIn("security_evaluation", sub_rep)
        self.assertEqual(sub_rep["header"]["alg"], "RS256")
        self.assertEqual(sub_rep["claims"]["aud"], "https://sts.corp.local")

    def test_workload_jwt_schema_keys(self):
        jwt = create_jwt()
        code, out, err = run_cli(["token", jwt, "--json"])
        self.assertEqual(code, 0)
        rep = json.loads(out)

        # Verify exact fields required by PROJECT.md
        self.assertIn("valid", rep)
        self.assertIn("header", rep)
        self.assertIn("claims", rep)
        self.assertIn("security_warnings", rep)
        self.assertIn("temporal", rep)
        self.assertIn("security_evaluation", rep)

        # Claims must contain standard RFC 7519 / workload claims
        claims = rep["claims"]
        self.assertIn("iss", claims)
        self.assertIn("sub", claims)
        self.assertIn("aud", claims)
        self.assertIn("exp", claims)


class TestAdversarialAndEdgeCases(unittest.TestCase):
    """Challenge 5: Adversarial, boundary and fuzz-style cases."""

    def test_alg_none_token_rejected_as_insecure(self):
        jwt = create_jwt(header={"alg": "none", "typ": "JWT"})
        rep = validate_jwt_workload(jwt)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["insecure_algorithm"])
        self.assertEqual(rep["security_evaluation"]["risk_level"], "CRITICAL")
        self.assertTrue(any("INSECURE_ALGORITHM" in w for w in rep["security_warnings"]))

    def test_wildcard_audience_token_rejected(self):
        now = int(time.time())
        jwt = create_jwt(claims={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:default:worker",
            "aud": "*",
            "exp": now + 3600,
        })
        rep = validate_jwt_workload(jwt)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_wildcard_audience"])
        self.assertEqual(rep["security_evaluation"]["risk_level"], "CRITICAL")
        self.assertTrue(any("WILDCARD_AUDIENCE" in w for w in rep["security_warnings"]))

    def test_wildcard_namespace_k8s_subject_rejected(self):
        now = int(time.time())
        jwt = create_jwt(claims={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:*:admin-account",
            "aud": "https://sts.corp.local",
            "exp": now + 3600,
        })
        rep = validate_jwt_workload(jwt)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        self.assertEqual(rep["security_evaluation"]["risk_level"], "CRITICAL")

    def test_spiffe_wildcard_subject_rejected(self):
        now = int(time.time())
        jwt = create_jwt(claims={
            "iss": "spiffe://domain.local",
            "sub": "spiffe://domain.local/ns/*/sa/app",
            "aud": "https://sts.corp.local",
            "exp": now + 3600,
        })
        rep = validate_jwt_workload(jwt)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        self.assertEqual(rep["security_evaluation"]["risk_level"], "CRITICAL")

    def test_token_future_nbf_rejected(self):
        now = int(time.time())
        jwt = create_jwt(claims={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:prod:app",
            "aud": "https://sts.corp.local",
            "exp": now + 3600,
            "nbf": now + 1000,
        })
        rep = validate_jwt_workload(jwt)
        self.assertFalse(rep["valid"])
        self.assertTrue(any("TOKEN_NOT_YET_VALID" in w for w in rep["security_warnings"]))

    def test_excessive_lifetime_triggers_warning_not_ephemeral(self):
        now = int(time.time())
        jwt = create_jwt(claims={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:prod:app",
            "aud": "https://sts.corp.local",
            "iat": now,
            "exp": now + (86400 * 7),  # 7 days
        })
        rep = validate_jwt_workload(jwt)
        self.assertFalse(rep["temporal"]["is_ephemeral"])
        self.assertTrue(any("EXCESSIVE_LIFETIME" in w for w in rep["security_warnings"]))

    def test_malformed_base64_mod1_length_fails_gracefully(self):
        with self.assertRaises(ValueError):
            b64url_decode("abcde")  # len 5 -> 5 % 4 = 1, illegal base64

    def test_jwt_with_four_dots_rejected(self):
        with self.assertRaises(ValueError):
            parse_workload_jwt("part1.part2.part3.part4")

    def test_jwt_with_one_dot_rejected(self):
        with self.assertRaises(ValueError):
            parse_workload_jwt("part1.part2")

    def test_jwt_with_garbage_characters_rejected(self):
        code, out, err = run_cli(["token", "invalid???token$$$"])
        self.assertEqual(code, 4)
        self.assertIn("Error parsing token", err)


if __name__ == "__main__":
    unittest.main()
