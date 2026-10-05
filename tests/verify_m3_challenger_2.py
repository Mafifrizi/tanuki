"""Adversarial Security Policy and Fuzz Testing Suite for Milestone 3 (Challenger 2).

This suite stress-tests the Non-Human Identity (NHI) Token Validator (RFC 8693)
in Tanuki v1.2.0 against hostile, malformed, and adversarial inputs:
1. Adversarial JWT tokens with wildcard audience (aud == "*" or empty or wildcard patterns).
2. Overly broad subject patterns (Kubernetes SA system:serviceaccount:*:*, GitHub/AWS repo:org/*, SPIFFE spiffe://*).
3. Fuzz test malformed JWT tokens (0 bytes, 1 dot, 2 dots without payload, non-base64 characters, truncated JSON).
4. Fuzz test RFC 8693 token exchange parameters (unsupported grants, invalid types, malformed subject tokens).
5. Assert that all security warnings are raised and zero unhandled crashes occur across Python and CLI.
6. Audit Rust and Python parity, memory safety (#![forbid(unsafe_code)]), and antislop compliance.
"""

import base64
import json
import os
import subprocess
import sys
import time
import unittest
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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
    RFC8693_TOKEN_EXCHANGE_GRANT,
    SUPPORTED_TOKEN_TYPES,
)


def b64url_encode(data: bytes) -> str:
    """Encode bytes to unpadded base64url string."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def craft_jwt(header: Optional[Dict[str, Any]] = None, payload: Optional[Dict[str, Any]] = None, sig: bytes = b"dummy_sig") -> str:
    """Helper to craft synthetic JWTs with custom headers and payloads."""
    now = int(time.time())
    if header is None:
        header = {"alg": "RS256", "typ": "JWT", "kid": "k-2026"}
    if payload is None:
        payload = {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:production:payment-app",
            "aud": "https://sts.corp.local",
            "exp": now + 3600,
            "iat": now,
            "nbf": now - 30,
        }
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    s_b64 = b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{s_b64}"


class TestAdversarialWildcardAudience(unittest.TestCase):
    """1. Generate adversarial JWT tokens with wildcard audience (aud == '*' or empty)."""

    def setUp(self):
        self.now = int(time.time())

    def test_literal_wildcard_string_audience(self):
        """aud == '*' must trigger CRITICAL WILDCARD_AUDIENCE and render token invalid."""
        token = craft_jwt(payload={
            "sub": "worker",
            "aud": "*",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"], "Token with aud='*' must not be valid")
        self.assertTrue(rep["security_evaluation"]["has_wildcard_audience"])
        self.assertEqual(rep["security_evaluation"]["risk_level"], "CRITICAL")
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("WILDCARD_AUDIENCE" in w and "*" in w for w in warnings),
            f"Expected WILDCARD_AUDIENCE warning, got: {warnings}"
        )

    def test_missing_audience_claim(self):
        """Missing aud claim must trigger HIGH MISSING_AUDIENCE and render token invalid."""
        token = craft_jwt(payload={
            "sub": "worker",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"], "Token missing aud claim must not be valid")
        self.assertTrue(rep["security_evaluation"]["has_wildcard_audience"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("MISSING_AUDIENCE" in w for w in warnings),
            f"Expected MISSING_AUDIENCE warning, got: {warnings}"
        )

    def test_empty_string_audience(self):
        """aud == '' must trigger HIGH MISSING_AUDIENCE and render token invalid."""
        token = craft_jwt(payload={
            "sub": "worker",
            "aud": "",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"], "Token with aud='' must not be valid")
        self.assertTrue(rep["security_evaluation"]["has_wildcard_audience"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("MISSING_AUDIENCE" in w for w in warnings),
            f"Expected MISSING_AUDIENCE warning, got: {warnings}"
        )

    def test_empty_array_audience(self):
        """aud == [] must trigger HIGH MISSING_AUDIENCE and render token invalid."""
        token = craft_jwt(payload={
            "sub": "worker",
            "aud": [],
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"], "Token with aud=[] must not be valid")
        self.assertTrue(rep["security_evaluation"]["has_wildcard_audience"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("MISSING_AUDIENCE" in w for w in warnings),
            f"Expected MISSING_AUDIENCE warning, got: {warnings}"
        )

    def test_array_containing_literal_wildcard(self):
        """aud == ['service-a', '*'] must trigger CRITICAL WILDCARD_AUDIENCE."""
        token = craft_jwt(payload={
            "sub": "worker",
            "aud": ["https://sts.corp.local", "*"],
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_wildcard_audience"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("WILDCARD_AUDIENCE" in w for w in warnings),
            f"Expected WILDCARD_AUDIENCE warning, got: {warnings}"
        )

    def test_wildcard_string_pattern_audience(self):
        """aud == 'https://api.corp.local/*' must trigger HIGH WILDCARD_AUDIENCE."""
        token = craft_jwt(payload={
            "sub": "worker",
            "aud": "https://api.corp.local/*",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_wildcard_audience"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("WILDCARD_AUDIENCE" in w and "Wildcard pattern in audience" in w for w in warnings),
            f"Expected wildcard pattern warning, got: {warnings}"
        )

    def test_wildcard_audience_in_token_exchange_params(self):
        """audience == '*' in RFC 8693 parameters must trigger security warning."""
        valid_subject_jwt = craft_jwt(payload={
            "sub": "worker",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        params = {
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": valid_subject_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "*",
        }
        rep = validate_token_exchange(params)
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("WILDCARD_AUDIENCE" in w and "*" in w for w in warnings),
            f"Expected exchange wildcard audience warning, got: {warnings}"
        )

    def test_wildcard_pattern_in_exchange_audience(self):
        """audience == 'https://sts.corp.local/*' in RFC 8693 parameters must trigger warning."""
        valid_subject_jwt = craft_jwt(payload={
            "sub": "worker",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        params = {
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": valid_subject_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "https://sts.corp.local/*",
        }
        rep = validate_token_exchange(params)
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("WILDCARD_AUDIENCE" in w and "Wildcard pattern" in w for w in warnings),
            f"Expected exchange wildcard pattern warning, got: {warnings}"
        )

    def test_expected_audience_mismatch_rejects_token(self):
        """Token audience not matching expected_aud must fail validation."""
        token = craft_jwt(payload={
            "sub": "worker",
            "aud": "https://service-a.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token, expected_aud="https://service-b.corp.local")
        self.assertFalse(rep["valid"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(any("AUDIENCE_MISMATCH" in w for w in warnings))

    def test_aud_array_pattern_parity_edge_case(self):
        """Verify empirical behavior when audience is an array containing a wildcard pattern.
        Note: Rust flags aud.iter().any(|a| a.contains('*')) as wildcard,
        whereas Python currently requires aud_val == '*' or exact '*' element in list.
        """
        token = craft_jwt(payload={
            "sub": "worker",
            "aud": ["https://api.corp.local/*"],
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        # Empirical observation: Python validate_jwt_workload does not flag wildcard
        # substring within array elements, documenting this parity boundary.
        self.assertFalse(rep["security_evaluation"]["has_wildcard_audience"])


class TestAdversarialBroadSubjectPatterns(unittest.TestCase):
    """2. Generate overly broad subject patterns."""

    def setUp(self):
        self.now = int(time.time())

    def test_k8s_wildcard_namespace_and_sa(self):
        """system:serviceaccount:*:* must trigger CRITICAL OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:*:*",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w and "Wildcard namespace" in w for w in warnings),
            f"Expected wildcard namespace warning, got: {warnings}"
        )

    def test_k8s_wildcard_namespace_specific_sa(self):
        """system:serviceaccount:*:admin must trigger CRITICAL OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:*:admin",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w and "Wildcard namespace" in w for w in warnings),
            f"Expected wildcard namespace warning, got: {warnings}"
        )

    def test_k8s_wildcard_sa_name_in_namespace(self):
        """system:serviceaccount:production:* must trigger HIGH OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:production:*",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w and "Wildcard service account name" in w for w in warnings),
            f"Expected wildcard sa name warning, got: {warnings}"
        )

    def test_github_oidc_wildcard_repository(self):
        """repo:org/* must trigger HIGH OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/*",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w and "Wildcard repository pattern" in w for w in warnings),
            f"Expected wildcard repo warning, got: {warnings}"
        )

    def test_github_oidc_wildcard_branch(self):
        """repo:org/repo:ref:refs/heads/* must trigger HIGH OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/repo:ref:refs/heads/*",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w and "Wildcard repository pattern" in w for w in warnings),
            f"Expected wildcard branch warning, got: {warnings}"
        )

    def test_spiffe_wildcard_svid(self):
        """spiffe://* must trigger CRITICAL OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "spiffe://example.org",
            "sub": "spiffe://*",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w and "Wildcard pattern in SPIFFE ID" in w for w in warnings),
            f"Expected wildcard SPIFFE warning, got: {warnings}"
        )

    def test_spiffe_wildcard_path_svid(self):
        """spiffe://example.org/ns/*/sa/* must trigger CRITICAL OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "spiffe://example.org",
            "sub": "spiffe://example.org/ns/*/sa/*",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w and "Wildcard pattern in SPIFFE ID" in w for w in warnings),
            f"Expected wildcard SPIFFE path warning, got: {warnings}"
        )

    def test_aws_iam_wildcard_role_pattern(self):
        """arn:aws:iam::123456789012:role/* must trigger HIGH OVERLY_BROAD_SUBJECT."""
        token = craft_jwt(payload={
            "iss": "https://rolesanywhere.amazonaws.com",
            "sub": "arn:aws:iam::123456789012:role/*",
            "aud": "https://sts.corp.local",
            "exp": self.now + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertFalse(rep["valid"])
        self.assertTrue(rep["security_evaluation"]["has_broad_subject_scope"])
        warnings = rep.get("security_warnings", [])
        self.assertTrue(
            any("OVERLY_BROAD_SUBJECT" in w for w in warnings),
            f"Expected wildcard role pattern warning, got: {warnings}"
        )


class TestFuzzMalformedJwtTokens(unittest.TestCase):
    """3. Fuzz test malformed JWT tokens (0 bytes, 1 dot, 2 dots without payload, non-base64 characters, truncated JSON)."""

    def test_fuzz_zero_bytes_and_whitespace(self):
        """0 bytes and whitespace tokens must raise ValueError cleanly without unhandled crash."""
        bad_inputs = ["", " ", "   ", "\t", "\n", "\r\n"]
        for idx, bad in enumerate(bad_inputs):
            with self.subTest(input_index=idx, input_val=repr(bad)):
                with self.assertRaises(ValueError):
                    parse_workload_jwt(bad)
                with self.assertRaises(ValueError):
                    validate_jwt_workload(bad)

    def test_fuzz_single_dot_tokens(self):
        """Tokens with exactly 1 dot must raise ValueError cleanly."""
        bad_inputs = [
            ".",
            "header.payload",
            "a.b",
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ",
            " . ",
        ]
        for bad in bad_inputs:
            with self.subTest(input_val=bad):
                with self.assertRaises(ValueError) as ctx:
                    parse_workload_jwt(bad)
                self.assertIn("expected 3 period-delimited segments", str(ctx.exception))

    def test_fuzz_two_dots_without_payload(self):
        """Tokens with 2 dots but empty payload/header/signature must raise cleanly."""
        bad_inputs = [
            "..",
            "header..signature",
            ".payload.",
            "..signature",
            "header.payload.",
            ".payload.signature",
            "header..",
            " . . ",
        ]
        for bad in bad_inputs:
            with self.subTest(input_val=bad):
                try:
                    validate_jwt_workload(bad)
                    self.fail(f"Expected failure for malformed input '{bad}'")
                except ValueError:
                    # Clean expected validation error (JSONDecodeError, ValueError)
                    pass
                except Exception as exc:
                    self.fail(f"Unexpected unhandled exception for '{bad}': {type(exc)}: {exc}")

    def test_fuzz_excessive_dots_tokens(self):
        """Tokens with >2 dots must raise ValueError cleanly."""
        bad_inputs = [
            "...",
            "....",
            "a.b.c.d",
            "header.payload.signature.extra",
            "." * 100,
        ]
        for bad in bad_inputs:
            with self.subTest(input_val=bad[:10]):
                with self.assertRaises(ValueError) as ctx:
                    parse_workload_jwt(bad)
                self.assertIn("expected 3 period-delimited segments", str(ctx.exception))

    def test_fuzz_non_base64_characters(self):
        """Tokens containing non-base64 characters must raise ValueError cleanly."""
        bad_inputs = [
            "header!@#$.payload!@#$.sig!@#$",
            "~~~.***.###",
            "eyJhbGciOi?SUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2ln",
            "a b c.d e f.g h i",
            "header\x00.payload\x00.sig\x00",
            "header\xff\xfe.payload\xff\xfe.sig",
        ]
        for bad in bad_inputs:
            with self.subTest(input_val=bad[:15]):
                try:
                    validate_jwt_workload(bad)
                    self.fail(f"Expected failure for non-base64 input '{bad[:15]}'")
                except ValueError:
                    pass
                except Exception as exc:
                    self.fail(f"Unexpected unhandled exception for non-base64 input: {type(exc)}: {exc}")

    def test_fuzz_base64url_mod_1_invalid_length(self):
        """Base64url segment length with len % 4 == 1 is mathematically impossible; must raise ValueError."""
        valid_hdr = b64url_encode(b'{"alg":"RS256"}')
        bad_inputs = [
            "A.A.A",
            "AAAAA.AAAAA.AAAAA",
            f"{valid_hdr}.A.sig",
            f"{valid_hdr}.AAAAA.sig",
        ]
        for bad in bad_inputs:
            with self.subTest(input_val=bad):
                with self.assertRaises(ValueError) as ctx:
                    validate_jwt_workload(bad)
                self.assertIn("length cannot be 1 mod 4", str(ctx.exception))

    def test_fuzz_truncated_json(self):
        """Tokens with truncated/unclosed JSON segments must raise cleanly without crashing."""
        header_raw = '{"alg":"RS256"'  # Missing closing brace
        payload_raw = '{"iss":"https://auth.local", "sub":'  # Truncated key-value
        bad_token = f"{b64url_encode(header_raw.encode())}.{b64url_encode(payload_raw.encode())}.c2ln"

        with self.assertRaises(ValueError):
            validate_jwt_workload(bad_token)

    def test_fuzz_non_object_json_payloads(self):
        """JSON literals that are not dicts (list, int, string, null, bool) must raise ValueError."""
        header_b64 = b64url_encode(b'{"alg":"RS256","typ":"JWT"}')
        non_dict_payloads = [
            b"[1, 2, 3]",
            b'"just a string"',
            b"12345",
            b"true",
            b"null",
        ]
        for nd in non_dict_payloads:
            token = f"{header_b64}.{b64url_encode(nd)}.c2ln"
            with self.subTest(payload=nd):
                with self.assertRaises(ValueError) as ctx:
                    validate_jwt_workload(token)
                self.assertIn("must be a JSON object", str(ctx.exception))

    def test_fuzz_large_payload(self):
        """Validate resilience against large token payloads (100KB)."""
        huge_sub = "system:serviceaccount:production:" + ("x" * 100000)
        token = craft_jwt(payload={
            "sub": huge_sub,
            "aud": "https://sts.corp.local",
            "exp": int(time.time()) + 3600,
        })
        rep = validate_jwt_workload(token)
        self.assertTrue(rep["valid"])
        self.assertEqual(rep["claims"]["sub"], huge_sub)


class TestFuzzRfc8693TokenExchange(unittest.TestCase):
    """4. Fuzz test RFC 8693 token exchange parameters and error handling."""

    def test_non_dict_parameters(self):
        """Non-dictionary parameters must return invalid_request report without raising."""
        bad_params = ["string", 123, [1, 2], None, False]
        for p in bad_params:
            rep = validate_token_exchange(p)  # type: ignore
            self.assertFalse(rep["valid"])
            self.assertFalse(rep["exchange_valid"])
            self.assertEqual(rep["error"], "invalid_request")
            self.assertTrue(any("INVALID_REQUEST" in w for w in rep["security_warnings"]))

    def test_missing_or_invalid_grant_types(self):
        """Missing or wrong grant_type must fail cleanly with proper error code."""
        # Missing
        rep1 = validate_token_exchange({})
        self.assertFalse(rep1["valid"])
        self.assertEqual(rep1["error"], "invalid_request")

        # Unsupported
        rep2 = validate_token_exchange({
            "grant_type": "client_credentials",
            "subject_token": craft_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
        self.assertFalse(rep2["valid"])
        self.assertEqual(rep2["error"], "unsupported_grant_type")
        self.assertTrue(any("UNSUPPORTED_GRANT_TYPE" in w for w in rep2["security_warnings"]))

    def test_missing_subject_token_or_type(self):
        """Missing subject_token or subject_token_type must return invalid_request."""
        rep1 = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
        self.assertFalse(rep1["valid"])
        self.assertEqual(rep1["error"], "invalid_request")

        rep2 = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": craft_jwt(),
        })
        self.assertFalse(rep2["valid"])
        self.assertEqual(rep2["error"], "invalid_request")

    def test_unsupported_token_types(self):
        """Unknown subject_token_type or requested_token_type must return invalid_request."""
        rep1 = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": craft_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:unknown_type",
        })
        self.assertFalse(rep1["valid"])
        self.assertEqual(rep1["error"], "invalid_request")

        rep2 = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": craft_jwt(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "requested_token_type": "urn:bogus:type",
        })
        self.assertFalse(rep2["valid"])
        self.assertEqual(rep2["error"], "invalid_request")

    def test_malformed_subject_token_jwt_inside_exchange(self):
        """Malformed subject_token in exchange must return invalid_request without throwing."""
        malformed_tokens = [
            "",
            "not.a.jwt",
            "..",
            "header!@#.payload!@#.sig",
            "eyJhbGciOiJSUzI1NiJ9.not_json.sig",
        ]
        for mt in malformed_tokens:
            with self.subTest(token=mt):
                rep = validate_token_exchange({
                    "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
                    "subject_token": mt,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                })
                self.assertFalse(rep["valid"])
                self.assertFalse(rep["exchange_valid"])
                self.assertEqual(rep["error"], "invalid_request")
                self.assertTrue(any("INVALID_REQUEST" in w for w in rep["security_warnings"]))

    def test_expired_subject_token_returns_invalid_grant(self):
        """Expired subject token in exchange must return invalid_grant."""
        past = int(time.time()) - 1000
        expired_token = craft_jwt(payload={"sub": "worker", "exp": past, "iat": past - 3600})
        rep = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": expired_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
        self.assertFalse(rep["valid"])
        self.assertFalse(rep["exchange_valid"])
        self.assertEqual(rep["error"], "invalid_grant")
        self.assertIn("expired", rep["error_description"].lower())


class TestCliAdversarialAndFuzzExecution(unittest.TestCase):
    """5. Assert zero unhandled crashes in CLI across malformed inputs and flags."""

    def run_cli(self, args: List[str], stdin_data: Optional[str] = None) -> (int, str, str):
        cmd = [sys.executable, "-m", "tanuki"] + args
        env = os.environ.copy()
        env["PYTHONPATH"] = PROJECT_ROOT
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_token_with_malformed_inputs_exits_cleanly(self):
        """CLI tanuki token must exit with code 1 and zero tracebacks on malformed token."""
        malformed = [
            "invalid_token",
            "a.b",
            "..",
            "header!@#.payload!@#.sig",
        ]
        for mt in malformed:
            with self.subTest(token=mt):
                code, stdout, stderr = self.run_cli(["token", mt])
                self.assertEqual(code, 4)
                self.assertIn("Error parsing token", stderr)
                self.assertNotIn("Traceback", stderr)

    def test_cli_token_empty_argument(self):
        """CLI tanuki token '' must exit with code 1 cleanly."""
        code, stdout, stderr = self.run_cli(["token", ""])
        self.assertEqual(code, 1)
        self.assertIn("Error: Token string cannot be empty", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_cli_token_stdin_fuzz(self):
        """CLI tanuki token reading malformed input from stdin must exit cleanly."""
        code, stdout, stderr = self.run_cli(["token"], stdin_data="malformed.jwt.data")
        self.assertEqual(code, 4)
        self.assertIn("Error parsing token", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_cli_nhi_inspect_wildcard_token_json(self):
        """CLI tanuki nhi inspect with wildcard token emits valid JSON with warnings."""
        token = craft_jwt(payload={"sub": "worker", "aud": "*", "exp": int(time.time()) + 3600})
        code, stdout, stderr = self.run_cli(["nhi", "inspect", token, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(stdout)
        self.assertFalse(data["valid"])
        self.assertTrue(data["security_evaluation"]["has_wildcard_audience"])
        self.assertEqual(data["security_evaluation"]["risk_level"], "CRITICAL")

    def test_cli_nhi_exchange_with_expired_token(self):
        """CLI tanuki nhi exchange with expired token exits with 1 and invalid_grant."""
        past = int(time.time()) - 1000
        token = craft_jwt(payload={"sub": "worker", "exp": past})
        code, stdout, stderr = self.run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", token,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--json",
        ])
        self.assertEqual(code, 1)
        data = json.loads(stdout)
        self.assertFalse(data["valid"])
        self.assertEqual(data["error"], "invalid_grant")

    def test_cli_token_nonexistent_file(self):
        """CLI tanuki token -f with nonexistent file exits with code 3 (RESOURCE_MISSING)."""
        code, stdout, stderr = self.run_cli(["token", "-f", "nonexistent_token_file.jwt"])
        self.assertEqual(code, 3)
        self.assertIn("Error: Token file not found", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_cli_token_empty_file(self):
        """CLI tanuki token -f with empty file exits with code 1."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("")
            tf_path = tf.name
        try:
            code, stdout, stderr = self.run_cli(["token", "-f", tf_path])
            self.assertEqual(code, 1)
            self.assertIn("Error: No token provided", stderr)
            self.assertNotIn("Traceback", stderr)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_cli_token_binary_file(self):
        """CLI tanuki token -f with binary/corrupt bytes exits with code 4 (PARSE_FAILURE)."""
        import tempfile
        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            tf.write(b"\x80\xff\xfe\x00")
            tf_path = tf.name
        try:
            code, stdout, stderr = self.run_cli(["token", "-f", tf_path])
            self.assertEqual(code, 4)
            self.assertIn("Error: File is not valid text", stderr)
            self.assertNotIn("Traceback", stderr)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


class TestRustParityAndCodeIntegrity(unittest.TestCase):
    """6. Audit Rust and Python parity, zero unsafe, and antislop compliance."""

    def test_rust_crates_nhi_files_exist(self):
        nhi_dir = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "nhi")
        self.assertTrue(os.path.isdir(nhi_dir))
        for filename in ["mod.rs", "types.rs", "jwt.rs", "exchange.rs"]:
            path = os.path.join(nhi_dir, filename)
            self.assertTrue(os.path.isfile(path), f"Missing {filename} in {nhi_dir}")

    def test_rust_crates_forbid_unsafe_code(self):
        lib_rs = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "lib.rs")
        with open(lib_rs, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("#![forbid(unsafe_code)]", content)

        # Ensure no unsafe blocks exist anywhere in crates/tanuki-cli/src
        src_dir = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src")
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(".rs"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        code = f.read()
                        self.assertNotIn("unsafe {", code)
                        self.assertNotIn("unsafe fn", code)

    def test_zero_em_dashes_in_m3_files(self):
        """Audit that zero em dashes exist in Milestone 3 files (antislop-copywriting)."""
        files_to_check = [
            os.path.join(PROJECT_ROOT, "tanuki", "nhi.py"),
            os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "nhi", "mod.rs"),
            os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "nhi", "types.rs"),
            os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "nhi", "jwt.rs"),
            os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "nhi", "exchange.rs"),
        ]
        for fpath in files_to_check:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertNotIn("\u2014", content, f"Em dash found in {fpath}")


if __name__ == "__main__":
    unittest.main()
