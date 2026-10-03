"""Forensic Integrity and Adversarial Stress Test Suite for Milestone 3 (NHI RFC 8693).

Independently executed by Forensic Integrity Auditor.
"""

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
    parse_workload_jwt,
    validate_jwt_workload,
    validate_token_exchange,
    RFC8693_TOKEN_EXCHANGE_GRANT,
    SUPPORTED_TOKEN_TYPES,
)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def make_jwt(header: dict, payload: dict, sig: bytes = b"sig_bytes") -> str:
    h_b = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_b = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"{b64url_encode(h_b)}.{b64url_encode(p_b)}.{b64url_encode(sig)}"


class TestAdversarialBase64AndJson(unittest.TestCase):
    """Stress test Base64URL and JSON decoder against malformed & boundary inputs."""

    def test_b64url_padding_fuzz(self):
        # Test mod 4 lengths
        for length in range(1, 64):
            data = os.urandom(length)
            enc = b64url_encode(data)
            dec = b64url_decode(enc)
            self.assertEqual(dec, data, f"Mismatch at length {length}")

    def test_b64url_invalid_modulo_1(self):
        # A single character or 5 characters cannot be valid Base64
        with self.assertRaises(ValueError):
            b64url_decode("x")
        with self.assertRaises(ValueError):
            b64url_decode("abcde")

    def test_decode_jwt_segment_rejects_non_object(self):
        # Valid JSON array but not object
        enc_arr = b64url_encode(b"[1, 2, 3]")
        with self.assertRaises(ValueError):
            decode_jwt_segment(enc_arr)

        # Valid JSON primitive string
        enc_str = b64url_encode(b'"hello world"')
        with self.assertRaises(ValueError):
            decode_jwt_segment(enc_str)

        # Valid JSON integer
        enc_num = b64url_encode(b"12345")
        with self.assertRaises(ValueError):
            decode_jwt_segment(enc_num)

        # Valid JSON boolean
        enc_bool = b64url_encode(b"true")
        with self.assertRaises(ValueError):
            decode_jwt_segment(enc_bool)

    def test_parse_jwt_segment_counts(self):
        # Empty string
        with self.assertRaises(ValueError):
            parse_workload_jwt("")
        with self.assertRaises(ValueError):
            parse_workload_jwt("   ")
        # 1 part
        with self.assertRaises(ValueError):
            parse_workload_jwt("part1")
        # 2 parts
        with self.assertRaises(ValueError):
            parse_workload_jwt("part1.part2")
        # 4 parts
        with self.assertRaises(ValueError):
            parse_workload_jwt("p1.p2.p3.p4")


class TestAdversarialJwtSecurityPolicies(unittest.TestCase):
    """Stress test security policies: wildcards, broad subjects, algorithms, and timing."""

    def test_wildcard_audience_variations(self):
        now = int(time.time())
        # Case 1: aud is string "*"
        jwt1 = make_jwt({"alg": "RS256"}, {"sub": "sa1", "aud": "*", "exp": now + 600})
        rep1 = validate_jwt_workload(jwt1)
        self.assertFalse(rep1["valid"])
        self.assertTrue(rep1["security_evaluation"]["has_wildcard_audience"])
        self.assertTrue(any("WILDCARD_AUDIENCE" in w for w in rep1["security_warnings"]))

        # Case 2: aud is list containing "*"
        jwt2 = make_jwt({"alg": "RS256"}, {"sub": "sa1", "aud": ["corp-api", "*"], "exp": now + 600})
        rep2 = validate_jwt_workload(jwt2)
        self.assertFalse(rep2["valid"])
        self.assertTrue(rep2["security_evaluation"]["has_wildcard_audience"])

        # Case 3: aud contains wildcard substring "*corp*"
        jwt3 = make_jwt({"alg": "RS256"}, {"sub": "sa1", "aud": "https://*.corp.local", "exp": now + 600})
        rep3 = validate_jwt_workload(jwt3)
        self.assertFalse(rep3["valid"])
        self.assertTrue(rep3["security_evaluation"]["has_wildcard_audience"])

        # Case 4: aud is missing
        jwt4 = make_jwt({"alg": "RS256"}, {"sub": "sa1", "exp": now + 600})
        rep4 = validate_jwt_workload(jwt4)
        self.assertFalse(rep4["valid"])
        self.assertTrue(rep4["security_evaluation"]["has_wildcard_audience"])
        self.assertTrue(any("MISSING_AUDIENCE" in w for w in rep4["security_warnings"]))

        # Case 5: aud is empty list
        jwt5 = make_jwt({"alg": "RS256"}, {"sub": "sa1", "aud": [], "exp": now + 600})
        rep5 = validate_jwt_workload(jwt5)
        self.assertFalse(rep5["valid"])
        self.assertTrue(rep5["security_evaluation"]["has_wildcard_audience"])

    def test_broad_subject_scope_variations(self):
        now = int(time.time())
        # Case 1: K8s namespace wildcard
        k8s_ns = make_jwt(
            {"alg": "RS256"},
            {"sub": "system:serviceaccount:*:app", "aud": "sts", "exp": now + 600},
        )
        rep_ns = validate_jwt_workload(k8s_ns)
        self.assertFalse(rep_ns["valid"])
        self.assertTrue(rep_ns["security_evaluation"]["has_broad_subject_scope"])

        # Case 2: K8s SA name wildcard
        k8s_sa = make_jwt(
            {"alg": "RS256"},
            {"sub": "system:serviceaccount:production:*", "aud": "sts", "exp": now + 600},
        )
        rep_sa = validate_jwt_workload(k8s_sa)
        self.assertFalse(rep_sa["valid"])
        self.assertTrue(rep_sa["security_evaluation"]["has_broad_subject_scope"])

        # Case 3: GitHub Actions repo wildcard
        gh_wild = make_jwt(
            {"alg": "RS256"},
            {"sub": "repo:org/*:pull_request", "aud": "sts", "exp": now + 600},
        )
        rep_gh = validate_jwt_workload(gh_wild)
        self.assertFalse(rep_gh["valid"])
        self.assertTrue(rep_gh["security_evaluation"]["has_broad_subject_scope"])

        # Case 4: SPIFFE SVID wildcard
        spiffe_wild = make_jwt(
            {"alg": "RS256"},
            {"sub": "spiffe://corp.internal/*", "aud": "sts", "exp": now + 600},
        )
        rep_spiffe = validate_jwt_workload(spiffe_wild)
        self.assertFalse(rep_spiffe["valid"])
        self.assertTrue(rep_spiffe["security_evaluation"]["has_broad_subject_scope"])

        # Case 5: Valid specific subject - must not flag
        valid_sub = make_jwt(
            {"alg": "RS256"},
            {"sub": "system:serviceaccount:production:payment-worker", "aud": "sts", "exp": now + 600},
        )
        rep_valid = validate_jwt_workload(valid_sub)
        self.assertTrue(rep_valid["valid"])
        self.assertFalse(rep_valid["security_evaluation"]["has_broad_subject_scope"])

    def test_algorithm_enforcement(self):
        now = int(time.time())
        # alg = none
        none_jwt = make_jwt({"alg": "none"}, {"sub": "sa", "aud": "sts", "exp": now + 600})
        rep_none = validate_jwt_workload(none_jwt)
        self.assertFalse(rep_none["valid"])
        self.assertTrue(rep_none["security_evaluation"]["insecure_algorithm"])
        self.assertEqual(rep_none["security_evaluation"]["risk_level"], "CRITICAL")

        # alg = HS256
        hs_jwt = make_jwt({"alg": "HS256"}, {"sub": "sa", "aud": "sts", "exp": now + 600})
        rep_hs = validate_jwt_workload(hs_jwt)
        self.assertTrue(any("SYMMETRIC_ALGORITHM" in w for w in rep_hs["security_warnings"]))

        # alg = RS256 (asymmetric)
        rs_jwt = make_jwt({"alg": "RS256"}, {"sub": "sa", "aud": "sts", "exp": now + 600})
        rep_rs = validate_jwt_workload(rs_jwt)
        self.assertFalse(rep_rs["security_evaluation"]["insecure_algorithm"])

    def test_temporal_evaluations(self):
        now = 1700000000

        # Expired token
        exp_jwt = make_jwt({"alg": "RS256"}, {"sub": "sa", "aud": "sts", "exp": now - 100})
        rep_exp = validate_jwt_workload(exp_jwt, now=now)
        self.assertFalse(rep_exp["valid"])
        self.assertTrue(rep_exp["temporal"]["is_expired"])
        self.assertEqual(rep_exp["temporal"]["remaining_human"], "Expired")

        # Future nbf token (not yet valid)
        future_jwt = make_jwt({"alg": "RS256"}, {"sub": "sa", "aud": "sts", "exp": now + 3600, "nbf": now + 120})
        rep_future = validate_jwt_workload(future_jwt, now=now)
        self.assertFalse(rep_future["valid"])
        self.assertTrue(any("TOKEN_NOT_YET_VALID" in w for w in rep_future["security_warnings"]))

        # Excessive lifetime (> 24h = 86400s)
        long_jwt = make_jwt({"alg": "RS256"}, {"sub": "sa", "aud": "sts", "iat": now, "exp": now + 100000})
        rep_long = validate_jwt_workload(long_jwt, now=now)
        self.assertFalse(rep_long["temporal"]["is_ephemeral"])
        self.assertTrue(any("EXCESSIVE_LIFETIME" in w for w in rep_long["security_warnings"]))


class TestAdversarialRfc8693TokenExchange(unittest.TestCase):
    """Stress test RFC 8693 token exchange validator against malformed and invalid requests."""

    def test_invalid_request_types(self):
        # Non-dictionary params
        rep = validate_token_exchange("not a dict")
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "invalid_request")

        # Missing grant_type
        rep = validate_token_exchange({"subject_token": "foo"})
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "invalid_request")

        # Unsupported grant_type
        rep = validate_token_exchange({"grant_type": "authorization_code", "subject_token": "foo"})
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "unsupported_grant_type")

        # Missing subject_token
        rep = validate_token_exchange({"grant_type": RFC8693_TOKEN_EXCHANGE_GRANT})
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "invalid_request")

        # Missing subject_token_type
        rep = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": "token123",
        })
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "invalid_request")

        # Unsupported subject_token_type
        rep = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": "token123",
            "subject_token_type": "urn:ietf:params:oauth:token-type:bogus",
        })
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "invalid_request")

    def test_expired_jwt_subject_returns_invalid_grant(self):
        past = int(time.time()) - 500
        expired_token = make_jwt({"alg": "RS256"}, {"sub": "sa", "aud": "sts", "exp": past})
        rep = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": expired_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "invalid_grant")

    def test_malformed_jwt_subject_returns_invalid_request(self):
        rep = validate_token_exchange({
            "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
            "subject_token": "not.a.valid.jwt.segment",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
        self.assertFalse(rep["valid"])
        self.assertEqual(rep["error"], "invalid_request")


class TestAdversarialCliBehavior(unittest.TestCase):
    """Stress test unified CLI entry points."""

    def run_cli(self, args, stdin_data=None):
        cmd = [sys.executable, "-m", "tanuki"] + args
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        env = os.environ.copy()
        env["PYTHONPATH"] = root
        proc = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True, cwd=root)
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_token_via_stdin(self):
        now = int(time.time())
        token = make_jwt({"alg": "RS256"}, {"sub": "stdin-sa", "aud": "sts", "exp": now + 3600})
        ret, stdout, stderr = self.run_cli(["token", "--json"], stdin_data=token)
        self.assertEqual(ret, 0)
        data = json.loads(stdout)
        self.assertTrue(data["valid"])
        self.assertEqual(data["claims"]["sub"], "stdin-sa")

    def test_cli_nhi_exchange_command(self):
        now = int(time.time())
        token = make_jwt({"alg": "RS256"}, {"sub": "exchange-sa", "aud": "https://sts.corp.local", "exp": now + 3600})
        ret, stdout, stderr = self.run_cli([
            "nhi", "exchange",
            "--grant-type", RFC8693_TOKEN_EXCHANGE_GRANT,
            "--subject-token", token,
            "--subject-token-type", "urn:ietf:params:oauth:token-type:jwt",
            "--audience", "https://sts.corp.local",
            "--json",
        ])
        self.assertEqual(ret, 0)
        data = json.loads(stdout)
        self.assertTrue(data["valid"])
        self.assertTrue(data["exchange_valid"])

    def test_cli_empty_token_arg_fails_gracefully(self):
        ret, stdout, stderr = self.run_cli(["token", ""])
        self.assertNotEqual(ret, 0)
        self.assertIn("Error", stderr)


if __name__ == "__main__":
    unittest.main()
