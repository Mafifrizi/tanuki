"""Tier 5 Adversarial Coverage Hardening Test Suite for Tanuki v1.2.0.

White-box adversarial tests probing:
1. Doctor: edge-case krb5.conf parsing, CCACHE non-standard principal types,
   corrupted credential counts, zero-byte /proc/keys, keytab corruptions, SSSD edge cases.
2. Telemetry: missing or malformed error codes, edge cases in ladder formatting,
   JSON serialization with special characters.
3. NHI RFC 8693: non-standard JWT claim types (boolean/list/int sub or iss),
   multi-segment audiences, token exchange with conflicting parameters,
   encoding boundaries and broad subject patterns.
4. Parity: Python vs Rust behavioral comparison and contract validation.
"""

import base64
import io
import json
import os
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tanuki.doctor import (
    DoctorReport,
    check_keytab,
    check_krb5_conf,
    check_sssd,
    check_ticket_lifetime,
    diagnose_system,
    parse_ccache_stream,
    parse_proc_keys,
)
from tanuki.nhi import (
    b64url_decode,
    decode_jwt_segment,
    detect_identity_type,
    format_exchange_report_terminal,
    format_token_report_terminal,
    parse_workload_jwt,
    validate_jwt_workload,
    validate_token_exchange,
)
from tanuki.protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution
from tanuki.telemetry import (
    ERROR_TELEMETRY,
    LADDER_TELEMETRY,
    OPERATIONAL_REMEDIATIONS,
    format_telemetry_inline,
    format_telemetry_terminal,
)


def _build_synthetic_jwt(header: dict, claims: dict) -> str:
    h_bytes = json.dumps(header).encode("utf-8")
    c_bytes = json.dumps(claims).encode("utf-8")
    h_b64 = base64.urlsafe_b64encode(h_bytes).decode("ascii").rstrip("=")
    c_b64 = base64.urlsafe_b64encode(c_bytes).decode("ascii").rstrip("=")
    return f"{h_b64}.{c_b64}.c2lnbmF0dXJlX2J5dGVz"


def _build_synthetic_ccache_binary(
    default_principal: str = "user@CORP.LOCAL",
    tickets: list = None,
    version: bytes = b"\x05\x04",
) -> bytes:
    if tickets is None:
        tickets = []

    stream = io.BytesIO()
    # Header: 2 bytes version + 2 bytes tag len + tags
    stream.write(version)
    stream.write(struct.pack(">H", 0))  # 0 header tags

    def write_principal(princ: str, name_type: int = 1):
        if "@" in princ:
            comp_part, realm = princ.split("@", 1)
            comps = comp_part.split("/") if comp_part else []
        else:
            comps = []
            realm = princ

        realm_b = realm.encode("utf-8")
        stream.write(struct.pack(">III", name_type, len(comps), len(realm_b)))
        stream.write(realm_b)
        for c in comps:
            cb = c.encode("utf-8")
            stream.write(struct.pack(">I", len(cb)))
            stream.write(cb)

    write_principal(default_principal)

    for t in tickets:
        client = t.get("client", default_principal)
        server = t.get("server", "krbtgt/CORP.LOCAL@CORP.LOCAL")
        client_name_type = t.get("client_name_type", 1)
        server_name_type = t.get("server_name_type", 1)
        authtime = t.get("authtime", 1700000000)
        starttime = t.get("starttime", 1700000000)
        endtime = t.get("endtime", 1700036000)
        renew_till = t.get("renew_till", 1700604800)
        addr_count = t.get("addr_count", 0)
        ad_count = t.get("ad_count", 0)
        ticket_data = t.get("ticket_data", b"\x01\x02\x03\x04")
        second_ticket = t.get("second_ticket", b"")

        write_principal(client, client_name_type)
        write_principal(server, server_name_type)

        # keyblock: enctype (2 bytes) + key len (4 bytes) + key
        key_data = b"\xaa" * 16
        stream.write(struct.pack(">HI", 18, len(key_data)))
        stream.write(key_data)

        # times
        stream.write(struct.pack(">IIII", authtime, starttime, endtime, renew_till))

        # is_skey
        stream.write(b"\x00")

        # flags (4 bytes)
        stream.write(struct.pack(">I", 0x40E00000))

        # addresses
        stream.write(struct.pack(">I", addr_count))
        for _ in range(addr_count):
            stream.write(struct.pack(">HI", 2, 4))
            stream.write(b"\x7f\x00\x00\x01")

        # authdata
        stream.write(struct.pack(">I", ad_count))
        for _ in range(ad_count):
            stream.write(struct.pack(">HI", 1, 4))
            stream.write(b"\x00\x00\x00\x00")

        # ticket data
        stream.write(struct.pack(">I", len(ticket_data)))
        stream.write(ticket_data)

        # second ticket
        stream.write(struct.pack(">I", len(second_ticket)))
        stream.write(second_ticket)

    return stream.getvalue()


class TestDoctorAdversarialKrb5Conf(unittest.TestCase):
    """Adversarial krb5.conf parsing probes."""

    def test_comments_within_section_header_lines(self):
        content = """# Global comment
[libdefaults] # inline comment on section header
    default_realm = CORP.LOCAL
[realms] ; semicolon inline comment on section header
    CORP.LOCAL = {
        kdc = dc01.corp.local
    }
[domain_realm]
    .corp.local = CORP.LOCAL
"""
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write(content)
            temp_path = f.name
        try:
            res = check_krb5_conf(temp_path)
            self.assertEqual(res["status"], "PASS")
            self.assertEqual(res["default_realm"], "CORP.LOCAL")
            self.assertTrue(res["is_realm_uppercase"])
            self.assertIn("CORP.LOCAL", res["realms"])
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_whitespace_inside_section_header_brackets(self):
        content = """
[   libdefaults   ]
    default_realm = CORP.LOCAL
[   realms   ]
    CORP.LOCAL = {
        kdc = dc01.corp.local
    }
"""
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write(content)
            temp_path = f.name
        try:
            res = check_krb5_conf(temp_path)
            self.assertEqual(res["status"], "PASS")
            self.assertEqual(res["default_realm"], "CORP.LOCAL")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_non_ascii_realm_capitalization(self):
        # Uppercase non-ASCII realm should PASS
        content_upper = """[libdefaults]
    default_realm = MÜNCHEN.LOCAL
"""
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write(content_upper)
            temp_upper = f.name
        try:
            res_upper = check_krb5_conf(temp_upper)
            self.assertEqual(res_upper["status"], "PASS")
            self.assertEqual(res_upper["default_realm"], "MÜNCHEN.LOCAL")
        finally:
            if os.path.exists(temp_upper):
                os.unlink(temp_upper)

        # Lowercase non-ASCII realm should FAIL
        content_lower = """[libdefaults]
    default_realm = münchen.local
"""
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write(content_lower)
            temp_lower = f.name
        try:
            res_lower = check_krb5_conf(temp_lower)
            self.assertEqual(res_lower["status"], "FAIL")
            self.assertIn("münchen.local", res_lower["lowercase_realms"])
        finally:
            if os.path.exists(temp_lower):
                os.unlink(temp_lower)

    def test_multiline_realm_values_and_nested_braces(self):
        content = """[libdefaults]
    default_realm = PROD.LOCAL
[realms]
    PROD.LOCAL = {
        kdc = dc1.prod.local:88 # Primary
        kdc = dc2.prod.local:88 # Secondary
        admin_server = dc1.prod.local
        default_domain = prod.local
    }
    BACKUP.LOCAL = {
        kdc = dc3.backup.local
    }
"""
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write(content)
            temp_path = f.name
        try:
            res = check_krb5_conf(temp_path)
            self.assertEqual(res["status"], "PASS")
            self.assertEqual(res["default_realm"], "PROD.LOCAL")
            self.assertIn("PROD.LOCAL", res["realms"])
            self.assertIn("BACKUP.LOCAL", res["realms"])
            # kdc lines inside braces should NOT be treated as realms
            self.assertNotIn("kdc", res["realms"])
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestDoctorAdversarialCcache(unittest.TestCase):
    """Adversarial CCACHE ticket parsing probes."""

    def test_non_standard_principal_types(self):
        # Name types: 2=KRB5_NT_SRV_INST, 10=KRB5_NT_ENTERPRISE_PRINCIPAL, 0=KRB5_NT_UNKNOWN
        tix = [
            {
                "client": "user@CORP.LOCAL",
                "client_name_type": 10,  # Enterprise principal
                "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                "server_name_type": 2,   # Service instance
                "endtime": int(time.time()) + 3600,
            }
        ]
        data = _build_synthetic_ccache_binary("user@CORP.LOCAL", tix)
        parsed = parse_ccache_stream(io.BytesIO(data))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["default_principal"], "user@CORP.LOCAL")
        self.assertEqual(parsed["server"], "krbtgt/CORP.LOCAL@CORP.LOCAL")
        self.assertGreater(parsed["endtime"], int(time.time()))

    def test_corrupted_credential_counts_and_address_counts(self):
        # Case A: Truncated single ticket stream with excessive addr_count claims (must not hang or crash)
        stream = io.BytesIO()
        stream.write(b"\x05\x04\x00\x00")  # version + 0 tag len
        # default principal
        stream.write(struct.pack(">III", 1, 1, 10) + b"CORP.LOCAL" + struct.pack(">I", 4) + b"user")
        # client principal
        stream.write(struct.pack(">III", 1, 1, 10) + b"CORP.LOCAL" + struct.pack(">I", 4) + b"user")
        # server principal
        stream.write(struct.pack(">III", 1, 2, 10) + b"CORP.LOCAL" + struct.pack(">I", 6) + b"krbtgt" + struct.pack(">I", 10) + b"CORP.LOCAL")
        # keyblock (enctype 18, key len 16)
        stream.write(struct.pack(">HI", 18, 16) + b"\x00" * 16)
        # times
        stream.write(struct.pack(">IIII", 1700000000, 1700000000, 1700036000, 1700604800))
        # is_skey + flags
        stream.write(b"\x00" + struct.pack(">I", 0))
        # addr_count claim 99999 but stream ends!
        stream.write(struct.pack(">I", 99999))

        data = stream.getvalue()
        # Single corrupted ticket returns None (cannot extract valid ticket)
        parsed_corrupt = parse_ccache_stream(io.BytesIO(data))
        self.assertIsNone(parsed_corrupt)

        # Case B: Valid ticket followed by corrupted/truncated ticket with excessive addr_count
        now = int(time.time())
        t1 = {"client": "user@CORP.LOCAL", "server": "krbtgt/CORP.LOCAL@CORP.LOCAL", "endtime": now + 3600}
        data_valid = _build_synthetic_ccache_binary("user@CORP.LOCAL", [t1])
        # Append corrupt entry
        corrupt_entry = (
            struct.pack(">III", 1, 1, 10) + b"CORP.LOCAL" + struct.pack(">I", 4) + b"user" +
            struct.pack(">III", 1, 2, 10) + b"CORP.LOCAL" + struct.pack(">I", 6) + b"krbtgt" + struct.pack(">I", 10) + b"CORP.LOCAL" +
            struct.pack(">HI", 18, 16) + b"\x00" * 16 +
            struct.pack(">IIII", 1700000000, 1700000000, 1700036000, 1700604800) +
            b"\x00" + struct.pack(">I", 0) +
            struct.pack(">I", 99999)
        )
        parsed_mixed = parse_ccache_stream(io.BytesIO(data_valid + corrupt_entry))
        self.assertIsNotNone(parsed_mixed)
        self.assertEqual(parsed_mixed["default_principal"], "user@CORP.LOCAL")
        self.assertEqual(parsed_mixed["endtime"], now + 3600)

    def test_zero_byte_proc_keys(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            temp_keys = f.name
        try:
            with patch("os.path.isfile", side_effect=lambda p: True if p == "/proc/keys" else os.path.isfile(p)):
                with patch("builtins.open", side_effect=lambda p, *a, **k: io.StringIO("") if p == "/proc/keys" else open(p, *a, **k)):
                    keys = parse_proc_keys()
                    self.assertEqual(keys, [])
        finally:
            if os.path.exists(temp_keys):
                os.unlink(temp_keys)


class TestDoctorAdversarialKeytabAndSssd(unittest.TestCase):
    """Adversarial keytab and SSSD probe boundaries."""

    def test_keytab_corrupt_magic_bytes(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"\x00\x00")
            temp_path = f.name
        try:
            res = check_keytab(temp_path)
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("Invalid keytab magic bytes", res["details"])
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_keytab_truncated_header(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"\x05")  # only 1 byte
            temp_path = f.name
        try:
            res = check_keytab(temp_path)
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("Invalid keytab format", res["details"])
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_keytab_v1_deprecated(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"\x05\x01")  # Keytab v1
            temp_path = f.name
        try:
            res = check_keytab(temp_path)
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("Deprecated Keytab v1", res["details"])
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_sssd_stale_pid_file(self):
        # Write PID 99999999 which does not exist
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("99999999\n")
            temp_pid = f.name
        try:
            res = check_sssd(sssd_pipe="/nonexistent/pipe", sssd_pid=temp_pid)
            self.assertFalse(res["daemon_running"])
            self.assertEqual(res["status"], "WARN")
            self.assertTrue(any("Stale PID" in i for i in res["issues"]))
        finally:
            if os.path.exists(temp_pid):
                os.unlink(temp_pid)

    def test_diagnose_system_deterministic_latency(self):
        rep = diagnose_system(keytab_path="/nonexistent/kt", krb5_conf_path="/nonexistent/conf")
        self.assertIsInstance(rep, DoctorReport)
        self.assertLess(rep.duration_ms, 50.0, "Pre-flight diagnosis must execute well under 50ms")


class TestTelemetryAdversarial(unittest.TestCase):
    """Adversarial telemetry and decision ladder probes."""

    def test_missing_and_malformed_error_code_queries(self):
        malformed_inputs = [
            "",
            "   ",
            "\t\n",
            "NON_EXISTENT_KERB_ERR",
            "123456789",
            "'; DROP TABLE errors; --",
            "<script>alert(1)</script>",
            "KRB_*",
            "STATUS_.*",
            "NULL",
        ]
        for query in malformed_inputs:
            res = find_error_resolution(query)
            if query.strip() in ("", "NULL") or "KERB" in query or "TABLE" in query or "script" in query:
                self.assertIsNone(res, f"Query '{query}' should return None")

    def test_decision_ladder_formatting_and_telemetry_coupling(self):
        self.assertEqual(len(DECISION_LADDER), 5)
        for rung in DECISION_LADDER:
            self.assertIn("telemetry", rung)
            t = rung["telemetry"]
            self.assertIsInstance(t.get("auditd"), list)
            self.assertIsInstance(t.get("event_ids"), list)
            self.assertIsInstance(t.get("sigma"), list)
            self.assertIsInstance(t.get("falco"), list)
            inline = format_telemetry_inline(t)
            self.assertIsInstance(inline, str)
            self.assertGreater(len(inline), 0)

    def test_json_serialization_with_special_characters(self):
        special_str = "Error with quotes \" and backslash \\ and control \t\r\n and unicode: München / 東京"
        fake_telemetry = {
            "auditd": [f"-w /etc/{special_str} -p r"],
            "event_ids": [4768],
            "sigma": [{"title": special_str, "status": "stable", "logsource": "linux:auditd", "tags": []}],
            "falco": [{"rule": "test", "priority": "INFO", "condition": special_str, "output": "out"}],
        }
        json_output = json.dumps(fake_telemetry)
        parsed = json.loads(json_output)
        self.assertEqual(parsed["auditd"][0], f"-w /etc/{special_str} -p r")
        self.assertEqual(parsed["sigma"][0]["title"], special_str)


class TestNhiAdversarialJwt(unittest.TestCase):
    """Adversarial NHI RFC 8693 workload JWT validation probes."""

    def test_non_standard_sub_claim_types(self):
        # 1. Integer subject
        token_int_sub = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": 123456, "iss": "https://auth.corp.local", "aud": "https://ad.corp.local", "exp": int(time.time()) + 3600},
        )
        rep1 = validate_jwt_workload(token_int_sub)
        self.assertTrue(rep1["valid"])
        self.assertEqual(rep1["identity_type"], "Workload Identity Token")

        # 2. Boolean subject
        token_bool_sub = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": True, "iss": "https://auth.corp.local", "aud": "https://ad.corp.local", "exp": int(time.time()) + 3600},
        )
        rep2 = validate_jwt_workload(token_bool_sub)
        self.assertTrue(rep2["valid"])

        # 3. List subject
        token_list_sub = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": ["cluster-admin", "system:node"], "iss": "https://auth.corp.local", "aud": "https://ad.corp.local", "exp": int(time.time()) + 3600},
        )
        rep3 = validate_jwt_workload(token_list_sub)
        self.assertTrue(rep3["valid"])

    def test_non_standard_iss_claim_types(self):
        # 1. Integer issuer
        token_int_iss = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": "user1", "iss": 99999, "aud": "https://ad.corp.local", "exp": int(time.time()) + 3600},
        )
        rep1 = validate_jwt_workload(token_int_iss)
        self.assertTrue(rep1["valid"])

        # 2. Boolean issuer
        token_bool_iss = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": "user1", "iss": False, "aud": "https://ad.corp.local", "exp": int(time.time()) + 3600},
        )
        rep2 = validate_jwt_workload(token_bool_iss)
        self.assertTrue(rep2["valid"])

    def test_multi_segment_audiences(self):
        now = int(time.time())
        token_multi_aud = _build_synthetic_jwt(
            {"alg": "RS256"},
            {
                "sub": "user1",
                "iss": "https://auth.corp.local",
                "aud": [
                    "https://service-a.corp.local",
                    "https://service-b.corp.local",
                    "https://ad.corp.local",
                ],
                "exp": now + 3600,
            },
        )

        # Expected aud matches one of the multi-segment items -> VALID
        rep_match = validate_jwt_workload(token_multi_aud, expected_aud="https://ad.corp.local")
        self.assertTrue(rep_match["valid"])
        self.assertNotIn("AUDIENCE_MISMATCH", [f["code"] for f in rep_match["security_evaluation"]["findings"]])

        # Expected aud does not match any item -> INVALID
        rep_mismatch = validate_jwt_workload(token_multi_aud, expected_aud="https://unknown.corp.local")
        self.assertFalse(rep_mismatch["valid"])
        self.assertIn("AUDIENCE_MISMATCH", [f["code"] for f in rep_mismatch["security_evaluation"]["findings"]])

        # Multi-segment audience containing wildcard '*' -> INVALID (CRITICAL)
        token_wildcard_in_list = _build_synthetic_jwt(
            {"alg": "RS256"},
            {
                "sub": "user1",
                "iss": "https://auth.corp.local",
                "aud": ["https://service-a.corp.local", "*"],
                "exp": now + 3600,
            },
        )
        rep_wild = validate_jwt_workload(token_wildcard_in_list)
        self.assertFalse(rep_wild["valid"])
        self.assertIn("WILDCARD_AUDIENCE", [f["code"] for f in rep_wild["security_evaluation"]["findings"]])

    def test_broad_subject_patterns(self):
        now = int(time.time())

        # Wildcard K8s namespace
        k8s_ns_wild = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": "system:serviceaccount:*:deployer", "aud": "https://ad.corp.local", "exp": now + 3600},
        )
        rep1 = validate_jwt_workload(k8s_ns_wild)
        self.assertFalse(rep1["valid"])
        self.assertTrue(any("Wildcard namespace" in w for w in rep1["security_warnings"]))

        # Wildcard SPIFFE ID
        spiffe_wild = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": "spiffe://corp.local/ns/*/sa/app", "aud": "https://ad.corp.local", "exp": now + 3600},
        )
        rep2 = validate_jwt_workload(spiffe_wild)
        self.assertFalse(rep2["valid"])
        self.assertTrue(any("SPIFFE ID" in w for w in rep2["security_warnings"]))

        # Wildcard GitHub Actions OIDC repo
        gh_wild = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": "repo:org/*:ref:refs/heads/main", "aud": "https://ad.corp.local", "exp": now + 3600},
        )
        rep3 = validate_jwt_workload(gh_wild)
        self.assertFalse(rep3["valid"])
        self.assertTrue(any("GitHub OIDC" in w for w in rep3["security_warnings"]))

    def test_token_exchange_conflicting_parameters(self):
        valid_jwt = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": "system:serviceaccount:prod:billing", "aud": "https://ad.corp.local", "exp": int(time.time()) + 3600},
        )

        # 1. Invalid grant type
        p1 = {
            "grant_type": "urn:ietf:params:oauth:grant-type:password",
            "subject_token": valid_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        r1 = validate_token_exchange(p1)
        self.assertFalse(r1["valid"])
        self.assertEqual(r1["error"], "unsupported_grant_type")

        # 2. Missing subject_token
        p2 = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        r2 = validate_token_exchange(p2)
        self.assertFalse(r2["valid"])
        self.assertEqual(r2["error"], "invalid_request")

        # 3. Unsupported subject_token_type
        p3 = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": valid_jwt,
            "subject_token_type": "urn:custom:token-type:opaque",
        }
        r3 = validate_token_exchange(p3)
        self.assertFalse(r3["valid"])
        self.assertEqual(r3["error"], "invalid_request")

        # 4. Expired subject token inside valid exchange params
        expired_jwt = _build_synthetic_jwt(
            {"alg": "RS256"},
            {"sub": "user1", "aud": "https://ad.corp.local", "exp": int(time.time()) - 3600},
        )
        p4 = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": expired_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        r4 = validate_token_exchange(p4)
        self.assertFalse(r4["valid"])
        self.assertEqual(r4["error"], "invalid_grant")

        # 5. Wildcard audience parameter in exchange
        p5 = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": valid_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "*",
        }
        r5 = validate_token_exchange(p5)
        self.assertTrue(r5["valid"])  # Exchange structure is technically valid
        self.assertTrue(any("WILDCARD_AUDIENCE" in w for w in r5["security_warnings"]))


class TestRustParityAndDiscrepancies(unittest.TestCase):
    """Static parity and behavioral difference analysis between Python and Rust engines."""

    def test_error_dictionary_parity(self):
        rust_kerberos_path = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "protocol", "kerberos.rs")
        self.assertTrue(os.path.isfile(rust_kerberos_path))
        with open(rust_kerberos_path, "r", encoding="utf-8") as f:
            rust_content = f.read()

        py_codes = [e["code"] for e in ERROR_DICTIONARY]
        self.assertEqual(len(py_codes), 10)
        for code in py_codes:
            self.assertIn(f'code: "{code}"', rust_content, f"Missing {code} in Rust kerberos.rs")

    def test_decision_ladder_parity(self):
        rust_kerberos_path = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "protocol", "kerberos.rs")
        with open(rust_kerberos_path, "r", encoding="utf-8") as f:
            rust_content = f.read()

        self.assertEqual(len(DECISION_LADDER), 5)
        for rung in DECISION_LADDER:
            self.assertIn(f'rung: {rung["rung"]}', rust_content)
            self.assertIn(f'title: "{rung["title"]}"', rust_content)

    def test_forbid_unsafe_code_in_rust(self):
        lib_rs = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "src", "lib.rs")
        with open(lib_rs, "r", encoding="utf-8") as f:
            self.assertIn("#![forbid(unsafe_code)]", f.read())

    def test_zero_external_dependencies(self):
        # pyproject.toml dependencies must be empty
        pyproject_path = os.path.join(PROJECT_ROOT, "pyproject.toml")
        with open(pyproject_path, "r", encoding="utf-8") as f:
            pyproject_content = f.read()
            self.assertIn("dependencies = []", pyproject_content)

        # Cargo.toml dependencies must be empty
        cargo_path = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli", "Cargo.toml")
        with open(cargo_path, "r", encoding="utf-8") as f:
            cargo_content = f.read()
            # [dependencies] section should have no third-party crates
            dep_after = cargo_content.split("[dependencies]")[1]
            # Content before the next section header (e.g. [[bin]] or [lib])
            dep_lines = [line.strip() for line in dep_after.split("[")[0].splitlines() if line.strip() and not line.strip().startswith("#")]
            self.assertEqual(dep_lines, [], f"Expected empty [dependencies], got: {dep_lines}")


if __name__ == "__main__":
    unittest.main()
