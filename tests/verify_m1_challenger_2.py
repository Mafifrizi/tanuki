"""Empirical verification harness for Challenger 2 (Milestone 1 Doctor Engine)."""

import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tanuki.doctor import check_keytab, check_krb5_conf, diagnose_system



def make_keytab(entries: list) -> bytes:
    buf = io.BytesIO()
    buf.write(b"\x05\x02")
    for e in entries:
        realm = e.get("realm", "CORP.LOCAL").encode("utf-8")
        comps = [c.encode("utf-8") for c in e.get("comps", ["host"])]
        keytype = e.get("keytype", 18)
        kvno = e.get("kvno", 1)
        key_data = e.get("key", b"\x11" * 32)
        timestamp = 1700000000

        ebuf = io.BytesIO()
        ebuf.write(struct.pack(">h", len(comps)))
        ebuf.write(struct.pack(">h", len(realm)) + realm)
        for c in comps:
            ebuf.write(struct.pack(">h", len(c)) + c)
        ebuf.write(struct.pack(">I", 1))
        ebuf.write(struct.pack(">I", timestamp))
        ebuf.write(struct.pack(">B", kvno if kvno < 256 else 0))
        ebuf.write(struct.pack(">h", keytype))
        ebuf.write(struct.pack(">H", len(key_data)) + key_data)
        ebuf.write(struct.pack(">I", kvno))

        raw = ebuf.getvalue()
        buf.write(struct.pack(">i", len(raw)))
        buf.write(raw)
    return buf.getvalue()


def run_krb5_conf_boundary_tests() -> int:
    print("[*] Running /etc/krb5.conf Boundary Tests...")
    passed = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Comments and inline comments
        c1 = os.path.join(tmpdir, "comments.conf")
        with open(c1, "w", encoding="utf-8") as f:
            f.write("""
            # Comment line 1
            ; Semicolon comment
            # default_realm = deceptive.lowercase
            [libdefaults]
                default_realm = CORP.LOCAL # inline comment with } and {
                dns_lookup_realm = false ; inline semicolon
            [realms]
                CORP.LOCAL = { # inline open brace
                    kdc = 127.0.0.1 ; inline kdc
                } # inline close brace
            """)
        r1 = check_krb5_conf(c1)
        assert r1["status"] == "PASS", f"Comments test failed: {r1}"
        assert r1["default_realm"] == "CORP.LOCAL"
        assert r1["realms"] == ["CORP.LOCAL"]
        assert len(r1["lowercase_realms"]) == 0
        passed += 1
        print("  [+] Comments (#, ;, inline, deceptive keywords, braces in comments): PASS")

        # 2. Empty sections
        c2 = os.path.join(tmpdir, "empty_sections.conf")
        with open(c2, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n\n[realms]\n\n[domain_realm]\n")
        r2 = check_krb5_conf(c2)
        assert r2["status"] == "WARN", f"Empty sections test failed: {r2}"
        passed += 1
        print("  [+] Empty sections handling (graceful WARN, no crash): PASS")

        # 3. Lowercase in [libdefaults]
        c3 = os.path.join(tmpdir, "lower_libdefaults.conf")
        with open(c3, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n    default_realm = corp.local\n")
        r3 = check_krb5_conf(c3)
        assert r3["status"] == "FAIL"
        assert "corp.local" in r3["lowercase_realms"]
        passed += 1
        print("  [+] Lowercase default_realm in [libdefaults]: PASS (correctly flagged FAIL)")

        # 4. Lowercase in [realms]
        c4 = os.path.join(tmpdir, "lower_realms.conf")
        with open(c4, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n    default_realm = CORP.LOCAL\n[realms]\n    corp.local = { kdc = 127.0.0.1 }\n")
        r4 = check_krb5_conf(c4)
        assert r4["status"] == "FAIL"
        assert "corp.local" in r4["lowercase_realms"]
        passed += 1
        print("  [+] Lowercase realm in [realms]: PASS (correctly flagged FAIL)")

        # 5. Lowercase in BOTH [libdefaults] and [realms]
        c5 = os.path.join(tmpdir, "lower_both.conf")
        with open(c5, "w", encoding="utf-8") as f:
            f.write("[libdefaults]\n    default_realm = corp.local\n[realms]\n    corp.local = { kdc = 127.0.0.1 }\n")
        r5 = check_krb5_conf(c5)
        assert r5["status"] == "FAIL"
        assert "corp.local" in r5["lowercase_realms"]
        passed += 1
        print("  [+] Lowercase in both [libdefaults] and [realms]: PASS (correctly flagged FAIL)")

        # 6. Nested braces in [realms]
        c6 = os.path.join(tmpdir, "nested_braces.conf")
        with open(c6, "w", encoding="utf-8") as f:
            f.write("""
            [realms]
                CORP.LOCAL = {
                    kdc = kdc.corp.local
                    auth_to_local = {
                        rule = RULE:[1:$1@$0](.*@CORP.LOCAL)s/@CORP.LOCAL//
                        sub_block = {
                            key = val
                        }
                    }
                }
                SECOND.LOCAL = {
                    kdc = sec.corp.local
                }
            """)
        r6 = check_krb5_conf(c6)
        assert r6["status"] == "PASS", f"Nested braces test failed: {r6}"
        assert r6["realms"] == ["CORP.LOCAL", "SECOND.LOCAL"]
        assert len(r6["lowercase_realms"]) == 0
        passed += 1
        print("  [+] Nested braces tracking in [realms]: PASS (inner blocks ignored, all realms found)")

        # 7. CRLF line endings
        c7 = os.path.join(tmpdir, "crlf.conf")
        with open(c7, "wb") as f:
            f.write(b"[libdefaults]\r\n    default_realm = CORP.LOCAL\r\n[realms]\r\n    CORP.LOCAL = {\r\n        kdc = 127.0.0.1\r\n    }\r\n")
        r7 = check_krb5_conf(c7)
        assert r7["status"] == "PASS"
        assert r7["default_realm"] == "CORP.LOCAL"
        passed += 1
        print("  [+] Windows CRLF line endings compatibility: PASS")

    return passed


def run_keytab_permission_tests() -> int:
    print("\n[*] Running Keytab Permissions Boundary Tests...")
    passed = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        kt_path = os.path.join(tmpdir, "test.keytab")
        with open(kt_path, "wb") as f:
            f.write(make_keytab([{"realm": "CORP.LOCAL", "comps": ["host"], "keytype": 18}]))

        def test_mode(mode_val: int):
            m = MagicMock()
            m.st_mode = stat.S_IFREG | mode_val
            with patch("os.name", "posix"):
                with patch("os.stat", return_value=m):
                    return check_keytab(kt_path)

        # 0600
        r_0600 = test_mode(0o600)
        assert r_0600["status"] == "PASS" and r_0600["is_secure_permissions"] is True
        assert r_0600["permissions"] == "0600"
        passed += 1
        print("  [+] Mode 0600: PASS (secure)")

        # 0400
        r_0400 = test_mode(0o400)
        assert r_0400["status"] == "PASS" and r_0400["is_secure_permissions"] is True
        assert r_0400["permissions"] == "0400"
        passed += 1
        print("  [+] Mode 0400: PASS (secure read-only)")

        # 0644
        r_0644 = test_mode(0o644)
        assert r_0644["status"] == "FAIL" and r_0644["is_secure_permissions"] is False
        assert "world-readable" in r_0644["details"]
        assert "chmod 0600" in r_0644["recommendation"]
        passed += 1
        print("  [+] Mode 0644: PASS (correctly flagged FAIL world-readable)")

        # 0666
        r_0666 = test_mode(0o666)
        assert r_0666["status"] == "FAIL" and r_0666["is_secure_permissions"] is False
        assert "world-writable" in r_0666["details"]
        assert "chmod 0600" in r_0666["recommendation"]
        passed += 1
        print("  [+] Mode 0666: PASS (correctly flagged FAIL world-writable)")

        # 0777
        r_0777 = test_mode(0o777)
        assert r_0777["status"] == "FAIL" and r_0777["is_secure_permissions"] is False
        assert "chmod 0600" in r_0777["recommendation"]
        passed += 1
        print("  [+] Mode 0777: PASS (correctly flagged FAIL full access)")

        # Non-existent path
        r_none = check_keytab(os.path.join(tmpdir, "nonexistent.keytab"))
        assert r_none["status"] == "N_A" and r_none["exists"] is False
        assert "not found" in r_none["details"]
        passed += 1
        print("  [+] Non-existent path: PASS (N_A status, graceful error)")

    return passed


def run_json_schema_tests() -> int:
    print("\n[*] Running --json Schema Strict Validation Tests...")
    passed = 0

    # 1. Direct engine report schema validation
    rep = diagnose_system()
    raw_json = rep.to_json()
    data = json.loads(raw_json)

    required_top = ["status", "timestamp", "duration_ms", "execution_time_ms", "summary", "checks"]
    for k in required_top:
        assert k in data, f"Missing top-level key {k}"

    assert data["status"] in ("PASS", "WARN", "FAIL")
    assert isinstance(data["summary"], dict)
    assert all(k in data["summary"] for k in ("passed", "warnings", "failures"))
    assert len(data["checks"]) == 5

    expected_names = [
        "keytab_permissions",
        "realm_capitalization",
        "sssd_subsystem",
        "ticket_lifetime",
        "host_tooling",
    ]
    actual_names = [c["name"] for c in data["checks"]]
    assert actual_names == expected_names, f"Checks mismatch: {actual_names}"

    for c in data["checks"]:
        assert "name" in c and "status" in c and "details" in c and "recommendation" in c
        assert c["status"] in ("PASS", "WARN", "FAIL", "N_A", "EXPIRED")

    ticket_chk = next(c for c in data["checks"] if c["name"] == "ticket_lifetime")
    assert "remaining_seconds" in ticket_chk
    passed += 1
    print("  [+] Direct DoctorReport.to_json() strict schema conformance: PASS")

    # 2. CLI subprocess execution with --json
    cmd = [sys.executable, "-m", "tanuki", "doctor", "--json"]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    cli_data = json.loads(proc.stdout)
    assert cli_data["status"] in ("PASS", "WARN", "FAIL")
    assert len(cli_data["checks"]) == 5
    passed += 1
    print("  [+] CLI stdout purity and strict JSON parsing (`python -m tanuki doctor --json`): PASS")

    # 3. CLI subprocess execution with explicit options and --json
    with tempfile.TemporaryDirectory() as tmpdir:
        conf_p = os.path.join(tmpdir, "k.conf")
        with open(conf_p, "w") as f:
            f.write("[libdefaults]\ndefault_realm = CORP.LOCAL\n")
        kt_p = os.path.join(tmpdir, "k.keytab")
        with open(kt_p, "wb") as f:
            f.write(make_keytab([{"realm": "CORP.LOCAL", "comps": ["host"], "keytype": 18}]))

        cmd_opts = [
            sys.executable,
            "-m",
            "tanuki",
            "doctor",
            "--json",
            "--keytab",
            kt_p,
            "--krb5-conf",
            conf_p,
        ]
        proc_opts = subprocess.run(cmd_opts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        cli_opts_data = json.loads(proc_opts.stdout)
        realm_chk = next(c for c in cli_opts_data["checks"] if c["name"] == "realm_capitalization")
        assert realm_chk["status"] == "PASS"
        assert realm_chk["default_realm"] == "CORP.LOCAL"
        passed += 1
        print("  [+] CLI with explicit file arguments + --json: PASS")

    return passed


def main():
    print("=" * 72)
    print(" TANUKI v1.2.0 CHALLENGER 2 EMPIRICAL BOUNDARY & STRESS VERIFIER")
    print("=" * 72)

    k_tests = run_krb5_conf_boundary_tests()
    p_tests = run_keytab_permission_tests()
    j_tests = run_json_schema_tests()

    total = k_tests + p_tests + j_tests
    print("\n" + "=" * 72)
    print(f" CHALLENGER 2 SUMMARY: {total}/{total} Boundary & Stress Suites PASSED")
    print(" VERDICT: APPROVE")
    print("=" * 72)


if __name__ == "__main__":
    main()
