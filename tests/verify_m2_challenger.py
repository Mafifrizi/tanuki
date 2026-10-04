"""Empirical Challenger Verification & Stress Test Harness for Milestone 2.

This test harness executes deep empirical verification and stress tests:
1. Terminal Triage for all 10 Kerberos errors: asserts [TACTICAL CMD] and [BLUE TELEMETRY].
2. JSON Triage for all 10 Kerberos errors: parses stdout with json.loads and validates telemetry schema.
3. Decision Ladder (Terminal & JSON): asserts [BLUE TELEMETRY] sections and valid telemetry schema.
4. Edge cases & Adversarial inputs: Event ID lookup, case-insensitivity, substring match, unknown codes, flag order.
5. Zero-network compliance audit during triage and ladder lookups.
6. Rust source parity and safety constraint audit.
"""

import json
import os
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tanuki.protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution
from tanuki.telemetry import (
    ERROR_TELEMETRY,
    EVENT_DESCRIPTIONS,
    LADDER_TELEMETRY,
    OPERATIONAL_REMEDIATIONS,
    format_telemetry_inline,
    format_telemetry_terminal,
)

ALL_10_ERROR_CODES = [
    "KRB_AP_ERR_SKEW",
    "KDC_ERR_ETYPE_NOSUPP",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "KDC_ERR_PREAUTH_FAILED",
    "STATUS_MORE_PROCESSING_REQUIRED",
    "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_KEY_EXPIRED",
    "KDC_ERR_NAME_EXP",
    "KDC_ERR_PADATA_TYPE_NOSUPP",
]


def run_cli(args: List[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "tanuki"] + args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )


# -----------------------------------------------------------------------------
# Test Suite 1: Terminal Triage for all 10 Error Codes
# -----------------------------------------------------------------------------
def test_terminal_triage_all_10_codes() -> Tuple[bool, List[str]]:
    print("\n--- [Suite 1] Terminal Triage for all 10 Error Codes ---")
    failures = []

    for code in ALL_10_ERROR_CODES:
        res = run_cli(["triage", code])
        if res.returncode != 0:
            failures.append(f"Exit code non-zero for '{code}': {res.returncode}. Stderr: {res.stderr}")
            continue

        stdout = res.stdout

        # Assert mandatory sections
        if "[TACTICAL CMD]" not in stdout:
            failures.append(f"Missing '[TACTICAL CMD]' in terminal triage for '{code}'")

        if "[BLUE TELEMETRY]" not in stdout:
            failures.append(f"Missing '[BLUE TELEMETRY]' in terminal triage for '{code}'")

        # Assert backward-compatible lines
        if f"Found matching error: {code}" not in stdout:
            failures.append(f"Missing 'Found matching error: {code}' in stdout")

        if "Root Cause:" not in stdout:
            failures.append(f"Missing 'Root Cause:' in stdout for '{code}'")

        if "Resolution:" not in stdout:
            failures.append(f"Missing 'Resolution:' in stdout for '{code}'")

        # Assert detailed telemetry components
        if "Auditd Rules:" not in stdout:
            failures.append(f"Missing 'Auditd Rules:' in telemetry for '{code}'")

        if "Windows Event IDs:" not in stdout:
            failures.append(f"Missing 'Windows Event IDs:' in telemetry for '{code}'")

        if "Sigma Rules:" not in stdout:
            failures.append(f"Missing 'Sigma Rules:' in telemetry for '{code}'")

        if "Falco Signatures:" not in stdout:
            failures.append(f"Missing 'Falco Signatures:' in telemetry for '{code}'")

    success = len(failures) == 0
    print(f"Suite 1 result: {'PASS' if success else 'FAIL'} ({len(failures)} failures)")
    return success, failures


# -----------------------------------------------------------------------------
# Test Suite 2: JSON Triage for all 10 Error Codes
# -----------------------------------------------------------------------------
def test_json_triage_all_10_codes() -> Tuple[bool, List[str]]:
    print("\n--- [Suite 2] JSON Triage Schema & Deserialization for all 10 Error Codes ---")
    failures = []

    for code in ALL_10_ERROR_CODES:
        res = run_cli(["triage", code, "--json"])
        if res.returncode != 0:
            failures.append(f"Exit code non-zero for '{code} --json': {res.returncode}. Stderr: {res.stderr}")
            continue

        try:
            data = json.loads(res.stdout)
        except Exception as exc:
            failures.append(f"Invalid JSON emitted for '{code}': {exc}. Stdout: {res.stdout[:200]}")
            continue

        if not isinstance(data, dict):
            failures.append(f"JSON root is not dict for '{code}': {type(data)}")
            continue

        if data.get("code") != code:
            failures.append(f"Expected code '{code}', got '{data.get('code')}'")

        if "tactical_cmd" not in data or not isinstance(data["tactical_cmd"], str) or not data["tactical_cmd"]:
            failures.append(f"Missing or empty tactical_cmd in JSON for '{code}'")

        if "telemetry" not in data or not isinstance(data["telemetry"], dict):
            failures.append(f"Missing or non-dict telemetry in JSON for '{code}'")
            continue

        telem = data["telemetry"]

        # Validate auditd
        if "auditd" not in telem or not isinstance(telem["auditd"], list) or len(telem["auditd"]) == 0:
            failures.append(f"Missing or empty auditd rules list for '{code}'")
        else:
            for rule in telem["auditd"]:
                if not (rule.startswith("-w ") or rule.startswith("-a ")):
                    failures.append(f"Invalid auditd rule syntax in '{code}': {rule}")

        # Validate event_ids
        if "event_ids" not in telem or not isinstance(telem["event_ids"], list) or len(telem["event_ids"]) == 0:
            failures.append(f"Missing or empty event_ids list for '{code}'")
        else:
            for eid in telem["event_ids"]:
                if not isinstance(eid, int) or eid <= 0:
                    failures.append(f"Invalid event ID {eid} in '{code}'")

        # Validate sigma
        if "sigma" not in telem or not isinstance(telem["sigma"], list) or len(telem["sigma"]) == 0:
            failures.append(f"Missing or empty sigma list for '{code}'")
        else:
            for sig in telem["sigma"]:
                if not isinstance(sig, dict):
                    failures.append(f"Sigma item is not dict in '{code}': {sig}")
                    continue
                for req in ["title", "status", "logsource", "tags"]:
                    if req not in sig:
                        failures.append(f"Missing field '{req}' in sigma rule for '{code}'")
                if not isinstance(sig.get("tags"), list) or len(sig.get("tags")) == 0:
                    failures.append(f"Invalid or empty tags in sigma rule for '{code}'")

        # Validate falco
        if "falco" not in telem or not isinstance(telem["falco"], list) or len(telem["falco"]) == 0:
            failures.append(f"Missing or empty falco list for '{code}'")
        else:
            for fal in telem["falco"]:
                if not isinstance(fal, dict):
                    failures.append(f"Falco item is not dict in '{code}': {fal}")
                    continue
                for req in ["rule", "priority", "condition", "output"]:
                    if req not in fal:
                        failures.append(f"Missing field '{req}' in falco rule for '{code}'")
                if fal.get("priority") not in ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"]:
                    failures.append(f"Invalid falco priority '{fal.get('priority')}' in '{code}'")

    success = len(failures) == 0
    print(f"Suite 2 result: {'PASS' if success else 'FAIL'} ({len(failures)} failures)")
    return success, failures


# -----------------------------------------------------------------------------
# Test Suite 3: Tactical Decision Ladder (Terminal & JSON)
# -----------------------------------------------------------------------------
def test_decision_ladder() -> Tuple[bool, List[str]]:
    print("\n--- [Suite 3] Tactical Decision Ladder Terminal & JSON Verification ---")
    failures = []

    # 3.1 Terminal Output
    res_term = run_cli(["ladder"])
    if res_term.returncode != 0:
        failures.append(f"'tanuki ladder' failed with code {res_term.returncode}: {res_term.stderr}")
    else:
        out = res_term.stdout
        if "TANUKI 5-RUNG TACTICAL DECISION LADDER" not in out:
            failures.append("Missing header in 'tanuki ladder'")
        if "[BLUE TELEMETRY]" not in out:
            failures.append("Missing '[BLUE TELEMETRY]' in 'tanuki ladder'")
        for rung_idx in range(1, 6):
            if f"RUNG {rung_idx}" not in out:
                failures.append(f"Missing RUNG {rung_idx} in 'tanuki ladder' output")

        # Rung 5 structural tags
        rung5_tags = [
            "[TARGET]",
            "[PREREQUISITE]",
            "[TACTICAL CMD]",
            "[BLUE TELEMETRY]",
            "[EXPECTED ARTIFACT]",
            "[OPSEC RATIONALE]",
        ]
        for tag in rung5_tags:
            if tag not in out:
                failures.append(f"Missing required standard tag '{tag}' in ladder terminal output")

    # 3.2 JSON Output
    res_json = run_cli(["ladder", "--json"])
    if res_json.returncode != 0:
        failures.append(f"'tanuki ladder --json' failed with code {res_json.returncode}: {res_json.stderr}")
    else:
        try:
            rungs = json.loads(res_json.stdout)
        except Exception as exc:
            failures.append(f"Invalid JSON in 'tanuki ladder --json': {exc}")
            rungs = []

        if not isinstance(rungs, list) or len(rungs) != 5:
            failures.append(f"Expected list of 5 rungs in ladder JSON, got {len(rungs) if isinstance(rungs, list) else type(rungs)}")
        else:
            for idx, rung in enumerate(rungs, 1):
                if rung.get("rung") != idx:
                    failures.append(f"Rung index mismatch: expected {idx}, got {rung.get('rung')}")
                if "telemetry" not in rung or not isinstance(rung["telemetry"], dict):
                    failures.append(f"Missing telemetry block in ladder rung {idx}")
                    continue
                telem = rung["telemetry"]
                for field in ["auditd", "event_ids", "sigma", "falco"]:
                    if field not in telem:
                        failures.append(f"Missing '{field}' in telemetry of ladder rung {idx}")
                if not isinstance(telem["auditd"], list) or len(telem["auditd"]) == 0:
                    failures.append(f"Empty or non-list auditd in ladder rung {idx}")
                if not isinstance(telem["event_ids"], list) or len(telem["event_ids"]) == 0:
                    failures.append(f"Empty or non-list event_ids in ladder rung {idx}")

    success = len(failures) == 0
    print(f"Suite 3 result: {'PASS' if success else 'FAIL'} ({len(failures)} failures)")
    return success, failures


# -----------------------------------------------------------------------------
# Test Suite 4: Adversarial Input Mining & Edge Cases
# -----------------------------------------------------------------------------
def test_adversarial_inputs_and_edge_cases() -> Tuple[bool, List[str]]:
    print("\n--- [Suite 4] Adversarial Input Mining & Edge Cases ---")
    failures = []

    # 4.1 Lookup by Windows Event ID
    event_id_mappings = {
        "37": "KRB_AP_ERR_SKEW",
        "14": "KDC_ERR_ETYPE_NOSUPP",
        "6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        "24": "KDC_ERR_PREAUTH_FAILED",
        "7": "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        "18": "KDC_ERR_CLIENT_REVOKED",
        "23": "KDC_ERR_KEY_EXPIRED",
        "12": "KDC_ERR_NAME_EXP",
        "16": "KDC_ERR_PADATA_TYPE_NOSUPP",
    }
    for eid, expected_code in event_id_mappings.items():
        # Terminal mode
        res = run_cli(["triage", eid])
        if res.returncode != 0:
            failures.append(f"Event ID lookup failed for '{eid}' (code {res.returncode})")
        elif f"Found matching error: {expected_code}" not in res.stdout:
            failures.append(f"Event ID '{eid}' returned unexpected code in terminal: {res.stdout[:150]}")
        elif "[TACTICAL CMD]" not in res.stdout or "[BLUE TELEMETRY]" not in res.stdout:
            failures.append(f"Event ID '{eid}' missing sections in terminal output")

        # JSON mode
        res_j = run_cli(["triage", eid, "--json"])
        if res_j.returncode != 0:
            failures.append(f"Event ID JSON lookup failed for '{eid}' (code {res_j.returncode})")
        else:
            try:
                data = json.loads(res_j.stdout)
                if data.get("code") != expected_code:
                    failures.append(f"Event ID '{eid}' JSON expected {expected_code}, got {data.get('code')}")
                if "telemetry" not in data or not data["telemetry"].get("auditd"):
                    failures.append(f"Event ID '{eid}' JSON missing valid telemetry block")
            except Exception as exc:
                failures.append(f"Event ID '{eid}' JSON parse error: {exc}")

    # 4.2 Case-insensitivity tests
    case_variants = [
        ("krb_ap_err_skew", "KRB_AP_ERR_SKEW"),
        ("Kdc_Err_Etype_Nosupp", "KDC_ERR_ETYPE_NOSUPP"),
        ("status_more_processing_required", "STATUS_MORE_PROCESSING_REQUIRED"),
        ("kdc_err_padata_type_nosupp", "KDC_ERR_PADATA_TYPE_NOSUPP"),
    ]
    for variant, expected in case_variants:
        res = run_cli(["triage", variant])
        if res.returncode != 0 or f"Found matching error: {expected}" not in res.stdout:
            failures.append(f"Case-insensitive lookup failed for '{variant}': {res.stdout[:100]}")

    # 4.3 Substring match tests
    substring_variants = [
        ("SKEW", "KRB_AP_ERR_SKEW"),
        ("ETYPE", "KDC_ERR_ETYPE_NOSUPP"),
        ("PREAUTH", "KDC_ERR_PREAUTH_FAILED"),
        ("REVOKED", "KDC_ERR_CLIENT_REVOKED"),
    ]
    for sub, expected in substring_variants:
        res = run_cli(["triage", sub])
        if res.returncode != 0 or f"Found matching error: {expected}" not in res.stdout:
            failures.append(f"Substring lookup failed for '{sub}': {res.stdout[:100]}")

    # 4.4 Non-existent / Unknown error queries
    unknown_queries = [
        "NON_EXISTENT_ERR_9999",
        "XYZ_INVALID_CODE",
        "999999",
    ]
    for unk in unknown_queries:
        # Terminal mode should fail with exit code 1
        res = run_cli(["triage", unk])
        if res.returncode == 0:
            failures.append(f"Unknown query '{unk}' unexpectedly returned exit code 0")
        if "No matching error resolution found" not in res.stderr and "No matching error resolution found" not in res.stdout:
            failures.append(f"Unknown query '{unk}' missing error message")

        # JSON mode should output JSON error envelope with exit code 3
        res_j = run_cli(["triage", unk, "--json"])
        if res_j.returncode != 3:
            failures.append(f"Unknown query '{unk}' with --json expected exit code 3, got {res_j.returncode}")
        try:
            err_data = json.loads(res_j.stdout)
            if err_data.get("reason_code") != "UNKNOWN_ERROR_CODE":
                failures.append(f"Unknown query '{unk}' with --json expected reason_code UNKNOWN_ERROR_CODE, got {err_data.get('reason_code')}")
        except Exception as exc:
            failures.append(f"Unknown query '{unk}' with --json expected valid JSON error envelope, got error: {exc}")

    # 4.5 Full dictionary terminal and JSON
    res_full = run_cli(["triage"])
    if res_full.returncode != 0:
        failures.append(f"Full triage dictionary terminal failed (code {res_full.returncode})")
    elif "KERBEROS & SSSD ERROR RESOLUTION DICTIONARY" not in res_full.stdout:
        failures.append("Full triage dictionary missing header")

    res_full_j = run_cli(["triage", "--json"])
    if res_full_j.returncode != 0:
        failures.append(f"Full triage dictionary JSON failed (code {res_full_j.returncode})")
    else:
        try:
            full_data = json.loads(res_full_j.stdout)
            if len(full_data) != 10:
                failures.append(f"Full triage dictionary expected 10 items, got {len(full_data)}")
            for item in full_data:
                if "telemetry" not in item or "tactical_cmd" not in item:
                    failures.append(f"Item '{item.get('code')}' missing telemetry or tactical_cmd in full JSON")
        except Exception as exc:
            failures.append(f"Full triage dictionary JSON parse error: {exc}")

    # 4.6 Flag permutation tests
    res_perm1 = run_cli(["--json", "triage", "KRB_AP_ERR_SKEW"])
    if res_perm1.returncode != 0:
        failures.append(f"Flag permutation 'tanuki --json triage KRB_AP_ERR_SKEW' failed (code {res_perm1.returncode})")
    else:
        try:
            json.loads(res_perm1.stdout)
        except Exception:
            failures.append("Flag permutation 'tanuki --json triage KRB_AP_ERR_SKEW' did not output valid JSON")

    res_perm2 = run_cli(["--json", "ladder"])
    if res_perm2.returncode != 0:
        failures.append(f"Flag permutation 'tanuki --json ladder' failed (code {res_perm2.returncode})")
    else:
        try:
            json.loads(res_perm2.stdout)
        except Exception:
            failures.append("Flag permutation 'tanuki --json ladder' did not output valid JSON")

    success = len(failures) == 0
    print(f"Suite 4 result: {'PASS' if success else 'FAIL'} ({len(failures)} failures)")
    return success, failures


# -----------------------------------------------------------------------------
# Test Suite 5: Zero-Network & In-Process Execution Audit
# -----------------------------------------------------------------------------
def test_zero_network_triage_audit() -> Tuple[bool, List[str]]:
    print("\n--- [Suite 5] Zero-Network In-Process Audit ---")
    failures = []
    intercepted_calls = []

    orig_socket = socket.socket
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def mock_socket(*args, **kwargs):
        intercepted_calls.append("socket.socket() instantiated")
        raise RuntimeError("Network attempt detected")

    def mock_getaddrinfo(*args, **kwargs):
        intercepted_calls.append("socket.getaddrinfo() called")
        raise RuntimeError("DNS attempt detected")

    def mock_gethostbyname(*args, **kwargs):
        intercepted_calls.append("socket.gethostbyname() called")
        raise RuntimeError("DNS attempt detected")

    socket.socket = mock_socket
    socket.getaddrinfo = mock_getaddrinfo
    socket.gethostbyname = mock_gethostbyname

    try:
        # In-process triage lookups
        for code in ALL_10_ERROR_CODES:
            res = find_error_resolution(code)
            if not res or "telemetry" not in res:
                failures.append(f"find_error_resolution failed for '{code}'")

        # In-process formatters
        sample = ERROR_TELEMETRY["KRB_AP_ERR_SKEW"]["telemetry"]
        t_str = format_telemetry_terminal(sample)
        i_str = format_telemetry_inline(sample)
        if not t_str or not i_str:
            failures.append("formatters returned empty string")

    except Exception as exc:
        failures.append(f"In-process lookup triggered exception: {exc}")
    finally:
        socket.socket = orig_socket
        socket.getaddrinfo = orig_getaddrinfo
        socket.gethostbyname = orig_gethostbyname

    if intercepted_calls:
        for c in intercepted_calls:
            failures.append(f"Network call intercepted: {c}")

    success = len(failures) == 0
    print(f"Suite 5 result: {'PASS' if success else 'FAIL'} ({len(failures)} failures)")
    return success, failures


# -----------------------------------------------------------------------------
# Test Suite 6: Rust Core Parity & Safety Integrity Audit
# -----------------------------------------------------------------------------
def test_rust_core_parity_and_safety() -> Tuple[bool, List[str]]:
    print("\n--- [Suite 6] Rust Core Parity & Safety Integrity Audit ---")
    failures = []
    crates_dir = os.path.join(PROJECT_ROOT, "crates", "tanuki-cli")

    # 1. lib.rs #![forbid(unsafe_code)]
    lib_rs = os.path.join(crates_dir, "src", "lib.rs")
    if not os.path.isfile(lib_rs):
        failures.append(f"Missing {lib_rs}")
    else:
        with open(lib_rs, "r", encoding="utf-8") as f:
            content = f.read()
        if "#![forbid(unsafe_code)]" not in content:
            failures.append("Missing '#![forbid(unsafe_code)]' in crates/tanuki-cli/src/lib.rs")

    # 2. Check no unsafe blocks in any rust file
    src_dir = os.path.join(crates_dir, "src")
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".rs"):
                fpath = os.path.join(root, file)
                with open(fpath, "r", encoding="utf-8") as f:
                    code = f.read()
                if "unsafe {" in code or "unsafe fn" in code:
                    failures.append(f"Unsafe code detected in {fpath}")

    # 3. Check telemetry.rs coverage
    telem_rs = os.path.join(crates_dir, "src", "protocol", "telemetry.rs")
    if not os.path.isfile(telem_rs):
        failures.append(f"Missing {telem_rs}")
    else:
        with open(telem_rs, "r", encoding="utf-8") as f:
            telem_code = f.read()
        for code in ALL_10_ERROR_CODES:
            var_name = f"TELEMETRY_{code}"
            if var_name not in telem_code:
                failures.append(f"Missing Rust telemetry constant '{var_name}' in telemetry.rs")

        for rung_idx in range(1, 6):
            var_name = f"TELEMETRY_LADDER_RUNG_{rung_idx}"
            if var_name not in telem_code:
                failures.append(f"Missing Rust ladder telemetry constant '{var_name}' in telemetry.rs")

    # 4. Check kerberos.rs has tactical_cmd and telemetry
    kerberos_rs = os.path.join(crates_dir, "src", "protocol", "kerberos.rs")
    if not os.path.isfile(kerberos_rs):
        failures.append(f"Missing {kerberos_rs}")
    else:
        with open(kerberos_rs, "r", encoding="utf-8") as f:
            kerb_code = f.read()
        if "pub tactical_cmd: &'static str" not in kerb_code:
            failures.append("Missing tactical_cmd field in Rust ErrorResolution struct")
        if "pub telemetry: TelemetryData" not in kerb_code:
            failures.append("Missing telemetry field in Rust ErrorResolution struct")
        for code in ALL_10_ERROR_CODES:
            if f'code: "{code}"' not in kerb_code:
                failures.append(f"Missing error code '{code}' in Rust ERROR_DICTIONARY")

    # 5. Check antislop: zero em dashes across all Python and Rust sources
    check_paths = [
        os.path.join(PROJECT_ROOT, "tanuki", "telemetry.py"),
        os.path.join(PROJECT_ROOT, "tanuki", "protocol.py"),
        os.path.join(PROJECT_ROOT, "tanuki", "cli.py"),
        telem_rs,
        kerberos_rs,
        os.path.join(crates_dir, "src", "main.rs"),
    ]
    for p in check_paths:
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                c = f.read()
            if "\u2014" in c:
                failures.append(f"Banned em dash found in {p}")

    success = len(failures) == 0
    print(f"Suite 6 result: {'PASS' if success else 'FAIL'} ({len(failures)} failures)")
    return success, failures


# -----------------------------------------------------------------------------
# Main Test Harness Runner
# -----------------------------------------------------------------------------
def main() -> int:
    print("=" * 72)
    print(" EMPIRICAL VERIFICATION HARNESS: Milestone 2 Detection Telemetry")
    print("=" * 72)

    all_failures = []
    suites = [
        ("Suite 1: Terminal Triage (all 10 codes)", test_terminal_triage_all_10_codes),
        ("Suite 2: JSON Triage (all 10 codes)", test_json_triage_all_10_codes),
        ("Suite 3: Decision Ladder (Terminal & JSON)", test_decision_ladder),
        ("Suite 4: Adversarial Input Mining & Edge Cases", test_adversarial_inputs_and_edge_cases),
        ("Suite 5: Zero-Network In-Process Audit", test_zero_network_triage_audit),
        ("Suite 6: Rust Core Parity & Safety Integrity", test_rust_core_parity_and_safety),
    ]

    suite_results = {}
    for name, fn in suites:
        passed, fails = fn()
        suite_results[name] = passed
        if not passed:
            all_failures.extend(fails)

    print("\n" + "=" * 72)
    print(" SUMMARY OF EMPIRICAL VERIFICATION SUITE RESULTS")
    print("=" * 72)
    for name, passed in suite_results.items():
        print(f"  {name}: {'PASS' if passed else 'FAIL'}")

    overall_pass = len(all_failures) == 0
    print(f"\nTotal Failures: {len(all_failures)}")
    if all_failures:
        for f in all_failures:
            print(f"  [FAILURE] {f}")

    verdict = "APPROVE" if overall_pass else "REJECT"
    print("\n" + "=" * 72)
    print(f" FINAL MILESTONE 2 VERDICT: {verdict}")
    print("=" * 72)

    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
