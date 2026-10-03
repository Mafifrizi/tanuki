"""Unified Tanuki Command-Line Interface."""

import json
import os
import sys
from typing import List, Optional

from . import __version__
from .doctor import diagnose_system
from .kcm import (
    save_recovered_ticket,
    scan_for_ccache_blobs,
    triage_local_caches,
)
from .keytab import parse_keytab_file
from .nhi import (
    format_exchange_report_terminal,
    format_token_report_terminal,
    validate_jwt_workload,
    validate_token_exchange,
)
from .protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution
from .telemetry import format_telemetry_inline, format_telemetry_terminal

USAGE_TEXT = """Tanuki CLI - Linux Active Directory Triage Engine

USAGE:
    tanuki <COMMAND> [OPTIONS]
    tanuki <KEYTAB_PATH> [--json]

COMMANDS:
    keytab [PATH]       Inspect binary keytab file (RFC 4120)
    kcm [OPTIONS]       Extract SSSD KCM credential cache streams
    triage [QUERY]      Lookup Kerberos/SSSD error codes and resolutions
    ladder              Display the 5-rung Tactical Decision Ladder
    doctor [OPTIONS]    Run proactive pre-flight diagnostic health checks
    token [TOKEN]       Validate workload identity JWT (RFC 8693 / NHI)
    nhi [SUBCOMMAND]    Non-Human Identity inspection and token exchange

OPTIONS:
    -f, --file <PATH>   Target database or keytab file
    -o, --out <DIR>     Output directory for extracted caches (default: ./extracted_ccache)
    -a, --audience <AUD> Expected audience for workload validation
    -i, --issuer <ISS>   Expected issuer for workload validation
    --keytab <PATH>     Target keytab path for doctor
    --krb5-conf <PATH>  Target krb5.conf path for doctor
    --sssd-pipe <PATH>  Target SSSD KCM pipe socket path for doctor
    --sssd-pid <PATH>   Target SSSD pid path for doctor
    --ccache <PATH>     Target ccache path for doctor
    --json              Output structured JSON for agent and pipeline consumption
    -h, --help          Print help information
    -V, --version       Print version information"""


EXIT_SUCCESS = 0
EXIT_USAGE_ERROR = 1
EXIT_POLICY_STOP = 2
EXIT_RESOURCE_MISSING = 3
EXIT_PARSE_FAILURE = 4


def emit_cli_error(
    message: str,
    reason_code: str,
    category: str,
    exit_code: int,
    target: Optional[str] = None,
    details: Optional[str] = None,
    json_output: bool = False,
    telemetry: Optional[dict] = None,
) -> None:
    if json_output:
        payload = {
            "status": "REFUSED" if exit_code == EXIT_POLICY_STOP else "ERROR",
            "reason_code": reason_code,
            "category": category,
            "exit_code": exit_code,
            "message": message,
        }
        if target:
            payload["target"] = target
        if details:
            payload["details"] = details
        if telemetry:
            payload["telemetry"] = telemetry
        print(json.dumps(payload, indent=2))
    else:
        prefix = {
            EXIT_POLICY_STOP: "[POLICY STOP]",
            EXIT_RESOURCE_MISSING: "[RESOURCE MISSING]",
            EXIT_PARSE_FAILURE: "[PARSE FAILURE]",
            EXIT_USAGE_ERROR: "[USAGE ERROR]",
        }.get(exit_code, "[ERROR]")
        if message.startswith("Error:") or message.startswith("Error "):
            sys.stderr.write(f"{prefix} {message}\n")
        else:
            sys.stderr.write(f"{prefix} Error: {message}\n")
        if details:
            sys.stderr.write(f"  Details: {details}\n")
    sys.exit(exit_code)


def print_usage() -> None:
    print(USAGE_TEXT)


def handle_keytab(file_path: Optional[str], json_output: bool) -> None:
    if not file_path:
        emit_cli_error(
            "Error: Keytab path required. Example: tanuki keytab /etc/krb5.keytab",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )

    if not os.path.exists(file_path):
        emit_cli_error(
            f"Error reading keytab at '{file_path}': No such file or directory",
            reason_code="MISSING_KEYTAB",
            category="RESOURCE_MISSING",
            exit_code=EXIT_RESOURCE_MISSING,
            target=file_path,
            json_output=json_output,
        )

    try:
        entries = parse_keytab_file(file_path)
    except Exception as exc:
        emit_cli_error(
            f"Error parsing keytab: {exc}",
            reason_code="CORRUPT_KEYTAB",
            category="PARSE_FAILURE",
            exit_code=EXIT_PARSE_FAILURE,
            target=file_path,
            details=str(exc),
            json_output=json_output,
        )

    if json_output:
        print(json.dumps(entries, indent=2))
        return

    print("=" * 72)
    print(" TANUKI KEYTAB TRIAGE REPORT")
    print("=" * 72)
    for idx, e in enumerate(entries, 1):
        print(f"[{idx}] Principal : {e['principal']}")
        print(f"    KVNO      : {e['vno']}")
        print(f"    Enctype   : {e['enctype_name']} ({e['keytype']})")
        key_preview = e["key_hex"][:16] if len(e["key_hex"]) > 16 else e["key_hex"]
        print(f"    Key (Hex) : {key_preview}... (length: {e['key_len']} bytes)")

    aes_entries = [e for e in entries if e["keytype"] in (17, 18, 19, 20)]
    if aes_entries:
        sample = aes_entries[0]
        print("\n[+] Recommended Non-Interactive TGT Acquisition (Modern AES):")
        print(f"    $ kinit -k -t {file_path} {sample['principal']}")
        print("    $ export KRB5CCNAME=/tmp/krb5cc_$(id -u)")
    print("=" * 72)


def handle_kcm(file_path: Optional[str], out_dir: str, json_output: bool) -> None:
    if file_path:
        if not os.path.exists(file_path):
            emit_cli_error(
                f"Credential cache database not found: {file_path}",
                reason_code="MISSING_RESOURCE",
                category="RESOURCE_MISSING",
                exit_code=EXIT_RESOURCE_MISSING,
                target=file_path,
                json_output=json_output,
            )

        os.makedirs(out_dir, exist_ok=True)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as exc:
            emit_cli_error(
                f"Error reading database '{file_path}': {exc}",
                reason_code="CORRUPT_DATA",
                category="PARSE_FAILURE",
                exit_code=EXIT_PARSE_FAILURE,
                target=file_path,
                details=str(exc),
                json_output=json_output,
            )

        blobs = scan_for_ccache_blobs(data)
        if json_output:
            json_output_data = [
                {
                    "offset": b["offset"],
                    "header_len": b["header_len"],
                    "payload_size": b["payload_size"],
                    "default_principal": b["default_principal"],
                }
                for b in blobs
            ]
            print(json.dumps(json_output_data, indent=2))
            return

        print(f"[*] Found {len(blobs)} candidate ccache streams in {file_path}")
        for idx, b in enumerate(blobs, 1):
            out_file = os.path.join(out_dir, f"ticket_{idx}.ccache")
            save_recovered_ticket(out_file, b["data"])
            p_desc = f" ({b['default_principal']})" if b["default_principal"] else ""
            print(f"    -> Saved {out_file}{p_desc}")
    else:
        triage_local_caches(out_dir, json_mode=json_output)


def handle_triage(query: Optional[str], json_output: bool) -> None:
    if query:
        res = find_error_resolution(query)
        if res:
            if json_output:
                print(json.dumps(res, indent=2))
            else:
                print(f"Found matching error: {res['code']}")
                if res["event_id"]:
                    print(f"Event ID: {res['event_id']}")
                print(f"Root Cause: {res['root_cause']}")
                print(f"Resolution:\n{res['resolution']}")
                if "tactical_cmd" in res:
                    print()
                    print("[TACTICAL CMD]")
                    print(f"    $ {res['tactical_cmd']}")
                if "telemetry" in res:
                    print()
                    print(format_telemetry_terminal(res["telemetry"]))
        else:
            if json_output:
                print("null")
            else:
                sys.stderr.write(f"No matching error resolution found for '{query}'\n")
                sys.stderr.write("Run 'tanuki triage' without arguments to see all known error codes.\n")
            sys.exit(1)
    else:
        if json_output:
            print(json.dumps(ERROR_DICTIONARY, indent=2))
        else:
            print("=" * 72)
            print(" KERBEROS & SSSD ERROR RESOLUTION DICTIONARY")
            print("=" * 72)
            for item in ERROR_DICTIONARY:
                event = f" (Event {item['event_id']})" if item["event_id"] else ""
                print(f"\nError Code: {item['code']}{event}")
                print(f"Root Cause: {item['root_cause']}")
                print(f"Tactical Resolution:\n{item['resolution']}")
                if "tactical_cmd" in item:
                    print(f"[TACTICAL CMD]:\n    $ {item['tactical_cmd']}")
                if "telemetry" in item:
                    print(f"[BLUE TELEMETRY]:\n    {format_telemetry_inline(item['telemetry'])}")
            print("=" * 72)


def handle_ladder(json_output: bool) -> None:
    if json_output:
        print(json.dumps(DECISION_LADDER, indent=2))
        return

    print("=" * 72)
    print(" TANUKI 5-RUNG TACTICAL DECISION LADDER")
    print("=" * 72)
    for rung in DECISION_LADDER:
        print(f"[*] {rung['title']}")
        print(f"    {rung['description']}")
        if "telemetry" in rung:
            print(f"    [BLUE TELEMETRY] {format_telemetry_inline(rung['telemetry'])}\n")
        else:
            print()
    print("Command Output Standard:")
    print("    [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]")
    print("=" * 72)


def handle_doctor(
    json_output: bool,
    keytab_path: Optional[str] = None,
    krb5_conf: Optional[str] = None,
    sssd_pipe: Optional[str] = None,
    sssd_pid: Optional[str] = None,
    ccache_path: Optional[str] = None,
) -> None:
    kwargs = {}
    if keytab_path:
        kwargs["keytab_path"] = keytab_path
    if krb5_conf:
        kwargs["krb5_conf_path"] = krb5_conf
    if sssd_pipe:
        kwargs["sssd_pipe"] = sssd_pipe
    if sssd_pid:
        kwargs["sssd_pid"] = sssd_pid
    if ccache_path:
        kwargs["ccache_path"] = ccache_path

    report = diagnose_system(**kwargs)
    if json_output:
        print(report.to_json())
    else:
        print(report.format_checklist())

    if report.status == "FAIL":
        has_policy_stop = any(
            c.get("status") == "FAIL"
            and (not c.get("is_secure_permissions", True) or c.get("has_weak_enctypes", False))
            for c in report.checks
        )
        if has_policy_stop:
            sys.exit(EXIT_POLICY_STOP)

        has_missing_resource = any(
            c.get("status") in ("FAIL", "N_A") and not c.get("exists", True)
            for c in report.checks
            if c.get("name") in ("keytab_permissions", "sssd_subsystem")
        )
        if has_missing_resource:
            sys.exit(EXIT_RESOURCE_MISSING)

        sys.exit(EXIT_POLICY_STOP)


def handle_token(
    token_arg: Optional[str],
    file_path: Optional[str],
    audience: Optional[str],
    issuer: Optional[str],
    json_output: bool,
) -> None:
    raw_token: Optional[str] = None
    if file_path:
        if not os.path.exists(file_path):
            emit_cli_error(
                f"Error: Token file not found: {file_path}",
                reason_code="MISSING_RESOURCE",
                category="RESOURCE_MISSING",
                exit_code=EXIT_USAGE_ERROR,
                target=file_path,
                json_output=json_output,
            )
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_token = f.read().strip()
        except UnicodeDecodeError:
            emit_cli_error(
                f"Error: File is not valid text: {file_path}",
                reason_code="CORRUPT_DATA",
                category="PARSE_FAILURE",
                exit_code=EXIT_USAGE_ERROR,
                target=file_path,
                json_output=json_output,
            )
        except Exception as exc:
            emit_cli_error(
                f"Error reading token file: {exc}",
                reason_code="CORRUPT_DATA",
                category="PARSE_FAILURE",
                exit_code=EXIT_USAGE_ERROR,
                target=file_path,
                details=str(exc),
                json_output=json_output,
            )
    elif token_arg is not None:
        if token_arg == "":
            emit_cli_error(
                "Error: Token string cannot be empty",
                reason_code="MISSING_ARGUMENT",
                category="USAGE_ERROR",
                exit_code=EXIT_USAGE_ERROR,
                json_output=json_output,
            )
        if os.path.isfile(token_arg):
            try:
                with open(token_arg, "r", encoding="utf-8") as f:
                    raw_token = f.read().strip()
            except Exception:
                raw_token = token_arg.strip()
        else:
            raw_token = token_arg.strip()
    elif not sys.stdin.isatty():
        raw_token = sys.stdin.read().strip()

    if not raw_token:
        emit_cli_error(
            "Error: No token provided. Pass as argument, -f/--file, or via stdin.",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )

    try:
        report = validate_jwt_workload(raw_token, expected_aud=audience)
    except Exception as exc:
        emit_cli_error(
            f"Error parsing token: {exc}",
            reason_code="CORRUPT_DATA",
            category="PARSE_FAILURE",
            exit_code=EXIT_USAGE_ERROR,
            details=str(exc),
            json_output=json_output,
        )

    if json_output:
        print(report.to_json())
    else:
        print(report.format_terminal())


def handle_nhi(
    subcmd: str,
    positional_args: List[str],
    file_path: Optional[str],
    audience: Optional[str],
    issuer: Optional[str],
    grant_type: Optional[str],
    subject_token: Optional[str],
    subject_token_type: Optional[str],
    requested_token_type: Optional[str],
    json_output: bool,
) -> None:
    if subcmd == "inspect":
        token_arg = positional_args[0] if positional_args else None
        handle_token(token_arg, file_path, audience, issuer, json_output)
    elif subcmd == "exchange":
        params: Dict[str, Any] = {}
        if grant_type:
            params["grant_type"] = grant_type
        if subject_token:
            params["subject_token"] = subject_token
        elif file_path and os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                params["subject_token"] = f.read().strip()
        elif positional_args:
            params["subject_token"] = positional_args[0]
        if subject_token_type:
            params["subject_token_type"] = subject_token_type
        if audience:
            params["audience"] = audience
        if requested_token_type:
            params["requested_token_type"] = requested_token_type

        report = validate_token_exchange(params)
        if json_output:
            print(report.to_json())
        else:
            print(report.format_terminal())
        if not report.get("valid"):
            sys.exit(EXIT_USAGE_ERROR)
    elif subcmd == "scan":
        known_paths = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/run/secrets/kubernetes.io/serviceaccount/token",
        ]
        found = []
        for p in known_paths:
            if os.path.isfile(p):
                found.append(p)
        if json_output:
            print(json.dumps({"discovered_tokens": found}, indent=2))
        else:
            print("=" * 72)
            print(" TANUKI NHI PASSIVE TOKEN SCANNER")
            print("=" * 72)
            if found:
                for p in found:
                    print(f"[FOUND] {p}")
            else:
                print("No standard workload tokens discovered on local filesystem.")
            print("=" * 72)
    else:
        handle_token(subcmd, file_path, audience, issuer, json_output)


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        print_usage()
        sys.exit(1)

    global_json = False
    explicit_command: Optional[str] = None
    positional_args: List[str] = []
    file_opt: Optional[str] = None
    out_opt: Optional[str] = None
    keytab_opt: Optional[str] = None
    krb5_conf_opt: Optional[str] = None
    sssd_pipe_opt: Optional[str] = None
    sssd_pid_opt: Optional[str] = None
    ccache_opt: Optional[str] = None
    audience_opt: Optional[str] = None
    issuer_opt: Optional[str] = None
    grant_type_opt: Optional[str] = None
    subject_token_opt: Optional[str] = None
    subject_token_type_opt: Optional[str] = None
    requested_token_type_opt: Optional[str] = None

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print_usage()
            return
        elif arg in ("-V", "--version"):
            print(f"tanuki {__version__}")
            return
        elif arg == "--json":
            global_json = True
        elif arg in ("-f", "--file"):
            if i + 1 < len(argv):
                file_opt = argv[i + 1]
                i += 1
        elif arg in ("-o", "--out"):
            if i + 1 < len(argv):
                out_opt = argv[i + 1]
                i += 1
        elif arg in ("-a", "--audience"):
            if i + 1 < len(argv):
                audience_opt = argv[i + 1]
                i += 1
        elif arg in ("-i", "--issuer"):
            if i + 1 < len(argv):
                issuer_opt = argv[i + 1]
                i += 1
        elif arg == "--grant-type":
            if i + 1 < len(argv):
                grant_type_opt = argv[i + 1]
                i += 1
        elif arg == "--subject-token":
            if i + 1 < len(argv):
                subject_token_opt = argv[i + 1]
                i += 1
        elif arg == "--subject-token-type":
            if i + 1 < len(argv):
                subject_token_type_opt = argv[i + 1]
                i += 1
        elif arg == "--requested-token-type":
            if i + 1 < len(argv):
                requested_token_type_opt = argv[i + 1]
                i += 1
        elif arg == "--keytab":
            if i + 1 < len(argv):
                keytab_opt = argv[i + 1]
                i += 1
        elif arg == "--krb5-conf":
            if i + 1 < len(argv):
                krb5_conf_opt = argv[i + 1]
                i += 1
        elif arg == "--sssd-pipe":
            if i + 1 < len(argv):
                sssd_pipe_opt = argv[i + 1]
                i += 1
        elif arg == "--sssd-pid":
            if i + 1 < len(argv):
                sssd_pid_opt = argv[i + 1]
                i += 1
        elif arg == "--ccache":
            if i + 1 < len(argv):
                ccache_opt = argv[i + 1]
                i += 1
        elif explicit_command is None and arg in ("keytab", "kcm", "triage", "ladder", "doctor", "token", "nhi"):
            explicit_command = arg
        elif not arg.startswith("-"):
            positional_args.append(arg)
        else:
            sys.stderr.write(f"Unknown option: {arg}\n")
            print_usage()
            sys.exit(1)
        i += 1

    command = explicit_command
    if command is None:
        if file_opt or positional_args:
            command = "keytab"
        else:
            print_usage()
            sys.exit(1)

    if command == "keytab":
        target = file_opt or (positional_args[0] if positional_args else None)
        handle_keytab(target, global_json)
    elif command == "kcm":
        target = file_opt or (positional_args[0] if positional_args else None)
        out_dir = out_opt or "./extracted_ccache"
        handle_kcm(target, out_dir, global_json)
    elif command == "triage":
        query = positional_args[0] if positional_args else None
        handle_triage(query, global_json)
    elif command == "ladder":
        handle_ladder(global_json)
    elif command == "doctor":
        target_kt = keytab_opt or file_opt or (positional_args[0] if positional_args else None)
        handle_doctor(
            global_json,
            keytab_path=target_kt,
            krb5_conf=krb5_conf_opt,
            sssd_pipe=sssd_pipe_opt,
            sssd_pid=sssd_pid_opt,
            ccache_path=ccache_opt,
        )
    elif command == "token":
        token_arg = positional_args[0] if positional_args else None
        handle_token(token_arg, file_opt, audience_opt, issuer_opt, global_json)
    elif command == "nhi":
        subcmd = positional_args[0] if positional_args else "inspect"
        remaining_pos = positional_args[1:] if positional_args else []
        handle_nhi(
            subcmd,
            remaining_pos,
            file_opt,
            audience_opt,
            issuer_opt,
            grant_type_opt,
            subject_token_opt,
            subject_token_type_opt,
            requested_token_type_opt,
            global_json,
        )
    else:
        sys.stderr.write(f"Unknown command: {command}\n")
        print_usage()
        sys.exit(1)
