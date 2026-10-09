"""Unified Tanuki Command-Line Interface."""

import json
import os
import sys
from typing import Any, List, Optional

from . import __version__
from .adcs import format_adcs_report_terminal, scan_adcs
from .auth import acquire_tgt
from .config import discover_dc_via_srv, generate_krb5_conf
from .doctor import diagnose_system, render_card_header, supports_unicode
from .fix import run_fix
from .kcm import (
    save_recovered_ticket,
    scan_for_ccache_blobs,
    triage_local_caches,
)
from .keytab import parse_keytab_file
from .ldap import format_ldap_report_terminal, query_active_directory_ldap
from .nhi import (
    discover_cloud_mesh,
    exchange_token_live,
    format_exchange_report_terminal,
    format_live_exchange_terminal,
    format_mesh_report_terminal,
    format_token_report_terminal,
    validate_jwt_workload,
    validate_token_exchange,
)
from .pac import format_pac_report_terminal, parse_pac
from .protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution
from .purge import run_purge
from .telemetry import format_telemetry_inline, format_telemetry_terminal

TANUKI_BANNER = r""" _____     _     _   _   _   _   _  __   _____ 
|_   _|   / \   | \ | | | | | | | |/ /  |_   _|
  | |    / _ \  |  \| | | | | | | ' /     | |  
  | |   / ___ \ | |\  | | |_| | | . \     | |  
  |_|   /_/   \ |_| \_|  \___/  |_|\_\   |___| """


def _build_usage_text() -> str:
    header_lines = render_card_header(
        f"Tanuki CLI · Tactical Identity Operator (v{__version__})",
        "Autonomous Non-Human Identity (NHI) & Hybrid Active Directory Engine",
    )
    return (
        TANUKI_BANNER
        + "\n\n"
        + "\n".join(header_lines)
        + "\n\n"
        + """USAGE:
    tanuki <COMMAND> [OPTIONS]
    tanuki <KEYTAB_PATH> [--json]

COMMANDS:
    doctor [OPTIONS]    Run proactive pre-flight diagnostic health checks (<5ms)
    fix [OPTIONS]       Idempotent closed-loop self-healing remediation
    purge [OPTIONS]     Cryptographic zero-trace artifact sanitization (NIST SP 800-88)
    pac [PATH_OR_HEX]   Decode MS-PAC binary structures and privileges
    adcs [OPTIONS]      Passive AD CS certificate and template scanner (ESC1-ESC11)
    ldap [OPTIONS]      Query Active Directory via unprivileged SASL GSSAPI LDAP
    keytab [PATH]       Inspect binary keytab file (RFC 4120)
    config [OPTIONS]    Generate unprivileged zero-DNS Kerberos config (RFC 4120)
    auth [OPTIONS]      Acquire TGT using keytab via host kinit or fallback ctypes
    kcm [OPTIONS]       Extract SSSD KCM credential cache streams
    triage [QUERY]      Lookup Kerberos/SSSD error codes and resolutions
    ladder              Display the 5-rung Tactical Decision Ladder
    token [TOKEN]       Validate workload identity JWT (RFC 8693 / NHI)
    nhi [SUBCOMMAND]    Non-Human Identity inspection and token exchange
    skill [OPTIONS]     Display AI agent skill manifest and operational contract

OPTIONS:
    -i, --interactive   Launch fast, interactive TUI wizard menu
    -f, --file <PATH>   Target database, keytab, template or token file
    -o, --out <PATH>    Output directory for extracted caches or target config path
    -p, --principal <P> Kerberos principal for authentication
    -a, --audience <AUD> Expected audience for workload validation
    --issuer <ISS>      Expected issuer for workload validation
    --realm <REALM>     Target Kerberos realm (mandates uppercase)
    --kdc <HOST_OR_IP>  KDC address or hostname (supports multiple or comma-separated)
    --admin-server <HOST_OR_IP> Optional admin server for config
    --clock-skew <SECS> Clock skew tolerance in seconds (unprivileged hypervisors)
    --enforce-aes       Strictly enforce AES-128/256 and reject legacy RC4
    --fast              Enable RFC 6113 FAST armoring (fast_req_armoring = true)
    --armor-cache <PATH> Armor credentials cache path for FAST armoring
    --stdout            Print generated config directly to stdout
    --keytab <PATH>     Target keytab path for doctor/auth/config/fix
    --krb5-conf <PATH>  Target krb5.conf path for doctor/fix
    --sssd-pipe <PATH>  Target SSSD KCM pipe socket path for doctor
    --sssd-pid <PATH>   Target SSSD pid path for doctor
    --ccache <PATH>     Target ccache path for doctor/auth/fix
    --opsec             Include live host OPSEC sensor probe in pre-flight doctor
    --dry-run           Simulate remediation without applying changes (for tanuki fix)
    --all               Purge all discovered ticket caches and temp configs
    --host <HOST_OR_IP> Target Active Directory domain controller for LDAP
    --query <TYPE>      LDAP query category (spn, rbcd, shadow, unconstrained, all)
    --base-dn <DN>      Base DN for directory query (e.g. DC=corp,DC=local)
    --live              Execute live HTTP POST token exchange client (RFC 8693)
    --endpoint <URL>    STS endpoint URL for live token exchange
    --json              Output structured JSON for agent and pipeline consumption
    -h, --help          Print help information
    -V, --version       Print version information"""
    )

USAGE_TEXT = _build_usage_text()


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

    for line in render_card_header(
        "TANUKI KEYTAB TRIAGE REPORT",
        f"File: {file_path} · RFC 4120 Binary Structure",
    ):
        print(line)

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")

    for idx, e in enumerate(entries, 1):
        print(f"[{idx}] Principal : {e['principal']}")
        print(f"    {t_branch} KVNO      : {e['vno']}")
        print(f"    {t_branch} Enctype   : {e['enctype_name']} ({e['keytype']})")
        key_preview = e["key_hex"][:16] if len(e["key_hex"]) > 16 else e["key_hex"]
        print(f"    {l_branch} Key (Hex) : {key_preview}... (length: {e['key_len']} bytes)")

    aes_entries = [e for e in entries if e["keytype"] in (17, 18, 19, 20)]
    if aes_entries:
        sample = aes_entries[0]
        env_krb5_conf = os.environ.get("KRB5_CONFIG")
        prefix = f"KRB5_CONFIG={env_krb5_conf} " if env_krb5_conf else ""
        print("\n[+] Recommended Non-Interactive TGT Acquisition (Modern AES):")
        print(f"    $ {prefix}kinit -k -t {file_path} {sample['principal']}")
        print("    $ export KRB5CCNAME=/tmp/krb5cc_$(id -u)")

        import shutil
        if not shutil.which("kinit"):
            print("\n[!] Host Tooling Advisory:")
            print("    'kinit' utility not found on PATH.")
            print("    Install: sudo apt install krb5-user (Debian/Kali) or sudo dnf install krb5-workstation (RHEL)")
            print("    Unprivileged: Generate local config via 'tanuki config' and use portable client.")


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

        if os.path.islink(file_path):
            emit_cli_error(
                f"Refusing to read symbolic link: {file_path}",
                reason_code="INVALID_PARAMETER",
                category="USAGE_ERROR",
                exit_code=EXIT_USAGE_ERROR,
                target=file_path,
                json_output=json_output,
            )

        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        try:
            with open(file_path, "rb") as f:
                data = f.read(104857600)  # 100MB bound
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
                for line in render_card_header(
                    f"TANUKI PROTOCOL TRIAGE: {res['code']}",
                    f"Event ID: {res['event_id']} · Root Cause Diagnostic" if res.get("event_id") else "RFC / SSSD Error Vector Diagnostic",
                ):
                    print(line)
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
            emit_cli_error(
                f"No matching error resolution found for '{query}'",
                reason_code="UNKNOWN_ERROR_CODE",
                category="PROTOCOL_ERROR",
                exit_code=EXIT_RESOURCE_MISSING,
                target=query,
                details="Run 'tanuki triage' without arguments to see all known error codes.",
                json_output=json_output,
            )
    else:
        if json_output:
            print(json.dumps(ERROR_DICTIONARY, indent=2))
        else:
            for line in render_card_header(
                "KERBEROS & SSSD ERROR RESOLUTION DICTIONARY",
                f"{len(ERROR_DICTIONARY)} Pre-compiled Protocol Vectors · Dual-Use Detection Telemetry",
            ):
                print(line)

            for item in ERROR_DICTIONARY:
                event = f" (Event {item['event_id']})" if item["event_id"] else ""
                print(f"\nError Code: {item['code']}{event}")
                print(f"Root Cause: {item['root_cause']}")
                print(f"Tactical Resolution:\n{item['resolution']}")
                if "tactical_cmd" in item:
                    print(f"[TACTICAL CMD]:\n    $ {item['tactical_cmd']}")
                if "telemetry" in item:
                    print(f"[BLUE TELEMETRY]:\n    {format_telemetry_inline(item['telemetry'])}")


def handle_ladder(json_output: bool) -> None:
    if json_output:
        print(json.dumps(DECISION_LADDER, indent=2))
        return

    for line in render_card_header(
        "TANUKI 5-RUNG TACTICAL DECISION LADDER",
        "Disciplined Agent SOP · Zero-Noise OPSEC Standard",
    ):
        print(line)

    for rung in DECISION_LADDER:
        print(f"[*] {rung['title']}")
        print(f"    {rung['description']}")
        if "telemetry" in rung:
            print(f"    [BLUE TELEMETRY] {format_telemetry_inline(rung['telemetry'])}\n")
        else:
            print()
    print("Command Output Standard:")
    print("    [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]")


def handle_doctor(
    json_output: bool,
    keytab_path: Optional[str] = None,
    krb5_conf: Optional[str] = None,
    sssd_pipe: Optional[str] = None,
    sssd_pid: Optional[str] = None,
    ccache_path: Optional[str] = None,
    opsec: bool = False,
    secrets_path: Optional[str] = None,
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
    if opsec:
        kwargs["include_opsec"] = True
    if secrets_path:
        kwargs["secrets_path"] = secrets_path

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


def handle_config(
    realm_opt: Optional[str],
    kdc_opt: Optional[str],
    admin_server_opt: Optional[str],
    out_path: Optional[str],
    stdout_mode: bool,
    json_output: bool,
    keytab_opt: Optional[str] = None,
    clockskew_opt: Optional[int] = None,
    enforce_aes_opt: bool = False,
    kdc_list_opt: Optional[List[str]] = None,
    fast_opt: bool = False,
    armor_cache_opt: Optional[str] = None,
) -> None:
    clean_realm = None
    if realm_opt and realm_opt.strip():
        clean_realm = realm_opt.strip().upper()
    elif keytab_opt:
        if not os.path.exists(keytab_opt):
            emit_cli_error(
                f"Error reading keytab at '{keytab_opt}': No such file or directory",
                reason_code="MISSING_KEYTAB",
                category="RESOURCE_MISSING",
                exit_code=EXIT_RESOURCE_MISSING,
                target=keytab_opt,
                json_output=json_output,
            )
        try:
            with open(keytab_opt, "rb") as f:
                content_bytes = f.read()
            if not content_bytes:
                emit_cli_error(
                    f"Keytab file is empty: '{keytab_opt}'",
                    reason_code="EMPTY_KEYTAB",
                    category="PARSE_FAILURE",
                    exit_code=EXIT_PARSE_FAILURE,
                    target=keytab_opt,
                    json_output=json_output,
                )
            entries = parse_keytab_file(keytab_opt)
        except Exception as exc:
            emit_cli_error(
                f"Error parsing keytab: {exc}",
                reason_code="CORRUPT_KEYTAB",
                category="PARSE_FAILURE",
                exit_code=EXIT_PARSE_FAILURE,
                target=keytab_opt,
                details=str(exc),
                json_output=json_output,
            )
        if not entries:
            emit_cli_error(
                f"Keytab contains no entries: '{keytab_opt}'",
                reason_code="EMPTY_KEYTAB",
                category="PARSE_FAILURE",
                exit_code=EXIT_PARSE_FAILURE,
                target=keytab_opt,
                json_output=json_output,
            )
        for entry in entries:
            candidate = (entry.get("realm") or "").strip()
            if candidate:
                clean_realm = candidate.upper()
                break
        if not clean_realm:
            emit_cli_error(
                f"No non-empty realm found in keytab: '{keytab_opt}'",
                reason_code="EMPTY_KEYTAB",
                category="PARSE_FAILURE",
                exit_code=EXIT_PARSE_FAILURE,
                target=keytab_opt,
                json_output=json_output,
            )
    else:
        emit_cli_error(
            "Error: Realm required for configuration generation. Example: tanuki config --realm CORP.LOCAL --kdc 192.168.56.106",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )

    kdcs: List[str] = []
    if kdc_list_opt:
        kdcs = list(kdc_list_opt)
    elif kdc_opt:
        for k in kdc_opt.split(","):
            kc = k.strip()
            if kc and kc not in kdcs:
                kdcs.append(kc)

    if not kdcs and clean_realm:
        discovered = discover_dc_via_srv(clean_realm)
        if discovered:
            kdcs.append(discovered[0])

    if not kdcs:
        emit_cli_error(
            "Error: KDC address or hostname required. Example: tanuki config --realm CORP.LOCAL --kdc 192.168.56.106",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )

    target_admin = admin_server_opt.strip() if admin_server_opt else kdcs[0]

    content = generate_krb5_conf(
        realm=clean_realm,
        kdc=kdcs,
        admin_server=target_admin,
        clockskew=clockskew_opt,
        enforce_aes=enforce_aes_opt,
        fast=fast_opt,
        armor_cache=armor_cache_opt,
    )

    if stdout_mode and not json_output:
        sys.stdout.write(content)
        return

    target_file = out_path or "./krb5.conf"
    abs_path = os.path.abspath(target_file)
    try:
        parent_dir = os.path.dirname(abs_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError as exc:
        emit_cli_error(
            f"Failed to write configuration file: {exc}",
            reason_code="WRITE_ERROR",
            category="PARSE_FAILURE",
            exit_code=EXIT_PARSE_FAILURE,
            target=target_file,
            details=str(exc),
            json_output=json_output,
        )

    export_cmd = f"export KRB5_CONFIG={abs_path}"
    kdc_display = ",".join(kdcs) if len(kdcs) > 1 else kdcs[0]

    if json_output:
        res = {
            "status": "SUCCESS",
            "realm": clean_realm,
            "kdc": kdc_display,
            "admin_server": target_admin,
            "config_path": abs_path,
            "export_command": export_cmd,
            "content": content,
        }
        if clockskew_opt is not None:
            res["clockskew"] = clockskew_opt
        if enforce_aes_opt:
            res["enforce_aes"] = True
        if fast_opt:
            res["fast"] = True
        if armor_cache_opt:
            res["armor_cache"] = armor_cache_opt
        print(json.dumps(res, indent=2))
        return

    for line in render_card_header(
        "TANUKI UNPRIVILEGED KERBEROS CONFIG GENERATOR",
        "Zero-DNS Direct Routing · RFC 4120 Compliant",
    ):
        print(line)

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")

    print(f"[+] Output File    : {abs_path}")
    print(f"    {t_branch} Target Realm   : {clean_realm} (RFC 4120 uppercase convention)")
    for k in kdcs:
        print(f"    {t_branch} Target KDC     : {k} (zero-DNS direct routing)")
    print(f"    {t_branch} Admin Server   : {target_admin}")
    if clockskew_opt is not None:
        print(f"    {t_branch} Clock Skew     : {clockskew_opt}s (drift tolerance)")
    if enforce_aes_opt:
        print(f"    {t_branch} Encryption     : AES-128/256 enforced (RC4 disabled)")
    if fast_opt:
        print(f"    {t_branch} FAST Armoring : RFC 6113 FAST enabled (fast_req_armoring = true)")
    if armor_cache_opt:
        print(f"    {t_branch} Armor Cache   : {armor_cache_opt}")
    print(f"    {l_branch} Status         : Active configuration ready")
    print("\n[+] To activate in your current session (unprivileged / no root required):")
    print(f"    $ {export_cmd}")
    print("    $ kinit -k -t <keytab> <principal>")


def handle_auth(
    keytab_path: Optional[str],
    principal: Optional[str],
    ccache_path: Optional[str],
    json_output: bool,
    force_ctypes: bool = False,
    krb5_conf: Optional[str] = None,
    kdc: Optional[str] = None,
) -> None:
    if not keytab_path:
        emit_cli_error(
            "Error: Keytab path required. Example: tanuki auth --keytab /etc/krb5.keytab --principal host/srv01@CORP.LOCAL",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )

    res = acquire_tgt(
        keytab_path=keytab_path,
        principal=principal,
        ccache_path=ccache_path,
        force_ctypes=force_ctypes,
        krb5_conf=krb5_conf,
        kdc=kdc,
    )

    if res.get("status") == "SUCCESS":
        if json_output:
            print(json.dumps(res, indent=2))
            return

        for line in render_card_header(
            "TANUKI UNPRIVILEGED TICKET ACQUISITION",
            f"Method: {res.get('method')} · Non-Interactive Authentication",
        ):
            print(line)

        use_uni = supports_unicode()
        t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")

        print(f"[+] Principal      : {res['principal']}")
        print(f"    {t_branch} Keytab File    : {res['keytab']}")
        print(f"    {t_branch} Credential CC  : {res['ccache']}")
        print(f"    {l_branch} Auth Method    : {res.get('method', 'unknown')}")
        print("\n[+] Active Credential Cache Export:")
        print(f"    $ {res['export_command']}")
    else:
        exit_code = res.get("exit_code", EXIT_RESOURCE_MISSING)
        if res.get("reason_code") == "AUTH_FAILED":
            exit_code = EXIT_POLICY_STOP
        elif res.get("reason_code") == "CORRUPT_KEYTAB":
            exit_code = EXIT_PARSE_FAILURE
        elif res.get("reason_code") == "MISSING_PRINCIPAL":
            exit_code = EXIT_USAGE_ERROR
        elif res.get("reason_code") == "KDC_UNREACHABLE":
            exit_code = EXIT_RESOURCE_MISSING

        emit_cli_error(
            message=res.get("message", "Authentication failed"),
            reason_code=res.get("reason_code", "AUTH_ERROR"),
            category=res.get("category", "AUTHENTICATION_ERROR"),
            exit_code=exit_code,
            target=res.get("target") or res.get("keytab"),
            details=res.get("details") or res.get("recommendation"),
            json_output=json_output,
        )


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
                exit_code=EXIT_RESOURCE_MISSING,
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
                exit_code=EXIT_PARSE_FAILURE,
                target=file_path,
                json_output=json_output,
            )
        except Exception as exc:
            emit_cli_error(
                f"Error reading token file: {exc}",
                reason_code="CORRUPT_DATA",
                category="PARSE_FAILURE",
                exit_code=EXIT_PARSE_FAILURE,
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
            exit_code=EXIT_PARSE_FAILURE,
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
    live_mode: bool = False,
    endpoint_url: Optional[str] = None,
) -> None:
    if subcmd == "inspect":
        token_arg = positional_args[0] if positional_args else None
        handle_token(token_arg, file_path, audience, issuer, json_output)
    elif subcmd == "exchange":
        sub_tok = subject_token
        if not sub_tok and file_path and os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                sub_tok = f.read().strip()
        elif not sub_tok and positional_args:
            sub_tok = positional_args[0]

        if live_mode or endpoint_url:
            if not sub_tok:
                emit_cli_error(
                    "Error: subject_token required for live token exchange.",
                    reason_code="MISSING_ARGUMENT",
                    category="USAGE_ERROR",
                    exit_code=EXIT_USAGE_ERROR,
                    json_output=json_output,
                )
            ep = endpoint_url or "https://sts.corp.local/oauth/v2/token"
            live_res = exchange_token_live(
                endpoint=ep,
                subject_token=sub_tok,
                subject_token_type=subject_token_type or "urn:ietf:params:oauth:token-type:jwt",
                requested_token_type=requested_token_type,
                audience=audience,
            )
            if json_output:
                print(json.dumps(live_res, indent=2))
            else:
                print(format_live_exchange_terminal(live_res))
            if live_res.get("status") != "SUCCESS":
                sys.exit(EXIT_POLICY_STOP)
            return

        params: Dict[str, Any] = {}
        if grant_type:
            params["grant_type"] = grant_type
        if sub_tok:
            params["subject_token"] = sub_tok
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
    elif subcmd in ("mesh", "ingest"):
        rep = discover_cloud_mesh(spiffe_socket=file_path)
        if json_output:
            print(json.dumps(rep, indent=2))
        else:
            print(format_mesh_report_terminal(rep))
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
            for line in render_card_header(
                "TANUKI NHI PASSIVE TOKEN SCANNER",
                "Filesystem Workload Identity Probes",
            ):
                print(line)
            if found:
                for p in found:
                    print(f"[FOUND] {p}")
            else:
                print("No standard workload tokens discovered on local filesystem.")
    else:
        handle_token(subcmd, file_path, audience, issuer, json_output)


def handle_pac(source: Optional[str], json_output: bool, is_file: bool = False) -> None:
    if not source:
        emit_cli_error(
            "Error: PAC source required (file path, hex string, or base64). Example: tanuki pac ./ticket.pac",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )
    if (
        is_file
        or source.endswith((".pac", ".bin", ".raw", ".der"))
        or "/" in source
        or "\\" in source
    ) and not os.path.exists(source):
        emit_cli_error(
            f"Error reading PAC file at '{source}': No such file or directory",
            reason_code="MISSING_PAC_FILE",
            category="RESOURCE_MISSING",
            exit_code=EXIT_RESOURCE_MISSING,
            target=source,
            json_output=json_output,
        )
    try:
        res = parse_pac(source)
    except Exception as exc:
        emit_cli_error(
            f"Error decoding PAC: {exc}",
            reason_code="CORRUPT_PAC",
            category="PARSE_FAILURE",
            exit_code=EXIT_PARSE_FAILURE,
            target=source,
            details=str(exc),
            json_output=json_output,
        )
    if json_output:
        print(json.dumps(res, indent=2))
    else:
        print(format_pac_report_terminal(res))


def handle_fix(
    keytab_path: Optional[str],
    realm: Optional[str],
    kdc: Optional[str],
    krb5_conf: Optional[str],
    ccache_path: Optional[str],
    dry_run: bool,
    clock_skew: int,
    json_output: bool,
    krb_error: Optional[Any] = None,
) -> None:
    rep = run_fix(
        keytab_path=keytab_path,
        realm=realm,
        kdc=kdc,
        krb5_conf=krb5_conf,
        ccache_path=ccache_path,
        dry_run=dry_run,
        clock_skew=clock_skew,
        krb_error=krb_error,
    )
    if json_output:
        print(rep.to_json())
    else:
        print(rep.format_terminal())
    if rep.status == "ERROR":
        sys.exit(EXIT_POLICY_STOP)


def handle_purge(
    target_path: Optional[str],
    purge_all: bool,
    json_output: bool,
) -> None:
    if not target_path and not purge_all:
        emit_cli_error(
            "Error: Purge requires either --all to purge all caches or a target file (--target <file>). Example: tanuki purge --all",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )

    if target_path:
        if not os.path.exists(target_path) and not os.path.islink(target_path):
            emit_cli_error(
                f"Error: Purge target not found: {target_path}",
                reason_code="MISSING_TARGET_FILE",
                category="RESOURCE_MISSING",
                exit_code=EXIT_RESOURCE_MISSING,
                target=target_path,
                json_output=json_output,
            )
        if os.path.isdir(target_path):
            emit_cli_error(
                f"Error: Purge target is a directory, not a file: {target_path}",
                reason_code="INVALID_TARGET_DIRECTORY",
                category="USAGE_ERROR",
                exit_code=EXIT_USAGE_ERROR,
                target=target_path,
                json_output=json_output,
            )

    targets = [target_path] if target_path else None
    rep = run_purge(target_paths=targets, purge_all=purge_all)
    if json_output:
        print(rep.to_json())
    else:
        print(rep.format_terminal())

    if rep.status != "SUCCESS":
        sys.exit(EXIT_PARSE_FAILURE)


def handle_adcs(
    source: Optional[str],
    json_output: bool,
    is_file: bool = False,
) -> None:
    if not source:
        emit_cli_error(
            "Error: AD CS template or certificate source required. Example: tanuki adcs --file templates.json",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )
    if (
        is_file
        or source.endswith((".json", ".ldif", ".pem", ".crt", ".der", ".txt"))
        or "/" in source
        or "\\" in source
    ) and not os.path.exists(source):
        emit_cli_error(
            f"Error reading AD CS source at '{source}': No such file or directory",
            reason_code="MISSING_ADCS_FILE",
            category="RESOURCE_MISSING",
            exit_code=EXIT_RESOURCE_MISSING,
            target=source,
            json_output=json_output,
        )
    try:
        rep = scan_adcs(source=source)
    except Exception as exc:
        emit_cli_error(
            f"Error scanning AD CS source: {exc}",
            reason_code="ADCS_SCAN_ERROR",
            category="PARSE_FAILURE",
            exit_code=EXIT_PARSE_FAILURE,
            target=source,
            details=str(exc),
            json_output=json_output,
        )
    if json_output:
        print(json.dumps(rep, indent=2))
    else:
        print(format_adcs_report_terminal(rep))


def handle_ldap(
    host: Optional[str],
    query_type: str,
    base_dn: str,
    port: int,
    use_ssl: bool,
    json_output: bool,
) -> None:
    if not host:
        emit_cli_error(
            "Error: LDAP host/DC address required. Example: tanuki ldap --host 192.168.56.106",
            reason_code="MISSING_ARGUMENT",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            json_output=json_output,
        )
    rep = query_active_directory_ldap(
        host=host,
        query_type=query_type,
        base_dn=base_dn,
        port=port,
        use_ssl=use_ssl,
    )
    if json_output:
        print(json.dumps(rep, indent=2, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))
    else:
        print(format_ldap_report_terminal(rep))
    if rep.get("status") in ("BIND_FAILED", "CONNECTION_FAILED"):
        sys.exit(EXIT_RESOURCE_MISSING)


def run_tui_wizard() -> None:
    """Launch pure standard-library interactive TUI wizard menu."""
    while True:
        header_lines = render_card_header(
            f"Tanuki Interactive TUI Wizard (v{__version__})",
            "Select an action to execute or enter 0 to exit",
        )
        print()
        print(TANUKI_BANNER)
        print()
        for h in header_lines:
            print(h)
        print()
        print("  [1]  Doctor   : Pre-flight diagnostic health checks (<5ms)")
        print("  [2]  Fix      : Idempotent closed-loop self-healing remediation")
        print("  [3]  Keytab   : Inspect RFC 4120 binary keytab file")
        print("  [4]  Auth     : Acquire TGT non-interactively via keytab")
        print("  [5]  PAC      : Decode MS-PAC binary structures & privileges")
        print("  [6]  LDAP     : Query Active Directory via unprivileged SASL GSSAPI")
        print("  [7]  AD CS    : Passive certificate & template scanner (ESC1-ESC11)")
        print("  [8]  NHI      : Workload identity inspection & token exchange")
        print("  [9]  KCM      : Extract SSSD KCM credential cache streams")
        print("  [10] Triage   : Lookup Kerberos protocol error resolutions")
        print("  [11] Ladder   : Display 5-rung Tactical Decision Ladder")
        print("  [12] Purge    : Cryptographic zero-trace artifact sanitization")
        print("  [13] Skill    : Display AI agent skill manifest")
        print("  [0]  Exit")
        print()

        try:
            choice = input("Select an option [0-13]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting Tanuki.")
            sys.exit(0)

        if choice in ("0", "exit", "quit", "q"):
            print("Exiting Tanuki.")
            sys.exit(0)
        elif choice == "1":
            handle_doctor(json_output=False)
        elif choice == "2":
            handle_fix(None, None, None, None, None, False, 300, False)
        elif choice == "3":
            kt = input("Keytab path [/etc/krb5.keytab]: ").strip() or "/etc/krb5.keytab"
            handle_keytab(kt, json_output=False)
        elif choice == "4":
            kt = input("Keytab path [/etc/krb5.keytab]: ").strip() or "/etc/krb5.keytab"
            p = input("Principal (optional): ").strip() or None
            handle_auth(keytab_path=kt, principal=p, ccache_path=None, json_output=False)
        elif choice == "5":
            pac_src = input("Target PAC file path or hex: ").strip()
            handle_pac(pac_src, json_output=False)
        elif choice == "6":
            host = input("Target DC IP/Host: ").strip()
            q = input("Query type (spn/rbcd/shadow/unconstrained/all) [all]: ").strip() or "all"
            handle_ldap(host=host, query_type=q, base_dn="DC=corp,DC=local", port=389, use_ssl=False, json_output=False)
        elif choice == "7":
            src = input("Templates JSON or Certificate path: ").strip()
            handle_adcs(src, json_output=False)
        elif choice == "8":
            tok = input("Enter JWT token or path: ").strip()
            handle_token(tok, None, None, None, False)
        elif choice == "9":
            f = input("KCM database path (optional): ").strip() or None
            handle_kcm(f, "./extracted_ccache", False)
        elif choice == "10":
            q = input("Error code or query (blank for all): ").strip() or None
            handle_triage(q, False)
        elif choice == "11":
            handle_ladder(False)
        elif choice == "12":
            conf = input("Confirm purge all cached credentials and configs? (y/N): ").strip().lower()
            if conf == "y":
                handle_purge(None, purge_all=True, json_output=False)
            else:
                print("Purge aborted.")
        elif choice == "13":
            handle_skill(False)
        else:
            print("Invalid option.")

        input("\nPress Enter to return to menu...")


def handle_skill(json_output: bool) -> None:
    manifest = {
        "name": "tanuki",
        "version": __version__,
        "description": "Autonomous Non-Human Identity (NHI) and Hybrid Active Directory Operator for Linux.",
        "author": "Tanuki Open Source Initiative",
        "lineage": {
            "pioneer_unix_tradecraft": "Tim Brown (@timb-machine), creator of Linikatz",
            "pioneer_agentic_ladder": "Dietrich Gebert (@dietrichayala), creator of Ponytail",
        },
        "triggers": [
            "active directory",
            "kerberos",
            "keytab",
            "sssd",
            "kcm",
            "certipy",
            "ad cs",
            "shadow credentials",
            "rbcd",
            "workload identity",
            "tanuki doctor",
            "pre-flight",
            "telemetry",
            "auditd",
            "rfc 8693",
            "token exchange",
        ],
        "output_standard": "[TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]",
        "ladder": DECISION_LADDER,
    }

    if json_output:
        print(json.dumps(manifest, indent=2))
        return

    for line in render_card_header(
        "TANUKI AI AGENT SKILL MANIFEST",
        f"v{__version__} · Dual-Engine Non-Human Identity Operator",
    ):
        print(line)

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")

    print("[*] Intellectual Lineage & Pioneers:")
    print(f"    {t_branch} Tim Brown (@timb-machine)     : Linikatz & UNIX Active Directory Assessment")
    print(f"    {l_branch} Dietrich Gebert (@dietrichayala) : Ponytail Decision Ladder Methodology\n")

    print("[*] Tactical Activation Triggers:")
    triggers_str = ", ".join(manifest["triggers"][:8]) + ", ..."
    print(f"    {triggers_str}\n")

    print("[*] 5-Rung Operator Tactical Decision Ladder:")
    for rung in DECISION_LADDER:
        print(f"    [{rung['rung']}] {rung['title']}")
    print()
    print("[*] Deterministic Command Output Standard:")
    print(f"    {manifest['output_standard']}")


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    known_subcommands = {
        "keytab", "kcm", "triage", "ladder", "doctor", "token", "nhi", "config", "skill", "auth",
        "pac", "fix", "purge", "adcs", "ldap",
    }

    if not argv:
        if sys.stdin.isatty() and sys.stdout.isatty():
            run_tui_wizard()
            return
        print_usage()
        sys.exit(EXIT_USAGE_ERROR)

    if len(argv) == 1 and argv[0] in ("-i", "--interactive"):
        run_tui_wizard()
        return

    if "--interactive" in argv and not any(a in known_subcommands for a in argv):
        run_tui_wizard()
        return

    global_json = "--json" in argv
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
    realm_opt: Optional[str] = None
    kdc_opt: Optional[str] = None
    admin_server_opt: Optional[str] = None
    stdout_opt: bool = False
    grant_type_opt: Optional[str] = None
    subject_token_opt: Optional[str] = None
    subject_token_type_opt: Optional[str] = None
    requested_token_type_opt: Optional[str] = None
    principal_opt: Optional[str] = None
    clock_skew_opt: Optional[int] = None
    enforce_aes_opt: bool = False
    kdc_list_opt: List[str] = []
    force_ctypes_opt: bool = False
    opsec_opt: bool = False
    dry_run_opt: bool = False
    purge_all_opt: bool = False
    host_opt: Optional[str] = None
    query_opt: Optional[str] = None
    base_dn_opt: Optional[str] = None
    port_opt: int = 389
    ssl_opt: bool = False
    live_opt: bool = False
    endpoint_opt: Optional[str] = None
    fast_opt: bool = False
    armor_cache_opt: Optional[str] = None
    krb_error_opt: Optional[str] = None
    secrets_path_opt: Optional[str] = None

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
        elif arg == "--interactive":
            if not explicit_command:
                run_tui_wizard()
                return
        elif arg in ("-i", "--issuer"):
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                issuer_opt = argv[i + 1]
                i += 1
            elif not explicit_command and not any(a in known_subcommands for a in argv):
                run_tui_wizard()
                return
            else:
                emit_cli_error(
                    "Option requires an argument: -i/--issuer",
                    reason_code="MISSING_ARGUMENT",
                    category="USAGE_ERROR",
                    exit_code=EXIT_USAGE_ERROR,
                    json_output=global_json,
                )
        elif arg in ("-f", "--file", "--template-dump", "--target"):
            if i + 1 < len(argv):
                file_opt = argv[i + 1]
                i += 1
        elif arg in ("-o", "--out"):
            if i + 1 < len(argv):
                out_opt = argv[i + 1]
                i += 1
        elif arg in ("-p", "--principal"):
            if i + 1 < len(argv):
                principal_opt = argv[i + 1]
                i += 1
        elif arg in ("-a", "--audience"):
            if i + 1 < len(argv):
                audience_opt = argv[i + 1]
                i += 1
        elif arg == "--realm":
            if i + 1 < len(argv):
                realm_opt = argv[i + 1]
                i += 1
        elif arg == "--kdc":
            if i + 1 < len(argv):
                val = argv[i + 1]
                kdc_opt = val
                for part in val.split(","):
                    p = part.strip()
                    if p and p not in kdc_list_opt:
                        kdc_list_opt.append(p)
                i += 1
        elif arg == "--admin-server":
            if i + 1 < len(argv):
                admin_server_opt = argv[i + 1]
                i += 1
        elif arg in ("--clock-skew", "--clockskew"):
            if i + 1 < len(argv):
                try:
                    clock_skew_opt = int(argv[i + 1])
                except ValueError:
                    emit_cli_error(
                        f"Invalid clock-skew value: {argv[i + 1]}",
                        reason_code="INVALID_ARGUMENT",
                        category="USAGE_ERROR",
                        exit_code=EXIT_USAGE_ERROR,
                        target=argv[i + 1],
                        json_output=global_json,
                    )
                i += 1
        elif arg == "--enforce-aes":
            enforce_aes_opt = True
        elif arg == "--fast":
            fast_opt = True
        elif arg == "--armor-cache":
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                armor_cache_opt = argv[i + 1]
                i += 1
            else:
                emit_cli_error(
                    "Option requires an argument: --armor-cache",
                    reason_code="MISSING_ARGUMENT",
                    category="USAGE_ERROR",
                    exit_code=EXIT_USAGE_ERROR,
                    json_output=global_json,
                )
        elif arg == "--use-ctypes":
            force_ctypes_opt = True
        elif arg == "--stdout":
            stdout_opt = True
        elif arg == "--opsec":
            opsec_opt = True
        elif arg == "--dry-run":
            dry_run_opt = True
        elif arg == "--all":
            purge_all_opt = True
        elif arg in ("--host", "--server"):
            if i + 1 < len(argv):
                host_opt = argv[i + 1]
                i += 1
        elif arg == "--query":
            if i + 1 < len(argv):
                query_opt = argv[i + 1]
                i += 1
        elif arg == "--base-dn":
            if i + 1 < len(argv):
                base_dn_opt = argv[i + 1]
                i += 1
        elif arg == "--port":
            if i + 1 < len(argv):
                try:
                    port_opt = int(argv[i + 1])
                except ValueError:
                    port_opt = 389
                i += 1
        elif arg == "--ssl":
            ssl_opt = True
        elif arg == "--live":
            live_opt = True
        elif arg == "--endpoint":
            if i + 1 < len(argv):
                endpoint_opt = argv[i + 1]
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
        elif arg in ("--krb-error", "--error"):
            if i + 1 < len(argv):
                krb_error_opt = argv[i + 1]
                i += 1
        elif arg == "--secrets-path":
            if i + 1 < len(argv):
                secrets_path_opt = argv[i + 1]
                i += 1
        elif explicit_command is None and arg in (
            "keytab", "kcm", "triage", "ladder", "doctor", "token", "nhi", "config", "skill", "auth",
            "pac", "fix", "purge", "adcs", "ldap",
        ):
            explicit_command = arg
        elif not arg.startswith("-"):
            positional_args.append(arg)
        else:
            emit_cli_error(
                f"Unknown option: {arg}",
                reason_code="UNKNOWN_OPTION",
                category="USAGE_ERROR",
                exit_code=EXIT_USAGE_ERROR,
                target=arg,
                json_output=global_json,
            )
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
    elif command == "auth":
        target_kt = keytab_opt or file_opt or (positional_args[0] if positional_args else None)
        target_princ = principal_opt or (positional_args[1] if len(positional_args) > 1 else None)
        target_ccache = ccache_opt or out_opt
        handle_auth(
            keytab_path=target_kt,
            principal=target_princ,
            ccache_path=target_ccache,
            json_output=global_json,
            force_ctypes=force_ctypes_opt,
            krb5_conf=krb5_conf_opt,
            kdc=kdc_opt,
        )
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
            opsec=opsec_opt,
            secrets_path=secrets_path_opt,
        )
    elif command == "pac":
        target = file_opt or (positional_args[0] if positional_args else None)
        handle_pac(target, global_json, is_file=bool(file_opt))
    elif command == "fix":
        target_kt = keytab_opt or file_opt or (positional_args[0] if positional_args else None)
        handle_fix(
            keytab_path=target_kt,
            realm=realm_opt,
            kdc=kdc_opt,
            krb5_conf=krb5_conf_opt,
            ccache_path=ccache_opt,
            dry_run=dry_run_opt,
            clock_skew=clock_skew_opt or 300,
            json_output=global_json,
            krb_error=krb_error_opt,
        )
    elif command == "purge":
        target = file_opt or (positional_args[0] if positional_args else None)
        handle_purge(target, purge_all_opt, global_json)
    elif command == "adcs":
        target = file_opt or (positional_args[0] if positional_args else None)
        handle_adcs(target, global_json, is_file=bool(file_opt))
    elif command == "ldap":
        target_host = host_opt or (positional_args[0] if positional_args else None)
        effective_base_dn = base_dn_opt
        if not effective_base_dn and realm_opt:
            r_parts = [p.strip() for p in realm_opt.strip().split(".") if p.strip()]
            if r_parts:
                effective_base_dn = ",".join(f"DC={p}" for p in r_parts)
        handle_ldap(
            host=target_host,
            query_type=query_opt or "spn",
            base_dn=effective_base_dn or "DC=corp,DC=local",
            port=port_opt,
            use_ssl=ssl_opt,
            json_output=global_json,
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
            live_mode=live_opt,
            endpoint_url=endpoint_opt,
        )
    elif command == "config":
        handle_config(
            realm_opt=realm_opt,
            kdc_opt=kdc_opt,
            admin_server_opt=admin_server_opt,
            out_path=out_opt or file_opt or (positional_args[0] if positional_args else None),
            stdout_mode=stdout_opt,
            json_output=global_json,
            keytab_opt=keytab_opt,
            clockskew_opt=clock_skew_opt,
            enforce_aes_opt=enforce_aes_opt,
            kdc_list_opt=kdc_list_opt if kdc_list_opt else None,
            fast_opt=fast_opt,
            armor_cache_opt=armor_cache_opt,
        )
    elif command == "skill":
        handle_skill(global_json)
    else:
        emit_cli_error(
            f"Unknown command: {command}",
            reason_code="UNKNOWN_COMMAND",
            category="USAGE_ERROR",
            exit_code=EXIT_USAGE_ERROR,
            target=command,
            json_output=global_json,
        )
