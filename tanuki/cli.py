"""Unified Tanuki Command-Line Interface."""

import json
import os
import sys
from typing import List, Optional

from . import __version__
from .kcm import (
    save_recovered_ticket,
    scan_for_ccache_blobs,
    triage_local_caches,
)
from .keytab import parse_keytab_file
from .protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution

USAGE_TEXT = """Tanuki CLI - Linux Active Directory Triage Engine

USAGE:
    tanuki <COMMAND> [OPTIONS]
    tanuki <KEYTAB_PATH> [--json]

COMMANDS:
    keytab [PATH]       Inspect binary keytab file (RFC 4120)
    kcm [OPTIONS]       Extract SSSD KCM credential cache streams
    triage [QUERY]      Lookup Kerberos/SSSD error codes and resolutions
    ladder              Display the 5-rung Tactical Decision Ladder

OPTIONS:
    -f, --file <PATH>   Target database or keytab file
    -o, --out <DIR>     Output directory for extracted caches (default: ./extracted_ccache)
    --json              Output structured JSON for agent and pipeline consumption
    -h, --help          Print help information
    -V, --version       Print version information"""


def print_usage() -> None:
    print(USAGE_TEXT)


def handle_keytab(file_path: Optional[str], json_output: bool) -> None:
    if not file_path:
        sys.stderr.write("Error: Keytab path required. Example: tanuki keytab /etc/krb5.keytab\n")
        sys.exit(1)

    if not os.path.exists(file_path):
        sys.stderr.write(f"Error reading keytab at '{file_path}': No such file or directory\n")
        sys.exit(1)

    try:
        entries = parse_keytab_file(file_path)
    except Exception as exc:
        sys.stderr.write(f"Error parsing keytab: {exc}\n")
        sys.exit(1)

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
            sys.stderr.write(f"File not found: {file_path}\n")
            sys.exit(1)

        os.makedirs(out_dir, exist_ok=True)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as exc:
            sys.stderr.write(f"Error reading database '{file_path}': {exc}\n")
            sys.exit(1)

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
        print(f"    {rung['description']}\n")
    print("Command Output Standard:")
    print("    [TARGET] -> [PREREQUISITE] -> [TACTICAL COMMAND] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]")
    print("=" * 72)


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
        elif explicit_command is None and arg in ("keytab", "kcm", "triage", "ladder"):
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
    else:
        sys.stderr.write(f"Unknown command: {command}\n")
        print_usage()
        sys.exit(1)
