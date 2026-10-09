#!/usr/bin/env python3
"""Inspect and triage binary Kerberos Keytab files (RFC 4120 / Keytab v2)."""

import argparse
import io
import json
import os
import shutil
import struct
import sys
from typing import Any, Dict, List, Optional

EXIT_SUCCESS = 0
EXIT_USAGE_ERROR = 1
EXIT_RESOURCE_MISSING = 3
EXIT_PARSE_FAILURE = 4


def emit_error(
    message: str,
    reason_code: str,
    category: str,
    exit_code: int,
    target: Optional[str] = None,
    details: Optional[str] = None,
    json_output: bool = False,
) -> None:
    if json_output:
        payload: Dict[str, Any] = {
            "status": "ERROR",
            "reason_code": reason_code,
            "category": category,
            "exit_code": exit_code,
            "message": message,
        }
        if target:
            payload["target"] = target
        if details:
            payload["details"] = details
        print(json.dumps(payload, indent=2))
    else:
        prefix = {
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


def supports_unicode() -> bool:
    try:
        return sys.stdout.encoding.lower().startswith("utf") or sys.platform != "win32"
    except (AttributeError, LookupError):
        return False


def render_card_header(title: str, subtitle: Optional[str] = None, width: int = 72) -> List[str]:
    use_uni = supports_unicode()
    dot = "·" if use_uni else "|"

    clean_title = title.replace("·", dot)
    res = [f"[{clean_title}]"]
    if subtitle:
        clean_sub = subtitle.replace("·", dot)
        res.append(f" {clean_sub}")
    return res


ENCTYPE_MAP = {
    1: "des-cbc-crc",
    3: "des-cbc-md5",
    16: "des3-cbc-sha1-kd",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    23: "rc4-hmac",
}

MAX_COMPONENTS = 256
MAX_ENTRY_SIZE = 1048576
MIN_INT32 = -2147483648


def parse_keytab_stream(stream: io.BytesIO) -> List[Dict[str, Any]]:
    header = stream.read(2)
    if len(header) < 2 or header[0] != 0x05 or header[1] != 0x02:
        raise ValueError("Invalid keytab format (expected Keytab v2 signature 0x0502)")

    entries: List[Dict[str, Any]] = []

    while True:
        size_bytes = stream.read(4)
        if not size_bytes:
            break
        if len(size_bytes) < 4:
            raise ValueError("Unexpected end of keytab stream (truncated entry size)")

        (entry_size,) = struct.unpack(">i", size_bytes)
        if entry_size == 0:
            continue

        if entry_size == MIN_INT32:
            raise ValueError("Malformed keytab entry: integer overflow in entry size (MIN_INT32)")

        if entry_size < 0:
            skip_len = abs(entry_size)
            if skip_len > MAX_ENTRY_SIZE:
                raise ValueError(f"Keytab hole skip size exceeds safety limit ({skip_len} bytes)")
            skipped = stream.read(skip_len)
            if len(skipped) < skip_len:
                raise ValueError("Unexpected end of keytab stream in deleted entry hole")
            continue

        if entry_size > MAX_ENTRY_SIZE:
            raise ValueError(
                f"Malformed keytab entry: entry size exceeds maximum limit ({entry_size} > {MAX_ENTRY_SIZE})"
            )

        raw_entry = stream.read(entry_size)
        if len(raw_entry) < entry_size:
            raise ValueError(
                f"Unexpected end of keytab stream: expected {entry_size} bytes, got {len(raw_entry)}"
            )

        entry_io = io.BytesIO(raw_entry)

        comp_count_bytes = entry_io.read(2)
        if len(comp_count_bytes) < 2:
            raise ValueError("Malformed keytab entry: missing component count")
        (num_components,) = struct.unpack(">h", comp_count_bytes)
        if num_components < 0:
            raise ValueError("Malformed keytab entry: negative component count")
        if num_components > MAX_COMPONENTS:
            raise ValueError(
                f"Malformed keytab entry: excessive component count ({num_components} > {MAX_COMPONENTS})"
            )

        realm_len_bytes = entry_io.read(2)
        if len(realm_len_bytes) < 2:
            raise ValueError("Malformed keytab entry: missing realm length")
        (realm_len,) = struct.unpack(">H", realm_len_bytes)
        realm_bytes = entry_io.read(realm_len)
        if len(realm_bytes) < realm_len:
            raise ValueError("Malformed keytab entry: realm bounds exceeded")
        realm = realm_bytes.decode("utf-8", errors="replace")

        components: List[str] = []
        for _ in range(num_components):
            comp_len_bytes = entry_io.read(2)
            if len(comp_len_bytes) < 2:
                raise ValueError("Malformed keytab entry: missing component length")
            (comp_len,) = struct.unpack(">H", comp_len_bytes)
            comp_bytes = entry_io.read(comp_len)
            if len(comp_bytes) < comp_len:
                raise ValueError("Malformed keytab entry: component bounds exceeded")
            comp = comp_bytes.decode("utf-8", errors="replace")
            components.append(comp)

        if components:
            principal = f"{'/'.join(components)}@{realm}"
        else:
            principal = f"@{realm}"

        meta_bytes = entry_io.read(4 + 4 + 1 + 2 + 2)
        if len(meta_bytes) < 13:
            raise ValueError("Malformed keytab entry: missing key metadata fields")
        (name_type, timestamp, vno8, keytype, key_len) = struct.unpack(
            ">IIBhH", meta_bytes
        )

        key_bytes = entry_io.read(key_len)
        if len(key_bytes) < key_len:
            raise ValueError("Malformed keytab entry: key data bounds exceeded")

        vno = vno8
        remaining = entry_size - entry_io.tell()
        if remaining >= 4:
            (vno32,) = struct.unpack(">I", entry_io.read(4))
            if vno32 != 0:
                vno = vno32
        elif remaining > 0:
            raise ValueError("Malformed keytab entry: incomplete 32-bit KVNO field")

        entries.append(
            {
                "principal": principal,
                "realm": realm,
                "components": components,
                "vno": vno,
                "keytype": keytype,
                "enctype_name": ENCTYPE_MAP.get(keytype, f"unknown({keytype})"),
                "key_len": key_len,
                "key_hex": key_bytes.hex(),
                "timestamp": timestamp,
            }
        )

    return entries


def parse_keytab_bytes(data: bytes) -> List[Dict[str, Any]]:
    return parse_keytab_stream(io.BytesIO(data))


def parse_keytab_file(filepath: str) -> List[Dict[str, Any]]:
    if os.path.islink(filepath):
        raise ValueError(f"Refusing to read symbolic link: {filepath}")
    with open(filepath, "rb") as f:
        return parse_keytab_stream(io.BytesIO(f.read(10485760)))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tanuki Keytab Inspector: Parse binary keytab without external dependencies"
    )
    parser.add_argument("keytab_path", help="Path to /etc/krb5.keytab or custom keytab")
    parser.add_argument(
        "--json", action="store_true", help="Output parsed entries as JSON"
    )
    args = parser.parse_args()

    if not os.path.exists(args.keytab_path):
        emit_error(
            f"Error reading keytab at '{args.keytab_path}': No such file or directory",
            reason_code="MISSING_KEYTAB",
            category="RESOURCE_MISSING",
            exit_code=EXIT_RESOURCE_MISSING,
            target=args.keytab_path,
            json_output=args.json,
        )

    if os.path.getsize(args.keytab_path) == 0:
        emit_error(
            f"Keytab file is empty: '{args.keytab_path}'",
            reason_code="EMPTY_KEYTAB",
            category="PARSE_FAILURE",
            exit_code=EXIT_PARSE_FAILURE,
            target=args.keytab_path,
            json_output=args.json,
        )

    try:
        entries = parse_keytab_file(args.keytab_path)
    except Exception as exc:
        emit_error(
            f"Error parsing keytab: {exc}",
            reason_code="CORRUPT_KEYTAB",
            category="PARSE_FAILURE",
            exit_code=EXIT_PARSE_FAILURE,
            target=args.keytab_path,
            details=str(exc),
            json_output=args.json,
        )

    if args.json:
        print(json.dumps(entries, indent=2))
        return

    for line in render_card_header(
        "TANUKI KEYTAB TRIAGE REPORT",
        f"File: {args.keytab_path} · RFC 4120 Binary Structure",
    ):
        print(line)

    use_uni = supports_unicode()
    t_branch, l_branch = ("├──", "└──") if use_uni else ("|--", "`--")

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
        print(f"    $ {prefix}kinit -k -t {args.keytab_path} {sample['principal']}")
        print("    $ export KRB5CCNAME=/tmp/krb5cc_$(id -u)")

        if not shutil.which("kinit"):
            print("\n[!] Host Tooling Advisory:")
            print("    'kinit' utility not found on PATH.")
            print("    Install: sudo apt install krb5-user (Debian/Kali) or sudo dnf install krb5-workstation (RHEL)")
            print("    Unprivileged: Generate local config via 'tanuki config' and use portable client.")


if __name__ == "__main__":
    main()
