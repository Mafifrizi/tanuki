"""E2E Test Fixtures and Synthetic Artifact Generators for Tanuki v1.2.0."""

import base64
import io
import json
import os
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def run_tanuki_cli(args: List[str], stdin_input: Optional[str] = None, timeout: float = 10.0) -> Tuple[int, str, str]:
    """Execute Tanuki CLI as an opaque-box subprocess."""
    cmd = [sys.executable, "-m", "tanuki"] + args
    env = os.environ.copy()
    env["PYTHONPATH"] = REPO_ROOT
    proc = subprocess.run(
        cmd,
        input=stdin_input,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def build_synthetic_keytab(
    realm: str = "CORP.LOCAL",
    principal_comps: Optional[List[str]] = None,
    key_bytes: Optional[bytes] = None,
    keytype: int = 18,
    kvno: int = 3,
    version: int = 0x0502,
    timestamp: int = 1700000000,
) -> bytes:
    """Construct an RFC 4120 compliant binary keytab stream."""
    if principal_comps is None:
        principal_comps = ["HOST", "linux01.corp.local"]
    if key_bytes is None:
        key_bytes = b"\x11" * 32

    buf = io.BytesIO()
    buf.write(struct.pack(">H", version))

    entry_buf = io.BytesIO()
    entry_buf.write(struct.pack(">h", len(principal_comps)))
    realm_b = realm.encode("utf-8")
    entry_buf.write(struct.pack(">h", len(realm_b)) + realm_b)
    for comp in principal_comps:
        comp_b = comp.encode("utf-8")
        entry_buf.write(struct.pack(">h", len(comp_b)) + comp_b)

    entry_buf.write(struct.pack(">I", 1))  # name_type KRB5_NT_PRINCIPAL
    entry_buf.write(struct.pack(">I", timestamp))
    entry_buf.write(struct.pack(">B", kvno if kvno < 256 else 0))
    entry_buf.write(struct.pack(">h", keytype))
    entry_buf.write(struct.pack(">H", len(key_bytes)) + key_bytes)
    entry_buf.write(struct.pack(">I", kvno))

    raw_entry = entry_buf.getvalue()
    buf.write(struct.pack(">i", len(raw_entry)))
    buf.write(raw_entry)
    return buf.getvalue()


def build_multi_entry_keytab(entries: List[Dict[str, Any]], version: int = 0x0502) -> bytes:
    """Construct a binary keytab with multiple principal/enctype entries."""
    buf = io.BytesIO()
    buf.write(struct.pack(">H", version))

    for entry in entries:
        principal_comps = entry.get("principal_comps", ["HOST", "linux01.corp.local"])
        realm = entry.get("realm", "CORP.LOCAL")
        key_bytes = entry.get("key_bytes", b"\x11" * 32)
        keytype = entry.get("keytype", 18)
        kvno = entry.get("kvno", 1)
        timestamp = entry.get("timestamp", 1700000000)

        entry_buf = io.BytesIO()
        entry_buf.write(struct.pack(">h", len(principal_comps)))
        realm_b = realm.encode("utf-8")
        entry_buf.write(struct.pack(">h", len(realm_b)) + realm_b)
        for comp in principal_comps:
            comp_b = comp.encode("utf-8")
            entry_buf.write(struct.pack(">h", len(comp_b)) + comp_b)

        entry_buf.write(struct.pack(">I", 1))
        entry_buf.write(struct.pack(">I", timestamp))
        entry_buf.write(struct.pack(">B", kvno if kvno < 256 else 0))
        entry_buf.write(struct.pack(">h", keytype))
        entry_buf.write(struct.pack(">H", len(key_bytes)) + key_bytes)
        entry_buf.write(struct.pack(">I", kvno))

        raw_entry = entry_buf.getvalue()
        buf.write(struct.pack(">i", len(raw_entry)))
        buf.write(raw_entry)

    return buf.getvalue()


def build_synthetic_ccache(
    default_realm: str = "CORP.LOCAL",
    default_comps: Optional[List[str]] = None,
    creds: Optional[List[Dict[str, Any]]] = None,
    version: int = 0x0504,
) -> bytes:
    """Construct a MIT Kerberos CCACHE v4 binary stream."""
    if default_comps is None:
        default_comps = ["admin"]

    buf = io.BytesIO()
    buf.write(struct.pack(">H", version))
    buf.write(struct.pack(">H", 0))  # headerlen = 0 (no tag array)

    # Write default principal
    buf.write(struct.pack(">I", 1))  # name_type
    buf.write(struct.pack(">I", len(default_comps)))
    realm_b = default_realm.encode("utf-8")
    buf.write(struct.pack(">I", len(realm_b)) + realm_b)
    for comp in default_comps:
        comp_b = comp.encode("utf-8")
        buf.write(struct.pack(">I", len(comp_b)) + comp_b)

    if creds is not None:
        for cred in creds:
            c_realm = cred.get("client_realm", default_realm).encode("utf-8")
            c_comps = cred.get("client_comps", default_comps)
            s_realm = cred.get("server_realm", default_realm).encode("utf-8")
            s_comps = cred.get("server_comps", ["krbtgt", default_realm])

            # Client principal
            buf.write(struct.pack(">I", 1))
            buf.write(struct.pack(">I", len(c_comps)))
            buf.write(struct.pack(">I", len(c_realm)) + c_realm)
            for comp in c_comps:
                cb = comp.encode("utf-8")
                buf.write(struct.pack(">I", len(cb)) + cb)

            # Server principal
            buf.write(struct.pack(">I", 2))
            buf.write(struct.pack(">I", len(s_comps)))
            buf.write(struct.pack(">I", len(s_realm)) + s_realm)
            for comp in s_comps:
                cb = comp.encode("utf-8")
                buf.write(struct.pack(">I", len(cb)) + cb)

            # Keyblock
            keytype = cred.get("keytype", 18)
            key_data = cred.get("key_data", b"\x22" * 32)
            buf.write(struct.pack(">H", keytype))
            buf.write(struct.pack(">I", len(key_data)) + key_data)

            # Timestamps
            now = int(time.time())
            authtime = cred.get("authtime", now - 300)
            starttime = cred.get("starttime", now - 300)
            endtime = cred.get("endtime", now + 28800)
            renew_till = cred.get("renew_till", now + 86400)

            buf.write(struct.pack(">I", authtime))
            buf.write(struct.pack(">I", starttime))
            buf.write(struct.pack(">I", endtime))
            buf.write(struct.pack(">I", renew_till))

            # Flags and structures
            buf.write(struct.pack(">B", 0))  # is_skey
            buf.write(struct.pack(">I", 0x40e00000))  # ticket_flags
            buf.write(struct.pack(">I", 0))  # address count = 0
            buf.write(struct.pack(">I", 0))  # authdata count = 0

            ticket = cred.get("ticket", b"\x30\x82\x01\x00" + b"\x00" * 32)
            second_ticket = cred.get("second_ticket", b"")
            buf.write(struct.pack(">I", len(ticket)) + ticket)
            buf.write(struct.pack(">I", len(second_ticket)) + second_ticket)

    return buf.getvalue()


def build_synthetic_krb5_conf(
    default_realm: str = "CORP.LOCAL",
    realms: Optional[Dict[str, Dict[str, str]]] = None,
    domain_realm: Optional[Dict[str, str]] = None,
) -> str:
    """Construct an /etc/krb5.conf configuration string."""
    lines = ["[libdefaults]", f"    default_realm = {default_realm}", "    dns_lookup_kdc = false", ""]
    if realms:
        lines.append("[realms]")
        for r_name in realms.keys():
            lines.append(f"    {r_name} = {{}}")
        lines.append("")
    if domain_realm:
        lines.append("[domain_realm]")
        for d, r in domain_realm.items():
            lines.append(f"    {d} = {r}")
        lines.append("")
    return "\n".join(lines)


def b64url_encode(data: bytes) -> str:
    """Encode bytes using Base64URL without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def build_synthetic_jwt(
    header: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
    signature_bytes: bytes = b"simulated_signature_bytes_here_1234",
) -> str:
    """Construct a synthetic JWT token string."""
    if header is None:
        header = {"alg": "RS256", "typ": "JWT", "kid": "k8s-key-1"}
    if payload is None:
        now = int(time.time())
        payload = {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:production:payment-processor",
            "aud": "https://sts.corp.local",
            "exp": now + 3600,
            "nbf": now - 60,
            "iat": now,
        }

    h_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    return f"{b64url_encode(h_bytes)}.{b64url_encode(p_bytes)}.{b64url_encode(signature_bytes)}"
