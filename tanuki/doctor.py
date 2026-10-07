"""Proactive Pre-flight Diagnostic Engine for Linux Active Directory."""

import errno
import io
import json
import os
import stat
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import sys
from .keytab import ENCTYPE_MAP, parse_keytab_stream


def supports_unicode() -> bool:
    try:
        encoding = sys.stdout.encoding or "ascii"
        "┌───┐│└┘·├╰".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError, AttributeError):
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


class DoctorReport:
    """Diagnostic report holding results from all pre-flight health checks."""

    def __init__(
        self,
        status: str,
        checks: List[Dict[str, Any]],
        duration_ms: float,
        timestamp: Optional[str] = None,
    ) -> None:
        self.status = status
        self.checks = checks
        self.duration_ms = duration_ms
        self.execution_time_ms = duration_ms
        self.timestamp = timestamp or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.summary = self._compute_summary()

    def _compute_summary(self) -> Dict[str, int]:
        passed = sum(1 for c in self.checks if c.get("status") == "PASS")
        warnings = sum(1 for c in self.checks if c.get("status") in ("WARN", "EXPIRED"))
        failures = sum(1 for c in self.checks if c.get("status") == "FAIL")
        return {"passed": passed, "warnings": warnings, "failures": failures}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 2),
            "execution_time_ms": round(self.duration_ms, 2),
            "summary": self.summary,
            "checks": self.checks,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def format_checklist(self) -> str:
        hostname = (
            os.environ.get("HOSTNAME")
            or os.environ.get("COMPUTERNAME")
            or "localhost"
        )
        lines: List[str] = []
        lines.extend(render_card_header(
            "TANUKI PRE-FLIGHT DOCTOR (v1.2.1)",
            f"Host: {hostname} · Mode: Passive Diagnostic (0 network packets)",
        ))
        lines.append("")

        for check in self.checks:
            name = check.get("name", "check")
            c_status = check.get("status", "N_A")
            details = check.get("details", "")
            rec = check.get("recommendation")

            title_map = {
                "keytab_permissions": "Keytab Integrity      ",
                "realm_capitalization": "Kerberos Configuration",
                "sssd_subsystem": "SSSD Subsystem        ",
                "ticket_lifetime": "Active Ticket Cache   ",
                "host_tooling": "Kerberos Host Tooling ",
                "opsec_sensors": "Host OPSEC Sensors    ",
            }
            display_title = title_map.get(name, name.replace("_", " ").title().ljust(22))

            lines.append(f"[{c_status}] {display_title} : {details}")
            if rec:
                lines.append(f"       Action Required        : {rec}")

        lines.append("")
        lines.append(
            f"OVERALL HEALTH: {self.status} "
            f"({self.summary['passed']} passed, {self.summary['warnings']} warnings, {self.summary['failures']} failures)"
        )
        lines.append(
            f"Execution Time: {self.duration_ms:.2f} ms | Network Packets Emitted: 0"
        )
        return "\n".join(lines)


def check_keytab(keytab_path: str = "/etc/krb5.keytab") -> Dict[str, Any]:
    """Validate keytab existence, binary header magic, permissions, and encryption types."""
    result: Dict[str, Any] = {
        "name": "keytab_permissions",
        "status": "PASS",
        "details": "",
        "recommendation": None,
        "path": keytab_path,
        "exists": False,
        "readable": False,
        "valid_format": False,
        "format_version": 0,
        "permissions": "N_A",
        "is_secure_permissions": False,
        "entry_count": 0,
        "encryption_types": [],
        "has_weak_enctypes": False,
        "issues": [],
        "error_code": None,
    }

    try:
        st = os.stat(keytab_path)
        result["exists"] = True
    except FileNotFoundError:
        result["status"] = "N_A"
        result["error_code"] = "ENOENT"
        result["details"] = f"Keytab file not found: {keytab_path}"
        result["recommendation"] = f"Join domain or generate keytab at {keytab_path}"
        result["issues"].append(f"File does not exist: {keytab_path}")
        return result
    except PermissionError as exc:
        result["exists"] = True
        result["status"] = "FAIL"
        result["error_code"] = "EACCES"
        result["details"] = f"Read access denied: {exc}"
        username = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        result["recommendation"] = (
            f"Grant POSIX ACL (setfacl -m u:{username}:r {keytab_path}), group delegation (0640), "
            f"or use unprivileged NHI token exchange (tanuki token / RFC 8693) into "
            f"KRB5CCNAME=FILE:/tmp/krb5cc_{uid}_tanuki or KEYRING:persistent:{uid}"
        )
        result["issues"].append(str(exc))
        return result
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            result["status"] = "N_A"
            result["error_code"] = "ENOENT"
            result["details"] = f"Keytab file not found: {keytab_path}"
            result["recommendation"] = f"Join domain or generate keytab at {keytab_path}"
            result["issues"].append(f"File does not exist: {keytab_path}")
            return result
        elif exc.errno == errno.EACCES:
            result["exists"] = True
            result["status"] = "FAIL"
            result["error_code"] = "EACCES"
            result["details"] = f"Read access denied: {exc}"
            username = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
            uid = os.getuid() if hasattr(os, "getuid") else 1000
            result["recommendation"] = (
                f"Grant POSIX ACL (setfacl -m u:{username}:r {keytab_path}), group delegation (0640), "
                f"or use unprivileged NHI token exchange (tanuki token / RFC 8693) into "
                f"KRB5CCNAME=FILE:/tmp/krb5cc_{uid}_tanuki or KEYRING:persistent:{uid}"
            )
            result["issues"].append(str(exc))
            return result
        result["status"] = "N_A"
        result["error_code"] = "ENOENT"
        result["details"] = f"Keytab file not found: {keytab_path}"
        result["recommendation"] = f"Join domain or generate keytab at {keytab_path}"
        result["issues"].append(str(exc))
        return result

    is_windows = os.name == "nt"
    if not is_windows:
        try:
            mode = st.st_mode
            posix_octal = f"{mode & 0o777:04o}"
            result["permissions"] = posix_octal

            is_world_readable = bool(mode & 0o004)
            is_world_writable = bool(mode & 0o002)
            is_group_readable = bool(mode & 0o040)

            if is_world_readable or is_world_writable:
                result["status"] = "FAIL"
                result["is_secure_permissions"] = False
                perm_desc = "world-writable" if is_world_writable else "world-readable"
                result["details"] = f"{posix_octal} ({perm_desc}: insecure)"
                result["recommendation"] = f"chmod 0600 {keytab_path}"
                result["issues"].append(
                    f"Insecure permissions {posix_octal}: {perm_desc}"
                )
            elif is_group_readable:
                result["status"] = "WARN"
                result["is_secure_permissions"] = False
                result["details"] = f"{posix_octal} (group-readable: conditional)"
                result["recommendation"] = f"chmod 0600 {keytab_path}"
                result["issues"].append(
                    f"Group-readable permissions {posix_octal} require service group ownership"
                )
            else:
                result["is_secure_permissions"] = True
                result["details"] = f"{posix_octal} (secure)"
        except OSError as exc:
            result["status"] = "FAIL"
            result["details"] = f"Stat failed: {exc}"
            result["issues"].append(str(exc))
            return result
    else:
        result["permissions"] = "N/A (Windows platform)"
        result["is_secure_permissions"] = True
        result["details"] = "Permissions N/A on Windows"

    try:
        with open(keytab_path, "rb") as f:
            data = f.read(65536)
        result["readable"] = True
    except PermissionError as exc:
        result["status"] = "FAIL"
        result["error_code"] = "EACCES"
        result["details"] = f"Read access denied: {exc}"
        username = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        result["recommendation"] = (
            f"Grant POSIX ACL (setfacl -m u:{username}:r {keytab_path}), group delegation (0640), "
            f"or use unprivileged NHI token exchange (tanuki token / RFC 8693) into "
            f"KRB5CCNAME=FILE:/tmp/krb5cc_{uid}_tanuki or KEYRING:persistent:{uid}"
        )
        result["issues"].append(str(exc))
        return result
    except OSError as exc:
        if exc.errno == errno.EACCES:
            result["status"] = "FAIL"
            result["error_code"] = "EACCES"
            result["details"] = f"Read access denied: {exc}"
            username = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
            uid = os.getuid() if hasattr(os, "getuid") else 1000
            result["recommendation"] = (
                f"Grant POSIX ACL (setfacl -m u:{username}:r {keytab_path}), group delegation (0640), "
                f"or use unprivileged NHI token exchange (tanuki token / RFC 8693) into "
                f"KRB5CCNAME=FILE:/tmp/krb5cc_{uid}_tanuki or KEYRING:persistent:{uid}"
            )
            result["issues"].append(str(exc))
            return result
        result["status"] = "FAIL"
        result["details"] = f"Read access denied: {exc}"
        result["recommendation"] = f"Ensure read permissions for {keytab_path}"
        result["issues"].append(str(exc))
        return result

    if len(data) == 0:
        result["status"] = "FAIL"
        result["details"] = "Keytab file is empty (0 bytes)"
        result["recommendation"] = f"Regenerate valid keytab at {keytab_path}"
        result["issues"].append("Empty file")
        return result

    if len(data) < 2:
        result["status"] = "FAIL"
        result["details"] = "Invalid keytab format (header < 2 bytes)"
        result["recommendation"] = f"Regenerate valid keytab at {keytab_path}"
        result["issues"].append("Header truncated")
        return result

    if data[0] == 0x05 and data[1] == 0x02:
        result["valid_format"] = True
        result["format_version"] = 2
    elif data[0] == 0x05 and data[1] == 0x01:
        result["valid_format"] = False
        result["format_version"] = 1
        result["status"] = "FAIL"
        result["details"] = "Deprecated Keytab v1 format detected"
        result["recommendation"] = "Upgrade keytab to Keytab v2 format"
        result["issues"].append("Deprecated format v1")
        return result
    else:
        result["status"] = "FAIL"
        result["details"] = (
            f"Invalid keytab magic bytes (got 0x{data[0]:02x}{data[1]:02x}, expected 0x0502)"
        )
        result["recommendation"] = f"Regenerate valid keytab at {keytab_path}"
        result["issues"].append("Invalid header magic")
        return result

    try:
        entries = parse_keytab_stream(io.BytesIO(data))
        result["entry_count"] = len(entries)
        enctypes: List[str] = []
        for e in entries:
            name = e.get("enctype_name", str(e.get("keytype")))
            if name not in enctypes:
                enctypes.append(name)
            if e.get("keytype") in (1, 2, 3, 23):
                result["has_weak_enctypes"] = True
        result["encryption_types"] = enctypes

        if result["has_weak_enctypes"]:
            result["issues"].append(
                "Legacy weak encryption types detected (DES/RC4)"
            )
            if result["status"] == "PASS":
                result["status"] = "WARN"

        summary_detail = (
            f"{result['permissions']} (secure), "
            if result["is_secure_permissions"] and not is_windows
            else (f"{result['details']}, " if result["details"] else "")
        )
        result["details"] = (
            f"{summary_detail}Keytab v2 ({len(entries)} entries, enctypes: {', '.join(enctypes) or 'none'})"
        ).strip(", ")

    except ValueError as exc:
        result["status"] = "FAIL"
        result["details"] = f"Corrupted keytab: {exc}"
        result["recommendation"] = f"Re-export valid keytab to {keytab_path}"
        result["issues"].append(f"Corrupted entry: {exc}")

    return result


def check_krb5_conf(krb5_conf_path: Optional[str] = None) -> Dict[str, Any]:
    """Parse /etc/krb5.conf sections and verify uppercase realm names per RFC 4120 § 6.1."""
    env_krb5_conf = os.environ.get("KRB5_CONFIG")
    is_env_source = False
    if krb5_conf_path is None:
        if env_krb5_conf:
            krb5_conf_path = env_krb5_conf
            is_env_source = True
        else:
            krb5_conf_path = "/etc/krb5.conf"

    result: Dict[str, Any] = {
        "name": "realm_capitalization",
        "status": "PASS",
        "details": "",
        "recommendation": None,
        "path": krb5_conf_path,
        "source": "KRB5_CONFIG" if is_env_source else "path",
        "exists": False,
        "default_realm": None,
        "is_realm_uppercase": True,
        "realms": [],
        "lowercase_realms": [],
        "issues": [],
    }

    if not os.path.exists(krb5_conf_path):
        result["status"] = "N_A"
        result["details"] = f"Configuration file not found: {krb5_conf_path}"
        result["recommendation"] = (
            f"Install krb5-user or configure {krb5_conf_path} (unprivileged: generate via 'tanuki config' and export KRB5_CONFIG)"
        )
        result["issues"].append(f"File not found: {krb5_conf_path}")
        return result

    result["exists"] = True

    try:
        with open(krb5_conf_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        result["status"] = "FAIL"
        result["details"] = f"Read access denied: {exc}"
        result["issues"].append(str(exc))
        return result

    current_section: Optional[str] = None
    brace_depth = 0
    default_realm: Optional[str] = None
    realms_seen: List[str] = []
    lowercase_realms: List[str] = []

    for line_num, raw_line in enumerate(lines, 1):
        clean = raw_line.split("#")[0].split(";")[0].strip()
        if not clean:
            continue

        if clean.startswith("[") and clean.endswith("]"):
            current_section = clean[1:-1].strip().lower()
            brace_depth = 0
            continue

        if current_section == "libdefaults":
            if "=" in clean:
                key, val = clean.split("=", 1)
                key = key.strip()
                val = val.strip()
                if key == "default_realm":
                    default_realm = val
                    if any(c.islower() for c in val):
                        lowercase_realms.append(val)
                        result["issues"].append(
                            f"Line {line_num}: Lowercase default_realm '{val}' in [libdefaults]"
                        )

        elif current_section == "realms":
            if brace_depth == 0 and "=" in clean:
                left, _ = clean.split("=", 1)
                realm_cand = left.strip()
                if realm_cand and "{" not in realm_cand and "}" not in realm_cand:
                    if realm_cand not in realms_seen:
                        realms_seen.append(realm_cand)
                    if any(c.islower() for c in realm_cand):
                        if realm_cand not in lowercase_realms:
                            lowercase_realms.append(realm_cand)
                        result["issues"].append(
                            f"Line {line_num}: Lowercase realm definition '{realm_cand}' in [realms]"
                        )
            brace_depth += clean.count("{") - clean.count("}")
            if brace_depth < 0:
                brace_depth = 0

        elif current_section == "domain_realm":
            if "=" in clean:
                domain_part, realm_part = clean.split("=", 1)
                rhs_realm = realm_part.strip()
                lhs_domain = domain_part.strip()
                if rhs_realm:
                    if any(c.islower() for c in rhs_realm):
                        if rhs_realm not in lowercase_realms:
                            lowercase_realms.append(rhs_realm)
                        result["issues"].append(
                            f"Line {line_num}: Lowercase target realm '{rhs_realm}' for domain '{lhs_domain}' in [domain_realm]"
                        )
                    elif rhs_realm not in realms_seen:
                        realms_seen.append(rhs_realm)

    result["default_realm"] = default_realm
    result["realms"] = realms_seen
    result["lowercase_realms"] = lowercase_realms

    if lowercase_realms:
        result["status"] = "FAIL"
        result["is_realm_uppercase"] = False
        result["details"] = (
            f"Lowercase realm detected: {', '.join(lowercase_realms)} (RFC 4120 mandates uppercase)"
        )
        result["recommendation"] = (
            f"Capitalize realm names in {krb5_conf_path} to match Active Directory uppercase convention"
        )
    elif default_realm:
        result["status"] = "PASS"
        result["details"] = f"Default realm: {default_realm} (uppercase)"
    elif realms_seen:
        result["status"] = "PASS"
        result["details"] = f"Realms configured: {', '.join(realms_seen)} (uppercase)"
    else:
        result["status"] = "WARN"
        result["details"] = "No realm definitions discovered in configuration"
        result["recommendation"] = "Define default_realm in [libdefaults]"

    return result


def check_sssd(
    sssd_pipe: str = "/var/lib/sss/pipes/kcm",
    sssd_pid: str = "/var/run/sssd.pid",
    secrets_path: str = "/var/lib/sss/secrets/secrets.ldb",
) -> Dict[str, Any]:
    """Inspect SSSD daemon process status, KCM domain socket, and secrets database permissions."""
    result: Dict[str, Any] = {
        "name": "sssd_subsystem",
        "status": "PASS",
        "details": "",
        "recommendation": None,
        "daemon_running": False,
        "pid": None,
        "kcm_socket_path": sssd_pipe,
        "kcm_socket_active": False,
        "secrets_path": secrets_path,
        "secrets_status": "N_A",
        "secrets_error": None,
        "issues": [],
    }

    pid_candidates = [sssd_pid, "/run/sssd.pid", "/var/run/sssd.pid"]
    found_pid: Optional[int] = None

    for pid_path in pid_candidates:
        if os.path.isfile(pid_path):
            try:
                with open(pid_path, "r", encoding="utf-8") as f:
                    p_text = f.read().strip()
                if p_text.isdigit():
                    cand = int(p_text)
                    proc_stat = f"/proc/{cand}"
                    if os.path.exists(proc_stat):
                        found_pid = cand
                        result["daemon_running"] = True
                        result["pid"] = found_pid
                        break
                    else:
                        result["issues"].append(
                            f"Stale PID file {pid_path} points to non-existent process {cand}"
                        )
            except OSError:
                pass

    if not result["daemon_running"] and os.path.isdir("/proc"):
        sssd_footprints = ("/var/lib/sss", "/etc/sssd", "/usr/sbin/sssd", "/usr/lib/sssd")
        if any(os.path.exists(p) for p in sssd_footprints):
            try:
                for entry in os.listdir("/proc"):
                    if entry.isdigit():
                        comm_path = f"/proc/{entry}/comm"
                        if os.path.isfile(comm_path):
                            try:
                                with open(comm_path, "r", encoding="utf-8") as f:
                                    comm = f.read().strip()
                                if comm == "sssd":
                                    result["daemon_running"] = True
                                    result["pid"] = int(entry)
                                    break
                            except OSError:
                                pass
            except OSError:
                pass

    if os.path.exists(sssd_pipe):
        try:
            st = os.stat(sssd_pipe)
            if stat.S_ISSOCK(st.st_mode):
                result["kcm_socket_active"] = True
            else:
                result["issues"].append(
                    f"KCM path {sssd_pipe} exists but is not a UNIX domain socket"
                )
        except OSError as exc:
            result["issues"].append(f"Cannot stat {sssd_pipe}: {exc}")
    else:
        result["issues"].append(f"KCM socket not found at {sssd_pipe}")

    # Audit SSSD secrets database (/var/lib/sss/secrets/secrets.ldb)
    try:
        with open(secrets_path, "rb") as f:
            f.read(16)
        result["secrets_status"] = "READABLE"
    except FileNotFoundError:
        result["secrets_status"] = "ENOENT"
        result["secrets_error"] = "ENOENT"
    except PermissionError as exc:
        result["secrets_status"] = "EACCES"
        result["secrets_error"] = "EACCES"
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            result["secrets_status"] = "ENOENT"
            result["secrets_error"] = "ENOENT"
        elif exc.errno == errno.EACCES:
            result["secrets_status"] = "EACCES"
            result["secrets_error"] = "EACCES"
        else:
            result["secrets_status"] = "ERROR"
            result["secrets_error"] = str(exc)

    if result["daemon_running"] and result["kcm_socket_active"]:
        result["status"] = "PASS"
        result["details"] = (
            f"Active (PID {result['pid']}), KCM socket available at {sssd_pipe}"
        )
    elif result["daemon_running"] and not result["kcm_socket_active"]:
        result["status"] = "WARN"
        result["details"] = (
            f"SSSD running (PID {result['pid']}) but KCM socket missing at {sssd_pipe}"
        )
        result["recommendation"] = "Verify KCM responder configuration in /etc/sssd/sssd.conf"
    elif not result["daemon_running"] and result["kcm_socket_active"]:
        result["status"] = "WARN"
        result["details"] = f"KCM socket exists but SSSD daemon is not running"
        result["recommendation"] = "Start SSSD daemon: systemctl start sssd"
    else:
        result["status"] = "WARN"
        result["details"] = "SSSD daemon inactive and KCM socket not present"
        result["recommendation"] = "Start SSSD if host is configured for domain authentication"

    if result["secrets_status"] == "EACCES":
        username = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        sec_rec = (
            f"Grant POSIX ACL (setfacl -m u:{username}:r {secrets_path}), group delegation (0640), "
            f"or use unprivileged NHI token exchange (tanuki token / RFC 8693) into "
            f"KRB5CCNAME=FILE:/tmp/krb5cc_{uid}_tanuki or KEYRING:persistent:{uid}"
        )
        result["issues"].append(f"SSSD secrets database inaccessible (EACCES): {secrets_path}")
        if result["recommendation"]:
            result["recommendation"] += f"; {sec_rec}"
        else:
            result["recommendation"] = sec_rec

    return result


def _read_principal(stream: io.BytesIO) -> Optional[str]:
    head = stream.read(12)
    if len(head) < 12:
        return None
    try:
        _name_type, num_components, realm_len = struct.unpack(">III", head)
    except struct.error:
        return None

    if num_components > 64 or realm_len > 1024:
        return None

    realm_b = stream.read(realm_len)
    if len(realm_b) < realm_len:
        return None
    realm = realm_b.decode("utf-8", errors="replace")

    components: List[str] = []
    for _ in range(num_components):
        len_b = stream.read(4)
        if len(len_b) < 4:
            return None
        (comp_len,) = struct.unpack(">I", len_b)
        if comp_len > 1024:
            return None
        comp_b = stream.read(comp_len)
        if len(comp_b) < comp_len:
            return None
        components.append(comp_b.decode("utf-8", errors="replace"))

    if components:
        return f"{'/'.join(components)}@{realm}"
    return f"@{realm}"


def parse_ccache_stream(stream: io.BytesIO) -> Optional[Dict[str, Any]]:
    """Parse MIT Kerberos CCACHE v4 binary stream extracting primary credentials and expiration."""
    head = stream.read(4)
    if len(head) < 4:
        return None

    if head[:2] != b"\x05\x04":
        return None

    (header_len,) = struct.unpack(">H", head[2:4])
    tags = stream.read(header_len)
    if len(tags) < header_len:
        return None

    default_principal = _read_principal(stream)
    if default_principal is None:
        return None

    best_ticket: Optional[Dict[str, Any]] = None
    all_tickets: List[Dict[str, Any]] = []

    def _finalize_ticket(bt: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if bt is None:
            return None
        has_weak = any(t.get("enctype") in (1, 2, 3, 23) for t in all_tickets)
        enctype_names = list(dict.fromkeys(t["enctype_name"] for t in all_tickets))
        res = dict(bt)
        res["tickets"] = all_tickets
        res["enctypes"] = enctype_names
        res["has_weak_enctypes"] = has_weak
        return res

    while True:
        client = _read_principal(stream)
        if client is None:
            break
        server = _read_principal(stream)
        if server is None:
            break

        keyblock_head = stream.read(6)
        if len(keyblock_head) < 6:
            break
        enctype, key_len = struct.unpack(">HI", keyblock_head)
        key_data = stream.read(key_len)
        if len(key_data) < key_len:
            break

        times = stream.read(16)
        if len(times) < 16:
            break
        authtime, starttime, endtime, renew_till = struct.unpack(">IIII", times)

        is_skey_b = stream.read(1)
        if len(is_skey_b) < 1:
            break

        flags_b = stream.read(4)
        if len(flags_b) < 4:
            break

        addr_count_b = stream.read(4)
        if len(addr_count_b) < 4:
            break
        (addr_count,) = struct.unpack(">I", addr_count_b)
        for _ in range(addr_count):
            ahead = stream.read(6)
            if len(ahead) < 6:
                return _finalize_ticket(best_ticket)
            _, alen = struct.unpack(">HI", ahead)
            adata = stream.read(alen)
            if len(adata) < alen:
                return _finalize_ticket(best_ticket)

        ad_count_b = stream.read(4)
        if len(ad_count_b) < 4:
            break
        (ad_count,) = struct.unpack(">I", ad_count_b)
        for _ in range(ad_count):
            ahead = stream.read(6)
            if len(ahead) < 6:
                return _finalize_ticket(best_ticket)
            _, alen = struct.unpack(">HI", ahead)
            adata = stream.read(alen)
            if len(adata) < alen:
                return _finalize_ticket(best_ticket)

        t_len_b = stream.read(4)
        if len(t_len_b) < 4:
            break
        (t_len,) = struct.unpack(">I", t_len_b)
        t_data = stream.read(t_len)
        if len(t_data) < t_len:
            break

        sec_len_b = stream.read(4)
        if len(sec_len_b) < 4:
            break
        (sec_len,) = struct.unpack(">I", sec_len_b)
        sec_data = stream.read(sec_len)
        if len(sec_data) < sec_len:
            break

        enctype_name = ENCTYPE_MAP.get(enctype, f"unknown_{enctype}")
        cand = {
            "default_principal": default_principal,
            "client": client,
            "server": server,
            "enctype": enctype,
            "enctype_name": enctype_name,
            "authtime": authtime,
            "starttime": starttime,
            "endtime": endtime,
            "renew_till": renew_till,
        }
        all_tickets.append(cand)

        if endtime == 0:
            continue

        if best_ticket is None:
            best_ticket = cand
        elif "krbtgt" in server and "krbtgt" not in best_ticket.get("server", ""):
            best_ticket = cand
        elif endtime > best_ticket.get("endtime", 0):
            best_ticket = cand

    return _finalize_ticket(best_ticket)


def parse_proc_keys() -> List[Dict[str, Any]]:
    """Passively parse /proc/keys for active or expired Kerberos keyrings."""
    keys: List[Dict[str, Any]] = []
    if not os.path.isfile("/proc/keys"):
        return keys

    try:
        with open("/proc/keys", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 8:
                    desc = " ".join(parts[7:])
                    if "krb" in desc.lower() or "ccache" in desc.lower():
                        flags = parts[1]
                        is_expired = "E" in flags
                        keys.append(
                            {
                                "id": parts[0],
                                "flags": flags,
                                "type": parts[6],
                                "desc": desc,
                                "is_expired": is_expired,
                            }
                        )
    except OSError:
        pass

    return keys


def check_ticket_lifetime(
    ccache_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect active Kerberos ticket lifetime across local CCACHE files and Kernel Keyring."""
    result: Dict[str, Any] = {
        "name": "ticket_lifetime",
        "status": "PASS",
        "details": "",
        "recommendation": None,
        "remaining_seconds": 0,
        "cache_type": "NONE",
        "cache_path": None,
        "default_principal": None,
        "service_principal": None,
        "issued_time": None,
        "expiry_time": None,
        "remaining_human": "N/A",
        "is_expired": False,
        "renewable_until": None,
        "keyring_tickets_found": 0,
        "issues": [],
        "has_weak_enctypes": False,
        "tickets_found": 0,
        "encryption_types": [],
    }

    target_ccache = ccache_path
    if not target_ccache:
        env_cc = os.environ.get("KRB5CCNAME")
        if env_cc:
            if env_cc.startswith("FILE:") or env_cc.startswith("/"):
                target_ccache = env_cc[5:] if env_cc.startswith("FILE:") else env_cc
            elif env_cc.startswith("KEYRING:"):
                result["cache_type"] = "KEYRING"
            elif env_cc.startswith("KCM:"):
                result["cache_type"] = "KCM"

    if not target_ccache:
        uid = getattr(os, "getuid", lambda: None)()
        candidates = []
        if uid is not None:
            candidates.append(f"/tmp/krb5cc_{uid}")
        candidates.extend(["/tmp/krb5cc_0", "/tmp/krb5cc_1000"])

        for cand in candidates:
            if os.path.isfile(cand):
                target_ccache = cand
                break

    parsed_ticket: Optional[Dict[str, Any]] = None
    if target_ccache and os.path.isfile(target_ccache):
        result["cache_type"] = "FILE"
        result["cache_path"] = target_ccache
        try:
            with open(target_ccache, "rb") as f:
                data = f.read(131072)
            parsed_ticket = parse_ccache_stream(io.BytesIO(data))
        except OSError as exc:
            result["issues"].append(f"Cannot read CCACHE {target_ccache}: {exc}")

    keyring_keys = parse_proc_keys()
    result["keyring_tickets_found"] = len(keyring_keys)

    now = int(time.time())

    if parsed_ticket:
        result["has_weak_enctypes"] = parsed_ticket.get("has_weak_enctypes", False)
        result["tickets_found"] = len(parsed_ticket.get("tickets", []))
        result["encryption_types"] = parsed_ticket.get("enctypes", [])

    if parsed_ticket and parsed_ticket.get("endtime", 0) > 0:
        endtime = parsed_ticket["endtime"]
        authtime = parsed_ticket.get("authtime", 0)
        renew_till = parsed_ticket.get("renew_till", 0)
        remaining = endtime - now

        result["default_principal"] = parsed_ticket.get("default_principal")
        result["service_principal"] = parsed_ticket.get("server")
        result["remaining_seconds"] = remaining
        result["issued_time"] = (
            datetime.fromtimestamp(authtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            if authtime > 0
            else None
        )
        result["expiry_time"] = datetime.fromtimestamp(endtime, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%SZ"
        )
        result["renewable_until"] = (
            datetime.fromtimestamp(renew_till, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            if renew_till > 0
            else None
        )

        if remaining <= 0:
            result["status"] = "EXPIRED"
            result["is_expired"] = True
            result["remaining_human"] = "Expired"
            result["details"] = (
                f"Principal {result['default_principal']} expired at {result['expiry_time']}"
            )
            result["recommendation"] = "Acquire fresh ticket via kinit"
        elif remaining < 1800:
            result["status"] = "WARN"
            result["is_expired"] = False
            mins = remaining // 60
            secs = remaining % 60
            result["remaining_human"] = f"{mins}m {secs}s"
            result["details"] = (
                f"Expiring soon: {result['remaining_human']} remaining for {result['default_principal']}"
            )
            result["recommendation"] = "Renew active Kerberos ticket via kinit -R"
        else:
            result["status"] = "PASS"
            result["is_expired"] = False
            hours = remaining // 3600
            mins = (remaining % 3600) // 60
            secs = remaining % 60
            result["remaining_human"] = f"{hours}h {mins}m {secs}s"
            enctype_suffix = f" [{', '.join(result['encryption_types'])}]" if result.get("encryption_types") else ""
            result["details"] = (
                f"{result['remaining_human']} remaining{enctype_suffix} for {result['default_principal']} (expires {result['expiry_time']})"
            )

        if result["has_weak_enctypes"]:
            result["issues"].append(
                "Legacy weak encryption types detected in ticket cache (RC4-HMAC / DES)"
            )
            if result["status"] == "PASS":
                result["status"] = "WARN"
            weak_names = [e for e in result["encryption_types"] if "rc4" in e.lower() or "des" in e.lower()] or result["encryption_types"]
            result["details"] = f"{result['details']} [WARN: Weak session key ({', '.join(weak_names)}) detected]"
            result["recommendation"] = (
                "Enforce Kerberos AES-256 and purge weak tickets (refer to Tactical Decision Ladder Rung 2: Zero-Noise OPSEC Filter; re-request via kinit with AES)"
            )

    elif keyring_keys:
        result["cache_type"] = "KEYRING"
        active_keys = [k for k in keyring_keys if not k.get("is_expired")]
        if active_keys:
            result["status"] = "PASS"
            result["details"] = f"{len(active_keys)} active ticket keyring(s) in /proc/keys"
        else:
            result["status"] = "EXPIRED"
            result["is_expired"] = True
            result["details"] = "All Kerberos keyring tickets in /proc/keys are expired"
            result["recommendation"] = "Re-authenticate using kinit"

    else:
        result["status"] = "N_A"
        result["details"] = "No active Kerberos tickets found in file caches or kernel keyring"
        result["recommendation"] = "Run kinit to acquire Kerberos credentials"

    return result


_DEFAULT_HOST_TOOLS_CACHE: Optional[Dict[str, Any]] = None


def check_host_tools(search_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit host availability of Kerberos client utilities (kinit, klist, kvno)."""
    global _DEFAULT_HOST_TOOLS_CACHE
    if search_path is None and _DEFAULT_HOST_TOOLS_CACHE is not None:
        return {k: list(v) if isinstance(v, list) else v for k, v in _DEFAULT_HOST_TOOLS_CACHE.items()}

    exts = [".exe", ""] if os.name == "nt" else [""]
    path_dirs = (search_path or os.environ.get("PATH", "")).split(os.pathsep)

    kinit_path: Optional[str] = None
    klist_path: Optional[str] = None
    kvno_path: Optional[str] = None

    for d in path_dirs:
        if not d:
            continue
        for ext in exts:
            cand = os.path.join(d, "kinit" + ext)
            if os.path.isfile(cand):
                kinit_path = cand
                break
        if kinit_path:
            break

    if kinit_path:
        bin_dir = os.path.dirname(kinit_path)
        for ext in exts:
            p_list = os.path.join(bin_dir, "klist" + ext)
            if os.path.isfile(p_list):
                klist_path = p_list
            p_vno = os.path.join(bin_dir, "kvno" + ext)
            if os.path.isfile(p_vno):
                kvno_path = p_vno

    result: Dict[str, Any] = {
        "name": "host_tooling",
        "status": "PASS" if kinit_path else "WARN",
        "details": "",
        "recommendation": None,
        "kinit_present": bool(kinit_path),
        "kinit_path": kinit_path,
        "klist_present": bool(klist_path),
        "klist_path": klist_path,
        "kvno_present": bool(kvno_path),
        "kvno_path": kvno_path,
        "os_family": "windows" if os.name == "nt" else "posix",
        "package_hint": "krb5-user",
        "issues": [],
    }

    if kinit_path:
        tools_found = ["kinit"]
        if klist_path:
            tools_found.append("klist")
        if kvno_path:
            tools_found.append("kvno")
        result["status"] = "PASS"
        result["details"] = f"Utilities available: {', '.join(tools_found)} (kinit: {kinit_path})"
        if search_path is None:
            _DEFAULT_HOST_TOOLS_CACHE = {k: list(v) if isinstance(v, list) else v for k, v in result.items()}
        return result

    result["status"] = "WARN"
    result["details"] = "Kerberos client utility ('kinit') not found on PATH"
    result["issues"].append("kinit missing from PATH")

    install_cmd = "Install krb5-user (Debian/Kali) or krb5-workstation (RHEL)"
    if os.name != "nt" and os.path.isfile("/etc/os-release"):
        try:
            with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as f:
                os_release_text = f.read().lower()
            if any(d in os_release_text for d in ("debian", "ubuntu", "kali")):
                result["os_family"] = "debian"
                install_cmd = "sudo apt install krb5-user"
            elif any(r in os_release_text for r in ("rhel", "centos", "fedora", "rocky", "alma")):
                result["os_family"] = "rhel"
                result["package_hint"] = "krb5-workstation"
                install_cmd = "sudo dnf install krb5-workstation"
            elif "alpine" in os_release_text:
                result["os_family"] = "alpine"
                result["package_hint"] = "krb5"
                install_cmd = "apk add krb5"
            elif "arch" in os_release_text:
                result["os_family"] = "arch"
                result["package_hint"] = "krb5"
                install_cmd = "pacman -S krb5"
        except OSError:
            pass
    elif os.name == "nt":
        install_cmd = "Use native Windows Kerberos / PowerShell"

    result["recommendation"] = (
        f"Install client tools: {install_cmd} (unprivileged: use portable client with KRB5_CONFIG)"
    )
    if search_path is None:
        _DEFAULT_HOST_TOOLS_CACHE = {k: list(v) if isinstance(v, list) else v for k, v in result.items()}
    return result


def check_opsec_sensors(
    audit_rules_dir: str = "/etc/audit/rules.d",
    audit_rules_file: str = "/etc/audit/audit.rules",
    netlink_path: str = "/proc/net/netlink",
    auditd_pid_path: str = "/run/auditd.pid",
    falco_socket: str = "/var/run/falco/falco.sock",
    keytab_path: str = "/etc/krb5.keytab",
    ccache_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Passively inspect host OPSEC sensors (Auditd, Netlink, Falco) monitoring credential paths."""
    result: Dict[str, Any] = {
        "name": "opsec_sensors",
        "status": "PASS",
        "details": "No active Auditd or Falco watch rules detected on credential paths",
        "recommendation": None,
        "audit_netlink_active": False,
        "auditd_running": False,
        "falco_active": False,
        "keytab_monitored": False,
        "ccache_monitored": False,
        "monitored_paths": [],
        "issues": [],
    }

    # 1. Audit Netlink Socket Probe (/proc/net/netlink)
    if os.path.isfile(netlink_path):
        try:
            with open(netlink_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for line in content.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "9":
                    result["audit_netlink_active"] = True
                    break
        except OSError:
            pass

    # 2. Audit Daemon Running Check (/run/auditd.pid or /var/run/auditd.pid)
    pid_candidates = [auditd_pid_path, "/var/run/auditd.pid"]
    for p in pid_candidates:
        if os.path.isfile(p):
            result["auditd_running"] = True
            break

    # 3. Falco Socket Presence
    falco_candidates = [falco_socket, "/run/falco/falco.sock"]
    for fs in falco_candidates:
        if os.path.exists(fs):
            result["falco_active"] = True
            break

    # 4. Audit Rules Inspection
    rules_text = ""
    if os.path.isdir(audit_rules_dir):
        try:
            for fname in sorted(os.listdir(audit_rules_dir)):
                if fname.endswith(".rules"):
                    fpath = os.path.join(audit_rules_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            rules_text += "\n" + f.read()
                    except OSError:
                        pass
        except OSError:
            pass

    if os.path.isfile(audit_rules_file):
        try:
            with open(audit_rules_file, "r", encoding="utf-8", errors="replace") as f:
                rules_text += "\n" + f.read()
        except OSError:
            pass

    norm_kt = os.path.abspath(keytab_path) if keytab_path else "/etc/krb5.keytab"
    kt_watched = False
    cc_watched = False
    monitored: List[str] = []

    for line in rules_text.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if "-w " in line:
            parts = line.split()
            if "-w" in parts:
                idx = parts.index("-w")
                if idx + 1 < len(parts):
                    wpath = parts[idx + 1]
                    norm_w = os.path.abspath(wpath)
                    if norm_w == norm_kt or norm_kt.startswith(norm_w.rstrip("/\\") + "/"):
                        kt_watched = True
                        if wpath not in monitored:
                            monitored.append(wpath)
                    if ccache_path and (norm_w == os.path.abspath(ccache_path) or "/tmp/krb5cc" in wpath):
                        cc_watched = True
                        if wpath not in monitored:
                            monitored.append(wpath)
                    elif "/tmp/krb5cc" in wpath or "krb5cc" in wpath:
                        cc_watched = True
                        if wpath not in monitored:
                            monitored.append(wpath)

    result["keytab_monitored"] = kt_watched
    result["ccache_monitored"] = cc_watched
    result["monitored_paths"] = monitored

    if kt_watched or cc_watched:
        result["status"] = "WARN"
        targets = ", ".join(monitored)
        result["details"] = f"Host auditd watch rule actively monitoring credential paths: {targets}"
        result["issues"].append(f"Audit rule watches: {targets}")
        result["recommendation"] = "Accessing keytab or ccache will emit an Auditd kernel event. Prefer memory injection."
    elif result["falco_active"]:
        result["status"] = "WARN"
        result["details"] = "Falco daemon socket active on host; credential file syscalls may trigger alerts"
        result["recommendation"] = "Verify Falco rule coverage for /etc/krb5.keytab access before reading."
    elif result["auditd_running"] or result["audit_netlink_active"]:
        result["status"] = "PASS"
        result["details"] = "Audit daemon active, but no watch rules targeting keytab or ccache"
    else:
        if os.name == "nt":
            result["status"] = "PASS"
            result["details"] = "Platform not monitored by Linux netlink/auditd"
        else:
            result["status"] = "PASS"
            result["details"] = "No active Auditd or Falco monitoring detected on host"

    return result


def diagnose_system(
    keytab_path: str = "/etc/krb5.keytab",
    krb5_conf_path: Optional[str] = None,
    sssd_pipe: str = "/var/lib/sss/pipes/kcm",
    sssd_pid: str = "/var/run/sssd.pid",
    ccache_path: Optional[str] = None,
    tools_search_path: Optional[str] = None,
    include_opsec: bool = False,
    audit_rules_dir: str = "/etc/audit/rules.d",
    audit_rules_file: str = "/etc/audit/audit.rules",
    netlink_path: str = "/proc/net/netlink",
    auditd_pid_path: str = "/run/auditd.pid",
    falco_socket: str = "/var/run/falco/falco.sock",
    secrets_path: str = "/var/lib/sss/secrets/secrets.ldb",
) -> DoctorReport:
    """Run all pre-flight diagnostic probes deterministically in <5ms without network emissions."""
    t0 = time.perf_counter()

    resolved_krb5_conf = krb5_conf_path or os.environ.get("KRB5_CONFIG", "/etc/krb5.conf")

    checks = [
        check_keytab(keytab_path),
        check_krb5_conf(resolved_krb5_conf),
        check_sssd(sssd_pipe, sssd_pid, secrets_path),
        check_ticket_lifetime(ccache_path),
        check_host_tools(tools_search_path),
    ]

    if include_opsec:
        checks.append(
            check_opsec_sensors(
                audit_rules_dir=audit_rules_dir,
                audit_rules_file=audit_rules_file,
                netlink_path=netlink_path,
                auditd_pid_path=auditd_pid_path,
                falco_socket=falco_socket,
                keytab_path=keytab_path,
                ccache_path=ccache_path,
            )
        )

    has_fail = any(c.get("status") == "FAIL" for c in checks)
    has_warn = any(c.get("status") in ("WARN", "EXPIRED") for c in checks)

    if has_fail:
        overall_status = "FAIL"
    elif has_warn:
        overall_status = "WARN"
    else:
        overall_status = "PASS"

    duration_ms = (time.perf_counter() - t0) * 1000.0
    return DoctorReport(
        status=overall_status,
        checks=checks,
        duration_ms=duration_ms,
    )
