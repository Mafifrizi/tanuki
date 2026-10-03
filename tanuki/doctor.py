"""Proactive Pre-flight Diagnostic Engine for Linux Active Directory."""

import io
import json
import os
import stat
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .keytab import ENCTYPE_MAP, parse_keytab_stream


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
        lines.append("=" * 72)
        lines.append(" TANUKI PRE-FLIGHT DOCTOR (v1.2.0)")
        lines.append(f" Host: {hostname} | Mode: Passive Diagnostic")
        lines.append("=" * 72)

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
            }
            display_title = title_map.get(name, name.replace("_", " ").title().ljust(22))

            lines.append(f"[{c_status}] {display_title} : {details}")
            if rec:
                lines.append(f"       Action Required        : {rec}")

        lines.append("-" * 72)
        lines.append(
            f"OVERALL HEALTH: {self.status} "
            f"({self.summary['passed']} passed, {self.summary['warnings']} warnings, {self.summary['failures']} failures)"
        )
        lines.append(
            f"Execution Time: {self.duration_ms:.2f} ms | Network Packets Emitted: 0"
        )
        lines.append("=" * 72)
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
    }

    if not os.path.exists(keytab_path):
        result["status"] = "N_A"
        result["details"] = f"Keytab file not found: {keytab_path}"
        result["recommendation"] = f"Join domain or generate keytab at {keytab_path}"
        result["issues"].append(f"File does not exist: {keytab_path}")
        return result

    result["exists"] = True

    is_windows = os.name == "nt"
    if not is_windows:
        try:
            st = os.stat(keytab_path)
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
    except OSError as exc:
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


def check_krb5_conf(krb5_conf_path: str = "/etc/krb5.conf") -> Dict[str, Any]:
    """Parse /etc/krb5.conf sections and verify uppercase realm names per RFC 4120 § 6.1."""
    result: Dict[str, Any] = {
        "name": "realm_capitalization",
        "status": "PASS",
        "details": "",
        "recommendation": None,
        "path": krb5_conf_path,
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
        result["recommendation"] = f"Install krb5-user or configure {krb5_conf_path}"
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
) -> Dict[str, Any]:
    """Inspect SSSD daemon process status and KCM domain socket availability."""
    result: Dict[str, Any] = {
        "name": "sssd_subsystem",
        "status": "PASS",
        "details": "",
        "recommendation": None,
        "daemon_running": False,
        "pid": None,
        "kcm_socket_path": sssd_pipe,
        "kcm_socket_active": False,
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
        _enctype, key_len = struct.unpack(">HI", keyblock_head)
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
                return best_ticket
            _, alen = struct.unpack(">HI", ahead)
            stream.read(alen)

        ad_count_b = stream.read(4)
        if len(ad_count_b) < 4:
            break
        (ad_count,) = struct.unpack(">I", ad_count_b)
        for _ in range(ad_count):
            ahead = stream.read(6)
            if len(ahead) < 6:
                return best_ticket
            _, alen = struct.unpack(">HI", ahead)
            stream.read(alen)

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

        if endtime == 0:
            continue

        cand = {
            "default_principal": default_principal,
            "client": client,
            "server": server,
            "authtime": authtime,
            "starttime": starttime,
            "endtime": endtime,
            "renew_till": renew_till,
        }

        if best_ticket is None:
            best_ticket = cand
        elif "krbtgt" in server and "krbtgt" not in best_ticket.get("server", ""):
            best_ticket = cand
        elif endtime > best_ticket.get("endtime", 0):
            best_ticket = cand

    if best_ticket is None:
        return {
            "default_principal": default_principal,
            "server": None,
            "authtime": 0,
            "endtime": 0,
            "renew_till": 0,
        }

    return best_ticket


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
            result["details"] = (
                f"{result['remaining_human']} remaining for {result['default_principal']} (expires {result['expiry_time']})"
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


def diagnose_system(
    keytab_path: str = "/etc/krb5.keytab",
    krb5_conf_path: str = "/etc/krb5.conf",
    sssd_pipe: str = "/var/lib/sss/pipes/kcm",
    sssd_pid: str = "/var/run/sssd.pid",
    ccache_path: Optional[str] = None,
) -> DoctorReport:
    """Run all pre-flight diagnostic probes deterministically in <5ms without network emissions."""
    t0 = time.perf_counter()

    checks = [
        check_keytab(keytab_path),
        check_krb5_conf(krb5_conf_path),
        check_sssd(sssd_pipe, sssd_pid),
        check_ticket_lifetime(ccache_path),
    ]

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
