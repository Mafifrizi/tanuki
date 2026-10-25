"""Unprivileged Kerberos Configuration Generator for Linux Active Directory."""

import ipaddress
import os
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple, Union


_KRB5_CONF_FORBIDDEN_CHARS = set("\r\n\x00;#{}[]=")
_KRB5_CONF_KDC_FORBIDDEN_CHARS = set("\r\n\x00;#{} =")


def _validate_krb5_conf_token(value: str, field_name: str) -> None:
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field_name} cannot contain newline characters")
    if any(ch in _KRB5_CONF_FORBIDDEN_CHARS for ch in value):
        raise ValueError(f"{field_name} contains forbidden configuration syntax characters")


def _strip_kdc_transport_prefix(token: str) -> str:
    if token.lower().startswith(("tcp/", "udp/")):
        return token[4:]
    return token


def _validate_ipv6_with_optional_zone(addr_text: str, raw_kdc: str) -> None:
    addr_part, pct_sep, zone_part = addr_text.partition("%")
    if not addr_part or (pct_sep and (not zone_part or not all(ch.isalnum() or ch in "._-" for ch in zone_part))):
        raise ValueError(f"KDC contains invalid IPv6 address literal: {raw_kdc!r}")
    try:
        ipaddress.IPv6Address(addr_part)
    except ValueError as exc:
        raise ValueError(f"KDC contains invalid IPv6 address literal: {raw_kdc!r}") from exc


def _normalize_kdc_candidates(kdc: Union[str, List[str]]) -> List[str]:
    if not kdc:
        raise ValueError("KDC cannot be empty")
    if isinstance(kdc, str):
        kdc_candidates = [k.strip() for k in kdc.split(",") if k.strip()]
    elif isinstance(kdc, (list, tuple)):
        kdc_candidates = []
        for item in kdc:
            for k in item.split(","):
                k_clean = k.strip()
                if k_clean and k_clean not in kdc_candidates:
                    kdc_candidates.append(k_clean)
    else:
        raw = str(kdc).strip()
        kdc_candidates = [raw] if raw else []
    if not kdc_candidates:
        raise ValueError("KDC cannot be empty")
    return kdc_candidates


def generate_krb5_conf(
    realm: str,
    kdc: Union[str, List[str]],
    admin_server: Optional[str] = None,
    dns_lookup_realm: bool = False,
    dns_lookup_kdc: bool = False,
    ticket_lifetime: str = "24h",
    renew_lifetime: str = "7d",
    forwardable: bool = True,
    rdns: bool = False,
    udp_preference_limit: int = 0,
    clockskew: Optional[int] = None,
    enforce_aes: bool = False,
    fast: bool = False,
    armor_cache: Optional[str] = None,
) -> str:
    """Generate an RFC 4120-compliant Kerberos configuration with uppercase realm."""
    if not realm or not realm.strip():
        raise ValueError("Realm cannot be empty")
    _validate_krb5_conf_token(realm, "Realm")
    if not kdc:
        raise ValueError("KDC cannot be empty")

    clean_realm = realm.strip().upper()
    if any(ch.isspace() for ch in clean_realm):
        raise ValueError("Realm cannot contain whitespace")
    domain = clean_realm.lower()

    _validate_krb5_conf_token(ticket_lifetime, "ticket_lifetime")
    _validate_krb5_conf_token(renew_lifetime, "renew_lifetime")

    if armor_cache is not None:
        armor_cache = armor_cache.strip()
        if not armor_cache:
            armor_cache = None
        else:
            _validate_krb5_conf_token(armor_cache, "armor_cache")

    if admin_server is not None:
        admin_server = admin_server.strip()
        if not admin_server:
            admin_server = None
        else:
            _validate_krb5_conf_token(admin_server, "admin_server")
            if any(ch.isspace() for ch in admin_server) or "/" in admin_server:
                raise ValueError("admin_server contains forbidden configuration syntax characters")

    kdc_candidates = _normalize_kdc_candidates(kdc)

    for k in kdc_candidates:
        if any(ch in _KRB5_CONF_KDC_FORBIDDEN_CHARS or ch.isspace() for ch in k):
            raise ValueError(f"KDC contains forbidden configuration syntax characters: {k!r}")
        k_host = _strip_kdc_transport_prefix(k)
        if not k_host:
            raise ValueError(f"KDC contains invalid transport prefix without host: {k!r}")
        if "/" in k_host:
            raise ValueError(f"KDC contains invalid transport prefix: {k!r}")
        if "[" in k_host or "]" in k_host:
            if not (k_host.startswith("[") and k_host.count("[") == 1 and k_host.count("]") == 1):
                raise ValueError(f"KDC contains forbidden configuration syntax characters: {k!r}")
            inner, suffix = k_host[1:].split("]", 1)
            _validate_ipv6_with_optional_zone(inner, k)
            if suffix and not (suffix.startswith(":") and suffix[1:].isdigit() and 1 <= int(suffix[1:]) <= 65535):
                raise ValueError(f"KDC contains invalid port suffix: {k!r}")
        elif k_host.count(":") == 1:
            host_part, port_part = k_host.split(":", 1)
            if not host_part or not (port_part.isdigit() and 1 <= int(port_part) <= 65535):
                raise ValueError(f"KDC contains invalid host:port syntax: {k!r}")
        elif k_host.count(":") >= 2:
            _validate_ipv6_with_optional_zone(k_host, k)

    admin_target = admin_server if admin_server else _strip_kdc_transport_prefix(kdc_candidates[0])

    dns_realm_str = "true" if dns_lookup_realm else "false"
    dns_kdc_str = "true" if dns_lookup_kdc else "false"
    rdns_str = "true" if rdns else "false"
    forwardable_str = "true" if forwardable else "false"

    libdefaults_lines = [
        "[libdefaults]",
        f"    default_realm = {clean_realm}",
        f"    dns_lookup_realm = {dns_realm_str}",
        f"    dns_lookup_kdc = {dns_kdc_str}",
        f"    rdns = {rdns_str}",
        f"    udp_preference_limit = {udp_preference_limit}",
        f"    ticket_lifetime = {ticket_lifetime}",
        f"    renew_lifetime = {renew_lifetime}",
        f"    forwardable = {forwardable_str}",
    ]

    if clockskew is not None:
        libdefaults_lines.append(f"    clockskew = {clockskew}")

    if enforce_aes:
        libdefaults_lines.append("    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96")
        libdefaults_lines.append("    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96")

    if fast or armor_cache:
        libdefaults_lines.append("    fast_req_armoring = true")

    if armor_cache:
        libdefaults_lines.append(f"    armor_cache = {armor_cache}")

    libdefaults_block = "\n".join(libdefaults_lines)
    kdc_lines = "\n".join(f"        kdc = {k}" for k in kdc_candidates)

    return f"""{libdefaults_block}

[realms]
    {clean_realm} = {{
{kdc_lines}
        admin_server = {admin_target}
    }}

[domain_realm]
    .{domain} = {clean_realm}
    {domain} = {clean_realm}
"""


def write_krb5_conf_file(
    filepath: str,
    realm: str,
    kdc: Union[str, List[str]],
    admin_server: Optional[str] = None,
    clockskew: Optional[int] = None,
    enforce_aes: bool = False,
    fast: bool = False,
    armor_cache: Optional[str] = None,
) -> Dict[str, Any]:
    """Write generated Kerberos configuration to target filepath."""
    content = generate_krb5_conf(
        realm=realm,
        kdc=kdc,
        admin_server=admin_server,
        clockskew=clockskew,
        enforce_aes=enforce_aes,
        fast=fast,
        armor_cache=armor_cache,
    )
    abs_path = os.path.abspath(filepath)
    if os.path.islink(abs_path):
        raise ValueError(f"Refusing to write to symbolic link: {abs_path}")
    parent_dir = os.path.dirname(abs_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(abs_path, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)

    kdc_candidates = _normalize_kdc_candidates(kdc)
    clean_admin = admin_server.strip() if (admin_server and admin_server.strip()) else None
    admin_target = clean_admin if clean_admin else _strip_kdc_transport_prefix(kdc_candidates[0])
    kdc_str = ",".join(kdc_candidates)

    res: Dict[str, Any] = {
        "status": "SUCCESS",
        "realm": realm.strip().upper(),
        "kdc": kdc_str,
        "admin_server": admin_target,
        "config_path": abs_path,
        "export_command": f"export KRB5_CONFIG={abs_path}",
        "content": content,
    }
    if fast:
        res["fast"] = True
    if armor_cache and armor_cache.strip():
        res["armor_cache"] = armor_cache.strip()
    return res


def build_dns_srv_query(qname: str, tx_id: Optional[int] = None) -> bytes:
    """Build RFC 1035 / RFC 2782 DNS query packet for SRV record (QTYPE 33)."""
    tid = tx_id if tx_id is not None else int.from_bytes(os.urandom(2), "big")
    # Header: ID, Flags (0x0100 standard query, recursion desired), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    labels = [lbl.encode("utf-8") for lbl in qname.strip(".").split(".") if lbl]
    qname_bytes = bytearray()
    for lbl in labels:
        qname_bytes.append(len(lbl))
        qname_bytes.extend(lbl)
    qname_bytes.append(0)
    # Question: QNAME, QTYPE=33 (SRV), QCLASS=1 (IN)
    question = bytes(qname_bytes) + struct.pack(">HH", 33, 1)
    return header + question


def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse domain name from DNS packet handling compression pointers."""
    labels: List[str] = []
    jumped = False
    next_offset = offset
    visited = 0
    while visited < 64:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            if not jumped:
                next_offset = offset
                jumped = True
            offset = pointer
            visited += 1
        else:
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
            offset += length
            visited += 1
    return ".".join(labels), next_offset


def _is_valid_dns_hostname(hostname: str) -> bool:
    clean = hostname.strip(".")
    if not clean or len(clean) > 253:
        return False
    return all(ch.isalnum() or ch in ".-_" for ch in clean)


def parse_srv_response(
    data: bytes, expected_tx_id: Optional[int] = None
) -> List[Tuple[int, int, int, str]]:
    """Parse SRV records from DNS response packet. Returns list of (priority, weight, port, target)."""
    if len(data) < 12:
        return []
    _tid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", data[:12])
    if expected_tx_id is not None and _tid != expected_tx_id:
        return []
    if (flags & 0x8000) == 0:
        return []
    if (flags & 0x000F) != 0:
        return []
    MAX_SRV_RECORDS = 64
    if ancount > MAX_SRV_RECORDS:
        ancount = MAX_SRV_RECORDS
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_dns_name(data, offset)
        offset += 4  # QTYPE (2) + QCLASS (2)

    records: List[Tuple[int, int, int, str]] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        if rtype == 33 and rdlength >= 6 and offset + 6 <= len(data):  # SRV
            priority, weight, port = struct.unpack(">HHH", data[offset : offset + 6])
            target, _ = parse_dns_name(data, offset + 6)
            if target and _is_valid_dns_hostname(target):
                records.append((priority, weight, port, target))
        offset += rdlength

    records.sort(key=lambda r: (r[0], -r[1]))
    return records


def get_system_nameservers() -> List[str]:
    """Retrieve system DNS nameservers from /etc/resolv.conf or common defaults."""
    servers: List[str] = []
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        ns = parts[1].strip()
                        if ns and ns not in servers:
                            servers.append(ns)
        except OSError:
            pass
    for fb in ("127.0.0.53", "127.0.0.1", "10.0.2.3", "192.168.56.1"):
        if fb not in servers:
            servers.append(fb)
    return servers


def query_dns_srv(
    srv_record: str,
    nameserver: str = "127.0.0.1",
    port: int = 53,
    timeout: float = 0.8,
) -> List[Tuple[int, int, int, str]]:
    """Query DNS SRV record via UDP socket with pure standard library."""
    tx_id = int.from_bytes(os.urandom(2), byteorder="big")
    query_bytes = build_dns_srv_query(srv_record, tx_id=tx_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query_bytes, (nameserver, port))
        resp, _ = sock.recvfrom(4096)
        return parse_srv_response(resp, expected_tx_id=tx_id)
    except Exception:
        return []
    finally:
        sock.close()


def discover_dc_via_srv(realm: str, timeout: float = 0.8) -> Optional[Tuple[str, int]]:
    """Discover Domain Controller host and port via DNS SRV query (_kerberos._tcp and _ldap._tcp)."""
    clean_realm = realm.strip().lower()
    if not clean_realm:
        return None
    srv_candidates = [
        f"_kerberos._tcp.{clean_realm}",
        f"_ldap._tcp.{clean_realm}",
    ]
    nameservers = get_system_nameservers()
    for srv in srv_candidates:
        for ns in nameservers:
            records = query_dns_srv(srv, nameserver=ns, timeout=timeout)
            if records:
                return records[0][3], records[0][2]
    return None
