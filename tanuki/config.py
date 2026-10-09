"""Unprivileged Kerberos Configuration Generator for Linux Active Directory."""

import os
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple, Union


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
    if "\n" in realm or "\r" in realm:
        raise ValueError("Realm cannot contain newline characters")
    if not kdc:
        raise ValueError("KDC cannot be empty")

    clean_realm = realm.strip().upper()
    domain = clean_realm.lower()

    if armor_cache is not None:
        armor_cache = armor_cache.strip()
        if not armor_cache:
            armor_cache = None
        elif "\n" in armor_cache or "\r" in armor_cache:
            raise ValueError("armor_cache cannot contain newline characters")

    if admin_server is not None:
        if "\n" in admin_server or "\r" in admin_server:
            raise ValueError("admin_server cannot contain newline characters")

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
        kdc_candidates = [str(kdc).strip()]

    if not kdc_candidates:
        raise ValueError("KDC cannot be empty")

    for k in kdc_candidates:
        if "\n" in k or "\r" in k:
            raise ValueError("KDC cannot contain newline characters")

    admin_target = admin_server.strip() if admin_server else kdc_candidates[0]

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
    parent_dir = os.path.dirname(abs_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(abs_path, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)

    kdc_str = kdc if isinstance(kdc, str) else ",".join(kdc)

    res: Dict[str, Any] = {
        "status": "SUCCESS",
        "realm": realm.strip().upper(),
        "kdc": kdc_str,
        "admin_server": admin_server.strip() if admin_server else (kdc.split(",")[0].strip() if isinstance(kdc, str) else kdc[0]),
        "config_path": abs_path,
        "export_command": f"export KRB5_CONFIG={abs_path}",
        "content": content,
    }
    if fast:
        res["fast"] = True
    if armor_cache:
        res["armor_cache"] = armor_cache
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


def parse_srv_response(data: bytes) -> List[Tuple[int, int, int, str]]:
    """Parse SRV records from DNS response packet. Returns list of (priority, weight, port, target)."""
    if len(data) < 12:
        return []
    _tid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", data[:12])
    if (flags & 0x000F) != 0:
        return []
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
        if rtype == 33 and rdlength >= 6:  # SRV
            priority, weight, port = struct.unpack(">HHH", data[offset : offset + 6])
            target, _ = parse_dns_name(data, offset + 6)
            if target:
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
    query_bytes = build_dns_srv_query(srv_record)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query_bytes, (nameserver, port))
        resp, _ = sock.recvfrom(4096)
        return parse_srv_response(resp)
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
