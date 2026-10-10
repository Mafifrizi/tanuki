"""Unprivileged SASL GSSAPI LDAP Query Engine (tanuki ldap).

Pure standard-library LDAPv3 client over TCP port 389 (LDAP) and port 636 (LDAPS).
Authenticates via active Kerberos ccache tickets (SASL GSSAPI) or unprivileged binds.
Queries Active Directory for:
- Service Principal Names (SPNs) for Kerberoasting triage.
- Resource-Based Constrained Delegation (RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity).
- Shadow Credentials (msDS-KeyCredentialLink).
- Unconstrained Delegation accounts (UAC flag 0x80000).
"""

import json
import os
import socket
import ssl
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from .doctor import render_card_header, supports_unicode

# ASN.1 Universal Tags
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_ENUMERATED = 0x0A
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

# LDAP Protocol Application Tags
LDAP_REQ_BIND = 0x60
LDAP_RESP_BIND = 0x61
LDAP_REQ_UNBIND = 0x42
LDAP_REQ_SEARCH = 0x63
LDAP_RESP_SEARCH_ENTRY = 0x64
LDAP_RESP_SEARCH_DONE = 0x65

# LDAP Search Scopes
SCOPE_BASE = 0
SCOPE_ONE_LEVEL = 1
SCOPE_SUBTREE = 2

# LDAP Filter Tags
FILTER_AND = 0xA0
FILTER_OR = 0xA1
FILTER_NOT = 0xA2
FILTER_EQUALITY = 0xA3
FILTER_SUBSTRINGS = 0xA4
FILTER_GE = 0xA5
FILTER_LE = 0xA6
FILTER_PRESENT = 0x87
FILTER_EXTENSIBLE = 0xA9

BINARY_AD_ATTRIBUTES = {
    "msds-allowedtoactonbehalfofotheridentity",
    "msds-keycredentiallink",
    "objectsid",
    "objectguid",
    "usercertificate",
    "ntsecuritydescriptor",
    "tokengroups",
}


class LdapError(Exception):
    """Raised when LDAP network or BER parsing encounters an error."""
    pass


def ber_encode_length(length: int) -> bytes:
    """Encode length into ASN.1 BER format."""
    if length < 0x80:
        return bytes([length])
    len_bytes = []
    temp = length
    while temp > 0:
        len_bytes.insert(0, temp & 0xFF)
        temp >>= 8
    return bytes([0x80 | len(len_bytes)] + len_bytes)


def ber_encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode Tag-Length-Value into ASN.1 BER bytes."""
    return bytes([tag]) + ber_encode_length(len(value)) + value


def ber_encode_int(val: int) -> bytes:
    """Encode signed integer into ASN.1 BER INTEGER."""
    if val == 0:
        return ber_encode_tlv(TAG_INTEGER, b"\x00")
    b = []
    temp = val
    if val > 0:
        while temp > 0:
            b.insert(0, temp & 0xFF)
            temp >>= 8
        if b[0] & 0x80:
            b.insert(0, 0x00)
    else:
        # Negative integer two's complement
        temp = val
        while True:
            b.insert(0, temp & 0xFF)
            if (temp >= -128 and temp < 0 and (b[0] & 0x80)) or (temp == -1 and (b[0] & 0x80)):
                break
            temp >>= 8
    return ber_encode_tlv(TAG_INTEGER, bytes(b))


def ber_encode_string(s: str) -> bytes:
    """Encode UTF-8 string into ASN.1 BER OCTET STRING."""
    return ber_encode_tlv(TAG_OCTET_STRING, s.encode("utf-8"))


def ber_encode_sequence(elements: List[bytes]) -> bytes:
    """Encode list of TLV byte chunks into ASN.1 BER SEQUENCE."""
    return ber_encode_tlv(TAG_SEQUENCE, b"".join(elements))


def ber_decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Decode single BER TLV element with strict bounds checking.

    Returns (tag, value_bytes, next_offset).
    """
    if offset >= len(data):
        raise LdapError(f"Unexpected end of BER stream at offset {offset}")

    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise LdapError("Truncated BER length byte")

    len_byte = data[offset]
    offset += 1

    if (len_byte & 0x80) == 0:
        length = len_byte
    else:
        num_len_bytes = len_byte & 0x7F
        if num_len_bytes == 0 or offset + num_len_bytes > len(data):
            raise LdapError(f"Invalid BER multi-byte length at offset {offset}")
        length = int.from_bytes(data[offset : offset + num_len_bytes], byteorder="big")
        offset += num_len_bytes

    if offset + length > len(data):
        raise LdapError(f"BER value out of bounds: length {length} > remaining {len(data) - offset}")

    val = data[offset : offset + length]
    return tag, val, offset + length


def ber_decode_int(data: bytes) -> int:
    """Decode BER INTEGER payload into Python int."""
    if not data:
        return 0
    return int.from_bytes(data, byteorder="big", signed=True)


def ber_decode_string(data: bytes) -> str:
    """Decode BER OCTET STRING payload into string."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def build_ldap_bind_request(
    msg_id: int,
    bind_dn: str = "",
    password: Optional[str] = None,
    sasl_mechanism: Optional[str] = None,
    sasl_credentials: Optional[bytes] = None,
) -> bytes:
    """Construct an LDAPv3 BindRequest message."""
    version_bytes = ber_encode_int(3)
    name_bytes = ber_encode_string(bind_dn)

    if sasl_mechanism:
        # SASL Bind: [APPLICATION 3] (0xA3) SEQUENCE { mechanism OCTET STRING, credentials OCTET STRING OPTIONAL }
        sasl_elems = [ber_encode_string(sasl_mechanism)]
        if sasl_credentials:
            sasl_elems.append(ber_encode_tlv(TAG_OCTET_STRING, sasl_credentials))
        auth_bytes = ber_encode_tlv(0xA3, b"".join(sasl_elems))
    else:
        # Simple Bind: [0x80] OCTET STRING password (or empty for anonymous)
        pwd_bytes = (password or "").encode("utf-8")
        auth_bytes = ber_encode_tlv(0x80, pwd_bytes)

    bind_req_payload = version_bytes + name_bytes + auth_bytes
    bind_req_bytes = ber_encode_tlv(LDAP_REQ_BIND, bind_req_payload)

    msg_id_bytes = ber_encode_int(msg_id)
    return ber_encode_sequence([msg_id_bytes, bind_req_bytes])


def build_ldap_search_filter(attribute: str, value: str = "*") -> bytes:
    """Construct LDAP search filter TLV bytes."""
    if value == "*":
        # Present filter: [0x87] attributeName
        return ber_encode_tlv(FILTER_PRESENT, attribute.encode("utf-8"))
    else:
        # Equality filter: [0xA3] SEQUENCE { attributeDesc OCTET STRING, assertionValue OCTET STRING }
        eq_payload = ber_encode_string(attribute) + ber_encode_string(value)
        return ber_encode_tlv(FILTER_EQUALITY, eq_payload)


def build_ldap_search_request(
    msg_id: int,
    base_dn: str,
    scope: int = SCOPE_SUBTREE,
    filter_bytes: Optional[bytes] = None,
    attributes: Optional[List[str]] = None,
    size_limit: int = 100,
    time_limit: int = 10,
) -> bytes:
    """Construct an LDAPv3 SearchRequest message."""
    base_bytes = ber_encode_string(base_dn)
    scope_bytes = ber_encode_tlv(TAG_ENUMERATED, bytes([scope]))
    deref_bytes = ber_encode_tlv(TAG_ENUMERATED, b"\x00")  # neverDerefAliases
    size_bytes = ber_encode_int(size_limit)
    time_bytes = ber_encode_int(time_limit)
    types_only_bytes = ber_encode_tlv(TAG_BOOLEAN, b"\x00")

    if filter_bytes is None:
        filter_bytes = build_ldap_search_filter("objectClass", "*")

    attr_list = attributes or []
    attr_elems = [ber_encode_string(a) for a in attr_list]
    attrs_bytes = ber_encode_sequence(attr_elems)

    search_payload = (
        base_bytes
        + scope_bytes
        + deref_bytes
        + size_bytes
        + time_bytes
        + types_only_bytes
        + filter_bytes
        + attrs_bytes
    )
    search_req_bytes = ber_encode_tlv(LDAP_REQ_SEARCH, search_payload)
    msg_id_bytes = ber_encode_int(msg_id)
    return ber_encode_sequence([msg_id_bytes, search_req_bytes])


def parse_ldap_response_stream(raw_data: bytes) -> List[Dict[str, Any]]:
    """Parse received LDAP stream into structured message objects."""
    messages: List[Dict[str, Any]] = []
    offset = 0

    while offset < len(raw_data):
        try:
            tag, seq_val, offset = ber_decode_tlv(raw_data, offset)
            if tag != TAG_SEQUENCE:
                continue

            inner_off = 0
            id_tag, id_val, inner_off = ber_decode_tlv(seq_val, inner_off)
            msg_id = ber_decode_int(id_val)

            op_tag, op_val, _ = ber_decode_tlv(seq_val, inner_off)

            if op_tag == LDAP_RESP_BIND:
                res_code = 0
                matched_dn = ""
                diagnostic_message = ""
                if op_val:
                    if op_val[0] in (TAG_ENUMERATED, TAG_INTEGER):
                        try:
                            _, res_bytes, inner_b_off = ber_decode_tlv(op_val, 0)
                            res_code = ber_decode_int(res_bytes)
                            if inner_b_off < len(op_val):
                                _, dn_bytes, inner_b_off = ber_decode_tlv(op_val, inner_b_off)
                                matched_dn = ber_decode_string(dn_bytes)
                            if inner_b_off < len(op_val):
                                _, diag_bytes, inner_b_off = ber_decode_tlv(op_val, inner_b_off)
                                diagnostic_message = ber_decode_string(diag_bytes)
                        except Exception:
                            res_code = op_val[0]
                    else:
                        res_code = op_val[0]
                messages.append({
                    "message_id": msg_id,
                    "type": "bind_response",
                    "result_code": res_code,
                    "matched_dn": matched_dn,
                    "diagnostic_message": diagnostic_message,
                    "success": (res_code == 0),
                })
            elif op_tag == LDAP_RESP_SEARCH_ENTRY:
                e_off = 0
                dn_tag, dn_val, e_off = ber_decode_tlv(op_val, e_off)
                dn = ber_decode_string(dn_val)

                attrs_tag, attrs_val, _ = ber_decode_tlv(op_val, e_off)
                attrs_dict: Dict[str, List[Any]] = {}

                a_off = 0
                while a_off < len(attrs_val):
                    _, attr_seq, a_off = ber_decode_tlv(attrs_val, a_off)
                    sub_off = 0
                    _, type_val, sub_off = ber_decode_tlv(attr_seq, sub_off)
                    attr_name = ber_decode_string(type_val)
                    is_binary = attr_name.lower() in BINARY_AD_ATTRIBUTES

                    _, vals_set, _ = ber_decode_tlv(attr_seq, sub_off)
                    vals_list: List[Any] = []
                    v_off = 0
                    while v_off < len(vals_set):
                        _, v_bytes, v_off = ber_decode_tlv(vals_set, v_off)
                        if is_binary:
                            vals_list.append(v_bytes)
                        else:
                            vals_list.append(ber_decode_string(v_bytes))

                    attrs_dict[attr_name] = vals_list

                messages.append({
                    "message_id": msg_id,
                    "type": "search_entry",
                    "dn": dn,
                    "attributes": attrs_dict,
                })
            elif op_tag == LDAP_RESP_SEARCH_DONE:
                res_code = 0
                matched_dn = ""
                diagnostic_message = ""
                if op_val:
                    if op_val[0] in (TAG_ENUMERATED, TAG_INTEGER):
                        try:
                            _, res_bytes, inner_s_off = ber_decode_tlv(op_val, 0)
                            res_code = ber_decode_int(res_bytes)
                            if inner_s_off < len(op_val):
                                _, dn_bytes, inner_s_off = ber_decode_tlv(op_val, inner_s_off)
                                matched_dn = ber_decode_string(dn_bytes)
                            if inner_s_off < len(op_val):
                                _, diag_bytes, inner_s_off = ber_decode_tlv(op_val, inner_s_off)
                                diagnostic_message = ber_decode_string(diag_bytes)
                        except Exception:
                            res_code = op_val[0]
                    else:
                        res_code = op_val[0]
                messages.append({
                    "message_id": msg_id,
                    "type": "search_done",
                    "result_code": res_code,
                    "matched_dn": matched_dn,
                    "diagnostic_message": diagnostic_message,
                })
        except Exception:
            break

    return messages


def is_ldap_message_done(data: bytes) -> bool:
    """Check if stream contains a completely framed LDAP_RESP_BIND or LDAP_RESP_SEARCH_DONE."""
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data) or data[offset] != TAG_SEQUENCE:
            offset += 1
            continue
        try:
            tag, seq_val, next_off = ber_decode_tlv(data, offset)
            if tag == TAG_SEQUENCE:
                _, _, inner_off = ber_decode_tlv(seq_val, 0)
                if inner_off < len(seq_val):
                    op_tag = seq_val[inner_off]
                    if op_tag in (LDAP_RESP_BIND, LDAP_RESP_SEARCH_DONE):
                        return True
            offset = next_off
        except Exception:
            break
    return False


class LdapClient:
    """Pure standard-library LDAPv3 client for unprivileged Active Directory reconnaissance."""

    def __init__(
        self,
        host: str,
        port: int = 389,
        use_ssl: bool = False,
        timeout: float = 5.0,
        verify_ssl: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.sock: Optional[socket.socket] = None
        self.msg_counter = 1
        self.connected = False

    def connect(self) -> None:
        """Establish TCP or LDAPS connection."""
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout)
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                if self.verify_ssl:
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                else:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            else:
                self.sock = raw_sock

            self.sock.connect((self.host, self.port))
            self.connected = True
        except Exception as exc:
            self.connected = False
            raise LdapError(f"Connection to LDAP server {self.host}:{self.port} failed: {exc}")

    def close(self) -> None:
        """Close socket connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.connected = False

    def send_and_recv(self, req_bytes: bytes) -> bytes:
        """Send LDAP request bytes and receive response."""
        if not self.sock:
            raise LdapError("Not connected")

        self.sock.sendall(req_bytes)
        chunks = []
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                joined = b"".join(chunks)
                if is_ldap_message_done(joined):
                    break
        except socket.timeout:
            pass

        return b"".join(chunks)

    def bind(
        self,
        bind_dn: str = "",
        password: Optional[str] = None,
        sasl_mechanism: Optional[str] = None,
    ) -> bool:
        """Execute LDAP Bind request."""
        msg_id = self.msg_counter
        self.msg_counter += 1

        req = build_ldap_bind_request(
            msg_id=msg_id,
            bind_dn=bind_dn,
            password=password,
            sasl_mechanism=sasl_mechanism,
        )
        resp_data = self.send_and_recv(req)
        parsed = parse_ldap_response_stream(resp_data)
        for msg in parsed:
            if msg.get("type") == "bind_response":
                return bool(msg.get("success"))
        return False

    def search(
        self,
        base_dn: str,
        filter_bytes: Optional[bytes] = None,
        attributes: Optional[List[str]] = None,
        size_limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Execute LDAP Search request and return entries."""
        msg_id = self.msg_counter
        self.msg_counter += 1

        req = build_ldap_search_request(
            msg_id=msg_id,
            base_dn=base_dn,
            filter_bytes=filter_bytes,
            attributes=attributes,
            size_limit=size_limit,
        )
        resp_data = self.send_and_recv(req)
        parsed = parse_ldap_response_stream(resp_data)
        for m in parsed:
            if m.get("type") == "search_done":
                rc = m.get("result_code", 0)
                if rc != 0:
                    diag = (m.get("diagnostic_message") or "").replace("\x00", "").strip()
                    err_msg = f"LDAP search rejected with code {rc}"
                    if diag:
                        err_msg += f" ({diag})"
                    raise RuntimeError(err_msg)
        entries = [m for m in parsed if m.get("type") == "search_entry"]
        return entries


def probe_tcp_port(host: str, port: int = 389, timeout: float = 0.8) -> Tuple[bool, Optional[str]]:
    """Fast non-blocking socket probe (<800ms) before initiating live wire operations."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return True, None
    except Exception as exc:
        return False, str(exc)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def query_active_directory_ldap(
    host: str,
    query_type: str = "spn",
    base_dn: str = "DC=corp,DC=local",
    port: int = 389,
    use_ssl: bool = False,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Execute unprivileged AD diagnostic queries (SPN, RBCD, Shadow Credentials, Unconstrained)."""
    # Fast non-blocking socket probe (<800ms) before initiating LDAP bind
    probe_timeout = min(timeout, 0.8)
    reachable, err_msg = probe_tcp_port(host, port, timeout=probe_timeout)
    if not reachable:
        remediation = f"ssh -L 8888:{host}:88 user@pivot -N / ssh -L {port}:{host}:{port} user@pivot -N"
        return {
            "status": "CONNECTION_FAILED",
            "host": host,
            "port": port,
            "query_type": query_type,
            "base_dn": base_dn,
            "error": f"Port {port} unreachable on host '{host}' ({err_msg}). Tactical remediation: Verify network route/firewall or configure SSH port-forwarding pivot: {remediation}",
            "remediation": remediation,
            "entries": [],
            "count": 0,
        }

    client = LdapClient(host=host, port=port, use_ssl=use_ssl, timeout=timeout)
    results: List[Dict[str, Any]] = []

    attr_map = {
        "spn": ["sAMAccountName", "servicePrincipalName", "userAccountControl"],
        "rbcd": ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        "shadow": ["sAMAccountName", "msDS-KeyCredentialLink"],
        "unconstrained": ["sAMAccountName", "userAccountControl"],
    }

    try:
        client.connect()
        # Bind unprivileged / anonymous / GSSAPI
        bound = client.bind()
        if not bound:
            return {
                "status": "BIND_FAILED",
                "host": host,
                "query_type": query_type,
                "message": "LDAP bind failed (anonymous or unprivileged access disallowed)",
                "entries": [],
                "count": 0,
            }

        target_queries = [query_type] if query_type != "all" else ["spn", "rbcd", "shadow", "unconstrained"]

        for q in target_queries:
            attrs = attr_map.get(q, ["sAMAccountName"])
            f_bytes = None
            if q == "spn":
                f_bytes = build_ldap_search_filter("servicePrincipalName", "*")
            elif q == "rbcd":
                f_bytes = build_ldap_search_filter("msDS-AllowedToActOnBehalfOfOtherIdentity", "*")
            elif q == "shadow":
                f_bytes = build_ldap_search_filter("msDS-KeyCredentialLink", "*")
            elif q == "unconstrained":
                f_bytes = build_ldap_search_filter("userAccountControl", "*")

            entries = client.search(base_dn=base_dn, filter_bytes=f_bytes, attributes=attrs)
            for e in entries:
                e["query_category"] = q
                if q == "rbcd":
                    rbcd_raw_list = e.get("attributes", {}).get("msDS-AllowedToActOnBehalfOfOtherIdentity", [])
                    if rbcd_raw_list and isinstance(rbcd_raw_list[0], (bytes, bytearray)):
                        try:
                            from .pac import parse_rbcd_security_descriptor
                            e["rbcd_parsed"] = parse_rbcd_security_descriptor(bytes(rbcd_raw_list[0]))
                        except Exception as parse_exc:
                            e["rbcd_parse_error"] = str(parse_exc)
                elif q == "shadow":
                    shadow_raw_list = e.get("attributes", {}).get("msDS-KeyCredentialLink", []) or e.get("attributes", {}).get("msds-keycredentiallink", [])
                    if shadow_raw_list:
                        e["shadow_credentials"] = []
                        for s_item in shadow_raw_list:
                            try:
                                from .shadow import parse_key_credential_link
                                e["shadow_credentials"].append(parse_key_credential_link(s_item))
                            except Exception as parse_exc:
                                e["shadow_credentials"].append({"error": str(parse_exc)})
                results.append(e)

        return {
            "status": "SUCCESS",
            "host": host,
            "port": port,
            "query_type": query_type,
            "base_dn": base_dn,
            "count": len(results),
            "entries": results,
        }
    except Exception as exc:
        status_name = "SEARCH_FAILED" if getattr(client, "connected", False) else "CONNECTION_FAILED"
        return {
            "status": status_name,
            "host": host,
            "port": port,
            "query_type": query_type,
            "base_dn": base_dn,
            "error": str(exc),
            "entries": [],
            "count": 0,
        }
    finally:
        client.close()


def format_ldap_report_terminal(report: Dict[str, Any]) -> str:
    """Format LDAP query results into clean terminal card header and tree."""
    lines: List[str] = []
    host = report.get("host", "Unknown")
    q_type = report.get("query_type", "spn").upper()
    lines.extend(render_card_header(
        "TANUKI UNPRIVILEGED LDAP QUERY ENGINE",
        f"Target: {host}:{report.get('port', 389)} · Query: {q_type} · Found: {report.get('count', 0)}",
    ))

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")
    v_line = "│ " if use_uni else "| "

    if report.get("status") != "SUCCESS":
        lines.append(f"[!] LDAP Operation Status: {report.get('status')}")
        err_msg = report.get("error") or report.get("message", "Unknown error")
        lines.append(f"    {l_branch} Details: {err_msg}")
        return "\n".join(lines)

    entries = report.get("entries", [])
    if not entries:
        lines.append(f"[*] Query returned 0 matching directory objects for filter '{q_type}'.")
        return "\n".join(lines)

    lines.append(f"[+] Discovered Active Directory Objects ({len(entries)} entries):\n")
    for idx, e in enumerate(entries):
        is_last = idx == len(entries) - 1
        branch = l_branch if is_last else t_branch
        dn = e.get("dn", "Unknown DN")
        attrs = e.get("attributes", {})
        sam = attrs.get("sAMAccountName", [dn])[0]
        cat = e.get("query_category", "AD-OBJECT").upper()

        lines.append(f"[{cat}] {sam}")
        lines.append(f"    {t_branch} DN: {dn}")
        for a_name, a_vals in attrs.items():
            if a_name != "sAMAccountName":
                if a_name.lower() == "msds-allowedtoactonbehalfofotheridentity":
                    for v in a_vals:
                        if isinstance(v, (bytes, bytearray)):
                            try:
                                from .pac import parse_rbcd_security_descriptor
                                r_desc = parse_rbcd_security_descriptor(bytes(v))
                                t_sids = r_desc.get("allowed_trustee_sids", [])
                                lines.append(f"    {t_branch} {a_name} (RBCD):")
                                lines.append(f"    {v_line}  {t_branch} ACE Count: {r_desc.get('ace_count', 0)}")
                                if t_sids:
                                    for s_idx, s in enumerate(t_sids):
                                        sub_b = l_branch if s_idx == len(t_sids) - 1 else t_branch
                                        lines.append(f"    {v_line}  {sub_b} Allowed Trustee: {s}")
                                else:
                                    lines.append(f"    {v_line}  {l_branch} Allowed Trustee: None")
                            except Exception as pe:
                                lines.append(f"    {t_branch} {a_name}: <binary: {len(v)} bytes, parse error: {pe}>")
                        else:
                            lines.append(f"    {t_branch} {a_name}: {v}")
                    continue
                elif a_name.lower() == "msds-keycredentiallink":
                    for v in a_vals:
                        try:
                            from .shadow import parse_key_credential_link
                            s_rep = parse_key_credential_link(v)
                            lines.append(f"    {t_branch} {a_name} (Shadow Credential v{s_rep.get('version_str', '2.0')}):")
                            lines.append(f"    {v_line}  {t_branch} Key ID   : {s_rep.get('key_id', 'N/A')}")
                            lines.append(f"    {v_line}  {t_branch} Usage    : {s_rep.get('key_usage', 'N/A')} (Source: {s_rep.get('key_source', 'N/A')})")
                            km = s_rep.get("key_material") or {}
                            if km.get("key_type") == "RSA":
                                lines.append(f"    {v_line}  {t_branch} Key Type : RSA {km.get('bit_length')} bits")
                            elif km.get("key_type") == "ECC":
                                lines.append(f"    {v_line}  {t_branch} Key Type : ECC {km.get('curve')}")
                            lines.append(f"    {v_line}  {l_branch} Device ID: {s_rep.get('device_id', 'N/A')}")
                        except Exception as pe:
                            lines.append(f"    {t_branch} {a_name}: <parse error: {pe}>")
                    continue

                val_strs: List[str] = []
                for v in a_vals[:3]:
                    if isinstance(v, bytes):
                        val_strs.append(f"<binary: {len(v)} bytes, hex: {v[:8].hex()}...>")
                    else:
                        val_strs.append(str(v))
                val_preview = ", ".join(val_strs)
                if len(a_vals) > 3:
                    val_preview += f" (+{len(a_vals) - 3} more)"
                lines.append(f"    {t_branch} {a_name}: {val_preview}")
        if not is_last:
            lines.append("")

    return "\n".join(lines)
