"""MS-PAC Bounded NDR Binary Decoder (RFC 4120 / MS-PAC).

Provides pure standard-library parsing of Active Directory Privilege Attribute
Certificate (PAC) structures embedded in Kerberos tickets. Extracts user SIDs,
primary group RIDs, group memberships (Domain Admins RID 512, Enterprise Admins
RID 519), and User Account Control (UAC) flags with strict bounded buffer checks.
"""

import base64
import binascii
import io
import json
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

from .doctor import render_card_header, supports_unicode

# PAC Buffer Types (MS-PAC 2.2.1)
PAC_LOGON_INFO = 1
PAC_SERVER_CHECKSUM = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO = 10
PAC_UPN_DNS_INFO = 12
PAC_ATTRIBUTES_INFO = 16
PAC_REQUESTOR_SID = 17

BUFFER_TYPE_NAMES = {
    PAC_LOGON_INFO: "PAC_LOGON_INFO",
    PAC_SERVER_CHECKSUM: "PAC_SERVER_CHECKSUM",
    PAC_PRIVSVR_CHECKSUM: "PAC_PRIVSVR_CHECKSUM",
    PAC_CLIENT_INFO: "PAC_CLIENT_INFO",
    PAC_UPN_DNS_INFO: "PAC_UPN_DNS_INFO",
    PAC_ATTRIBUTES_INFO: "PAC_ATTRIBUTES_INFO",
    PAC_REQUESTOR_SID: "PAC_REQUESTOR_SID",
}

# Well-Known Active Directory RIDs
DOMAIN_ADMINS_RID = 512
DOMAIN_USERS_RID = 513
DOMAIN_GUESTS_RID = 514
DOMAIN_COMPUTERS_RID = 515
DOMAIN_CONTROLLERS_RID = 516
SCHEMA_ADMINS_RID = 518
ENTERPRISE_ADMINS_RID = 519
GROUP_POLICY_CREATOR_OWNERS_RID = 520
BUILTIN_ADMINISTRATORS_RID = 544

WELL_KNOWN_RIDS = {
    DOMAIN_ADMINS_RID: "Domain Admins",
    DOMAIN_USERS_RID: "Domain Users",
    DOMAIN_GUESTS_RID: "Domain Guests",
    DOMAIN_COMPUTERS_RID: "Domain Computers",
    DOMAIN_CONTROLLERS_RID: "Domain Controllers",
    SCHEMA_ADMINS_RID: "Schema Admins",
    ENTERPRISE_ADMINS_RID: "Enterprise Admins",
    GROUP_POLICY_CREATOR_OWNERS_RID: "Group Policy Creator Owners",
    BUILTIN_ADMINISTRATORS_RID: "Administrators",
}

# User Account Control (UAC) Flags (MS-SAMR 2.2.1.13)
UAC_FLAGS_MAP = {
    0x0001: "ACCOUNTDISABLE",
    0x0002: "HOMEDIR_REQUIRED",
    0x0004: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "SERVER_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}


class PacDecodeError(Exception):
    """Raised when PAC binary structure violates bounds or specification."""
    pass


def decode_uac_flags(uac_val: int) -> List[str]:
    """Decode bitmask of User Account Control flags."""
    flags: List[str] = []
    for mask, name in UAC_FLAGS_MAP.items():
        if uac_val & mask:
            flags.append(name)
    return flags


def parse_rpc_sid(data: bytes, offset: int = 0) -> Tuple[str, int]:
    """Parse binary RPC_SID structure with strict bounds validation.

    Format:
      - SubAuthorityCount: 1 byte
      - Revision: 1 byte
      - IdentifierAuthority: 6 bytes (big-endian 48-bit int)
      - SubAuthorities: SubAuthorityCount * 4 bytes (little-endian uint32 each)

    Returns (sid_string, bytes_consumed).
    """
    if len(data) - offset < 8:
        raise PacDecodeError(f"Buffer underflow parsing RPC_SID at offset {offset}")

    sub_auth_count = data[offset]
    revision = data[offset + 1]
    id_auth = int.from_bytes(data[offset + 2 : offset + 8], byteorder="big")

    total_len = 8 + (sub_auth_count * 4)
    if len(data) - offset < total_len:
        raise PacDecodeError(
            f"Buffer underflow reading {sub_auth_count} subauthorities at offset {offset}"
        )

    sub_authorities: List[int] = []
    for i in range(sub_auth_count):
        sa_offset = offset + 8 + (i * 4)
        (sa,) = struct.unpack_from("<I", data, sa_offset)
        sub_authorities.append(sa)

    sid_parts = [f"S-{revision}-{id_auth}"] + [str(sa) for sa in sub_authorities]
    sid_str = "-".join(sid_parts)
    return sid_str, total_len


def parse_windows_sid(data: bytes, offset: int = 0) -> Tuple[str, int]:
    """Parse standard Windows binary SID (MS-DTYP 2.4.2) with strict bounds validation.

    Format:
      - Revision: 1 byte
      - SubAuthorityCount: 1 byte
      - IdentifierAuthority: 6 bytes (big-endian 48-bit int)
      - SubAuthorities: SubAuthorityCount * 4 bytes (little-endian uint32 each)

    Returns (sid_string, bytes_consumed).
    """
    if len(data) - offset < 8:
        raise PacDecodeError(f"Buffer underflow reading SID header at offset {offset}")

    revision = data[offset]
    sub_auth_count = data[offset + 1]
    id_auth = int.from_bytes(data[offset + 2 : offset + 8], byteorder="big")

    total_len = 8 + (sub_auth_count * 4)
    if len(data) - offset < total_len:
        raise PacDecodeError(
            f"Buffer underflow reading {sub_auth_count} subauthorities at offset {offset}"
        )

    sub_authorities: List[int] = []
    for i in range(sub_auth_count):
        sa_offset = offset + 8 + (i * 4)
        (sa,) = struct.unpack_from("<I", data, sa_offset)
        sub_authorities.append(sa)

    sid_parts = [f"S-{revision}-{id_auth}"] + [str(sa) for sa in sub_authorities]
    return "-".join(sid_parts), total_len


def parse_rbcd_security_descriptor(data: bytes) -> Dict[str, Any]:
    """Parse Active Directory msDS-AllowedToActOnBehalfOfOtherIdentity (SECURITY_DESCRIPTOR_RELATIVE).

    Extracts DACL offset, ACE count, and permitted Trustee SIDs configured for RBCD.
    """
    if len(data) < 20:
        raise PacDecodeError(
            f"Buffer underflow reading SECURITY_DESCRIPTOR_RELATIVE header: {len(data)} bytes < 20"
        )

    revision, sbz1, control, off_owner, off_group, off_sacl, off_dacl = struct.unpack_from(
        "<BBHIIII", data, 0
    )

    result: Dict[str, Any] = {
        "revision": revision,
        "control": control,
        "dacl_offset": off_dacl,
        "ace_count": 0,
        "trustee_sids": [],
        "aces": [],
    }

    if off_dacl == 0:
        return result

    if off_dacl + 8 > len(data):
        raise PacDecodeError(f"Buffer underflow reading ACL header at offset {off_dacl}")

    acl_rev, acl_sbz1, acl_size, ace_count, acl_sbz2 = struct.unpack_from(
        "<BBHHH", data, off_dacl
    )

    if off_dacl + acl_size > len(data):
        raise PacDecodeError(
            f"ACL size {acl_size} exceeds remaining buffer length {len(data) - off_dacl}"
        )

    result["ace_count"] = ace_count
    trustee_sids: List[str] = []
    aces_detail: List[Dict[str, Any]] = []

    cur_off = off_dacl + 8
    for _ in range(ace_count):
        if cur_off + 4 > off_dacl + acl_size:
            break
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, cur_off)
        if ace_size < 4 or cur_off + ace_size > off_dacl + acl_size:
            break

        mask = 0
        sid_str = None

        if cur_off + 8 <= off_dacl + acl_size:
            (mask,) = struct.unpack_from("<I", data, cur_off + 4)

        try:
            if ace_type in (0x05, 0x06, 0x0B, 0x0C):
                obj_flags_off = cur_off + 8
                if obj_flags_off + 4 <= cur_off + ace_size:
                    (flags,) = struct.unpack_from("<I", data, obj_flags_off)
                    sid_start = cur_off + 12
                    if flags & 0x01:
                        sid_start += 16
                    if flags & 0x02:
                        sid_start += 16
                    if sid_start < cur_off + ace_size:
                        sid_str, _ = parse_windows_sid(data, sid_start)
            else:
                sid_start = cur_off + 8
                if sid_start < cur_off + ace_size:
                    sid_str, _ = parse_windows_sid(data, sid_start)
        except Exception:
            pass

        ace_info = {
            "type": ace_type,
            "flags": ace_flags,
            "size": ace_size,
            "mask": mask,
            "trustee_sid": sid_str,
        }
        aces_detail.append(ace_info)
        if sid_str and sid_str not in trustee_sids:
            trustee_sids.append(sid_str)

        cur_off += ace_size

    result["trustee_sids"] = trustee_sids
    result["aces"] = aces_detail
    return result


parse_nt_security_descriptor = parse_rbcd_security_descriptor


def parse_rpc_unicode_string(
    data: bytes, str_hdr_offset: int, deferral_offset: int
) -> Tuple[str, int]:
    """Decode NDR RPC_UNICODE_STRING and its deferral with bounds validation.

    Header (8 bytes):
      - Length: uint16 (bytes, excluding null terminator)
      - MaxLength: uint16
      - BufferPtr: uint32

    Deferral:
      - MaxCount: uint32
      - Offset: uint32
      - ActualCount: uint32
      - Characters: ActualCount * 2 bytes (UTF-16LE)
    """
    if len(data) - str_hdr_offset < 8:
        raise PacDecodeError(f"Buffer underflow reading RPC_UNICODE_STRING header at {str_hdr_offset}")

    length, max_length, buffer_ptr = struct.unpack_from("<HHI", data, str_hdr_offset)
    if buffer_ptr == 0 or length == 0:
        return "", deferral_offset

    if deferral_offset % 4 != 0:
        deferral_offset += (4 - (deferral_offset % 4))

    if len(data) - deferral_offset < 12:
        return "", deferral_offset

    max_count, offset_chars, actual_count = struct.unpack_from("<III", data, deferral_offset)
    str_bytes_len = actual_count * 2
    char_start = deferral_offset + 12
    char_end = char_start + str_bytes_len

    if char_end > len(data):
        raise PacDecodeError(f"Buffer underflow reading string characters from {char_start} to {char_end}")

    raw_str_bytes = data[char_start:char_end]
    new_deferral_offset = char_end
    if new_deferral_offset % 4 != 0:
        new_deferral_offset += (4 - (new_deferral_offset % 4))

    try:
        decoded = raw_str_bytes.decode("utf-16le").rstrip("\x00")
    except UnicodeDecodeError:
        decoded = raw_str_bytes.decode("latin-1", errors="replace").rstrip("\x00")

    return decoded, new_deferral_offset


def parse_pac_client_info(data: bytes) -> Dict[str, Any]:
    """Parse PAC_CLIENT_INFO buffer (Type 10)."""
    if len(data) < 10:
        raise PacDecodeError("PAC_CLIENT_INFO buffer underflow (requires at least 10 bytes)")

    client_id = int.from_bytes(data[0:8], byteorder="little")
    name_len = struct.unpack_from("<H", data, 8)[0]
    if len(data) < 10 + name_len:
        raise PacDecodeError("PAC_CLIENT_INFO name length exceeds buffer bounds")

    raw_name = data[10 : 10 + name_len]
    try:
        client_name = raw_name.decode("utf-16le").rstrip("\x00")
    except UnicodeDecodeError:
        client_name = raw_name.decode("latin-1", errors="replace").rstrip("\x00")

    return {
        "client_id": client_id,
        "name_length": name_len,
        "client_name": client_name,
    }


def parse_pac_signature(data: bytes, sig_type_name: str) -> Dict[str, Any]:
    """Parse PAC signature buffer (Type 6 or 7)."""
    if len(data) < 4:
        raise PacDecodeError(f"{sig_type_name} underflow (requires at least 4 bytes)")

    (sig_type,) = struct.unpack_from("<I", data, 0)
    sig_data = data[4:]
    return {
        "signature_type": sig_type,
        "signature_hex": sig_data.hex(),
        "signature_len": len(sig_data),
    }


def parse_pac_logon_info(data: bytes) -> Dict[str, Any]:
    """Decode PAC_LOGON_INFO buffer with bounded NDR parsing.

    Parses KERB_VALIDATION_INFO structure:
    - User RID and Primary Group RID
    - Domain SID
    - Group RIDs and computed Group SIDs
    - High privilege flags (Domain Admins RID 512, Enterprise Admins RID 519)
    - User Account Control (UAC) flags
    """
    if len(data) < 32:
        raise PacDecodeError("PAC_LOGON_INFO buffer underflow (less than 32 bytes)")

    offset = 0
    # Check for RPC Type Serialization Version 1 Header
    if len(data) >= 16 and data[0:2] == b"\x01\x10":
        offset = 16

    # Optional referent ID pointer (4 bytes)
    if offset + 4 <= len(data):
        (ref_ptr,) = struct.unpack_from("<I", data, offset)
        if ref_ptr != 0:
            offset += 4

    struct_start = offset
    min_fixed_hdr = 172
    if len(data) - struct_start < min_fixed_hdr:
        raise PacDecodeError(
            f"PAC_LOGON_INFO fixed header truncated ({len(data) - struct_start} < {min_fixed_hdr} bytes)"
        )

    # Offsets relative to struct_start:
    # 48..56: EffectiveName (RPC_UNICODE_STRING)
    # 56..64: FullName (RPC_UNICODE_STRING)
    # 96..98: LogonCount (u16)
    # 98..100: BadPasswordCount (u16)
    # 100..104: UserId (u32)
    # 104..108: PrimaryGroupId (u32)
    # 108..112: GroupCount (u32)
    # 112..116: GroupIdsPtr (u32)
    # 116..120: UserAccountControl (u32)
    # 148..152: ResourceGroupDomainSidPtr (u32)
    # 152..156: ResourceGroupCount (u32)
    # 156..160: ResourceGroupIdsPtr (u32)
    # 160..164: LogonDomainIdPtr (u32)
    # 164..172: LogonDomainName (RPC_UNICODE_STRING)

    eff_name_hdr = struct_start + 48
    full_name_hdr = struct_start + 56
    user_id_offset = struct_start + 100
    prim_group_offset = struct_start + 104
    group_count_offset = struct_start + 108
    group_ids_ptr_offset = struct_start + 112
    uac_offset = struct_start + 116
    domain_sid_ptr_offset = struct_start + 160
    domain_name_hdr = struct_start + 164

    (user_rid,) = struct.unpack_from("<I", data, user_id_offset)
    (primary_group_rid,) = struct.unpack_from("<I", data, prim_group_offset)
    (group_count,) = struct.unpack_from("<I", data, group_count_offset)
    (group_ids_ptr,) = struct.unpack_from("<I", data, group_ids_ptr_offset)
    (uac_raw,) = struct.unpack_from("<I", data, uac_offset)
    (domain_sid_ptr,) = struct.unpack_from("<I", data, domain_sid_ptr_offset)

    # Deferral parsing begins after fixed header
    # Standard KERB_VALIDATION_INFO size before pointees is typically ~220-256 bytes
    # We locate the deferral area dynamically or scan for Domain SID and groups
    deferral_start = struct_start + min_fixed_hdr
    # Align to 4 bytes
    if deferral_start % 4 != 0:
        deferral_start += (4 - (deferral_start % 4))

    curr_def = deferral_start
    effective_name = ""
    full_name = ""
    domain_name = ""

    # Parse string deferrals if in bounds
    if curr_def < len(data):
        try:
            effective_name, curr_def = parse_rpc_unicode_string(data, eff_name_hdr, curr_def)
            full_name, curr_def = parse_rpc_unicode_string(data, full_name_hdr, curr_def)
        except Exception:
            pass

    # Extract Group Memberships
    # In NDR, GroupIds pointee is: Count (uint32), then Count * (RID: u32, Attr: u32)
    group_rids: List[int] = []
    group_details: List[Dict[str, Any]] = []

    # If group_ids_ptr is set and group_count > 0, locate group array
    if group_ids_ptr != 0 and 0 < group_count <= 2048:
        # Search for group count marker in remaining buffer
        found_group_offset = None
        for probe in range(deferral_start, len(data) - 4, 4):
            val = struct.unpack_from("<I", data, probe)[0]
            if val == group_count:
                # Check if enough bytes remain for group_count * 8
                needed = probe + 4 + (group_count * 8)
                if needed <= len(data):
                    found_group_offset = probe + 4
                    break

        if found_group_offset is not None:
            for g_idx in range(group_count):
                g_pos = found_group_offset + (g_idx * 8)
                rid, attr = struct.unpack_from("<II", data, g_pos)
                group_rids.append(rid)
                group_details.append({
                    "rid": rid,
                    "attributes": attr,
                    "name": WELL_KNOWN_RIDS.get(rid, f"Group RID {rid}"),
                    "is_critical": rid in (DOMAIN_ADMINS_RID, ENTERPRISE_ADMINS_RID, SCHEMA_ADMINS_RID, BUILTIN_ADMINISTRATORS_RID),
                })

    # Extract Domain SID
    # Search for RPC_SID marker in data:
    # Revision=1, SubAuthCount between 1 and 8, Authority=5 (NT Authority: 00 00 00 00 00 05)
    domain_sid = "S-1-5-21-UNKNOWN"
    for probe in range(struct_start, len(data) - 8):
        # Look for sub_auth_count and revision 1 followed by authority 5
        sub_cnt = data[probe]
        rev = data[probe + 1]
        auth_bytes = data[probe + 2 : probe + 8]
        if rev == 1 and 3 <= sub_cnt <= 6 and auth_bytes == b"\x00\x00\x00\x00\x00\x05":
            try:
                cand_sid, _ = parse_rpc_sid(data, probe)
                if "S-1-5-21-" in cand_sid:
                    domain_sid = cand_sid
                    break
            except Exception:
                continue

    # Compute full SIDs
    user_sid = f"{domain_sid}-{user_rid}"
    primary_group_sid = f"{domain_sid}-{primary_group_rid}"

    group_sids: List[str] = []
    for rid in group_rids:
        group_sids.append(f"{domain_sid}-{rid}")

    is_domain_admin = DOMAIN_ADMINS_RID in group_rids or any(
        s.endswith(f"-{DOMAIN_ADMINS_RID}") for s in group_sids
    )
    is_enterprise_admin = ENTERPRISE_ADMINS_RID in group_rids or any(
        s.endswith(f"-{ENTERPRISE_ADMINS_RID}") for s in group_sids
    )
    is_schema_admin = SCHEMA_ADMINS_RID in group_rids or any(
        s.endswith(f"-{SCHEMA_ADMINS_RID}") for s in group_sids
    )

    uac_flags = decode_uac_flags(uac_raw)
    unconstrained_delegation = "TRUSTED_FOR_DELEGATION" in uac_flags
    constrained_delegation = "TRUSTED_TO_AUTH_FOR_DELEGATION" in uac_flags

    return {
        "user_name": effective_name or "Unknown",
        "full_name": full_name,
        "domain_sid": domain_sid,
        "user_rid": user_rid,
        "user_sid": user_sid,
        "primary_group_rid": primary_group_rid,
        "primary_group_sid": primary_group_sid,
        "group_count": len(group_rids),
        "group_rids": group_rids,
        "group_sids": group_sids,
        "group_details": group_details,
        "is_domain_admin": is_domain_admin,
        "is_enterprise_admin": is_enterprise_admin,
        "is_schema_admin": is_schema_admin,
        "uac_raw": uac_raw,
        "uac_flags": uac_flags,
        "unconstrained_delegation": unconstrained_delegation,
        "constrained_delegation": constrained_delegation,
    }


def parse_pac_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse binary PAC stream with strict bounded decoding (PACTYPE)."""
    if len(raw_bytes) < 8:
        raise PacDecodeError(f"PAC buffer underflow: got {len(raw_bytes)} bytes, require at least 8")

    c_buffers, version = struct.unpack_from("<II", raw_bytes, 0)
    if version != 0:
        raise PacDecodeError(f"Invalid PAC version: {version} (expected 0)")

    if c_buffers > 64:
        raise PacDecodeError(f"PAC buffer count {c_buffers} exceeds safety limit of 64")

    header_size = 8 + (c_buffers * 16)
    if len(raw_bytes) < header_size:
        raise PacDecodeError(
            f"Truncated PAC header: require {header_size} bytes for {c_buffers} buffers, got {len(raw_bytes)}"
        )

    buffers_meta: List[Dict[str, Any]] = []
    logon_info: Optional[Dict[str, Any]] = None
    client_info: Optional[Dict[str, Any]] = None
    server_checksum: Optional[Dict[str, Any]] = None
    privsvr_checksum: Optional[Dict[str, Any]] = None
    requestor_sid: Optional[str] = None

    for i in range(c_buffers):
        pos = 8 + (i * 16)
        ul_type, cb_size, offset = struct.unpack_from("<IIQ", raw_bytes, pos)

        if offset + cb_size > len(raw_bytes):
            raise PacDecodeError(
                f"PAC buffer {i} (type {ul_type}) out of bounds: offset {offset} + size {cb_size} > {len(raw_bytes)}"
            )

        buf_data = raw_bytes[offset : offset + cb_size]
        buf_entry = {
            "index": i,
            "type_id": ul_type,
            "type_name": BUFFER_TYPE_NAMES.get(ul_type, f"TYPE_{ul_type}"),
            "size": cb_size,
            "offset": offset,
        }
        buffers_meta.append(buf_entry)

        if ul_type == PAC_LOGON_INFO:
            try:
                logon_info = parse_pac_logon_info(buf_data)
            except Exception as exc:
                logon_info = {"error": str(exc)}
        elif ul_type == PAC_CLIENT_INFO:
            try:
                client_info = parse_pac_client_info(buf_data)
            except Exception as exc:
                client_info = {"error": str(exc)}
        elif ul_type == PAC_SERVER_CHECKSUM:
            try:
                server_checksum = parse_pac_signature(buf_data, "SERVER_CHECKSUM")
            except Exception as exc:
                server_checksum = {"error": str(exc)}
        elif ul_type == PAC_PRIVSVR_CHECKSUM:
            try:
                privsvr_checksum = parse_pac_signature(buf_data, "PRIVSVR_CHECKSUM")
            except Exception as exc:
                privsvr_checksum = {"error": str(exc)}
        elif ul_type == PAC_REQUESTOR_SID:
            try:
                requestor_sid, _ = parse_rpc_sid(buf_data, 0)
            except Exception as exc:
                requestor_sid = f"Error: {exc}"

    return {
        "status": "SUCCESS",
        "buffer_count": c_buffers,
        "version": version,
        "buffers": buffers_meta,
        "logon_info": logon_info,
        "client_info": client_info,
        "server_checksum": server_checksum,
        "privsvr_checksum": privsvr_checksum,
        "requestor_sid": requestor_sid,
    }


def extract_pac_from_authorization_data(authdata_bytes: bytes) -> bytes:
    """Extract AD-WIN2K-PAC (ad-type 128) from RFC 4120 AuthorizationData stream."""
    # Look for PAC header signature inside authorization data
    # PAC header starts with cBuffers (1..32) and Version 0: [cBuffers u32, 0x00000000]
    for probe in range(0, len(authdata_bytes) - 8):
        c_bufs, ver = struct.unpack_from("<II", authdata_bytes, probe)
        if 1 <= c_bufs <= 16 and ver == 0:
            hdr_len = 8 + (c_bufs * 16)
            if probe + hdr_len <= len(authdata_bytes):
                # Verify first buffer offset
                first_type, first_size, first_offset = struct.unpack_from(
                    "<IIQ", authdata_bytes, probe + 8
                )
                if first_offset >= hdr_len and probe + first_offset + first_size <= len(authdata_bytes):
                    return authdata_bytes[probe:]
    return authdata_bytes


def parse_pac(source: str) -> Dict[str, Any]:
    """Parse PAC from file path, hex string, base64 string, or raw bytes."""
    data: Optional[bytes] = None

    if os.path.isfile(source):
        with open(source, "rb") as f:
            data = f.read()
    else:
        # Try hex decode
        clean_src = source.strip()
        try:
            data = bytes.fromhex(clean_src)
        except ValueError:
            # Try base64 decode
            try:
                data = base64.b64decode(clean_src)
            except Exception:
                raise PacDecodeError(f"Unable to read PAC from path, hex, or base64: {source[:32]}...")

    pac_bytes = extract_pac_from_authorization_data(data)
    return parse_pac_bytes(pac_bytes)


def format_pac_report_terminal(report: Dict[str, Any]) -> str:
    """Format parsed PAC report into clean terminal tree structure."""
    lines: List[str] = []
    lines.extend(render_card_header(
        "TANUKI MS-PAC PRIVILEGE DECODER",
        f"RFC 4120 · [MS-PAC] Bounded NDR Decoder · {report.get('buffer_count', 0)} Buffers",
    ))

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")
    v_line = "│ " if use_uni else "| "

    logon = report.get("logon_info") or {}
    client = report.get("client_info") or {}

    user_name = logon.get("user_name") or client.get("client_name") or "Unknown"
    user_sid = logon.get("user_sid", "N/A")
    prim_sid = logon.get("primary_group_sid", "N/A")
    is_da = logon.get("is_domain_admin", False)
    is_ea = logon.get("is_enterprise_admin", False)

    priv_status = "CRITICAL / DOMAIN ADMIN" if (is_da or is_ea) else "STANDARD USER"
    lines.append(f"[+] Account Identity : {user_name}")
    lines.append(f"    {t_branch} User SID       : {user_sid}")
    lines.append(f"    {t_branch} Primary Group  : {prim_sid}")
    lines.append(f"    {t_branch} Privilege Tier : {priv_status}")

    groups = logon.get("group_details", [])
    if groups:
        lines.append(f"    {t_branch} Group Memberships ({len(groups)} groups):")
        for idx, g in enumerate(groups):
            is_last = idx == len(groups) - 1
            branch = l_branch if is_last else t_branch
            crit_flag = " [CRITICAL]" if g.get("is_critical") else ""
            lines.append(f"    {v_line}  {branch} RID {g['rid']} ({g['name']}){crit_flag}")
    else:
        lines.append(f"    {t_branch} Group Memberships : None parsed")

    uac_flags = logon.get("uac_flags", [])
    uac_str = ", ".join(uac_flags) if uac_flags else "NORMAL_ACCOUNT"
    lines.append(f"    {l_branch} UAC Flags      : {uac_str}")

    if logon.get("unconstrained_delegation"):
        lines.append("\n[!] OPSEC RISK DETECTED:")
        lines.append("    TRUSTED_FOR_DELEGATION flag is set (Unconstrained Delegation).")
        lines.append("    Kerberos TGTs forwarded to this host can be harvested from memory.")

    return "\n".join(lines)
