"""Active Directory msDS-KeyCredentialLink Binary Parser (MS-ADTS 2.2.20).

Provides pure standard library parsing of Shadow Credentials and Windows Hello
for Business (WHfB) Key Credential structures in Active Directory.
Supports Version 1.0 (0x00000100) and Version 2.0 (0x00000200), RSA, and ECC.
"""

import datetime
import hashlib
import os
import struct
from typing import Any, Dict, List, Optional, Union

KEY_USAGE_MAP = {
    0x01: "NGC",
    0x02: "FIDO",
    0x03: "FEK",
}

KEY_SOURCE_MAP = {
    0x00: "AD",
    0x01: "AzureAD",
}

IDENTIFIER_NAMES = {
    0x01: "KEY_ID",
    0x02: "KEY_HASH",
    0x03: "KEY_MATERIAL",
    0x04: "KEY_USAGE",
    0x05: "KEY_SOURCE",
    0x06: "DEVICE_ID",
    0x07: "CUSTOM_KEY_INFORMATION",
    0x08: "KEY_APPROXIMATE_LAST_LOGON_TIME",
    0x09: "KEY_CREATION_TIME",
}


class ShadowCredentialDecodeError(Exception):
    """Raised when msDS-KeyCredentialLink binary structure violates bounds or specification."""
    pass


def parse_filetime_to_iso(ft_val: int) -> Optional[str]:
    """Convert 64-bit Windows FILETIME (100ns intervals since 1601-01-01) to ISO-8601 UTC.
    
    Uses safe datetime.timedelta arithmetic to prevent Windows C-runtime crashes
    on timestamps prior to 1970.
    """
    if ft_val <= 0:
        return None
    try:
        base_epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        delta_microseconds = ft_val // 10
        dt = base_epoch + datetime.timedelta(microseconds=delta_microseconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None


def parse_cng_public_key(data: bytes) -> Dict[str, Any]:
    """Parse CNG BCRYPT_RSAKEY_BLOB or BCRYPT_ECCKEY_BLOB structures."""
    if len(data) < 8:
        raise ShadowCredentialDecodeError(f"Truncated CNG public key header: {len(data)} < 8 bytes")

    magic = data[0:4]
    if magic in (b"RSA1", b"RSA2"):
        if len(data) < 24:
            raise ShadowCredentialDecodeError(f"Truncated BCRYPT_RSAKEY_BLOB: {len(data)} < 24 bytes")
        _, bit_len, cb_pub_exp, cb_mod, _, _ = struct.unpack_from("<IIIIII", data, 0)
        offset = 24
        if offset + cb_pub_exp + cb_mod > len(data):
            raise ShadowCredentialDecodeError("Buffer underflow reading RSA public exponent or modulus")
        pub_exp = int.from_bytes(data[offset : offset + cb_pub_exp], byteorder="big")
        offset += cb_pub_exp
        modulus_bytes = data[offset : offset + cb_mod]
        return {
            "key_type": "RSA",
            "magic": magic.decode("latin-1"),
            "bit_length": bit_len,
            "public_exponent": pub_exp,
            "modulus_length": cb_mod,
            "modulus_hex": modulus_bytes.hex(),
        }
    elif magic in (b"ECS1", b"ECS3", b"ECS5", b"ECK1", b"ECK2", b"ECK3", b"ECK4", b"ECK5", b"ECK6"):
        _, cb_key = struct.unpack_from("<II", data, 0)
        offset = 8
        if offset + (2 * cb_key) > len(data):
            raise ShadowCredentialDecodeError("Buffer underflow reading ECC coordinates")
        x_bytes = data[offset : offset + cb_key]
        y_bytes = data[offset + cb_key : offset + (2 * cb_key)]
        
        curve_name = "P-256"
        if magic in (b"ECS3", b"ECK3", b"ECK4"):
            curve_name = "P-384"
        elif magic in (b"ECS5", b"ECK5", b"ECK6"):
            curve_name = "P-521"
            
        key_algo = "ECDSA"
        if magic in (b"ECK2", b"ECK4", b"ECK6"):
            key_algo = "ECDH"
            
        return {
            "key_type": "ECC",
            "algorithm": key_algo,
            "magic": magic.decode("latin-1"),
            "curve": curve_name,
            "coordinate_length": cb_key,
            "x_hex": x_bytes.hex(),
            "y_hex": y_bytes.hex(),
        }
    else:
        return {
            "key_type": "UNKNOWN",
            "magic_hex": magic.hex(),
            "raw_hex": data.hex(),
        }


def parse_guid_bytes(data: bytes) -> str:
    """Parse 16-byte Windows GUID into standard UUID string format."""
    if len(data) < 16:
        raise ShadowCredentialDecodeError("Buffer underflow reading GUID")
    d1, d2, d3 = struct.unpack_from("<IHH", data, 0)
    d4 = data[8:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[:2].hex()}-{d4[2:].hex()}".lower()


def parse_custom_key_information(data: bytes) -> Dict[str, Any]:
    """Parse CustomKeyInformation structure ([MS-ADTS] 2.2.20.5)."""
    if len(data) < 2:
        return {"raw_hex": data.hex()}
    version = data[0]
    flags = data[1]
    res: Dict[str, Any] = {
        "version": version,
        "flags_raw": flags,
        "attestation": bool(flags & 0x01),
        "mfa_not_used": bool(flags & 0x02),
    }
    if len(data) > 2:
        res["extended_hex"] = data[2:].hex()
    return res


def parse_key_credential_link(raw_input: Union[bytes, bytearray, str]) -> Dict[str, Any]:
    """Dissect msDS-KeyCredentialLink binary blob or DN-Binary string ([MS-ADTS] 2.2.20)."""
    target_dn = ""
    raw_bytes = b""
    if isinstance(raw_input, str):
        clean = raw_input.strip()
        if len(clean) < 260 and os.path.isfile(clean):
            with open(clean, "rb") as f:
                raw_bytes = f.read()
        elif clean.startswith(("B:", "b:")):
            parts = clean.split(":", 3)
            if len(parts) >= 4:
                char_count = int(parts[1])
                target_dn = parts[3]
                raw_bytes = bytes.fromhex(parts[2][:char_count])
            else:
                raise ShadowCredentialDecodeError(f"Malformed DN-Binary string: {clean[:40]}")
        else:
            try:
                raw_bytes = bytes.fromhex(clean)
            except ValueError:
                raise ShadowCredentialDecodeError(f"Invalid hex string input: {clean[:40]}")
    elif isinstance(raw_input, (bytes, bytearray)):
        raw_bytes = bytes(raw_input)
    else:
        raise ShadowCredentialDecodeError(f"Unsupported input type: {type(raw_input)}")

    if len(raw_bytes) < 4:
        raise ShadowCredentialDecodeError(f"Buffer underflow: {len(raw_bytes)} < 4 bytes")

    (version,) = struct.unpack_from("<I", raw_bytes, 0)
    if version not in (0x00000100, 0x00000200):
        raise ShadowCredentialDecodeError(f"Unsupported Key Credential version: 0x{version:08x}")

    offset = 4
    entries: List[Dict[str, Any]] = []
    key_id: Optional[str] = None
    key_hash: Optional[str] = None
    key_usage_name: Optional[str] = None
    key_source_name: Optional[str] = None
    device_id: Optional[str] = None
    creation_time: Optional[str] = None
    last_logon_time: Optional[str] = None
    key_material: Optional[Dict[str, Any]] = None
    custom_key_info: Optional[Dict[str, Any]] = None
    raw_key_material_bytes: Optional[bytes] = None

    while offset < len(raw_bytes):
        if len(raw_bytes) - offset < 3:
            raise ShadowCredentialDecodeError(f"Truncated entry header at offset {offset}")
        length, identifier = struct.unpack_from("<HB", raw_bytes, offset)
        val_start = offset + 3
        val_end = val_start + length
        if val_end > len(raw_bytes):
            raise ShadowCredentialDecodeError(f"Entry value out of bounds: {val_end} > {len(raw_bytes)}")
        val_bytes = raw_bytes[val_start:val_end]
        id_name = IDENTIFIER_NAMES.get(identifier, f"UNKNOWN_0x{identifier:02x}")

        entry_dict: Dict[str, Any] = {
            "identifier": identifier,
            "identifier_name": id_name,
            "length": length,
            "raw_hex": val_bytes.hex(),
        }

        if identifier == 0x01:
            key_id = val_bytes.hex()
            entry_dict["key_id"] = key_id
        elif identifier == 0x02:
            key_hash = val_bytes.hex()
            entry_dict["key_hash"] = key_hash
        elif identifier == 0x03:
            raw_key_material_bytes = val_bytes
            try:
                key_material = parse_cng_public_key(val_bytes)
                entry_dict["public_key"] = key_material
            except Exception as pe:
                entry_dict["public_key_error"] = str(pe)
        elif identifier == 0x04 and length >= 1:
            key_usage_name = KEY_USAGE_MAP.get(val_bytes[0], f"UNKNOWN_0x{val_bytes[0]:02x}")
            entry_dict["key_usage"] = key_usage_name
        elif identifier == 0x05 and length >= 1:
            key_source_name = KEY_SOURCE_MAP.get(val_bytes[0], f"UNKNOWN_0x{val_bytes[0]:02x}")
            entry_dict["key_source"] = key_source_name
        elif identifier == 0x06 and length == 16:
            device_id = parse_guid_bytes(val_bytes)
            entry_dict["device_id"] = device_id
        elif identifier == 0x07:
            custom_key_info = parse_custom_key_information(val_bytes)
            entry_dict["custom_key_information"] = custom_key_info
        elif identifier == 0x08 and length == 8:
            (ft,) = struct.unpack_from("<Q", val_bytes, 0)
            last_logon_time = parse_filetime_to_iso(ft)
            entry_dict["last_logon_time"] = last_logon_time
        elif identifier == 0x09 and length == 8:
            (ft,) = struct.unpack_from("<Q", val_bytes, 0)
            creation_time = parse_filetime_to_iso(ft)
            entry_dict["creation_time"] = creation_time

        entries.append(entry_dict)
        offset = val_end

    # Cryptographic integrity check
    integrity_valid = True
    integrity_issues: List[str] = []
    if key_id and raw_key_material_bytes:
        computed_key_id = hashlib.sha256(raw_key_material_bytes).hexdigest()
        if key_id.lower() != computed_key_id.lower():
            integrity_valid = False
            integrity_issues.append("KeyID does not match SHA-256 of KeyMaterial")

    return {
        "status": "SUCCESS",
        "version": version,
        "version_str": "2.0" if version == 0x00000200 else "1.0",
        "raw_length": len(raw_bytes),
        "target_dn": target_dn,
        "key_id": key_id,
        "key_hash": key_hash,
        "key_usage": key_usage_name,
        "key_source": key_source_name,
        "device_id": device_id,
        "creation_time": creation_time,
        "last_logon_time": last_logon_time,
        "key_material": key_material,
        "custom_key_information": custom_key_info,
        "integrity_valid": integrity_valid,
        "integrity_issues": integrity_issues,
        "entries_count": len(entries),
        "entries": entries,
    }


def format_shadow_report_terminal(report: Dict[str, Any]) -> str:
    """Format parsed Shadow Credential into a clean terminal report."""
    if report.get("status") != "SUCCESS":
        return f"[ERROR] Failed to parse Shadow Credential: {report.get('error')}"

    lines = [
        "[+] Active Directory Shadow Credential ([MS-ADTS] 2.2.20)",
        f"    Structure Version : {report.get('version_str')} (0x{report.get('version', 0):08x})",
        f"    Blob Length       : {report.get('raw_length')} bytes",
    ]
    if report.get("target_dn"):
        lines.append(f"    Target Identity   : {report.get('target_dn')}")
    if report.get("key_id"):
        lines.append(f"    Key ID (SHA-256)  : {report.get('key_id')}")
    if report.get("key_usage"):
        lines.append(f"    Key Usage         : {report.get('key_usage')}")
    if report.get("key_source"):
        lines.append(f"    Key Source        : {report.get('key_source')}")
    if report.get("device_id"):
        lines.append(f"    Device ID (GUID)  : {report.get('device_id')}")
    if report.get("creation_time"):
        lines.append(f"    Creation Time     : {report.get('creation_time')}")
    if report.get("last_logon_time"):
        lines.append(f"    Last Logon Time   : {report.get('last_logon_time')}")

    km = report.get("key_material")
    if km:
        k_type = km.get("key_type", "UNKNOWN")
        if k_type == "RSA":
            lines.append(f"    Public Key Type   : RSA ({km.get('bit_length')} bits, e={km.get('public_exponent')})")
            mod_hex = km.get("modulus_hex", "")
            if len(mod_hex) > 32:
                lines.append(f"    Modulus Preview   : {mod_hex[:32]}... ({km.get('modulus_length')} bytes)")
            else:
                lines.append(f"    Modulus           : {mod_hex}")
        elif k_type == "ECC":
            lines.append(f"    Public Key Type   : {km.get('algorithm', 'ECC')} Curve {km.get('curve')}")
            lines.append(f"    Coordinates (X,Y) : X={km.get('x_hex', '')[:16]}... Y={km.get('y_hex', '')[:16]}...")

    if not report.get("integrity_valid", True):
        lines.append("    [!] Integrity Warning:")
        for issue in report.get("integrity_issues", []):
            lines.append(f"        - {issue}")

    return "\n".join(lines)
