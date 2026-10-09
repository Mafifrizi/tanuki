"""RFC 4120 Binary Keytab Parser (Keytab v2)."""

import io
import os
import struct
from typing import Any, Dict, List

MAX_ENTRY_SIZE = 1048576  # 1MB max per keytab entry
MIN_INT32 = -2147483648   # Prevent abs() overflow on 32-bit signed ints

ENCTYPE_MAP = {
    1: "des-cbc-crc",
    3: "des-cbc-md5",
    16: "des3-cbc-sha1-kd",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    23: "rc4-hmac",
}

MAX_COMPONENTS = 256


def parse_keytab_stream(stream: io.BytesIO) -> List[Dict[str, Any]]:
    """Parse binary Keytab v2 stream into structured entry dictionaries."""
    header = stream.read(2)
    if len(header) < 2 or header[0] != 0x05 or header[1] != 0x02:
        raise ValueError("Invalid keytab format (expected Keytab v2 signature 0x0502)")

    entries: List[Dict[str, Any]] = []

    while True:
        size_bytes = stream.read(4)
        if not size_bytes:
            break
        if len(size_bytes) < 4:
            raise ValueError("Unexpected end of keytab stream (truncated entry size)")

        (entry_size,) = struct.unpack(">i", size_bytes)
        if entry_size == 0:
            continue

        if entry_size == MIN_INT32:
            raise ValueError("Malformed keytab entry: integer overflow in entry size (MIN_INT32)")

        if entry_size < 0:
            skip_len = abs(entry_size)
            if skip_len > MAX_ENTRY_SIZE:
                raise ValueError(f"Keytab hole skip size exceeds safety limit ({skip_len} bytes)")
            skipped = stream.read(skip_len)
            if len(skipped) < skip_len:
                raise ValueError("Unexpected end of keytab stream in deleted entry hole")
            continue

        if entry_size > MAX_ENTRY_SIZE:
            raise ValueError(
                f"Malformed keytab entry: entry size exceeds maximum limit ({entry_size} > {MAX_ENTRY_SIZE})"
            )

        raw_entry = stream.read(entry_size)
        if len(raw_entry) < entry_size:
            raise ValueError(
                f"Unexpected end of keytab stream: expected {entry_size} bytes, got {len(raw_entry)}"
            )

        entry_io = io.BytesIO(raw_entry)

        comp_count_bytes = entry_io.read(2)
        if len(comp_count_bytes) < 2:
            raise ValueError("Malformed keytab entry: missing component count")
        (num_components,) = struct.unpack(">h", comp_count_bytes)
        if num_components < 0:
            raise ValueError("Malformed keytab entry: negative component count")
        if num_components > MAX_COMPONENTS:
            raise ValueError(
                f"Malformed keytab entry: excessive component count ({num_components} > {MAX_COMPONENTS})"
            )

        realm_len_bytes = entry_io.read(2)
        if len(realm_len_bytes) < 2:
            raise ValueError("Malformed keytab entry: missing realm length")
        (realm_len,) = struct.unpack(">H", realm_len_bytes)
        realm_bytes = entry_io.read(realm_len)
        if len(realm_bytes) < realm_len:
            raise ValueError("Malformed keytab entry: realm bounds exceeded")
        realm = realm_bytes.decode("utf-8", errors="replace")

        components: List[str] = []
        for _ in range(num_components):
            comp_len_bytes = entry_io.read(2)
            if len(comp_len_bytes) < 2:
                raise ValueError("Malformed keytab entry: missing component length")
            (comp_len,) = struct.unpack(">H", comp_len_bytes)
            comp_bytes = entry_io.read(comp_len)
            if len(comp_bytes) < comp_len:
                raise ValueError("Malformed keytab entry: component bounds exceeded")
            comp = comp_bytes.decode("utf-8", errors="replace")
            components.append(comp)

        if components:
            principal = f"{'/'.join(components)}@{realm}"
        else:
            principal = f"@{realm}"

        meta_bytes = entry_io.read(4 + 4 + 1 + 2 + 2)
        if len(meta_bytes) < 13:
            raise ValueError("Malformed keytab entry: missing key metadata fields")
        (name_type, timestamp, vno8, keytype, key_len) = struct.unpack(
            ">IIBhH", meta_bytes
        )

        key_bytes = entry_io.read(key_len)
        if len(key_bytes) < key_len:
            raise ValueError("Malformed keytab entry: key data bounds exceeded")

        vno = vno8
        remaining = entry_size - entry_io.tell()
        if remaining >= 4:
            (vno32,) = struct.unpack(">I", entry_io.read(4))
            if vno32 != 0:
                vno = vno32
        elif remaining > 0:
            raise ValueError("Malformed keytab entry: incomplete 32-bit KVNO field")

        entries.append(
            {
                "principal": principal,
                "realm": realm,
                "components": components,
                "vno": vno,
                "keytype": keytype,
                "enctype_name": ENCTYPE_MAP.get(keytype, f"unknown({keytype})"),
                "key_len": key_len,
                "key_hex": key_bytes.hex(),
                "timestamp": timestamp,
            }
        )

    return entries


def parse_keytab_bytes(data: bytes) -> List[Dict[str, Any]]:
    """Parse raw bytes as Keytab v2 binary format."""
    return parse_keytab_stream(io.BytesIO(data))


def parse_keytab_file(filepath: str) -> List[Dict[str, Any]]:
    """Read file and parse Keytab v2 entries."""
    if os.path.islink(filepath):
        raise ValueError(f"Refusing to read symbolic link: {filepath}")
    with open(filepath, "rb") as f:
        return parse_keytab_stream(io.BytesIO(f.read(10485760)))
