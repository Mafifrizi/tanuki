"""Unit tests for MS-PAC Bounded NDR Binary Decoder (tanuki pac)."""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.pac import (
    DOMAIN_ADMINS_RID,
    ENTERPRISE_ADMINS_RID,
    PAC_CLIENT_INFO,
    PAC_LOGON_INFO,
    PacDecodeError,
    decode_uac_flags,
    format_pac_report_terminal,
    parse_pac,
    parse_pac_bytes,
    parse_rpc_sid,
)


def build_synthetic_pac_bytes(
    user_name: str = "Administrator",
    domain_name: str = "CORP",
    is_da: bool = True,
    unconstrained: bool = False,
) -> bytes:
    """Build a valid binary PAC payload containing PAC_LOGON_INFO and PAC_CLIENT_INFO."""
    client_name_bytes = user_name.encode("utf-16le")
    client_buf = struct.pack("<QH", 0x01D9A00000000000, len(client_name_bytes)) + client_name_bytes

    c_buffers = 2
    version = 0

    offset_client = 40
    size_client = len(client_buf)

    offset_logon = (offset_client + size_client + 7) & ~7

    # Construct KERB_VALIDATION_INFO payload (data[0:4] = 0 so struct_start = 0)
    logon_buf = bytearray(400)

    # EffectiveName RPC_UNICODE_STRING at offset 48
    u_bytes = user_name.encode("utf-16le")
    struct.pack_into("<HHI", logon_buf, 48, len(u_bytes), len(u_bytes) + 2, 0x00020004)

    # UserId at offset 100
    struct.pack_into("<I", logon_buf, 100, 500)
    # PrimaryGroupId at offset 104
    struct.pack_into("<I", logon_buf, 104, 513)

    groups = [513]
    if is_da:
        groups.append(DOMAIN_ADMINS_RID)

    # GroupCount at offset 108
    struct.pack_into("<I", logon_buf, 108, len(groups))
    # GroupIdsPtr at offset 112
    struct.pack_into("<I", logon_buf, 112, 0x00020008)

    # UserAccountControl at offset 116
    uac = 0x0200  # NORMAL_ACCOUNT
    if unconstrained:
        uac |= 0x80000  # TRUSTED_FOR_DELEGATION
    struct.pack_into("<I", logon_buf, 116, uac)

    # DomainSidPtr at offset 160
    struct.pack_into("<I", logon_buf, 160, 0x00020010)

    # Deferral starts after min_fixed_hdr (172)
    # 1. EffectiveName deferral at offset 176:
    # MaxCount, Offset, ActualCount, Characters
    char_count = len(user_name)
    struct.pack_into("<III", logon_buf, 176, char_count, 0, char_count)
    logon_buf[188 : 188 + len(u_bytes)] = u_bytes

    # Align to 4 bytes:
    group_def_pos = 188 + len(u_bytes)
    if group_def_pos % 4 != 0:
        group_def_pos += (4 - (group_def_pos % 4))

    # 2. Groups array deferral:
    # Count (uint32) followed by (RID uint32, Attributes uint32) pairs
    struct.pack_into("<I", logon_buf, group_def_pos, len(groups))
    for idx, rid in enumerate(groups):
        struct.pack_into("<II", logon_buf, group_def_pos + 4 + (idx * 8), rid, 0x07)

    sid_def_pos = group_def_pos + 4 + (len(groups) * 8)
    if sid_def_pos % 4 != 0:
        sid_def_pos += (4 - (sid_def_pos % 4))

    # 3. Domain SID RPC_SID: S-1-5-21-1111-2222-3333
    sid_bytes = bytes([4, 1, 0, 0, 0, 0, 0, 5]) + struct.pack("<IIII", 21, 1111, 2222, 3333)
    logon_buf[sid_def_pos : sid_def_pos + len(sid_bytes)] = sid_bytes

    size_logon = sid_def_pos + len(sid_bytes)
    if size_logon % 8 != 0:
        size_logon += (8 - (size_logon % 8))

    hdr = struct.pack("<II", c_buffers, version)
    desc1 = struct.pack("<IIQ", PAC_CLIENT_INFO, size_client, offset_client)
    desc2 = struct.pack("<IIQ", PAC_LOGON_INFO, size_logon, offset_logon)

    pac = bytearray()
    pac.extend(hdr)
    pac.extend(desc1)
    pac.extend(desc2)
    if len(pac) < offset_client:
        pac.extend(b"\x00" * (offset_client - len(pac)))
    pac.extend(client_buf)
    if len(pac) < offset_logon:
        pac.extend(b"\x00" * (offset_logon - len(pac)))
    pac.extend(logon_buf[:size_logon])

    return bytes(pac)


class TestPacDecoder(unittest.TestCase):
    def test_decode_uac_flags(self):
        flags = decode_uac_flags(0x80000 | 0x0200)
        self.assertIn("TRUSTED_FOR_DELEGATION", flags)
        self.assertIn("NORMAL_ACCOUNT", flags)
        self.assertEqual(len(flags), 2)

    def test_parse_rpc_sid_valid(self):
        # S-1-5-32-544 (Builtin Administrators)
        data = bytes([2, 1, 0, 0, 0, 0, 0, 5]) + struct.pack("<II", 32, 544)
        sid, consumed = parse_rpc_sid(data, 0)
        self.assertEqual(sid, "S-1-5-32-544")
        self.assertEqual(consumed, 16)

    def test_parse_rpc_sid_truncated_fails(self):
        with self.assertRaises(PacDecodeError):
            parse_rpc_sid(b"\x04\x01\x00", 0)

    def test_parse_pac_bytes_domain_admin(self):
        pac_data = build_synthetic_pac_bytes(user_name="adm_ops", is_da=True, unconstrained=True)
        report = parse_pac_bytes(pac_data)
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["buffer_count"], 2)
        logon = report["logon_info"]
        self.assertIsNotNone(logon)
        self.assertTrue(logon["is_domain_admin"])
        self.assertTrue(logon["unconstrained_delegation"])
        self.assertIn(DOMAIN_ADMINS_RID, logon["group_rids"])
        self.assertIn("TRUSTED_FOR_DELEGATION", logon["uac_flags"])

    def test_parse_pac_bytes_standard_user(self):
        pac_data = build_synthetic_pac_bytes(user_name="regular_user", is_da=False, unconstrained=False)
        report = parse_pac_bytes(pac_data)
        logon = report["logon_info"]
        self.assertFalse(logon["is_domain_admin"])
        self.assertFalse(logon["unconstrained_delegation"])

    def test_parse_pac_hex_string(self):
        pac_data = build_synthetic_pac_bytes(user_name="hex_user", is_da=False)
        hex_str = pac_data.hex()
        report = parse_pac(hex_str)
        self.assertEqual(report["status"], "SUCCESS")

    def test_parse_pac_file_input(self):
        pac_data = build_synthetic_pac_bytes(user_name="file_user", is_da=True)
        with tempfile.NamedTemporaryFile(suffix=".pac", delete=False) as f:
            f.write(pac_data)
            tmp_path = f.name
        try:
            report = parse_pac(tmp_path)
            self.assertEqual(report["status"], "SUCCESS")
            logon = report["logon_info"]
            self.assertTrue(logon["is_domain_admin"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_pac_corrupt_data(self):
        with self.assertRaises(PacDecodeError):
            parse_pac_bytes(b"\x00\x00\x00")

    def test_format_pac_report_terminal(self):
        pac_data = build_synthetic_pac_bytes(user_name="sec_admin", is_da=True, unconstrained=True)
        report = parse_pac_bytes(pac_data)
        term_out = format_pac_report_terminal(report)
        self.assertIn("TANUKI MS-PAC PRIVILEGE DECODER", term_out)
        self.assertIn("CRITICAL / DOMAIN ADMIN", term_out)
        self.assertIn("OPSEC RISK DETECTED", term_out)

    def test_parse_pac_symlink_rejected(self):
        if not hasattr(os, "symlink"):
            return
        pac_data = build_synthetic_pac_bytes(user_name="sym_user")
        with tempfile.NamedTemporaryFile(suffix=".pac", delete=False) as f:
            f.write(pac_data)
            tmp_path = f.name
        symlink_path = tmp_path + ".sym"
        try:
            try:
                os.symlink(tmp_path, symlink_path)
            except OSError:
                return
            with self.assertRaises(PacDecodeError):
                parse_pac(symlink_path)
        finally:
            if os.path.exists(symlink_path):
                try:
                    os.unlink(symlink_path)
                except OSError:
                    pass
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def test_parse_pac_attributes_info(self):
        from tanuki.pac import parse_pac_attributes_info
        # PAC_WAS_REQUESTED (0x01) and PAC_WAS_GIVEN_IMPLICITLY (0x02)
        raw_attr = struct.pack("<II", 2, 0x00000003)
        res = parse_pac_attributes_info(raw_attr)
        self.assertEqual(res["flags_length"], 2)
        self.assertTrue(res["pac_was_requested"])
        self.assertTrue(res["pac_was_given_implicitly"])

        raw_attr_req_only = struct.pack("<II", 2, 0x00000001)
        res_req = parse_pac_attributes_info(raw_attr_req_only)
        self.assertTrue(res_req["pac_was_requested"])
        self.assertFalse(res_req["pac_was_given_implicitly"])

        with self.assertRaises(PacDecodeError):
            parse_pac_attributes_info(b"\x00\x00")

    def test_parse_pac_signatures_and_guid(self):
        from tanuki.pac import parse_pac_signature, parse_pac_guid
        # Type -138 / 4294967158 (HMAC-SHA1-96-AES256)
        sig_bytes = struct.pack("<I", 4294967158) + b"\x01" * 12
        sig_info = parse_pac_signature(sig_bytes, "SERVER_CHECKSUM")
        self.assertEqual(sig_info["signature_type_signed"], -138)
        self.assertEqual(sig_info["algorithm"], "KERB_CHECKSUM_HMAC_SHA1_96_AES256")

        guid_bytes = bytes.fromhex("11223344556677889900aabbccddeeff")
        guid_str = parse_pac_guid(guid_bytes)
        self.assertEqual(guid_str, "44332211-6655-8877-9900-aabbccddeeff")


if __name__ == "__main__":
    unittest.main()
