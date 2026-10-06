"""Unit tests for Windows Event ID triage lookups, LDAP BER decoding, RBCD binary descriptor parsing, and FAST config synthesis."""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.config import generate_krb5_conf, write_krb5_conf_file
from tanuki.ldap import (
    BINARY_AD_ATTRIBUTES,
    LDAP_RESP_BIND,
    LDAP_RESP_SEARCH_DONE,
    LDAP_RESP_SEARCH_ENTRY,
    TAG_ENUMERATED,
    TAG_SEQUENCE,
    ber_encode_int,
    ber_encode_sequence,
    ber_encode_string,
    ber_encode_tlv,
    format_ldap_report_terminal,
    parse_ldap_response_stream,
)
from tanuki.pac import (
    PacDecodeError,
    parse_nt_security_descriptor,
    parse_rbcd_security_descriptor,
    parse_windows_sid,
)
from tanuki.protocol import ERROR_DICTIONARY, find_error_resolution


class TestEventIdTriageLookup(unittest.TestCase):
    """Verify Windows Event ID triage lookup and FAST armoring error integration."""

    def test_lookup_by_windows_event_ids(self):
        # Event ID 4768 (Kerberos TGT Request)
        res_4768 = find_error_resolution("4768")
        self.assertIsNotNone(res_4768)
        self.assertIn(4768, res_4768["telemetry"]["event_ids"])

        # Event ID 4769 (Kerberos Service Ticket Request)
        res_4769 = find_error_resolution("4769")
        self.assertIsNotNone(res_4769)
        self.assertIn(4769, res_4769["telemetry"]["event_ids"])

        # Event ID 4771 (Kerberos Pre-authentication Failed)
        res_4771 = find_error_resolution("4771")
        self.assertIsNotNone(res_4771)
        self.assertIn(4771, res_4771["telemetry"]["event_ids"])

    def test_lookup_fast_armoring_error_by_code(self):
        item = find_error_resolution("KDC_ERR_PREAUTH_REQUIRED_FOR_FAST")
        self.assertIsNotNone(item)
        self.assertEqual(item["code"], "KDC_ERR_PREAUTH_REQUIRED_FOR_FAST")
        self.assertEqual(item["event_id"], 93)
        self.assertIn("FAST", item["root_cause"])
        self.assertIn("fast_req_armoring", item["resolution"])
        self.assertIn("tactical_cmd", item)
        self.assertIn("telemetry", item)

    def test_lookup_fast_armoring_error_by_kerberos_code_93(self):
        item = find_error_resolution("93")
        self.assertIsNotNone(item)
        self.assertEqual(item["code"], "KDC_ERR_PREAUTH_REQUIRED_FOR_FAST")

    def test_cli_triage_windows_event_id_json(self):
        cmd = [sys.executable, "-m", "tanuki", "triage", "4768", "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIn("code", data)
        self.assertIn(4768, data["telemetry"]["event_ids"])

    def test_cli_triage_fast_code_json(self):
        cmd = [sys.executable, "-m", "tanuki", "triage", "93", "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["code"], "KDC_ERR_PREAUTH_REQUIRED_FOR_FAST")
        self.assertEqual(data["event_id"], 93)


class TestLdapBerDecoderAndBinaryAttributes(unittest.TestCase):
    """Verify ASN.1 BER resultCode decoding bug fix and preservation of raw binary AD attributes."""

    def test_ber_decode_bind_response_enumerated_success(self):
        # Real-world LDAP BindResponse: op_val starts with TAG_ENUMERATED (0x0A, len 1, val 0x00)
        result_code_tlv = bytes([TAG_ENUMERATED, 0x01, 0x00])
        matched_dn_tlv = ber_encode_string("")
        diag_msg_tlv = ber_encode_string("")
        bind_resp_payload = result_code_tlv + matched_dn_tlv + diag_msg_tlv

        bind_resp_tlv = ber_encode_tlv(LDAP_RESP_BIND, bind_resp_payload)
        msg_id_tlv = ber_encode_int(1)
        full_ldap_msg = ber_encode_sequence([msg_id_tlv, bind_resp_tlv])

        messages = parse_ldap_response_stream(full_ldap_msg)
        self.assertEqual(len(messages), 1)
        msg = messages[0]
        self.assertEqual(msg["type"], "bind_response")
        self.assertEqual(msg["result_code"], 0)
        self.assertTrue(msg["success"])

    def test_ber_decode_bind_response_enumerated_invalid_credentials(self):
        # Invalid credentials error (49 = 0x31)
        result_code_tlv = bytes([TAG_ENUMERATED, 0x01, 0x31])
        matched_dn_tlv = ber_encode_string("")
        diag_msg_tlv = ber_encode_string("80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v3839")
        bind_resp_payload = result_code_tlv + matched_dn_tlv + diag_msg_tlv

        bind_resp_tlv = ber_encode_tlv(LDAP_RESP_BIND, bind_resp_payload)
        msg_id_tlv = ber_encode_int(2)
        full_ldap_msg = ber_encode_sequence([msg_id_tlv, bind_resp_tlv])

        messages = parse_ldap_response_stream(full_ldap_msg)
        self.assertEqual(len(messages), 1)
        msg = messages[0]
        self.assertEqual(msg["type"], "bind_response")
        self.assertEqual(msg["result_code"], 49)
        self.assertFalse(msg["success"])

    def test_ber_decode_search_done_enumerated_success(self):
        # SearchResultDone with TAG_ENUMERATED 0x00
        result_code_tlv = bytes([TAG_ENUMERATED, 0x01, 0x00])
        matched_dn_tlv = ber_encode_string("")
        diag_msg_tlv = ber_encode_string("")
        search_done_payload = result_code_tlv + matched_dn_tlv + diag_msg_tlv

        search_done_tlv = ber_encode_tlv(LDAP_RESP_SEARCH_DONE, search_done_payload)
        msg_id_tlv = ber_encode_int(3)
        full_ldap_msg = ber_encode_sequence([msg_id_tlv, search_done_tlv])

        messages = parse_ldap_response_stream(full_ldap_msg)
        self.assertEqual(len(messages), 1)
        msg = messages[0]
        self.assertEqual(msg["type"], "search_done")
        self.assertEqual(msg["result_code"], 0)

    def test_preserve_binary_active_directory_attributes(self):
        # Build synthetic LDAP search entry containing text and binary attributes
        dn = "CN=DC01,OU=Domain Controllers,DC=corp,DC=local"
        dn_tlv = ber_encode_string(dn)

        # Text attribute: sAMAccountName
        sam_name_tlv = ber_encode_string("sAMAccountName")
        sam_val_set = ber_encode_tlv(0x31, ber_encode_string("DC01$"))
        sam_seq = ber_encode_sequence([sam_name_tlv, sam_val_set])

        # Binary attribute: msDS-AllowedToActOnBehalfOfOtherIdentity
        rbcd_raw_bytes = b"\x01\x00\x04\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x24\x00\x01\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x02\x00\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x51\x04\x00\x00"
        rbcd_name_tlv = ber_encode_string("msDS-AllowedToActOnBehalfOfOtherIdentity")
        rbcd_val_set = ber_encode_tlv(0x31, ber_encode_tlv(0x04, rbcd_raw_bytes))
        rbcd_seq = ber_encode_sequence([rbcd_name_tlv, rbcd_val_set])

        # Binary attribute: objectSid
        sid_raw_bytes = b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x51\x04\x00\x00"
        sid_name_tlv = ber_encode_string("objectSid")
        sid_val_set = ber_encode_tlv(0x31, ber_encode_tlv(0x04, sid_raw_bytes))
        sid_seq = ber_encode_sequence([sid_name_tlv, sid_val_set])

        attrs_seq = ber_encode_sequence([sam_seq, rbcd_seq, sid_seq])
        entry_payload = dn_tlv + attrs_seq
        entry_tlv = ber_encode_tlv(LDAP_RESP_SEARCH_ENTRY, entry_payload)

        msg_id_tlv = ber_encode_int(4)
        full_ldap_msg = ber_encode_sequence([msg_id_tlv, entry_tlv])

        messages = parse_ldap_response_stream(full_ldap_msg)
        self.assertEqual(len(messages), 1)
        entry = messages[0]
        self.assertEqual(entry["type"], "search_entry")
        attrs = entry["attributes"]

        # String attribute is decoded to str
        self.assertEqual(attrs["sAMAccountName"], ["DC01$"])

        # Binary attributes are preserved as raw bytes
        rbcd_vals = attrs["msDS-AllowedToActOnBehalfOfOtherIdentity"]
        self.assertEqual(len(rbcd_vals), 1)
        self.assertIsInstance(rbcd_vals[0], bytes)
        self.assertEqual(rbcd_vals[0], rbcd_raw_bytes)

        sid_vals = attrs["objectSid"]
        self.assertEqual(len(sid_vals), 1)
        self.assertIsInstance(sid_vals[0], bytes)
        self.assertEqual(sid_vals[0], sid_raw_bytes)

    def test_format_ldap_report_terminal_with_binary_attributes(self):
        report = {
            "status": "SUCCESS",
            "host": "192.168.56.106",
            "port": 389,
            "query_type": "rbcd",
            "count": 1,
            "entries": [
                {
                    "dn": "CN=DC01,DC=corp,DC=local",
                    "attributes": {
                        "sAMAccountName": ["DC01$"],
                        "msDS-AllowedToActOnBehalfOfOtherIdentity": [b"\x01\x00\x04\x80\x14\x00\x00\x00"],
                    },
                    "query_category": "RBCD",
                }
            ],
        }
        text = format_ldap_report_terminal(report)
        self.assertIn("TANUKI UNPRIVILEGED LDAP QUERY ENGINE", text)
        self.assertIn("DC01$", text)
        self.assertIn("<binary: 8 bytes", text)


class TestBinaryNtSecurityDescriptorParser(unittest.TestCase):
    """Verify bounded binary parsing of NT Security Descriptors and RBCD Trustee SIDs."""

    def _build_synthetic_sid(self, revision: int, identifier_authority: int, sub_authorities: list) -> bytes:
        buf = bytearray()
        buf.append(revision)
        buf.append(len(sub_authorities))
        buf.extend(identifier_authority.to_bytes(6, byteorder="big"))
        for sa in sub_authorities:
            buf.extend(struct.pack("<I", sa))
        return bytes(buf)

    def test_parse_windows_sid_standard(self):
        # S-1-5-21-12345678-23456789-34567890-1105
        raw_sid = self._build_synthetic_sid(1, 5, [21, 12345678, 23456789, 34567890, 1105])
        sid_str, consumed = parse_windows_sid(raw_sid, 0)
        self.assertEqual(sid_str, "S-1-5-21-12345678-23456789-34567890-1105")
        self.assertEqual(consumed, len(raw_sid))

    def test_parse_windows_sid_truncated_fails(self):
        raw_sid = self._build_synthetic_sid(1, 5, [21, 1000])
        with self.assertRaises(PacDecodeError):
            parse_windows_sid(raw_sid[:7], 0)  # truncated header
        with self.assertRaises(PacDecodeError):
            parse_windows_sid(raw_sid[:12], 0)  # truncated subauthorities

    def test_parse_rbcd_security_descriptor_with_aces(self):
        # Build synthetic SECURITY_DESCRIPTOR_RELATIVE
        # Header: Revision=1, Sbz1=0, Control=0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT),
        # OffsetOwner=0, OffsetGroup=0, OffsetSacl=0, OffsetDacl=20
        sd_header = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20)

        # Trustee SID 1: S-1-5-21-111-222-333-1105
        sid1 = self._build_synthetic_sid(1, 5, [21, 111, 222, 333, 1105])
        # ACE 1: ACCESS_ALLOWED_ACE (type 0x00, flags 0, size = 4 + 4 + len(sid1), mask = 0x00020000)
        ace1_header = struct.pack("<BBH", 0, 0, 8 + len(sid1))
        ace1_mask = struct.pack("<I", 0x00020000)
        ace1_bytes = ace1_header + ace1_mask + sid1

        # Trustee SID 2: S-1-5-21-111-222-333-1106
        sid2 = self._build_synthetic_sid(1, 5, [21, 111, 222, 333, 1106])
        # ACE 2: ACCESS_ALLOWED_OBJECT_ACE (type 0x05, flags 0, mask = 0x00000100, obj_flags = 0x01, GUID = 16 bytes)
        obj_guid = b"\xaa" * 16
        ace2_len = 4 + 4 + 4 + len(obj_guid) + len(sid2)
        ace2_header = struct.pack("<BBH", 5, 0, ace2_len)
        ace2_mask = struct.pack("<I", 0x00000100)
        ace2_obj_flags = struct.pack("<I", 0x01)
        ace2_bytes = ace2_header + ace2_mask + ace2_obj_flags + obj_guid + sid2

        # ACL Header: AclRevision=2, Sbz1=0, AclSize = 8 + len(ace1) + len(ace2), AceCount=2, Sbz2=0
        acl_size = 8 + len(ace1_bytes) + len(ace2_bytes)
        acl_header = struct.pack("<BBHHH", 2, 0, acl_size, 2, 0)
        acl_bytes = acl_header + ace1_bytes + ace2_bytes

        full_sd_bytes = sd_header + acl_bytes

        res = parse_rbcd_security_descriptor(full_sd_bytes)
        self.assertEqual(res["revision"], 1)
        self.assertEqual(res["dacl_offset"], 20)
        self.assertEqual(res["ace_count"], 2)
        self.assertEqual(len(res["trustee_sids"]), 2)
        self.assertIn("S-1-5-21-111-222-333-1105", res["trustee_sids"])
        self.assertIn("S-1-5-21-111-222-333-1106", res["trustee_sids"])

        # Verify alias parse_nt_security_descriptor equivalence
        alias_res = parse_nt_security_descriptor(full_sd_bytes)
        self.assertEqual(alias_res, res)

    def test_parse_rbcd_security_descriptor_truncated_header_raises(self):
        with self.assertRaises(PacDecodeError):
            parse_rbcd_security_descriptor(b"\x01\x00\x04")

    def test_parse_rbcd_security_descriptor_null_dacl(self):
        sd_header = struct.pack("<BBHIIII", 1, 0, 0x8000, 0, 0, 0, 0)  # OffsetDacl=0
        res = parse_rbcd_security_descriptor(sd_header)
        self.assertEqual(res["dacl_offset"], 0)
        self.assertEqual(res["ace_count"], 0)
        self.assertEqual(res["trustee_sids"], [])


class TestFastConfigSynthesis(unittest.TestCase):
    """Verify RFC 6113 FAST armoring configuration synthesis."""

    def test_generate_krb5_conf_with_fast_enabled(self):
        conf = generate_krb5_conf("CORP.LOCAL", "192.168.56.106", fast=True)
        self.assertIn("default_realm = CORP.LOCAL", conf)
        self.assertIn("fast_req_armoring = true", conf)

    def test_generate_krb5_conf_with_armor_cache(self):
        conf = generate_krb5_conf(
            "CORP.LOCAL",
            "192.168.56.106",
            fast=True,
            armor_cache="/tmp/krb5cc_armor",
        )
        self.assertIn("fast_req_armoring = true", conf)
        self.assertIn("armor_cache = /tmp/krb5cc_armor", conf)

    def test_write_krb5_conf_file_with_fast(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "fast.conf")
            res = write_krb5_conf_file(
                target,
                "CORP.LOCAL",
                "192.168.56.106",
                fast=True,
                armor_cache="/var/run/armor.ccache",
            )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertTrue(res.get("fast"))
            self.assertEqual(res.get("armor_cache"), "/var/run/armor.ccache")
            self.assertTrue(os.path.isfile(target))
            with open(target, "r") as f:
                content = f.read()
            self.assertIn("fast_req_armoring = true", content)
            self.assertIn("armor_cache = /var/run/armor.ccache", content)

    def test_cli_config_fast_flag_stdout(self):
        cmd = [
            sys.executable,
            "-m",
            "tanuki",
            "config",
            "--realm",
            "CORP.LOCAL",
            "--kdc",
            "192.168.56.106",
            "--fast",
            "--stdout",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("fast_req_armoring = true", proc.stdout)

    def test_cli_config_fast_and_armor_cache_json(self):
        cmd = [
            sys.executable,
            "-m",
            "tanuki",
            "config",
            "--realm",
            "CORP.LOCAL",
            "--kdc",
            "192.168.56.106",
            "--fast",
            "--armor-cache",
            "/tmp/armor_ticket",
            "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "SUCCESS")
        self.assertTrue(data.get("fast"))
        self.assertEqual(data.get("armor_cache"), "/tmp/armor_ticket")
        self.assertIn("fast_req_armoring = true", data["content"])
        self.assertIn("armor_cache = /tmp/armor_ticket", data["content"])


if __name__ == "__main__":
    unittest.main()
