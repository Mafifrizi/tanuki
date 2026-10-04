"""Unit tests for Unprivileged SASL GSSAPI LDAP Query Engine (tanuki ldap)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.ldap import (
    LDAP_RESP_BIND,
    LDAP_RESP_SEARCH_DONE,
    LDAP_RESP_SEARCH_ENTRY,
    TAG_SEQUENCE,
    LdapError,
    ber_decode_int,
    ber_decode_string,
    ber_decode_tlv,
    ber_encode_int,
    ber_encode_length,
    ber_encode_sequence,
    ber_encode_string,
    ber_encode_tlv,
    build_ldap_bind_request,
    build_ldap_search_filter,
    build_ldap_search_request,
    format_ldap_report_terminal,
    parse_ldap_response_stream,
    query_active_directory_ldap,
)


class TestLdapEngine(unittest.TestCase):
    def test_ber_encode_decode_length(self):
        # Single byte length
        self.assertEqual(ber_encode_length(10), b"\x0a")
        # Multi byte length
        enc_long = ber_encode_length(300)
        self.assertEqual(enc_long[0], 0x82)  # 2 length bytes
        self.assertEqual(int.from_bytes(enc_long[1:], byteorder="big"), 300)

    def test_ber_encode_decode_int(self):
        for val in [0, 1, 127, 128, 255, 1024, 65535]:
            encoded = ber_encode_int(val)
            tag, payload, next_off = ber_decode_tlv(encoded, 0)
            self.assertEqual(tag, 0x02)  # INTEGER
            self.assertEqual(ber_decode_int(payload), val)

    def test_ber_encode_decode_string(self):
        s = "CORP.LOCAL"
        encoded = ber_encode_string(s)
        tag, payload, next_off = ber_decode_tlv(encoded, 0)
        self.assertEqual(tag, 0x04)  # OCTET STRING
        self.assertEqual(ber_decode_string(payload), s)

    def test_ber_encode_sequence(self):
        e1 = ber_encode_int(1)
        e2 = ber_encode_string("test")
        seq = ber_encode_sequence([e1, e2])
        tag, payload, _ = ber_decode_tlv(seq, 0)
        self.assertEqual(tag, TAG_SEQUENCE)

    def test_build_ldap_bind_request(self):
        bind_bytes = build_ldap_bind_request(msg_id=1, bind_dn="")
        tag, payload, _ = ber_decode_tlv(bind_bytes, 0)
        self.assertEqual(tag, TAG_SEQUENCE)
        # Message ID is first element
        _, id_val, n_off = ber_decode_tlv(payload, 0)
        self.assertEqual(ber_decode_int(id_val), 1)

    def test_build_ldap_search_request(self):
        f = build_ldap_search_filter("servicePrincipalName", "*")
        search_bytes = build_ldap_search_request(
            msg_id=2,
            base_dn="DC=corp,DC=local",
            filter_bytes=f,
            attributes=["sAMAccountName", "servicePrincipalName"],
        )
        tag, payload, _ = ber_decode_tlv(search_bytes, 0)
        self.assertEqual(tag, TAG_SEQUENCE)

    def test_parse_ldap_response_stream_synthetic(self):
        # Build synthetic BindResponse message:
        # Sequence: MessageID (1), BindResponse (resultCode 0, matchedDN "", diagnosticMsg "")
        bind_resp_payload = b"\x00\x04\x00\x04\x00"  # resultCode 0, empty octet strings
        bind_resp_tlv = ber_encode_tlv(LDAP_RESP_BIND, bind_resp_payload)
        msg_id_tlv = ber_encode_int(1)
        msg_tlv = ber_encode_sequence([msg_id_tlv, bind_resp_tlv])

        parsed = parse_ldap_response_stream(msg_tlv)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["type"], "bind_response")
        self.assertTrue(parsed[0]["success"])

    def test_query_active_directory_ldap_connection_failure(self):
        # Querying an unreachable address returns clean CONNECTION_FAILED dictionary
        rep = query_active_directory_ldap(
            host="127.0.0.1",
            port=65534,
            query_type="spn",
            timeout=0.1,
        )
        self.assertEqual(rep["status"], "CONNECTION_FAILED")
        self.assertEqual(rep["count"], 0)
        self.assertEqual(rep["entries"], [])

    def test_format_ldap_report_terminal(self):
        report = {
            "status": "SUCCESS",
            "host": "dc01.corp.local",
            "port": 389,
            "query_type": "spn",
            "count": 1,
            "entries": [
                {
                    "dn": "CN=sql_svc,CN=Users,DC=corp,DC=local",
                    "query_category": "spn",
                    "attributes": {
                        "sAMAccountName": ["sql_svc"],
                        "servicePrincipalName": ["MSSQLSvc/db01.corp.local:1433"],
                    },
                }
            ],
        }
        term_text = format_ldap_report_terminal(report)
        self.assertIn("TANUKI UNPRIVILEGED LDAP QUERY ENGINE", term_text)
        self.assertIn("SPN", term_text)
        self.assertIn("sql_svc", term_text)


if __name__ == "__main__":
    unittest.main()
