"""Unit tests for Passive AD CS Certificate & Template Scanner (tanuki adcs)."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.adcs import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_NO_SECURITY_EXTENSION,
    CT_FLAG_PEND_ALL_REQUESTS,
    OID_ANY_PURPOSE,
    OID_CERT_REQUEST_AGENT,
    OID_CLIENT_AUTH,
    OID_PKINIT_CLIENT_AUTH,
    OID_SMARTCARD_LOGON,
    evaluate_ca_misconfigurations,
    evaluate_template_misconfigurations,
    format_adcs_report_terminal,
    scan_adcs,
)


class TestAdcsScanner(unittest.TestCase):
    def test_esc1_detection(self):
        template = {
            "name": "ESC1-Vulnerable-Template",
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI-Enrollment-Flag": 0,
            "pKIExtendedKeyUsage": [OID_CLIENT_AUTH],
            "authorized_signatures": 0,
        }
        findings = evaluate_template_misconfigurations(template)
        vectors = [f["vector"] for f in findings]
        self.assertIn("ESC1", vectors)
        esc1 = next(f for f in findings if f["vector"] == "ESC1")
        self.assertEqual(esc1["severity"], "CRITICAL")
        self.assertIn("Enrollee Supplies Subject", esc1["title"])

    def test_esc1_mitigated_by_manager_approval(self):
        template = {
            "name": "ESC1-Mitigated",
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI-Enrollment-Flag": CT_FLAG_PEND_ALL_REQUESTS,  # Requires manager approval
            "pKIExtendedKeyUsage": [OID_CLIENT_AUTH],
            "authorized_signatures": 0,
        }
        findings = evaluate_template_misconfigurations(template)
        vectors = [f["vector"] for f in findings]
        self.assertNotIn("ESC1", vectors)

    def test_esc2_detection(self):
        template = {
            "name": "ESC2-AnyPurpose",
            "msPKI-Certificate-Name-Flag": 0,
            "pKIExtendedKeyUsage": [OID_ANY_PURPOSE],
        }
        findings = evaluate_template_misconfigurations(template)
        vectors = [f["vector"] for f in findings]
        self.assertIn("ESC2", vectors)
        esc2 = next(f for f in findings if f["vector"] == "ESC2")
        self.assertEqual(esc2["severity"], "HIGH")

    def test_esc3_detection(self):
        template = {
            "name": "ESC3-EnrollmentAgent",
            "msPKI-Certificate-Name-Flag": 0,
            "pKIExtendedKeyUsage": [OID_CERT_REQUEST_AGENT],
        }
        findings = evaluate_template_misconfigurations(template)
        vectors = [f["vector"] for f in findings]
        self.assertIn("ESC3", vectors)

    def test_esc9_detection(self):
        template = {
            "name": "ESC9-NoSecurityExtension",
            "msPKI-Enrollment-Flag": CT_FLAG_NO_SECURITY_EXTENSION,
            "pKIExtendedKeyUsage": [OID_CLIENT_AUTH],
        }
        findings = evaluate_template_misconfigurations(template)
        vectors = [f["vector"] for f in findings]
        self.assertIn("ESC9", vectors)

    def test_ca_misconfigurations_esc6_and_esc8(self):
        ca_config = {
            "ca_name": "CORP-CA01",
            "editf_san2": True,  # ESC6
            "http_enrollment_enabled": True,  # ESC8
            "extended_protection_enabled": False,
            "https_enforced": False,
        }
        findings = evaluate_ca_misconfigurations(ca_config)
        vectors = [f["vector"] for f in findings]
        self.assertIn("ESC6", vectors)
        self.assertIn("ESC8", vectors)

    def test_scan_adcs_json_file(self):
        templates = [
            {
                "name": "WebUserAuth",
                "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                "pKIExtendedKeyUsage": [OID_CLIENT_AUTH],
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(templates, f)
            tmp_path = f.name

        try:
            report = scan_adcs(source=tmp_path)
            self.assertEqual(report["status"], "SUCCESS")
            self.assertEqual(report["summary"]["critical"], 1)
            term_out = format_adcs_report_terminal(report)
            self.assertIn("TANUKI AD CS TEMPLATE & CERTIFICATE SCANNER", term_out)
            self.assertIn("ESC1", term_out)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_null_and_hex_flags_tolerance(self):
        template = {
            "name": "HexAndNullTemplate",
            "msPKI-Certificate-Name-Flag": "0x00000001",
            "msPKI-Enrollment-Flag": None,
            "msPKI-RA-Signature": None,
            "pKIExtendedKeyUsage": None,
        }
        findings = evaluate_template_misconfigurations(template)
        vectors = [f["vector"] for f in findings]
        self.assertIn("ESC1", vectors)
        self.assertIn("ESC2", vectors)

    def test_esc10_detection_tolerance(self):
        ca_config_hex = {
            "ca_name": "DC-CA01",
            "CertificateMappingMethods": "0x4",
        }
        findings_hex = evaluate_ca_misconfigurations(ca_config_hex)
        self.assertIn("ESC10", [f["vector"] for f in findings_hex])

        ca_config_int = {
            "ca_name": "DC-CA02",
            "CertificateMappingMethods": 2,
        }
        findings_int = evaluate_ca_misconfigurations(ca_config_int)
        self.assertIn("ESC10", [f["vector"] for f in findings_int])

    def test_esc1_normalized_eku_whitespace_and_alternate_oids(self):
        # 1. Whitespace padding around OID_CLIENT_AUTH
        t1 = {
            "name": "ESC1-Whitespace-EKU",
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI-Enrollment-Flag": 0,
            "pKIExtendedKeyUsage": [f"  {OID_CLIENT_AUTH}  "],
        }
        f1 = evaluate_template_misconfigurations(t1)
        self.assertIn("ESC1", [f["vector"] for f in f1])

        # 2. OID_SMARTCARD_LOGON
        t2 = {
            "name": "ESC1-SmartcardLogon",
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI-Enrollment-Flag": 0,
            "pKIExtendedKeyUsage": [OID_SMARTCARD_LOGON],
        }
        f2 = evaluate_template_misconfigurations(t2)
        self.assertIn("ESC1", [f["vector"] for f in f2])

        # 3. OID_PKINIT_CLIENT_AUTH
        t3 = {
            "name": "ESC1-PKInit",
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI-Enrollment-Flag": 0,
            "pKIExtendedKeyUsage": [OID_PKINIT_CLIENT_AUTH],
        }
        f3 = evaluate_template_misconfigurations(t3)
        self.assertIn("ESC1", [f["vector"] for f in f3])

        # 4. Fallback description text heuristic
        t4 = {
            "name": "ESC1-Text-Heuristic",
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI-Enrollment-Flag": 0,
            "pKIExtendedKeyUsage": ["Client Authentication for Workstation"],
        }
        f4 = evaluate_template_misconfigurations(t4)
        self.assertIn("ESC1", [f["vector"] for f in f4])

    def test_esc1_non_client_auth_eku_not_flagged(self):
        t = {
            "name": "NonClientAuth",
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI-Enrollment-Flag": 0,
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.3"],
        }
        f = evaluate_template_misconfigurations(t)
        self.assertNotIn("ESC1", [f["vector"] for f in f])

    def test_evaluate_template_scalar_and_none_eku_tolerance(self):
        # Scalar int EKU
        t_int = {
            "name": "ScalarIntEKU",
            "pKIExtendedKeyUsage": 12345,
        }
        f_int = evaluate_template_misconfigurations(t_int)
        self.assertIsInstance(f_int, list)

        # None inside EKU list
        t_none_elem = {
            "name": "NoneElemEKU",
            "pKIExtendedKeyUsage": [None, f"  {OID_CLIENT_AUTH}  "],
            "msPKI-Certificate-Name-Flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        }
        f_none = evaluate_template_misconfigurations(t_none_elem)
        self.assertIn("ESC1", [f["vector"] for f in f_none])

    def test_esc2_and_esc3_normalized_eku_whitespace(self):
        # ESC2 Any Purpose with whitespace
        t_esc2 = {
            "name": "ESC2-Whitespace",
            "msPKI-Enrollment-Flag": 0,
            "msPKI-RA-Signature": 0,
            "pKIExtendedKeyUsage": [f"  {OID_ANY_PURPOSE}  "],
        }
        f_esc2 = evaluate_template_misconfigurations(t_esc2)
        self.assertIn("ESC2", [f["vector"] for f in f_esc2])

        # ESC3 Request Agent with whitespace
        t_esc3 = {
            "name": "ESC3-Whitespace",
            "msPKI-Enrollment-Flag": 0,
            "msPKI-RA-Signature": 0,
            "pKIExtendedKeyUsage": [f"  {OID_CERT_REQUEST_AGENT}  "],
        }
        f_esc3 = evaluate_template_misconfigurations(t_esc3)
        self.assertIn("ESC3", [f["vector"] for f in f_esc3])


if __name__ == "__main__":
    unittest.main()
