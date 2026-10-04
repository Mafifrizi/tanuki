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


if __name__ == "__main__":
    unittest.main()
