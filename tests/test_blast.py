"""Unit Tests for Tanuki Active Directory Privilege Tiering and Blast Radius Engine."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

import tanuki
from tanuki.blast import (
    classify_identity_tier,
    evaluate_blast_radius,
    extract_ad_account_name,
    format_blast_report_terminal,
    generate_ad_remediations,
    get_event_4769_telemetry,
    run_blast,
)
from tests.e2e.fixtures import build_synthetic_keytab


class TestBlastTierClassification(unittest.TestCase):
    """Test identity classification into Tier 0, Tier 1, and Tier 2."""

    def test_tier_0_domain_admin_rid(self):
        tier_info = classify_identity_tier(
            principal="da_admin@LAB.LOCAL",
            group_rids=[512, 513],
        )
        self.assertEqual(tier_info["tier"], 0)
        self.assertEqual(tier_info["severity"], "CRITICAL")
        self.assertTrue(tier_info["is_critical"])
        self.assertGreaterEqual(tier_info["base_score"], 90)

    def test_tier_0_builtin_administrator_sid(self):
        tier_info = classify_identity_tier(
            principal="Administrator@LAB.LOCAL",
            user_sid="S-1-5-21-3524859768-892044447-4268052392-500",
        )
        self.assertEqual(tier_info["tier"], 0)
        self.assertEqual(tier_info["severity"], "CRITICAL")

    def test_tier_0_domain_controller_machine(self):
        tier_info = classify_identity_tier(
            principal="DC01$@LAB.LOCAL",
            uac_flags=["SERVER_TRUST_ACCOUNT"],
            is_dc=True,
        )
        self.assertEqual(tier_info["tier"], 0)
        self.assertEqual(tier_info["severity"], "CRITICAL")

    def test_tier_1_operator_rid(self):
        tier_info = classify_identity_tier(
            principal="server_operator@LAB.LOCAL",
            group_rids=[549, 513],
        )
        self.assertEqual(tier_info["tier"], 1)
        self.assertEqual(tier_info["severity"], "HIGH")
        self.assertFalse(tier_info["is_critical"])

    def test_tier_1_unconstrained_delegation(self):
        tier_info = classify_identity_tier(
            principal="web_server$@LAB.LOCAL",
            uac_flags=["TRUSTED_FOR_DELEGATION"],
        )
        self.assertEqual(tier_info["tier"], 1)
        self.assertEqual(tier_info["severity"], "HIGH")

    def test_tier_1_constrained_delegation(self):
        tier_info = classify_identity_tier(
            principal="app_service@LAB.LOCAL",
            uac_flags=["TRUSTED_TO_AUTH_FOR_DELEGATION"],
        )
        self.assertEqual(tier_info["tier"], 1)
        self.assertEqual(tier_info["severity"], "HIGH")

    def test_tier_1_registered_spn(self):
        tier_info = classify_identity_tier(
            principal="svc_sql@LAB.LOCAL",
            has_spn=True,
        )
        self.assertEqual(tier_info["tier"], 1)

    def test_tier_2_standard_user(self):
        tier_info = classify_identity_tier(
            principal="jdoe@LAB.LOCAL",
            user_sid="S-1-5-21-3524859768-892044447-4268052392-1105",
            primary_group_rid=513,
            group_rids=[513],
        )
        self.assertEqual(tier_info["tier"], 2)
        self.assertEqual(tier_info["severity"], "LOW")
        self.assertEqual(tier_info["base_score"], 20)


class TestBlastRadiusEvaluation(unittest.TestCase):
    """Test quantitative blast radius impact scoring."""

    def test_score_unconstrained_delegation_critical(self):
        tier_info = classify_identity_tier(
            principal="jump_host$@LAB.LOCAL",
            uac_flags=["TRUSTED_FOR_DELEGATION"],
        )
        blast = evaluate_blast_radius(
            principal="jump_host$@LAB.LOCAL",
            tier_info=tier_info,
            delegation_flags=["TRUSTED_FOR_DELEGATION"],
            accessible_spns=["cifs/dc01.lab.local"],
        )
        self.assertGreaterEqual(blast["score"], 85)
        self.assertEqual(blast["severity"], "CRITICAL")
        self.assertGreaterEqual(blast["lateral_path_count"], 1)

    def test_score_clamped_at_100(self):
        tier_info = classify_identity_tier(
            principal="super_dc$@LAB.LOCAL",
            is_dc=True,
        )
        blast = evaluate_blast_radius(
            principal="super_dc$@LAB.LOCAL",
            tier_info=tier_info,
            delegation_flags=["TRUSTED_FOR_DELEGATION", "TRUSTED_TO_AUTH_FOR_DELEGATION"],
            accessible_spns=["spn1", "spn2", "spn3", "spn4", "spn5", "spn6"],
            rbcd_targets=[{"target_name": "srv1"}, {"target_name": "srv2"}],
        )
        self.assertLessEqual(blast["score"], 100)
        self.assertEqual(blast["score"], 100)
        self.assertEqual(blast["severity"], "CRITICAL")

    def test_remediation_recipes_generation(self):
        tier_info = classify_identity_tier(
            principal="tanuki-nhi@LAB.LOCAL",
            has_spn=True,
        )
        recipes = generate_ad_remediations(
            principal="tanuki-nhi@LAB.LOCAL",
            tier_info=tier_info,
            delegation_flags=[],
            rbcd_targets=[{"target_name": "FS01"}],
            accessible_spns=["HTTP/tanuki-app.lab.local"],
        )
        self.assertGreaterEqual(len(recipes), 2)
        # Verify AES enforcement recipe exists
        aes_recipe = next((r for r in recipes if r["category"] == "ENCRYPTION_HARDENING"), None)
        self.assertIsNotNone(aes_recipe)
        self.assertIn("Set-ADUser", aes_recipe["powershell"])
        self.assertIn("AES128,AES256", aes_recipe["powershell"])

        # Verify RBCD clear recipe exists
        rbcd_recipe = next((r for r in recipes if r["category"] == "DELEGATION_HARDENING"), None)
        self.assertIsNotNone(rbcd_recipe)
        self.assertIn("msDS-AllowedToActOnBehalfOfOtherIdentity", rbcd_recipe["powershell"])
        self.assertIn('Identity "FS01"', rbcd_recipe["powershell"])

    def test_extract_ad_account_name_accuracy(self):
        self.assertEqual(extract_ad_account_name("HTTP/tanuki-app.lab.local@LAB.LOCAL"), "tanuki-app")
        self.assertEqual(extract_ad_account_name("cifs/DC01.lab.local@LAB.LOCAL"), "DC01")
        self.assertEqual(extract_ad_account_name("MSSQLSvc/sql01.corp.local:1433@CORP.LOCAL"), "sql01")
        self.assertEqual(extract_ad_account_name("tanuki-nhi@LAB.LOCAL"), "tanuki-nhi")
        self.assertEqual(extract_ad_account_name("DC01$@LAB.LOCAL"), "DC01$")

    def test_run_blast_standard_user_classified_as_tier_2(self):
        rep = run_blast(source="jdoe@LAB.LOCAL")
        self.assertEqual(rep["tier"], 2)
        self.assertEqual(rep["tier_label"], "Tier 2 (Workstation & User Endpoints)")
        self.assertEqual(rep["severity"], "LOW")
        self.assertEqual(rep["blast_score"], 25)
        self.assertIn("Standard domain user", rep["tier_details"]["matched_rules"][0])

    def test_run_blast_service_principal_clean_cmdlet_targeting(self):
        rep = run_blast(source="HTTP/tanuki-app.lab.local@LAB.LOCAL")
        self.assertEqual(rep["tier"], 1)
        self.assertEqual(rep["tier_label"], "Tier 1 (Server & Operator Infrastructure)")
        self.assertIn("Registered Service Principal Name", rep["tier_details"]["matched_rules"][0])
        # Verify PowerShell cmdlets target tanuki-app and NOT HTTP
        powershell_cmds = [r["powershell"] for r in rep["remediation_recipes"]]
        self.assertTrue(any('Set-ADUser -Identity "tanuki-app"' in cmd for cmd in powershell_cmds))
        self.assertTrue(any('-mapuser tanuki-app' in cmd for cmd in powershell_cmds))
        self.assertFalse(any('Identity "HTTP"' in cmd for cmd in powershell_cmds))
        self.assertFalse(any('-mapuser HTTP' in cmd for cmd in powershell_cmds))

    def test_cyclic_and_duplicate_rbcd_handling(self):
        tier_info = classify_identity_tier("tanuki-app$@LAB.LOCAL", has_spn=True)
        blast = evaluate_blast_radius(
            principal="tanuki-app$@LAB.LOCAL",
            tier_info=tier_info,
            rbcd_targets=[
                {"target_name": "tanuki-app$"},
                {"target_name": "FS01$"},
                {"target_name": "FS01$"},
            ],
        )
        self.assertEqual(blast["score"], 95)
        vectors = [p["vector"] for p in blast["lateral_paths"]]
        self.assertIn("Cyclic / Self-Referential RBCD Delegation Loop", vectors)
        # Verify FS01 is only in lateral paths once (deduplicated)
        fs01_paths = [p for p in blast["lateral_paths"] if p.get("target") == "FS01$"]
        self.assertEqual(len(fs01_paths), 1)

        recipes = generate_ad_remediations(
            principal="tanuki-app$@LAB.LOCAL",
            tier_info=tier_info,
            rbcd_targets=[
                {"target_name": "tanuki-app$"},
                {"target_name": "FS01$"},
                {"target_name": "FS01$"},
            ],
        )
        rbcd_rems = [r for r in recipes if r["category"] == "DELEGATION_HARDENING"]
        # Only two unique RBCD remediations (tanuki-app and FS01)
        self.assertEqual(len(rbcd_rems), 2)
        cmdlets = [r["powershell"] for r in rbcd_rems]
        self.assertTrue(any('Identity "tanuki-app"' in cmd for cmd in cmdlets))
        self.assertTrue(any('Identity "FS01"' in cmd for cmd in cmdlets))

    def test_event_4769_telemetry_schema(self):
        telem = get_event_4769_telemetry(spn="HTTP/tanuki-app.lab.local", client="tanuki-nhi@LAB.LOCAL")
        self.assertEqual(telem["event_id"], 4769)
        self.assertIn("TicketOptions", telem["fields"])
        self.assertEqual(telem["fields"]["ServiceName"], "HTTP/tanuki-app.lab.local")
        self.assertGreater(len(telem["auditd"]), 0)
        self.assertGreater(len(telem["sigma"]), 0)


class TestBlastCLI(unittest.TestCase):
    """Test tanuki blast CLI execution and formatting."""

    def test_cli_blast_json(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tanuki", "blast", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["operation"], "BLAST_RADIUS_ANALYSIS")
        self.assertIn("blast_score", data)
        self.assertIn("tier", data)
        self.assertIn("remediation_recipes", data)
        self.assertIn("telemetry", data)

    def test_cli_blast_terminal_no_em_dashes(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tanuki", "blast"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        output = proc.stdout
        self.assertIn("TANUKI PRIVILEGE TIERING & BLAST RADIUS ENGINE", output)
        self.assertNotIn("\u2014", output, "Output must strictly contain zero unicode em dashes")


if __name__ == "__main__":
    unittest.main()
