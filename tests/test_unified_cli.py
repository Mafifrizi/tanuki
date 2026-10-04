"""Comprehensive Unit Tests for Tanuki Unified CLI."""

import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tanuki
from tanuki.cli import main as cli_main
from tanuki.protocol import DECISION_LADDER, ERROR_DICTIONARY, find_error_resolution


def build_synthetic_keytab(realm: str, principal_comps: list, key_bytes: bytes, keytype: int = 18, kvno: int = 3) -> bytes:
    buf = io.BytesIO()
    buf.write(b"\x05\x02")

    entry_buf = io.BytesIO()
    entry_buf.write(struct.pack(">h", len(principal_comps)))
    realm_b = realm.encode("utf-8")
    entry_buf.write(struct.pack(">h", len(realm_b)) + realm_b)
    for comp in principal_comps:
        comp_b = comp.encode("utf-8")
        entry_buf.write(struct.pack(">h", len(comp_b)) + comp_b)

    entry_buf.write(struct.pack(">I", 1))  # name_type
    entry_buf.write(struct.pack(">I", 1700000000))  # timestamp
    entry_buf.write(struct.pack(">B", kvno if kvno < 256 else 0))
    entry_buf.write(struct.pack(">h", keytype))
    entry_buf.write(struct.pack(">H", len(key_bytes)) + key_bytes)
    entry_buf.write(struct.pack(">I", kvno))

    raw_entry = entry_buf.getvalue()
    buf.write(struct.pack(">i", len(raw_entry)))
    buf.write(raw_entry)
    return buf.getvalue()


class TestUnifiedCLI(unittest.TestCase):
    def run_cli_subprocess(self, args: list) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "tanuki"] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        )

    def test_cli_no_args_exits_with_error(self):
        res = self.run_cli_subprocess([])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Tanuki CLI", res.stdout)
        self.assertIn("COMMANDS:", res.stdout)

    def test_cli_version_flag(self):
        res = self.run_cli_subprocess(["--version"])
        self.assertEqual(res.returncode, 0)
        self.assertIn(f"tanuki {tanuki.__version__}", res.stdout)

    def test_cli_help_flag(self):
        res = self.run_cli_subprocess(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("USAGE:", res.stdout)
        self.assertIn("keytab", res.stdout)
        self.assertIn("kcm", res.stdout)
        self.assertIn("triage", res.stdout)
        self.assertIn("ladder", res.stdout)

    def test_cli_ladder_text(self):
        res = self.run_cli_subprocess(["ladder"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("TANUKI 5-RUNG TACTICAL DECISION LADDER", res.stdout)
        self.assertIn("RUNG 1: LOCAL PASSIVE TRIAGE", res.stdout)
        self.assertIn("RUNG 5: DETERMINISTIC ONE-LINER", res.stdout)

    def test_cli_ladder_json(self):
        res = self.run_cli_subprocess(["ladder", "--json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(len(data), 5)
        self.assertEqual(data[0]["rung"], 1)
        self.assertEqual(data[4]["rung"], 5)

    def test_cli_skill_text(self):
        res = self.run_cli_subprocess(["skill"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("TANUKI AI AGENT SKILL MANIFEST", res.stdout)
        self.assertIn("Tim Brown", res.stdout)
        self.assertIn("Dietrich Gebert", res.stdout)
        self.assertIn("5-Rung Operator Tactical Decision Ladder", res.stdout)

    def test_cli_skill_json(self):
        res = self.run_cli_subprocess(["skill", "--json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["name"], "tanuki")
        self.assertIn("triggers", data)
        self.assertIn("lineage", data)
        self.assertEqual(len(data["ladder"]), 5)

    def test_cli_triage_lookup_by_code(self):
        res = self.run_cli_subprocess(["triage", "KRB_AP_ERR_SKEW"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("Found matching error: KRB_AP_ERR_SKEW", res.stdout)
        self.assertIn("Event ID: 37", res.stdout)
        self.assertIn("Clock skew", res.stdout)

    def test_cli_triage_lookup_by_event_id_json(self):
        res = self.run_cli_subprocess(["triage", "14", "--json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["code"], "KDC_ERR_ETYPE_NOSUPP")
        self.assertEqual(data["event_id"], 14)

    def test_cli_triage_missing_query(self):
        res = self.run_cli_subprocess(["triage", "NOT_A_REAL_ERROR"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("No matching error resolution found", res.stderr)

    def test_cli_triage_missing_query_json(self):
        res = self.run_cli_subprocess(["triage", "NOT_A_REAL_ERROR", "--json"])
        self.assertEqual(res.returncode, 3)
        data = json.loads(res.stdout)
        self.assertEqual(data.get("status"), "ERROR")
        self.assertEqual(data.get("reason_code"), "UNKNOWN_ERROR_CODE")
        self.assertEqual(data.get("exit_code"), 3)

    def test_cli_triage_full_dictionary(self):
        res = self.run_cli_subprocess(["triage"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("KERBEROS & SSSD ERROR RESOLUTION DICTIONARY", res.stdout)
        self.assertIn("KRB_AP_ERR_SKEW", res.stdout)

    def test_cli_triage_full_dictionary_json(self):
        res = self.run_cli_subprocess(["triage", "--json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertGreaterEqual(len(data), 10)

    def test_cli_keytab_parsing(self):
        keytab_data = build_synthetic_keytab("CORP.LOCAL", ["host", "srv01.corp.local"], b"\x42" * 32, keytype=18, kvno=7)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(keytab_data)
            tf_path = tf.name

        try:
            res = self.run_cli_subprocess(["keytab", tf_path])
            self.assertEqual(res.returncode, 0)
            self.assertIn("TANUKI KEYTAB TRIAGE REPORT", res.stdout)
            self.assertIn("host/srv01.corp.local@CORP.LOCAL", res.stdout)
            self.assertIn("KVNO      : 7", res.stdout)
            self.assertIn("aes256-cts-hmac-sha1-96 (18)", res.stdout)

            # JSON mode
            res_json = self.run_cli_subprocess(["keytab", tf_path, "--json"])
            self.assertEqual(res_json.returncode, 0)
            data = json.loads(res_json.stdout)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["principal"], "host/srv01.corp.local@CORP.LOCAL")
            self.assertEqual(data[0]["vno"], 7)

            # Shorthand invocation without "keytab" subcommand
            res_shorthand = self.run_cli_subprocess([tf_path, "--json"])
            self.assertEqual(res_shorthand.returncode, 0)
            shorthand_data = json.loads(res_shorthand.stdout)
            self.assertEqual(len(shorthand_data), 1)
            self.assertEqual(shorthand_data[0]["principal"], "host/srv01.corp.local@CORP.LOCAL")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_cli_kcm_parsing(self):
        blob = bytearray(b"\x05\x04")
        blob += struct.pack(">H", 0)  # header_len = 0
        blob += struct.pack(">I", 1)  # name_type
        blob += struct.pack(">I", 1)  # num_components
        realm = b"CORP.LOCAL"
        blob += struct.pack(">I", len(realm)) + realm
        comp = b"svc_account"
        blob += struct.pack(">I", len(comp)) + comp

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldb") as tf:
            tf.write(blob)
            tf_path = tf.name

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                res = self.run_cli_subprocess(["kcm", "-f", tf_path, "-o", out_dir, "--json"])
                self.assertEqual(res.returncode, 0)
                data = json.loads(res.stdout)
                self.assertEqual(len(data), 1)
                self.assertEqual(data[0]["default_principal"], "svc_account@CORP.LOCAL")
            finally:
                if os.path.exists(tf_path):
                    os.remove(tf_path)

    def test_cli_keytab_missing_file_semantic_exit_and_json_reason(self):
        missing_path = "/nonexistent/test/path/krb5.keytab"
        res = self.run_cli_subprocess(["keytab", missing_path])
        self.assertEqual(res.returncode, 3)
        self.assertIn("[RESOURCE MISSING]", res.stderr)
        self.assertIn("Error reading keytab", res.stderr)

        res_json = self.run_cli_subprocess(["keytab", missing_path, "--json"])
        self.assertEqual(res_json.returncode, 3)
        data = json.loads(res_json.stdout)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["reason_code"], "MISSING_KEYTAB")
        self.assertEqual(data["category"], "RESOURCE_MISSING")
        self.assertEqual(data["exit_code"], 3)
        self.assertEqual(data["target"], missing_path)

    def test_cli_keytab_corrupt_file_semantic_exit_and_json_reason(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as tf:
            tf.write(b"\x05\x02corruptedbytes")
            tf_path = tf.name

        try:
            res = self.run_cli_subprocess(["keytab", tf_path])
            self.assertEqual(res.returncode, 4)
            self.assertIn("[PARSE FAILURE]", res.stderr)
            self.assertIn("Error parsing keytab", res.stderr)

            res_json = self.run_cli_subprocess(["keytab", tf_path, "--json"])
            self.assertEqual(res_json.returncode, 4)
            data = json.loads(res_json.stdout)
            self.assertEqual(data["status"], "ERROR")
            self.assertEqual(data["reason_code"], "CORRUPT_KEYTAB")
            self.assertEqual(data["category"], "PARSE_FAILURE")
            self.assertEqual(data["exit_code"], 4)
            self.assertIn("details", data)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_cli_doctor_policy_stop_semantic_exit(self):
        kt_data = build_synthetic_keytab("CORP.LOCAL", ["host", "srv01.corp.local"], b"\x01" * 32, keytype=18, kvno=1)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keytab") as kt_file:
            kt_file.write(kt_data)
            kt_path = kt_file.name

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf") as conf_file:
            conf_file.write("[libdefaults]\ndefault_realm = lowercase.realm.local\n")
            conf_path = conf_file.name

        try:
            res = self.run_cli_subprocess(["doctor", "--keytab", kt_path, "--krb5-conf", conf_path, "--json"])
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "FAIL")
        finally:
            if os.path.exists(kt_path):
                os.remove(kt_path)
            if os.path.exists(conf_path):
                os.remove(conf_path)

    def test_cli_kcm_missing_resource_semantic_exit(self):
        missing_db = "/nonexistent/test/path/secrets.ldb"
        res = self.run_cli_subprocess(["kcm", "-f", missing_db])
        self.assertEqual(res.returncode, 3)
        self.assertIn("[RESOURCE MISSING]", res.stderr)

        res_json = self.run_cli_subprocess(["kcm", "-f", missing_db, "--json"])
        self.assertEqual(res_json.returncode, 3)
        data = json.loads(res_json.stdout)
        self.assertEqual(data["status"], "ERROR")
        self.assertEqual(data["reason_code"], "MISSING_RESOURCE")
        self.assertEqual(data["category"], "RESOURCE_MISSING")
        self.assertEqual(data["exit_code"], 3)
        self.assertEqual(data["target"], missing_db)

    def test_cli_unknown_option_semantic_exit_code(self):
        res = self.run_cli_subprocess(["--invalid-flag"])
        self.assertEqual(res.returncode, 1)

    def test_cli_unknown_option_json(self):
        res = self.run_cli_subprocess(["--json", "--invalid-flag"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertEqual(data.get("status"), "ERROR")
    def test_cli_token_with_issuer_flag_does_not_hang(self):
        token_str = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdCJ9."
        res = self.run_cli_subprocess(["token", token_str, "-i", "https://example.com"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("TANUKI WORKLOAD IDENTITY VALIDATOR", res.stdout)
        self.assertIn("https://example.com", res.stdout)

    def test_cli_missing_issuer_argument(self):
        res = self.run_cli_subprocess(["token", "some.jwt.token", "-i"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Option requires an argument: -i/--issuer", res.stderr)

        res_json = self.run_cli_subprocess(["token", "some.jwt.token", "-i", "--json"])
        self.assertEqual(res_json.returncode, 1)
        data = json.loads(res_json.stdout)
        self.assertEqual(data.get("reason_code"), "MISSING_ARGUMENT")


if __name__ == "__main__":
    unittest.main()

