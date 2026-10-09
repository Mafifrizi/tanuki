import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from submit_kitploit import (
    verify_repository_reachability,
    format_kitploit_markdown,
    compile_submission_payload,
    DEFAULT_REPO_URL,
    DEFAULT_TOOL_NAME,
    DEFAULT_VERSION,
    KITPLOIT_SUBMISSION_URL,
)


class TestKitploitSubmission(unittest.TestCase):
    def test_format_kitploit_markdown(self):
        md = format_kitploit_markdown()
        self.assertIn("# Tanuki (tanuki-ad)", md)
        self.assertIn("pip install tanuki-ad", md)
        self.assertIn("tanuki doctor", md)
        self.assertNotIn("\u2014", md, "Em dash detected in KitPloit markdown payload")

    def test_verify_repository_reachability_skip_network(self):
        result = verify_repository_reachability(DEFAULT_REPO_URL, skip_network=True)
        self.assertTrue(result["skipped"])
        self.assertIsNone(result["reachable"])
        self.assertEqual(result["url"], DEFAULT_REPO_URL)

    @patch("urllib.request.urlopen")
    def test_verify_repository_reachability_mock_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = verify_repository_reachability("https://example.com/repo")
        self.assertTrue(result["reachable"])
        self.assertEqual(result["status_code"], 200)
        self.assertFalse(result["skipped"])

    @patch("urllib.request.urlopen")
    def test_verify_repository_reachability_mock_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://example.com/repo",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )

        result = verify_repository_reachability("https://example.com/repo")
        self.assertFalse(result["reachable"])
        self.assertEqual(result["status_code"], 404)
        self.assertIn("404", result["message"])

    @patch("urllib.request.urlopen")
    def test_verify_repository_reachability_mock_network_exception(self, mock_urlopen):
        mock_urlopen.side_effect = ConnectionResetError("Connection reset by peer")

        result = verify_repository_reachability("https://example.com/repo")
        self.assertFalse(result["reachable"])
        self.assertIsNone(result["status_code"])
        self.assertIn("Connection check failed", result["message"])

    def test_compile_submission_payload(self):
        payload = compile_submission_payload(skip_network=True)
        self.assertEqual(payload["submission_target"], KITPLOIT_SUBMISSION_URL)
        self.assertEqual(payload["tool_name"], DEFAULT_TOOL_NAME)
        self.assertEqual(payload["version"], DEFAULT_VERSION)
        self.assertIn("active-directory", payload["tags"])
        self.assertIn("markdown_payload", payload)
        self.assertTrue(payload["reachability_check"]["skipped"])

    def test_cli_execution_skip_network_json(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_kitploit.py")
        )
        with tempfile.TemporaryDirectory() as td:
            out_md = os.path.join(td, "kitploit.md")
            out_json = os.path.join(td, "kitploit.json")
            res = subprocess.run(
                [
                    sys.executable,
                    script_path,
                    "-o",
                    out_md,
                    "--out-json",
                    out_json,
                    "--skip-network",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            self.assertEqual(data["tool_name"], DEFAULT_TOOL_NAME)
            self.assertTrue(os.path.isfile(out_md))
            self.assertTrue(os.path.isfile(out_json))

    def test_cli_execution_pypi_url(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_kitploit.py")
        )
        with tempfile.TemporaryDirectory() as td:
            out_md = os.path.join(td, "kitploit.md")
            out_json = os.path.join(td, "kitploit.json")
            custom_pypi = "https://pypi.org/project/custom-tanuki/"
            res = subprocess.run(
                [
                    sys.executable,
                    script_path,
                    "-o",
                    out_md,
                    "--out-json",
                    out_json,
                    "--pypi-url",
                    custom_pypi,
                    "--skip-network",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            self.assertEqual(data["pypi_url"], custom_pypi)
            with open(out_md, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(custom_pypi, content)

    def test_cli_strict_failure_on_unreachable(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_kitploit.py")
        )
        with tempfile.TemporaryDirectory() as td:
            out_md = os.path.join(td, "kitploit.md")
            out_json = os.path.join(td, "kitploit.json")
            res = subprocess.run(
                [
                    sys.executable,
                    script_path,
                    "--repo",
                    "https://github.com/Mafifrizi/definitely-nonexistent-repository-889911",
                    "-o",
                    out_md,
                    "--out-json",
                    out_json,
                    "--strict",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 1)
            self.assertIn("[WARNING]", res.stdout)

    def test_zero_em_dashes_in_script_source(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_kitploit.py")
        )
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("\u2014", content, "Em dash found in submit_kitploit.py source code")


if __name__ == "__main__":
    unittest.main()
