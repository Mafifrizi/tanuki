"""Unit tests for Cloud Mesh Ingestion & RFC 8693 Live Token Exchange."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tanuki.nhi import (
    discover_cloud_mesh,
    exchange_token_live,
    fetch_imds_token,
    format_live_exchange_terminal,
    format_mesh_report_terminal,
)


class TestCloudMeshAndLiveExchange(unittest.TestCase):
    def test_discover_cloud_mesh_baseline(self):
        # On a regular dev machine with no cloud metadata or spiffe socket
        rep = discover_cloud_mesh(
            spiffe_socket="/nonexistent/spire/socket.sock",
            imds_url="http://127.0.0.1:65533",
            timeout=0.1,
        )
        self.assertIn("status", rep)
        self.assertIn("discovered_identities", rep)
        self.assertIsInstance(rep["discovered_identities"], list)

    def test_discover_cloud_mesh_with_spiffe_socket(self):
        with tempfile.NamedTemporaryFile(suffix=".sock") as tmp:
            rep = discover_cloud_mesh(
                spiffe_socket=tmp.name,
                imds_url="http://127.0.0.1:65533",
                timeout=0.1,
            )
            sources = [i.get("source") for i in rep["discovered_identities"]]
            self.assertIn("spiffe_workload_api", sources)

    def test_fetch_imds_token_unreachable(self):
        res = fetch_imds_token(
            cloud_provider="auto",
            imds_base_url="http://127.0.0.1:65533",
            timeout=0.1,
        )
        self.assertEqual(res["status"], "NOT_AVAILABLE")
        self.assertIsNone(res["token"])

    def test_exchange_token_live_connection_error(self):
        res = exchange_token_live(
            endpoint="http://127.0.0.1:65533/oauth/v2/token",
            subject_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig",
            timeout=0.1,
        )
        self.assertEqual(res["status"], "ERROR")
        self.assertIn(res["error"], ("connection_failure", "unexpected_error"))

    def test_format_live_exchange_terminal(self):
        res = {
            "status": "SUCCESS",
            "http_status": 200,
            "endpoint": "https://sts.corp.local/oauth/v2/token",
            "access_token": "eyJh...mocked_token",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        term = format_live_exchange_terminal(res)
        self.assertIn("TANUKI RFC 8693 LIVE TOKEN EXCHANGE", term)
        self.assertIn("200 OK", term)

    def test_format_mesh_report_terminal(self):
        rep = {
            "status": "SUCCESS",
            "count": 1,
            "discovered_identities": [
                {
                    "source": "spiffe_workload_api",
                    "path": "/tmp/spire-agent/public/api.sock",
                    "details": "Local SPIFFE agent socket available",
                }
            ],
        }
        term = format_mesh_report_terminal(rep)
        self.assertIn("TANUKI CLOUD MESH IDENTITY INGESTION", term)
        self.assertIn("spiffe_workload_api", term)


if __name__ == "__main__":
    unittest.main()
