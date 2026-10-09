import email
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from submit_packetstorm import (
    build_submission_body,
    create_rfc822_message,
    save_eml_file,
    send_via_smtp,
    find_default_distribution_archive,
    DEFAULT_TO,
    DEFAULT_FROM,
    DEFAULT_VERSION,
)


class TestPacketStormSubmission(unittest.TestCase):
    def test_build_submission_body(self):
        body = build_submission_body()
        self.assertIn("Title: Tanuki (tanuki-ad)", body)
        self.assertIn(f"Version: {DEFAULT_VERSION}", body)
        self.assertIn("pip install tanuki-ad", body)
        self.assertNotIn("\u2014", body, "Em dash detected in submission body")

    def test_create_rfc822_message_headers(self):
        msg = create_rfc822_message(
            to_addr="test@example.com",
            from_addr="Author <author@example.com>",
            subject="Test Subject",
            version="1.2.1",
        )
        self.assertEqual(msg["To"], "test@example.com")
        self.assertEqual(msg["From"], "Author <author@example.com>")
        self.assertEqual(msg["Subject"], "Test Subject")
        self.assertTrue(msg["Date"])
        self.assertTrue(msg["Message-ID"])
        self.assertEqual(msg["MIME-Version"], "1.0")

    def test_create_rfc822_message_with_attachment(self):
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tf:
            tf.write(b"fake_tar_gz_data")
            attach_path = tf.name

        try:
            msg = create_rfc822_message(attachment_path=attach_path)
            self.assertTrue(msg.is_multipart())
            parts = list(msg.iter_attachments())
            self.assertEqual(len(parts), 1)
            attachment = parts[0]
            self.assertEqual(attachment.get_filename(), os.path.basename(attach_path))
            self.assertEqual(attachment.get_content_type(), "application/gzip")
            self.assertEqual(attachment.get_content(), b"fake_tar_gz_data")
        finally:
            if os.path.exists(attach_path):
                os.unlink(attach_path)

    def test_save_eml_file(self):
        msg = create_rfc822_message()
        with tempfile.TemporaryDirectory() as td:
            out_eml = os.path.join(td, "submission.eml")
            saved = save_eml_file(msg, out_eml)
            self.assertTrue(saved.is_file())
            # Parse saved EML to verify valid RFC-822 format
            with open(saved, "rb") as f:
                parsed = email.message_from_binary_file(f)
            self.assertEqual(parsed["To"], DEFAULT_TO)
            self.assertEqual(parsed["From"], DEFAULT_FROM)

    @patch("smtplib.SMTP")
    def test_send_via_smtp_success(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        msg = create_rfc822_message()
        success, message = send_via_smtp(
            msg=msg,
            smtp_host="mail.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            use_tls=True,
        )
        self.assertTrue(success)
        mock_smtp_class.assert_called_once_with("mail.example.com", 587, timeout=15.0)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user", "pass")
        mock_server.send_message.assert_called_once_with(msg)
        mock_server.quit.assert_called_once()

    @patch("smtplib.SMTP")
    def test_send_via_smtp_no_tls(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        msg = create_rfc822_message()
        success, message = send_via_smtp(
            msg=msg,
            smtp_host="mail.example.com",
            smtp_port=25,
            use_tls=False,
        )
        self.assertTrue(success)
        mock_smtp_class.assert_called_once_with("mail.example.com", 25, timeout=15.0)
        mock_server.starttls.assert_not_called()
        mock_server.send_message.assert_called_once_with(msg)
        mock_server.quit.assert_called_once()

    @patch("smtplib.SMTP_SSL")
    def test_send_via_smtp_ssl(self, mock_smtp_ssl_class):
        mock_server = MagicMock()
        mock_smtp_ssl_class.return_value = mock_server

        msg = create_rfc822_message()
        success, message = send_via_smtp(
            msg=msg,
            smtp_host="mail.example.com",
            smtp_port=465,
            smtp_user="user",
            smtp_pass="pass",
        )
        self.assertTrue(success)
        mock_smtp_ssl_class.assert_called_once_with("mail.example.com", 465, timeout=15.0)
        mock_server.login.assert_called_once_with("user", "pass")
        mock_server.send_message.assert_called_once_with(msg)
        mock_server.quit.assert_called_once()

    @patch("smtplib.SMTP")
    def test_send_via_smtp_failure_handled(self, mock_smtp_class):
        mock_smtp_class.side_effect = ConnectionRefusedError("Connection refused")
        msg = create_rfc822_message()
        success, message = send_via_smtp(
            msg=msg,
            smtp_host="mail.example.com",
            smtp_port=25,
            use_tls=False,
        )
        self.assertFalse(success)
        self.assertIn("Connection refused", message)

    def test_cli_execution_json(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_packetstorm.py")
        )
        with tempfile.TemporaryDirectory() as td:
            out_eml = os.path.join(td, "test.eml")
            res = subprocess.run(
                [
                    sys.executable,
                    script_path,
                    "-o",
                    out_eml,
                    "--no-attach",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "SUCCESS")
            self.assertEqual(data["recipient"], DEFAULT_TO)
            self.assertTrue(os.path.isfile(out_eml))

    def test_cli_execution_dynamic_version_subject(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_packetstorm.py")
        )
        with tempfile.TemporaryDirectory() as td:
            out_eml = os.path.join(td, "test_ver.eml")
            res = subprocess.run(
                [
                    sys.executable,
                    script_path,
                    "-o",
                    out_eml,
                    "--version",
                    "2.0.0",
                    "--no-attach",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            self.assertIn("2.0.0", data["subject"])
            self.assertEqual(data["version"], "2.0.0")

    def test_cli_missing_attachment_fails(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_packetstorm.py")
        )
        res = subprocess.run(
            [
                sys.executable,
                script_path,
                "--attach",
                "/nonexistent/file/archive.tar.gz",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)

    def test_find_default_distribution_archive_ordering(self):
        with tempfile.TemporaryDirectory() as td:
            dist_dir = os.path.join(td, "dist")
            os.makedirs(dist_dir)
            f_old = os.path.join(dist_dir, "tanuki_ad-1.2.0.tar.gz")
            f_new = os.path.join(dist_dir, "tanuki_ad-1.2.1.tar.gz")
            with open(f_old, "w") as f:
                f.write("old")
            with open(f_new, "w") as f:
                f.write("new")

            from pathlib import Path
            chosen = find_default_distribution_archive(Path(td))
            self.assertEqual(chosen, f_new)

    def test_zero_em_dashes_in_script_source(self):
        script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "submit_packetstorm.py")
        )
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("\u2014", content, "Em dash found in submit_packetstorm.py source code")


if __name__ == "__main__":
    unittest.main()
