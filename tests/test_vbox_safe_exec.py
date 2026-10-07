"""Unit tests for VirtualBox safe execution wrapper."""

import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.vbox_safe_exec import (
    is_com_lock_error,
    safe_ipc_exec,
    safe_vbox_exec,
)


class TestVBoxSafeExec(unittest.TestCase):
    def test_is_com_lock_error(self):
        self.assertTrue(is_com_lock_error("Error 0x80bb0003: The object is not ready"))
        self.assertTrue(is_com_lock_error("VBOX_E_VM_ERROR occurred"))
        self.assertTrue(is_com_lock_error("Call to run failed: machine is locked"))
        self.assertFalse(is_com_lock_error("Permission denied"))
        self.assertFalse(is_com_lock_error("File not found"))
        self.assertFalse(is_com_lock_error(""))

    def test_safe_vbox_exec_retries_on_com_lock(self):
        attempts = 0

        def mock_executor(**kwargs):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                return {
                    "status": "ERROR",
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "VBoxManage: error: 0x80bb0003: The object is not ready",
                    "duration": 0.05,
                }
            return {
                "status": "SUCCESS",
                "returncode": 0,
                "stdout": "uid=0(root) gid=0(root)",
                "stderr": "",
                "duration": 0.02,
            }

        res = safe_vbox_exec(
            vm_name="Debian12_Lab",
            cmd_args=["id"],
            max_retries=3,
            base_delay=0.01,
            backoff_factor=1.5,
            executor=mock_executor,
        )

        self.assertEqual(attempts, 3)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["returncode"], 0)
        self.assertIn("uid=0", res["stdout"])

    def test_safe_vbox_exec_exhausts_retries(self):
        attempts = 0

        def mock_executor(**kwargs):
            nonlocal attempts
            attempts += 1
            return {
                "status": "ERROR",
                "returncode": 1,
                "stdout": "",
                "stderr": "VBoxManage: error: VBOX_E_VM_ERROR",
                "duration": 0.01,
            }

        res = safe_vbox_exec(
            vm_name="Debian12_Lab",
            cmd_args=["id"],
            max_retries=2,
            base_delay=0.01,
            executor=mock_executor,
        )

        # 1 initial + 2 retries = 3 attempts total
        self.assertEqual(attempts, 3)
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("VBOX_E_VM_ERROR", res["stderr"])

    def test_safe_vbox_exec_no_retry_on_regular_error(self):
        attempts = 0

        def mock_executor(**kwargs):
            nonlocal attempts
            attempts += 1
            return {
                "status": "ERROR",
                "returncode": 127,
                "stdout": "",
                "stderr": "bash: tanuki: command not found",
                "duration": 0.01,
            }

        res = safe_vbox_exec(
            vm_name="Debian12_Lab",
            cmd_args=["tanuki", "doctor"],
            max_retries=3,
            base_delay=0.01,
            executor=mock_executor,
        )

        # Should not retry normal command error
        self.assertEqual(attempts, 1)
        self.assertEqual(res["returncode"], 127)

    def test_safe_ipc_exec_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            task_id = "test_task_123"

            def guest_worker():
                # Simulate guest worker picking up task file and creating result
                task_path = os.path.join(tmp_dir, f"{task_id}.json")
                for _ in range(50):
                    if os.path.exists(task_path):
                        with open(task_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        result_path = os.path.join(tmp_dir, f"result_{task_id}.json")
                        with open(result_path, "w", encoding="utf-8") as f:
                            json.dump({
                                "returncode": 0,
                                "stdout": f"Executed: {data['command']}",
                                "stderr": "",
                            }, f)
                        break
                    time.sleep(0.02)

            t = threading.Thread(target=guest_worker)
            t.daemon = True
            t.start()

            res = safe_ipc_exec(
                shared_folder_dir=tmp_dir,
                command="kinit -k host/srv01@CORP.LOCAL",
                timeout=5.0,
                poll_interval=0.02,
                task_id=task_id,
            )

            t.join()
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["returncode"], 0)
            self.assertIn("Executed: kinit -k", res["stdout"])

            # Verify files were cleaned up
            self.assertFalse(os.path.exists(os.path.join(tmp_dir, f"{task_id}.json")))
            self.assertFalse(os.path.exists(os.path.join(tmp_dir, f"result_{task_id}.json")))

    def test_safe_ipc_exec_timeout(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = safe_ipc_exec(
                shared_folder_dir=tmp_dir,
                command="sleep 10",
                timeout=0.1,
                poll_interval=0.02,
            )
            self.assertEqual(res["status"], "TIMEOUT")
            self.assertEqual(res["returncode"], -1)

    def test_safe_ipc_exec_invalid_dir(self):
        res = safe_ipc_exec(
            shared_folder_dir="/nonexistent/directory/path/for/ipc",
            command="whoami",
        )
        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["returncode"], 1)


if __name__ == "__main__":
    unittest.main()
