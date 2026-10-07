#!/usr/bin/env python3
"""Host-side automation wrapper for VirtualBox environments.

Provides resilience against COM lock contention (0x80bb0003 / VBOX_E_VM_ERROR)
via exponential backoff retries and shared folder IPC queueing.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

COM_LOCK_ERROR_PATTERNS = [
    "0x80bb0003",
    "VBOX_E_VM_ERROR",
    "0x80004005",
    "VBOX_E_INVALID_OBJECT_STATE",
    "object is not ready",
    "machine is locked",
    "The virtual machine is being powered down",
]

DEFAULT_RETRIES = 3
DEFAULT_BASE_DELAY = 0.5
DEFAULT_BACKOFF_FACTOR = 2.0


def is_com_lock_error(output: str) -> bool:
    """Check if command output contains known VirtualBox COM lock contention errors."""
    if not output:
        return False
    lower = output.lower()
    return any(p.lower() in lower for p in COM_LOCK_ERROR_PATTERNS)


def execute_vbox_guestcontrol(
    vm_name: str,
    cmd_args: List[str],
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: int = 30,
    vboxmanage_bin: str = "VBoxManage",
) -> Dict[str, Any]:
    """Execute a command inside a VirtualBox VM using VBoxManage guestcontrol."""
    args = [vboxmanage_bin, "guestcontrol", vm_name, "run"]
    if username:
        args.extend(["--username", username])
    if password:
        args.extend(["--password", password])
    args.extend(["--exe", cmd_args[0]])
    if len(cmd_args) > 1:
        args.append("--")
        args.extend(cmd_args[1:])

    start_time = time.time()
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        duration = time.time() - start_time
        return {
            "status": "SUCCESS" if proc.returncode == 0 else "ERROR",
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "duration": round(duration, 3),
            "command": args,
        }
    except subprocess.TimeoutExpired as exc:
        duration = time.time() - start_time
        return {
            "status": "TIMEOUT",
            "returncode": -1,
            "stdout": exc.stdout if isinstance(exc.stdout, str) else "",
            "stderr": f"Command timed out after {timeout}s",
            "duration": round(duration, 3),
            "command": args,
        }
    except FileNotFoundError:
        return {
            "status": "NOT_FOUND",
            "returncode": 127,
            "stdout": "",
            "stderr": f"Executable '{vboxmanage_bin}' not found on host PATH",
            "duration": 0.0,
            "command": args,
        }


def safe_vbox_exec(
    vm_name: str,
    cmd_args: List[str],
    username: Optional[str] = None,
    password: Optional[str] = None,
    max_retries: int = DEFAULT_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    timeout: int = 30,
    executor: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Execute command in VM with exponential backoff on COM lock contention."""
    exec_fn = executor or execute_vbox_guestcontrol
    delay = base_delay
    last_res: Dict[str, Any] = {}

    for attempt in range(max_retries + 1):
        res = exec_fn(
            vm_name=vm_name,
            cmd_args=cmd_args,
            username=username,
            password=password,
            timeout=timeout,
        )
        last_res = res
        combined_output = f"{res.get('stdout', '')}\n{res.get('stderr', '')}"

        if res.get("returncode") != 0 and is_com_lock_error(combined_output):
            if attempt < max_retries:
                time.sleep(delay)
                delay *= backoff_factor
                continue
        return res

    return last_res


def safe_ipc_exec(
    shared_folder_dir: str,
    command: str,
    timeout: float = 30.0,
    poll_interval: float = 0.2,
    task_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute command via shared folder file IPC queue without graphical tampering.

    Host drops task_<task_id>.json and waits for result_<task_id>.json.
    """
    actual_dir = shared_folder_dir
    if not os.path.isdir(actual_dir) and actual_dir in (None, "", "./ipc_shared"):
        for cand in ("/media/sf_LAB", r"D:\kraii"):
            if os.path.isdir(cand):
                actual_dir = cand
                break

    if not os.path.isdir(actual_dir):
        return {
            "status": "ERROR",
            "returncode": 1,
            "stdout": "",
            "stderr": f"Shared folder directory does not exist: {shared_folder_dir}",
            "duration": 0.0,
        }

    tid = task_id or f"task_{uuid.uuid4().hex[:12]}"
    task_file = os.path.join(actual_dir, f"{tid}.json")
    result_file = os.path.join(actual_dir, f"result_{tid}.json")
    canonical_result_file = os.path.join(actual_dir, "result.json")
    used_canonical = False

    payload = {
        "task_id": tid,
        "command": command,
        "created_at": time.time(),
    }

    # Write task payload
    tmp_file = f"{task_file}.tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp_file, task_file)
    except OSError as exc:
        return {
            "status": "ERROR",
            "returncode": 1,
            "stdout": "",
            "stderr": f"Failed to write task payload: {exc}",
            "duration": 0.0,
        }

    start_time = time.time()
    try:
        while time.time() - start_time < timeout:
            target_res_path = None
            if os.path.exists(result_file):
                target_res_path = result_file
            elif os.path.exists(canonical_result_file):
                target_res_path = canonical_result_file

            if target_res_path:
                try:
                    with open(target_res_path, "r", encoding="utf-8") as f:
                        result_data = json.load(f)
                    if target_res_path == canonical_result_file:
                        res_tid = result_data.get("task_id")
                        if res_tid and res_tid != tid:
                            time.sleep(poll_interval)
                            continue
                        used_canonical = True

                    return {
                        "status": "SUCCESS" if result_data.get("returncode", 0) == 0 else "ERROR",
                        "returncode": result_data.get("returncode", 0),
                        "stdout": result_data.get("stdout", ""),
                        "stderr": result_data.get("stderr", ""),
                        "duration": round(time.time() - start_time, 3),
                        "task_id": tid,
                    }
                except (json.JSONDecodeError, OSError):
                    time.sleep(poll_interval)
                    continue
            time.sleep(poll_interval)

        return {
            "status": "TIMEOUT",
            "returncode": -1,
            "stdout": "",
            "stderr": f"IPC execution timed out after {timeout}s waiting for {result_file}",
            "duration": round(time.time() - start_time, 3),
            "task_id": tid,
        }
    finally:
        cleanup_targets = [task_file, result_file, tmp_file]
        if used_canonical:
            cleanup_targets.append(canonical_result_file)
        for path in cleanup_targets:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VirtualBox safe execution wrapper with COM backoff and shared folder IPC."
    )
    parser.add_argument("--mode", choices=["vboxmanage", "ipc"], default="ipc", help="Execution mode")
    parser.add_argument("--vm", help="VirtualBox VM name or UUID (for vboxmanage mode)")
    parser.add_argument("--cmd", required=True, help="Command to execute")
    parser.add_argument("--shared-dir", default="./ipc_shared", help="Host directory for shared folder IPC")
    parser.add_argument("--username", help="Guest username (vboxmanage mode)")
    parser.add_argument("--password", help="Guest password (vboxmanage mode)")
    parser.add_argument("--timeout", type=float, default=30.0, help="Command timeout in seconds")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Max retry attempts for COM locks")
    parser.add_argument("--base-delay", type=float, default=DEFAULT_BASE_DELAY, help="Base backoff delay in seconds")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    if args.mode == "vboxmanage":
        if not args.vm:
            sys.stderr.write("Error: --vm required for vboxmanage mode\n")
            sys.exit(1)
        res = safe_vbox_exec(
            vm_name=args.vm,
            cmd_args=args.cmd.split(),
            username=args.username,
            password=args.password,
            max_retries=args.retries,
            base_delay=args.base_delay,
            timeout=int(args.timeout),
        )
    else:
        res = safe_ipc_exec(
            shared_folder_dir=args.shared_dir,
            command=args.cmd,
            timeout=args.timeout,
        )

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Status: {res.get('status')} (exit {res.get('returncode')})")
        if res.get("stdout"):
            print(f"Stdout:\n{res.get('stdout')}")
        if res.get("stderr"):
            print(f"Stderr:\n{res.get('stderr')}")

    sys.exit(res.get("returncode", 0) if res.get("returncode", 0) >= 0 else 1)


if __name__ == "__main__":
    main()
