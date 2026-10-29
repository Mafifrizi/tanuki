"""Regression and edge-case tests for the 14 security and logic audit fixes."""

from __future__ import annotations

import base64
import ctypes
import errno
import gzip
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from tanuki import cli
from tanuki.auth import (
    acquire_tgs,
    acquire_tgs_via_ctypes,
    acquire_tgt,
    acquire_tgt_via_ctypes,
    find_krb5_library,
    inject_ticket_to_keyring,
)
from tanuki.config import generate_krb5_conf, parse_srv_response, write_krb5_conf_file
from tanuki.keytab import parse_keytab_bytes, parse_keytab_file, parse_keytab_stream
from tanuki.nhi import b64url_decode, parse_workload_jwt
from tanuki.purge import run_purge
from tanuki.shadow import parse_key_credential_link


def build_synthetic_shadow_blob(
    version: int = 0x00000200,
    key_type: str = "RSA",
    usage: int = 0x01,
    source: int = 0x00,
) -> bytes:
    """Test fixture: build a valid msDS-KeyCredentialLink binary blob per [MS-ADTS] 2.2.20."""
    blob = bytearray()
    blob.extend(struct.pack("<I", version))
    cng_hdr = struct.pack("<4sIIIII", b"RSA1", 2048, 3, 256, 0, 0)
    pub_exp = b"\x01\x00\x01"
    modulus = os.urandom(256)
    modulus = bytes([modulus[0] | 0x80]) + modulus[1:-1] + bytes([modulus[-1] | 0x01])
    km_bytes = cng_hdr + pub_exp + modulus
    blob.extend(struct.pack("<HB", len(km_bytes), 0x03))
    blob.extend(km_bytes)
    kid = hashlib.sha256(km_bytes).digest()
    blob.extend(struct.pack("<HB", len(kid), 0x01))
    blob.extend(kid)
    blob.extend(struct.pack("<HB", 1, 0x04))
    blob.append(usage)
    blob.extend(struct.pack("<HB", 1, 0x05))
    blob.append(source)
    dev_guid = bytes.fromhex("11223344556677889900aabbccddeeff")
    blob.extend(struct.pack("<HB", 16, 0x06))
    blob.extend(dev_guid)
    custom_info = bytes([0x01, 0x01])
    blob.extend(struct.pack("<HB", len(custom_info), 0x07))
    blob.extend(custom_info)
    ft_creation = 133918032000000000
    blob.extend(struct.pack("<HB", 8, 0x09))
    blob.extend(struct.pack("<Q", ft_creation))
    return bytes(blob)


def _build_keytab_v2_entry(
    realm: str = "LAB.LOCAL",
    components: list[str] | None = None,
    keytype: int = 18,
    key_bytes: bytes | None = None,
    vno: int = 3,
    timestamp: int = 1700000000,
) -> bytes:
    if components is None:
        components = ["HTTP", "srv01.lab.local"]
    if key_bytes is None:
        key_bytes = bytes(range(1, 33))  # 32-byte distinct AES-256 key

    realm_b = realm.encode("utf-8")
    body = bytearray()
    body.extend(struct.pack(">h", len(components)))
    body.extend(struct.pack(">H", len(realm_b)))
    body.extend(realm_b)
    for comp in components:
        cb = comp.encode("utf-8")
        body.extend(struct.pack(">H", len(cb)))
        body.extend(cb)
    body.extend(struct.pack(">IIBhH", 1, timestamp, vno & 0xFF, keytype, len(key_bytes)))
    body.extend(key_bytes)
    body.extend(struct.pack(">I", vno))
    return struct.pack(">i", len(body)) + bytes(body)


def _build_keytab_v2(entries_raw: list[bytes]) -> bytes:
    return b"\x05\x02" + b"".join(entries_raw)


def _encode_dns_labels(name: str) -> bytes:
    out = bytearray()
    for lbl in name.strip(".").split("."):
        b = lbl.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _build_srv_response(tx_id: int, declared_ancount: int, actual_records: int) -> bytes:
    qname = _encode_dns_labels("_kerberos._tcp.lab.local")
    header = struct.pack(">HHHHHH", tx_id, 0x8180, 1, declared_ancount, 0, 0)
    question = qname + struct.pack(">HH", 33, 1)
    answers = bytearray()
    for idx in range(actual_records):
        target = _encode_dns_labels(f"dc{idx:03d}.lab.local")
        rdata = struct.pack(">HHH", 0, 100, 88 + (idx % 10)) + target
        answers.extend(qname)
        answers.extend(struct.pack(">HHIH", 33, 1, 300, len(rdata)))
        answers.extend(rdata)
    return header + question + bytes(answers)


class TestFinding01KeyHexRedaction(unittest.TestCase):
    def test_parse_keytab_stream_redacts_raw_key_material(self):
        secret_key = bytes.fromhex(
            "deadbeef" + "0123456789abcdef" * 3 + "cafebabe"
        )
        self.assertEqual(len(secret_key), 32)
        kt_data = _build_keytab_v2([_build_keytab_v2_entry(key_bytes=secret_key)])

        entries = parse_keytab_stream(io.BytesIO(kt_data))
        self.assertEqual(len(entries), 1)
        entry = entries[0]

        self.assertNotIn("key_hex", entry)
        self.assertEqual(entry["key_preview"], "deadbeef...")
        expected_fp = hashlib.sha256(secret_key).hexdigest()[:16]
        self.assertEqual(entry["key_fingerprint"], expected_fp)
        self.assertEqual(len(entry["key_fingerprint"]), 16)

        serialized = json.dumps(entries)
        self.assertNotIn("key_hex", serialized)
        self.assertNotIn(secret_key[4:].hex(), serialized)

    def test_parse_keytab_empty_key_edge_case(self):
        kt_data = _build_keytab_v2([_build_keytab_v2_entry(key_bytes=b"")])
        entries = parse_keytab_bytes(kt_data)
        self.assertEqual(entries[0]["key_preview"], "...")
        self.assertEqual(entries[0]["key_fingerprint"], hashlib.sha256(b"").hexdigest()[:16])

    def test_cli_keytab_json_and_text_do_not_expose_key_hex(self):
        secret_key = bytes.fromhex("a1b2c3d4" + "ffeeddccbbaa9988" * 3 + "11223344")
        kt_data = _build_keytab_v2([_build_keytab_v2_entry(key_bytes=secret_key)])
        with tempfile.TemporaryDirectory() as tmpdir:
            kt_path = os.path.join(tmpdir, "svc.keytab")
            with open(kt_path, "wb") as f:
                f.write(kt_data)

            proc_json = subprocess.run(
                [sys.executable, "-m", "tanuki", "keytab", kt_path, "--json"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc_json.returncode, 0, msg=proc_json.stderr)
            self.assertNotIn("key_hex", proc_json.stdout)
            self.assertNotIn(secret_key[4:].hex(), proc_json.stdout)
            parsed = json.loads(proc_json.stdout)
            self.assertEqual(parsed[0]["key_preview"], "a1b2c3d4...")
            self.assertEqual(
                parsed[0]["key_fingerprint"],
                hashlib.sha256(secret_key).hexdigest()[:16],
            )

            buf = io.StringIO()
            with patch("sys.stdout", buf):
                cli.handle_keytab(kt_path, json_output=False)
            text_out = buf.getvalue()
            self.assertIn("a1b2c3d4...", text_out)
            self.assertNotIn("a1b2c3d4......", text_out)
            self.assertNotIn(secret_key[4:].hex(), text_out)


class TestFinding02Krb5ConfigEnvIsolation(unittest.TestCase):
    def setUp(self):
        self._saved_env = os.environ.get("KRB5_CONFIG")

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("KRB5_CONFIG", None)
        else:
            os.environ["KRB5_CONFIG"] = self._saved_env

    def test_acquire_tgt_via_ctypes_restores_unset_env_on_missing_lib_and_init_fail(self):
        os.environ.pop("KRB5_CONFIG", None)
        with patch("tanuki.auth.find_static_binary", return_value=None):
            res = acquire_tgt_via_ctypes(
                keytab_path="/tmp/fake.keytab",
                principal="svc@LAB.LOCAL",
                ccache_path="/tmp/fake.ccache",
                lib_path="/nonexistent/libkrb5.so.3",
                krb5_conf="/tmp/temp_krb5.conf",
            )
        self.assertEqual(res["reason_code"], "MISSING_GSSAPI_LIBRARY")
        self.assertNotIn("KRB5_CONFIG", os.environ)

        observed_env = {}
        mock_lib = MagicMock()

        def fake_init_ctx(_ctx_ptr):
            observed_env["during_init"] = os.environ.get("KRB5_CONFIG")
            return -1765328160

        mock_lib.krb5_init_context.side_effect = fake_init_ctx
        with patch("ctypes.CDLL", return_value=mock_lib):
            res2 = acquire_tgt_via_ctypes(
                keytab_path="/tmp/fake.keytab",
                principal="svc@LAB.LOCAL",
                ccache_path="/tmp/fake.ccache",
                lib_path="/usr/lib/libkrb5.so.3",
                krb5_conf="/tmp/temp_krb5.conf",
            )
        self.assertEqual(res2["reason_code"], "INIT_CONTEXT_FAILED")
        self.assertEqual(observed_env["during_init"], os.path.abspath("/tmp/temp_krb5.conf"))
        self.assertNotIn("KRB5_CONFIG", os.environ)

    def test_acquire_tgt_and_tgs_via_ctypes_restore_previous_env_even_on_exception(self):
        os.environ["KRB5_CONFIG"] = "/etc/original_krb5.conf"
        mock_lib = MagicMock()
        mock_lib.krb5_init_context.return_value = 0
        mock_lib.krb5_parse_name.side_effect = RuntimeError("boom inside ctypes")
        mock_lib.krb5_cc_resolve.side_effect = RuntimeError("boom inside tgs ctypes")

        with patch("ctypes.CDLL", return_value=mock_lib):
            with self.assertRaises(RuntimeError):
                acquire_tgt_via_ctypes(
                    keytab_path="/tmp/fake.keytab",
                    principal="svc@LAB.LOCAL",
                    ccache_path="/tmp/fake.ccache",
                    lib_path="/usr/lib/libkrb5.so.3",
                    krb5_conf="/tmp/override_tgt.conf",
                )
        self.assertEqual(os.environ.get("KRB5_CONFIG"), "/etc/original_krb5.conf")

        with patch("ctypes.CDLL", return_value=mock_lib):
            with self.assertRaises(RuntimeError):
                acquire_tgs_via_ctypes(
                    spn="HTTP/srv@LAB.LOCAL",
                    ccache_path="/tmp/fake.ccache",
                    lib_path="/usr/lib/libkrb5.so.3",
                    krb5_conf="/tmp/override_tgs.conf",
                )
        self.assertEqual(os.environ.get("KRB5_CONFIG"), "/etc/original_krb5.conf")

        res_tgs = acquire_tgs_via_ctypes(
            spn="HTTP/srv@LAB.LOCAL",
            ccache_path="/tmp/fake.ccache",
            lib_path="/nonexistent/libkrb5.so.3",
            krb5_conf="/tmp/override_tgs2.conf",
        )
        self.assertEqual(res_tgs["reason_code"], "MISSING_GSSAPI_LIBRARY")
        self.assertEqual(os.environ.get("KRB5_CONFIG"), "/etc/original_krb5.conf")


class TestFinding03ONofollowEloopSymlinkGuard(unittest.TestCase):
    def test_acquire_tgt_via_ctypes_rejects_eloop_toctou_symlink(self):
        mock_lib = MagicMock()
        mock_lib.krb5_init_context.return_value = 0
        mock_lib.krb5_parse_name.return_value = 0
        mock_lib.krb5_kt_resolve.return_value = 0

        with patch("ctypes.CDLL", return_value=mock_lib), \
             patch("tanuki.auth.os.name", "posix"), \
             patch("tanuki.auth.os.path.islink", return_value=False), \
             patch.object(os, "O_NOFOLLOW", 0x20000, create=True), \
             patch("tanuki.auth.os.open", side_effect=OSError(errno.ELOOP, "Symlink loop")):
            res = acquire_tgt_via_ctypes(
                keytab_path="/tmp/test.keytab",
                principal="svc@LAB.LOCAL",
                ccache_path="/tmp/race.ccache",
                lib_path="/usr/lib/libkrb5.so.3",
            )

        self.assertEqual(res["status"], "ERROR")
        self.assertEqual(res["reason_code"], "SYMLINK_REJECTED")
        self.assertEqual(res["category"], "SECURITY_VIOLATION")
        self.assertEqual(res["target"], os.path.abspath("/tmp/race.ccache"))
        mock_lib.krb5_cc_resolve.assert_not_called()

    def test_acquire_tgt_via_ctypes_allows_enoent_to_continue(self):
        mock_lib = MagicMock()
        mock_lib.krb5_init_context.return_value = 0
        mock_lib.krb5_parse_name.return_value = 0
        mock_lib.krb5_kt_resolve.return_value = 0
        mock_lib.krb5_cc_resolve.return_value = -1

        with patch("ctypes.CDLL", return_value=mock_lib), \
             patch("tanuki.auth.os.name", "posix"), \
             patch("tanuki.auth.os.path.islink", return_value=False), \
             patch.object(os, "O_NOFOLLOW", 0x20000, create=True), \
             patch("tanuki.auth.os.open", side_effect=OSError(errno.ENOENT, "Missing")):
            res = acquire_tgt_via_ctypes(
                keytab_path="/tmp/test.keytab",
                principal="svc@LAB.LOCAL",
                ccache_path="/tmp/new.ccache",
                lib_path="/usr/lib/libkrb5.so.3",
            )

        self.assertEqual(res["reason_code"], "CCACHE_RESOLVE_FAILED")
        mock_lib.krb5_cc_resolve.assert_called_once()

    def test_acquire_tgt_kinit_path_rejects_eloop_toctou_symlink(self):
        kt_data = _build_keytab_v2([_build_keytab_v2_entry()])
        with tempfile.TemporaryDirectory() as tmpdir:
            kt_path = os.path.join(tmpdir, "svc.keytab")
            cc_path = os.path.join(tmpdir, "race.ccache")
            with open(kt_path, "wb") as f:
                f.write(kt_data)

            with patch("shutil.which", return_value="/usr/bin/kinit"), \
                 patch("tanuki.auth.os.name", "posix"), \
                 patch("tanuki.auth.os.path.islink", return_value=False), \
                 patch.object(os, "O_NOFOLLOW", 0x20000, create=True), \
                 patch("tanuki.auth.os.open", side_effect=OSError(errno.ELOOP, "Symlink loop")), \
                 patch("tanuki.config.discover_dc_via_srv", return_value=None), \
                 patch("subprocess.run") as mock_run:
                res = acquire_tgt(kt_path, principal="HTTP/srv01.lab.local@LAB.LOCAL", ccache_path=cc_path)

            self.assertEqual(res["status"], "ERROR")
            self.assertEqual(res["reason_code"], "SYMLINK_REJECTED")
            self.assertEqual(res["category"], "SECURITY_VIOLATION")
            self.assertEqual(res["target"], os.path.abspath(cc_path))
            mock_run.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Requires real POSIX symlink and kernel O_NOFOLLOW")
    def test_real_posix_kernel_o_nofollow_eloop_without_mocking_os_open(self):
        kt_data = _build_keytab_v2([_build_keytab_v2_entry()])
        real_lib = find_krb5_library()
        with tempfile.TemporaryDirectory() as tmpdir:
            victim_path = os.path.join(tmpdir, "victim.txt")
            with open(victim_path, "wb") as vf:
                vf.write(b"SENSITIVE_VICTIM_CONTENT")
            kt_path = os.path.join(tmpdir, "svc.keytab")
            with open(kt_path, "wb") as kf:
                kf.write(kt_data)
            cc_link = os.path.join(tmpdir, "toctou_race.ccache")
            os.symlink(victim_path, cc_link)
            valid_conf = os.path.join(tmpdir, "valid_krb5.conf")
            with open(valid_conf, "w", encoding="utf-8") as cf:
                cf.write(generate_krb5_conf("LAB.LOCAL", "127.0.0.1"))

            mock_lib = MagicMock()
            mock_lib.krb5_init_context.return_value = 0
            mock_lib.krb5_parse_name.return_value = 0
            mock_lib.krb5_kt_resolve.return_value = 0

            with patch("ctypes.CDLL", return_value=mock_lib), \
                 patch("tanuki.auth.os.path.islink", return_value=False):
                res_ctypes = acquire_tgt_via_ctypes(
                    keytab_path=kt_path,
                    principal="HTTP/srv01.lab.local@LAB.LOCAL",
                    ccache_path=cc_link,
                    lib_path="/usr/lib/libkrb5.so.3",
                    krb5_conf=valid_conf,
                )

            self.assertEqual(res_ctypes["status"], "ERROR")
            self.assertEqual(res_ctypes["reason_code"], "SYMLINK_REJECTED")
            self.assertEqual(res_ctypes["category"], "SECURITY_VIOLATION")
            self.assertEqual(res_ctypes["target"], os.path.abspath(cc_link))
            mock_lib.krb5_cc_resolve.assert_not_called()

            if real_lib:
                with patch("tanuki.auth.os.path.islink", return_value=False):
                    res_real_ffi = acquire_tgt_via_ctypes(
                        keytab_path=kt_path,
                        principal="HTTP/srv01.lab.local@LAB.LOCAL",
                        ccache_path=cc_link,
                        lib_path=real_lib,
                        krb5_conf=valid_conf,
                    )
                self.assertEqual(res_real_ffi["status"], "ERROR")
                self.assertEqual(res_real_ffi["reason_code"], "SYMLINK_REJECTED")
                self.assertEqual(res_real_ffi["category"], "SECURITY_VIOLATION")
                self.assertEqual(res_real_ffi["target"], os.path.abspath(cc_link))

            with patch("shutil.which", return_value="/usr/bin/kinit"), \
                 patch("tanuki.auth.os.path.islink", return_value=False), \
                 patch("tanuki.ldap.probe_tcp_port", return_value=(True, "ok")), \
                 patch("subprocess.run") as mock_run:
                res_kinit = acquire_tgt(
                    kt_path,
                    principal="HTTP/srv01.lab.local@LAB.LOCAL",
                    ccache_path=cc_link,
                    krb5_conf=valid_conf,
                )

            self.assertEqual(res_kinit["status"], "ERROR")
            self.assertEqual(res_kinit["reason_code"], "SYMLINK_REJECTED")
            self.assertEqual(res_kinit["category"], "SECURITY_VIOLATION")
            self.assertEqual(res_kinit["target"], os.path.abspath(cc_link))
            mock_run.assert_not_called()

            with open(victim_path, "rb") as vf:
                self.assertEqual(vf.read(), b"SENSITIVE_VICTIM_CONTENT")


class TestFinding04InstallScriptIntegrity(unittest.TestCase):
    EXPECTED_SHA256 = "80bf7ff0ee1f47784eb265ff6a68ba609ea569deba49aa1e6c9eeaf6a5fbda30"

    def setUp(self):
        self.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.install_sh = os.path.join(self.repo_root, "install.sh")

    @staticmethod
    def _find_bash() -> str | None:
        if os.name == "nt":
            cand = r"C:\Program Files\Git\usr\bin\bash.exe"
            return cand if os.path.isfile(cand) else None
        return shutil.which("bash")

    @staticmethod
    def _populate_isolated_bin(
        fake_bin: str,
        bash_bin: str,
        include_sha256sum: bool,
        include_tar: bool,
    ) -> None:
        if os.name == "nt":
            bash_dir = os.path.dirname(bash_bin)
            allowed_exes = {
                "bash.exe", "sh.exe", "env.exe", "awk.exe", "gawk.exe",
                "mktemp.exe", "rm.exe", "mkdir.exe", "chmod.exe", "cat.exe",
                "cp.exe", "grep.exe", "dirname.exe", "pwd.exe",
            }
            if include_sha256sum:
                allowed_exes.add("sha256sum.exe")
            if include_tar:
                allowed_exes.update(("tar.exe", "gzip.exe"))
            for fname in os.listdir(bash_dir):
                low = fname.lower()
                if low.startswith("git"):
                    continue
                if low in allowed_exes or (low.endswith(".dll") and low.startswith("msys-")):
                    dst = os.path.join(fake_bin, fname)
                    if not os.path.exists(dst):
                        shutil.copy2(os.path.join(bash_dir, fname), dst)
        else:
            posix_tools = [
                "bash", "sh", "env", "awk", "mktemp", "rm", "mkdir",
                "chmod", "cat", "cp", "grep", "dirname", "pwd",
            ]
            if include_sha256sum:
                posix_tools.append("sha256sum" if shutil.which("sha256sum") else "shasum")
            if include_tar:
                posix_tools.extend(["tar", "gzip"])
            for tool in posix_tools:
                dst = os.path.join(fake_bin, tool)
                if os.path.exists(dst):
                    continue
                src = shutil.which(tool)
                if src:
                    os.symlink(src, dst)

    @staticmethod
    def _build_deterministic_mock_tar_gz() -> tuple[bytes, str]:
        tar_buf = io.BytesIO()
        files = {
            "tanuki-1.3.0/pyproject.toml": b'[project]\nname = "tanuki"\nversion = "1.3.0"\n',
            "tanuki-1.3.0/SKILL.md": b"# Tanuki Deterministic Skill Payload\n",
            "tanuki-1.3.0/.cursor/rules/tanuki.mdc": b"# Deterministic Cursor Rule\n",
        }
        with tarfile.open(fileobj=tar_buf, mode="w") as tf:
            for member_name, payload in sorted(files.items()):
                ti = tarfile.TarInfo(name=member_name)
                ti.size = len(payload)
                ti.mtime = 1700000000
                ti.mode = 0o644
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                tf.addfile(ti, io.BytesIO(payload))

        gz_buf = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, compresslevel=9, mtime=0) as gz:
            gz.write(tar_buf.getvalue())
        archive_bytes = gz_buf.getvalue()
        return archive_bytes, hashlib.sha256(archive_bytes).hexdigest()

    def test_install_sh_pins_tag_and_sha256_and_uses_pure_lf(self):
        with open(self.install_sh, "rb") as f:
            raw_bytes = f.read()

        self.assertNotIn(b"\r\n", raw_bytes)
        self.assertNotIn(b"\r", raw_bytes)
        content = raw_bytes.decode("utf-8")

        self.assertIn('TANUKI_VERSION="v1.3.0"', content)
        self.assertIn(f'TANUKI_SHA256="{self.EXPECTED_SHA256}"', content)
        self.assertRegex(content, r'TANUKI_SHA256="[0-9a-f]{64}"')
        self.assertNotIn("archive/refs/heads/main.tar.gz", content)
        self.assertIn('--branch "${TANUKI_VERSION}"', content)
        self.assertIn('curl -sSL --fail "${ARCHIVE_URL}" -o "${ARCHIVE_FILE}"', content)
        self.assertIn("SHA256 mismatch!", content)

        gitattributes_path = os.path.join(self.repo_root, ".gitattributes")
        self.assertTrue(os.path.isfile(gitattributes_path))
        with open(gitattributes_path, "rb") as gf:
            ga_bytes = gf.read()
        self.assertNotIn(b"\r", ga_bytes)
        self.assertIn("*.sh text eol=lf", ga_bytes.decode("utf-8"))

        build_musl_path = os.path.join(self.repo_root, "scripts", "build_musl.sh")
        with open(build_musl_path, "rb") as bf:
            bm_bytes = bf.read()
        self.assertNotIn(b"\r", bm_bytes)

    def test_install_sh_bash_syntax_and_checksum_rejection(self):
        bash_bin = self._find_bash()
        if not bash_bin:
            self.skipTest("POSIX bash not available on host")

        with open(self.install_sh, "rb") as sf:
            raw_script = sf.read()
        self.assertNotIn(b"\r\n", raw_script)

        syntax_res = subprocess.run([bash_bin, "-n"], input=raw_script, capture_output=True, timeout=10)
        self.assertEqual(syntax_res.returncode, 0, msg=syntax_res.stderr.decode("utf-8", errors="replace"))

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = os.path.join(tmpdir, "bin")
            fake_home = os.path.join(tmpdir, "home")
            fake_tmp = os.path.join(tmpdir, "tmp")
            empty_cwd = os.path.join(tmpdir, "cwd")
            for d in (fake_bin, fake_home, fake_tmp, empty_cwd):
                os.makedirs(d)

            marker_file = os.path.join(tmpdir, "tar_was_called")
            with open(os.path.join(fake_bin, "curl"), "w", encoding="utf-8", newline="\n") as f:
                f.write(
                    '#!/usr/bin/env bash\nout=""\nwhile [ $# -gt 0 ]; do\n'
                    '  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi\n'
                    'done\nprintf "tampered-payload" > "$out"\n'
                )
            with open(os.path.join(fake_bin, "tar"), "w", encoding="utf-8", newline="\n") as f:
                f.write('#!/usr/bin/env bash\necho "EXTRACTED" > "$TAR_MARKER"\nexit 0\n')
            if os.name != "nt":
                os.chmod(os.path.join(fake_bin, "curl"), 0o755)
                os.chmod(os.path.join(fake_bin, "tar"), 0o755)

            self._populate_isolated_bin(fake_bin, bash_bin, include_sha256sum=True, include_tar=False)

            env = dict(os.environ)
            env["PATH"] = fake_bin
            env["HOME"] = fake_home
            env["TMPDIR"] = fake_tmp
            env["TAR_MARKER"] = marker_file

            run_res = subprocess.run(
                [bash_bin],
                input=raw_script,
                cwd=empty_cwd,
                env=env,
                capture_output=True,
                timeout=15,
            )
            self.assertNotEqual(run_res.returncode, 0)
            stderr_text = run_res.stderr.decode("utf-8", errors="replace")
            self.assertIn("SHA256 mismatch!", stderr_text)
            self.assertFalse(os.path.exists(marker_file))
            self.assertEqual(os.listdir(fake_tmp), [])

    def test_install_sh_shasum_fallback_verifies_v1_3_0_archive_and_cleans_temp(self):
        bash_bin = self._find_bash()
        if not bash_bin:
            self.skipTest("POSIX bash not available on host")

        with open(self.install_sh, "rb") as sf:
            raw_script = sf.read()
        self.assertNotIn(b"\r\n", raw_script)

        prod_pin = f'TANUKI_SHA256="{self.EXPECTED_SHA256}"'.encode("ascii")
        self.assertIn(prod_pin, raw_script)

        mock_archive_bytes, mock_sha256 = self._build_deterministic_mock_tar_gz()
        mock_script = raw_script.replace(
            prod_pin,
            f'TANUKI_SHA256="{mock_sha256}"'.encode("ascii"),
            1,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_src = os.path.join(tmpdir, "v1.3.0.tar.gz")
            with open(archive_src, "wb") as af:
                af.write(mock_archive_bytes)

            fake_bin = os.path.join(tmpdir, "bin")
            fake_home = os.path.join(tmpdir, "home")
            fake_tmp = os.path.join(tmpdir, "tmp")
            empty_cwd = os.path.join(tmpdir, "cwd")
            for d in (fake_bin, fake_home, fake_tmp, empty_cwd):
                os.makedirs(d)

            shasum_marker = os.path.join(tmpdir, "shasum_called")
            with open(os.path.join(fake_bin, "curl"), "w", encoding="utf-8", newline="\n") as f:
                f.write(
                    '#!/usr/bin/env bash\nout=""\nwhile [ $# -gt 0 ]; do\n'
                    '  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi\n'
                    'done\ncp "$MOCK_ARCHIVE_SRC" "$out"\n'
                )
            with open(os.path.join(fake_bin, "shasum"), "w", encoding="utf-8", newline="\n") as f:
                f.write(
                    '#!/usr/bin/env bash\n'
                    'if [ "$1" = "-a" ] && [ "$2" = "256" ]; then\n'
                    '  echo "SHASUM_FALLBACK" > "$SHASUM_MARKER"\n'
                    '  shift 2\n'
                    '  exec _real_sha256sum "$@"\n'
                    'fi\nexit 2\n'
                )
            with open(os.path.join(fake_bin, "python3"), "w", encoding="utf-8", newline="\n") as f:
                f.write('#!/usr/bin/env bash\nexit 0\n')

            self._populate_isolated_bin(fake_bin, bash_bin, include_sha256sum=False, include_tar=True)

            if os.name == "nt":
                bash_dir = os.path.dirname(bash_bin)
                shutil.copy2(os.path.join(bash_dir, "sha256sum.exe"), os.path.join(fake_bin, "_real_sha256sum.exe"))
            else:
                for s in ("curl", "shasum", "python3"):
                    os.chmod(os.path.join(fake_bin, s), 0o755)
                real_sha = shutil.which("sha256sum")
                if real_sha:
                    os.symlink(real_sha, os.path.join(fake_bin, "_real_sha256sum"))
                else:
                    real_shasum = shutil.which("shasum")
                    if not real_shasum:
                        self.skipTest("Neither sha256sum nor shasum available on POSIX host")
                    with open(os.path.join(fake_bin, "_real_sha256sum"), "w", encoding="utf-8", newline="\n") as rf:
                        rf.write(f'#!/usr/bin/env bash\nexec "{real_shasum}" -a 256 "$@"\n')
                    os.chmod(os.path.join(fake_bin, "_real_sha256sum"), 0o755)

            env = dict(os.environ)
            env["PATH"] = fake_bin
            env["HOME"] = fake_home
            env["TMPDIR"] = fake_tmp
            env["MOCK_ARCHIVE_SRC"] = archive_src
            env["SHASUM_MARKER"] = shasum_marker

            run_res = subprocess.run(
                [bash_bin],
                input=mock_script,
                cwd=empty_cwd,
                env=env,
                capture_output=True,
                timeout=15,
            )
            stdout_text = run_res.stdout.decode("utf-8", errors="replace")
            stderr_text = run_res.stderr.decode("utf-8", errors="replace")
            self.assertEqual(run_res.returncode, 0, msg=f"STDOUT:\n{stdout_text}\nSTDERR:\n{stderr_text}")
            self.assertIn("Integrity verified.", stdout_text)
            self.assertTrue(os.path.isfile(shasum_marker))
            extracted_skill = os.path.join(fake_home, ".claude", "skills", "tanuki", "SKILL.md")
            extracted_rule = os.path.join(fake_home, ".cursor", "rules", "tanuki.mdc")
            self.assertTrue(os.path.isfile(extracted_skill))
            self.assertTrue(os.path.isfile(extracted_rule))
            with open(extracted_skill, "rb") as sf_out:
                self.assertEqual(sf_out.read(), b"# Tanuki Deterministic Skill Payload\n")
            with open(extracted_rule, "rb") as rf_out:
                self.assertEqual(rf_out.read(), b"# Deterministic Cursor Rule\n")
            self.assertEqual(os.listdir(fake_tmp), [])

            if os.name == "posix":
                direct_home = os.path.join(tmpdir, "direct_home")
                direct_cwd = os.path.join(tmpdir, "direct_cwd")
                os.makedirs(direct_home)
                os.makedirs(direct_cwd)
                standalone_script = os.path.join(direct_cwd, "install.sh")
                with open(standalone_script, "wb") as df:
                    df.write(mock_script)
                os.chmod(standalone_script, 0o755)
                env_direct = dict(env)
                env_direct["HOME"] = direct_home
                direct_res = subprocess.run(
                    [standalone_script],
                    cwd=direct_cwd,
                    env=env_direct,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(
                    direct_res.returncode,
                    0,
                    msg=direct_res.stderr.decode("utf-8", errors="replace"),
                )
                self.assertTrue(os.path.isfile(os.path.join(direct_home, ".claude", "skills", "tanuki", "SKILL.md")))
                self.assertEqual(os.listdir(fake_tmp), [])


class TestFinding05ShadowSyntheticModulusRandomness(unittest.TestCase):
    def test_synthetic_shadow_blobs_have_unique_2048bit_moduli_and_key_ids(self):
        blobs = [build_synthetic_shadow_blob() for _ in range(10)]
        self.assertEqual(len(set(blobs)), 10)

        key_ids = set()
        moduli = set()
        for blob in blobs:
            parsed = parse_key_credential_link(blob)
            self.assertTrue(parsed["integrity_valid"], msg=parsed.get("integrity_issues"))
            self.assertEqual(parsed["integrity_issues"], [])
            km = parsed["key_material"]
            self.assertEqual(km["key_type"], "RSA")
            self.assertEqual(km["bit_length"], 2048)
            self.assertEqual(km["public_exponent"], 65537)
            self.assertEqual(km["modulus_length"], 256)
            mod_hex = km["modulus_hex"]
            self.assertEqual(len(mod_hex), 512)
            self.assertEqual(int(mod_hex[:2], 16) & 0x80, 0x80)
            key_ids.add(parsed["key_id"])
            moduli.add(mod_hex)

        self.assertEqual(len(key_ids), 10)
        self.assertEqual(len(moduli), 10)


class TestFinding06And07KdcPortAndCommentParsing(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.kt_path = os.path.join(self.temp_dir.name, "test.keytab")
        with open(self.kt_path, "wb") as f:
            f.write(_build_keytab_v2([_build_keytab_v2_entry()]))
        self.cc_path = os.path.join(self.temp_dir.name, "test.ccache")
        with open(self.cc_path, "wb") as f:
            f.write(b"\x05\x04")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_srv_custom_port_probed_in_acquire_tgt_and_acquire_tgs(self):
        nonexistent_conf = os.path.join(self.temp_dir.name, "no_krb5.conf")
        with patch("tanuki.config.discover_dc_via_srv", return_value=("dc-alt.lab.local", 8888)), \
             patch("tanuki.ldap.probe_tcp_port", return_value=(False, "Connection refused")) as mock_probe:
            res_tgt = acquire_tgt(
                self.kt_path,
                principal="HTTP/srv01.lab.local@LAB.LOCAL",
                krb5_conf=nonexistent_conf,
            )
            self.assertEqual(res_tgt["reason_code"], "KDC_UNREACHABLE")
            mock_probe.assert_called_once_with("dc-alt.lab.local", 8888, timeout=0.8)

        with patch("tanuki.config.discover_dc_via_srv", return_value=("dc-alt.lab.local", 10088)), \
             patch("tanuki.ldap.probe_tcp_port", return_value=(False, "Connection refused")) as mock_probe_tgs:
            res_tgs = acquire_tgs(
                spn="HTTP/srv01.lab.local@LAB.LOCAL",
                ccache_path=self.cc_path,
                krb5_conf=nonexistent_conf,
            )
            self.assertEqual(res_tgs["reason_code"], "KDC_UNREACHABLE")
            mock_probe_tgs.assert_called_once_with("dc-alt.lab.local", 10088, timeout=0.8)

    def test_krb5_conf_inline_hash_and_semicolon_comments_and_kdc_timesync(self):
        conf_hash = os.path.join(self.temp_dir.name, "krb5_hash.conf")
        with open(conf_hash, "w", encoding="utf-8") as f:
            f.write(
                "[libdefaults]\n"
                "    kdc_timesync = 1\n"
                "[realms]\n"
                "    LAB.LOCAL = {\n"
                "        kdc = # empty comment line\n"
                "        kdc = ; semicolon empty line\n"
                "        kdc = dc01.lab.local#primary\n"
                "    }\n"
            )

        with patch("tanuki.ldap.probe_tcp_port", return_value=(False, "refused")) as mock_probe:
            res = acquire_tgt(self.kt_path, krb5_conf=conf_hash)
            self.assertEqual(res["reason_code"], "KDC_UNREACHABLE")
            mock_probe.assert_called_once_with("dc01.lab.local", 88, timeout=0.8)

        conf_semi = os.path.join(self.temp_dir.name, "krb5_semi.conf")
        with open(conf_semi, "w", encoding="utf-8") as f:
            f.write(
                "[realms]\n"
                "    LAB.LOCAL = {\n"
                "        kdc = dc02.lab.local:8888;role=primary,dc03.lab.local\n"
                "    }\n"
            )

        with patch("tanuki.ldap.probe_tcp_port", return_value=(False, "refused")) as mock_probe2:
            res2 = acquire_tgs(
                spn="HTTP/srv01.lab.local@LAB.LOCAL",
                ccache_path=self.cc_path,
                krb5_conf=conf_semi,
            )
            self.assertEqual(res2["reason_code"], "KDC_UNREACHABLE")
            mock_probe2.assert_called_once_with("dc02.lab.local", 8888, timeout=0.8)


class TestFinding08Ipv6KdcValidation(unittest.TestCase):
    def test_ipv6_kdc_with_and_without_port_and_transport_prefix_succeeds(self):
        from tanuki.auth import _parse_kdc_host_port

        cfg = generate_krb5_conf(realm="TEST.LOCAL", kdc="[2001:db8::1]:88")
        self.assertIn("kdc = [2001:db8::1]:88", cfg)
        self.assertIn("admin_server = [2001:db8::1]:88", cfg)

        cfg_tcp = generate_krb5_conf(realm="TEST.LOCAL", kdc="tcp/[2001:db8::1]:88")
        self.assertIn("kdc = tcp/[2001:db8::1]:88", cfg_tcp)
        self.assertIn("admin_server = [2001:db8::1]:88", cfg_tcp)

        cfg_tcp_v4 = generate_krb5_conf(realm="TEST.LOCAL", kdc="tcp/dc01.corp.local:88")
        self.assertIn("kdc = tcp/dc01.corp.local:88", cfg_tcp_v4)
        self.assertIn("admin_server = dc01.corp.local:88", cfg_tcp_v4)

        cfg_zone = generate_krb5_conf(realm="TEST.LOCAL", kdc="[fe80::1%eth0]:88")
        self.assertIn("kdc = [fe80::1%eth0]:88", cfg_zone)

        cfg_multi = generate_krb5_conf(
            realm="TEST.LOCAL",
            kdc=[
                "[2001:db8::1]",
                "[2001:db8::2]:8888",
                "tcp/[2001:db8::3]:88",
                "udp/[2001:db8::4]",
                "TCP/[2001:db8::5]:10088",
                "UDP/[::1]:88",
            ],
        )
        for expected_entry, expected_parsed in (
            ("[2001:db8::1]", ("2001:db8::1", 88)),
            ("[2001:db8::2]:8888", ("2001:db8::2", 8888)),
            ("tcp/[2001:db8::3]:88", ("2001:db8::3", 88)),
            ("udp/[2001:db8::4]", ("2001:db8::4", 88)),
            ("TCP/[2001:db8::5]:10088", ("2001:db8::5", 10088)),
            ("UDP/[::1]:88", ("::1", 88)),
        ):
            self.assertIn(f"kdc = {expected_entry}", cfg_multi)
            self.assertEqual(_parse_kdc_host_port(expected_entry), expected_parsed)

        with tempfile.TemporaryDirectory() as td:
            kt_path = os.path.join(td, "svc.keytab")
            with open(kt_path, "wb") as kf:
                kf.write(_build_keytab_v2([_build_keytab_v2_entry(realm="LAB.LOCAL")]))
            conf_path = os.path.join(td, "krb5_tcp_v6.conf")
            with open(conf_path, "w", encoding="utf-8") as cf:
                cf.write(generate_krb5_conf(realm="LAB.LOCAL", kdc="tcp/[2001:db8::99]:8888"))
            with patch("tanuki.ldap.probe_tcp_port", return_value=(False, "refused")) as mock_probe:
                res = acquire_tgt(kt_path, principal="HTTP/srv01.lab.local@LAB.LOCAL", krb5_conf=conf_path)
            self.assertEqual(res["reason_code"], "KDC_UNREACHABLE")
            mock_probe.assert_called_once_with("2001:db8::99", 8888, timeout=0.8)

    def test_kdc_injection_and_brackets_in_other_fields_rejected(self):
        for bad_kdc in (
            "bad\nkdc",
            "bad\rkdc",
            "bad;kdc",
            "bad#kdc",
            "bad=kdc",
            "bad kdc",
            "bad{kdc}",
            "http/[2001:db8::1]:88",
            "tcp/tcp/[2001:db8::1]:88",
            "http/dc01.corp.local:88",
            "tcp/tcp/dc01.corp.local:88",
            "tcp/[2001:db8::1]:99999",
            "dc01.corp.local:99999",
            ":88",
            ":::",
            "[10.0.0.1:88]",
            "[evil.com:88]",
            "[:]",
            "tcp/[:::]:88",
            "[fe80::1%]:88",
            "tcp/[not-ipv6]:88",
            "tcp/",
            "udp/",
            "tcp/ [2001:db8::1]:88",
        ):
            with self.assertRaises(ValueError, msg=f"Failed to reject {bad_kdc!r}"):
                generate_krb5_conf(realm="TEST.LOCAL", kdc=bad_kdc)

        with self.assertRaises(ValueError):
            generate_krb5_conf(realm="[TEST.LOCAL]", kdc="10.0.0.1")
        with self.assertRaises(ValueError):
            generate_krb5_conf(realm="TEST.LOCAL", kdc="10.0.0.1", admin_server="[2001:db8::1]")
        with self.assertRaises(ValueError):
            generate_krb5_conf(realm="TEST.LOCAL", kdc="10.0.0.1", admin_server="10.0.0.1\tevil")
        with self.assertRaises(ValueError):
            generate_krb5_conf(realm="TEST.LOCAL", kdc="10.0.0.1", admin_server="tcp/10.0.0.1")
        with self.assertRaises(ValueError):
            generate_krb5_conf(realm="TEST.LOCAL", kdc="10.0.0.1", armor_cache="/tmp/[armor]")


class TestFinding09SrvAncountCap(unittest.TestCase):
    def test_srv_ancount_capped_at_64_records(self):
        pkt_100 = _build_srv_response(tx_id=0x1234, declared_ancount=100, actual_records=100)
        records = parse_srv_response(pkt_100, expected_tx_id=0x1234)
        self.assertEqual(len(records), 64)

        pkt_forged = _build_srv_response(tx_id=0x5678, declared_ancount=65535, actual_records=3)
        records_short = parse_srv_response(pkt_forged, expected_tx_id=0x5678)
        self.assertEqual(len(records_short), 3)


class TestFinding10KeyringSyscallMap(unittest.TestCase):
    def test_all_supported_architectures_map_to_exact_add_key_syscall(self):
        expected = {
            "x86_64": 248,
            "aarch64": 217,
            "arm64": 217,
            "armv7l": 309,
            "armv6l": 309,
            "i386": 286,
            "i686": 286,
            "riscv64": 217,
            "ppc64le": 269,
            "s390x": 278,
        }
        for arch, expected_nr in expected.items():
            mock_libc = MagicMock()
            mock_libc.syscall.return_value = 42
            with patch("tanuki.auth.os.name", "posix"), \
                 patch("tanuki.auth.sys.platform", "linux"), \
                 patch("platform.machine", return_value=arch), \
                 patch("ctypes.CDLL", return_value=mock_libc):
                res = inject_ticket_to_keyring(b"\x05\x04ticketdata")
            self.assertEqual(res["status"], "SUCCESS", msg=arch)
            called_nr = mock_libc.syscall.call_args[0][0].value
            self.assertEqual(called_nr, expected_nr, msg=f"Wrong syscall for {arch}")

    def test_unknown_architecture_returns_unsupported_platform(self):
        mock_libc = MagicMock()
        with patch("tanuki.auth.os.name", "posix"), \
             patch("tanuki.auth.sys.platform", "linux"), \
             patch("platform.machine", return_value="mips64"), \
             patch("ctypes.CDLL", return_value=mock_libc):
            res = inject_ticket_to_keyring(b"\x05\x04ticketdata")
        self.assertEqual(res["status"], "UNSUPPORTED_PLATFORM")
        self.assertIn("mips64", res["message"])
        mock_libc.syscall.assert_not_called()


class TestFinding11RootPurgeCrossUserGuard(unittest.TestCase):
    def test_root_purge_defaults_to_uid_zero_unless_explicitly_allowed(self):
        glob_patterns_default: list[str] = []

        def record_glob_default(pattern: str):
            glob_patterns_default.append(pattern)
            return []

        with patch("tanuki.purge.os.name", "posix"), \
             patch("tanuki.purge.os.getuid", return_value=0, create=True), \
             patch("tanuki.purge.glob.glob", side_effect=record_glob_default):
            run_purge(purge_all=True)

        self.assertIn("/tmp/krb5cc_0*", glob_patterns_default)
        self.assertNotIn("/tmp/krb5cc_*", glob_patterns_default)

        glob_patterns_cross: list[str] = []

        def record_glob_cross(pattern: str):
            glob_patterns_cross.append(pattern)
            return []

        with patch("tanuki.purge.os.name", "posix"), \
             patch("tanuki.purge.os.getuid", return_value=0, create=True), \
             patch("tanuki.purge.glob.glob", side_effect=record_glob_cross):
            run_purge(purge_all=True, allow_cross_user_purge=True)

        self.assertIn("/tmp/krb5cc_*", glob_patterns_cross)
        self.assertNotIn("/tmp/krb5cc_0*", glob_patterns_cross)

        glob_patterns_user: list[str] = []
        with patch("tanuki.purge.os.name", "posix"), \
             patch("tanuki.purge.os.getuid", return_value=1000, create=True), \
             patch("tanuki.purge.glob.glob", side_effect=lambda p: glob_patterns_user.append(p) or []):
            run_purge(purge_all=True, allow_cross_user_purge=True)

        self.assertIn("/tmp/krb5cc_1000*", glob_patterns_user)
        self.assertNotIn("/tmp/krb5cc_*", glob_patterns_user)


class TestFinding12UnsupportedKrb5CcnameWarning(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.kt_path = os.path.join(self.temp_dir.name, "svc.keytab")
        with open(self.kt_path, "wb") as f:
            f.write(_build_keytab_v2([_build_keytab_v2_entry()]))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_warning_emitted_on_kinit_and_ctypes_success_for_non_file_schemes(self):
        for scheme_val in ("KCM:1000", "KEYRING:persistent:1000", "API:krb5cc", "MEMORY:ephemeral", "DIR:/run/cc"):
            with patch.dict(os.environ, {"KRB5CCNAME": scheme_val}, clear=False), \
                 patch("tanuki.config.discover_dc_via_srv", return_value=None), \
                 patch("shutil.which", return_value="/usr/bin/kinit"), \
                 patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
                res = acquire_tgt(
                    self.kt_path,
                    krb5_conf=os.path.join(self.temp_dir.name, "missing.conf"),
                )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertIn("warning", res)
            self.assertIn(scheme_val, res["warning"])
            self.assertIn(res["ccache"], res["warning"])

        # Verify ctypes fallback path also attaches warning on SUCCESS
        with patch.dict(os.environ, {"KRB5CCNAME": "KCM:session"}, clear=False), \
             patch("tanuki.config.discover_dc_via_srv", return_value=None), \
             patch("shutil.which", return_value=None), \
             patch(
                 "tanuki.auth.acquire_tgt_via_ctypes",
                 return_value={"status": "SUCCESS", "method": "ctypes", "ccache": "/tmp/krb5cc_1000"},
             ):
            res_ct = acquire_tgt(
                self.kt_path,
                krb5_conf=os.path.join(self.temp_dir.name, "missing.conf"),
            )
        self.assertEqual(res_ct["status"], "SUCCESS")
        self.assertIn("KCM:session", res_ct["warning"])

    def test_no_warning_on_error_or_file_scheme(self):
        with patch.dict(os.environ, {"KRB5CCNAME": "KCM:1000"}, clear=False), \
             patch("tanuki.ldap.probe_tcp_port", return_value=(False, "refused")):
            err_res = acquire_tgt(self.kt_path, kdc="192.0.2.10")
        self.assertEqual(err_res["status"], "ERROR")
        self.assertNotIn("warning", err_res)

        file_cc = os.path.join(self.temp_dir.name, "explicit_env.ccache")
        with patch.dict(os.environ, {"KRB5CCNAME": f"FILE:{file_cc}"}, clear=False), \
             patch("tanuki.config.discover_dc_via_srv", return_value=None), \
             patch("shutil.which", return_value="/usr/bin/kinit"), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
            ok_res = acquire_tgt(
                self.kt_path,
                krb5_conf=os.path.join(self.temp_dir.name, "missing.conf"),
            )
        self.assertEqual(ok_res["status"], "SUCCESS")
        self.assertNotIn("warning", ok_res)


class TestFinding13StrictBase64UrlDecode(unittest.TestCase):
    def test_standard_base64_plus_and_slash_rejected(self):
        with self.assertRaises(ValueError):
            b64url_decode("abc+def=")
        with self.assertRaises(ValueError):
            b64url_decode("abc/def=")
        with self.assertRaises(ValueError):
            b64url_decode("ab-c+def")

    def test_valid_base64url_accepted(self):
        # "abc-def_" is 8 valid Base64URL chars
        decoded = b64url_decode("abc-def_")
        self.assertEqual(decoded, base64.urlsafe_b64decode("abc-def_"))

    def test_jwt_with_standard_base64_chars_rejected(self):
        hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
        pay = base64.urlsafe_b64encode(b'{"sub":"svc","exp":9999999999}').decode().rstrip("=")
        with self.assertRaises(ValueError):
            parse_workload_jwt(f"{hdr}.{pay}.abc+def")


class TestFinding14OversizedKeytabFileRejected(unittest.TestCase):
    def test_normal_50kb_keytab_parses_cleanly(self):
        entry = _build_keytab_v2_entry()
        count = (50 * 1024) // len(entry)
        kt_bytes = _build_keytab_v2([entry] * count)
        self.assertGreaterEqual(len(kt_bytes), 45 * 1024)

        with tempfile.TemporaryDirectory() as tmpdir:
            kt_path = os.path.join(tmpdir, "normal_50kb.keytab")
            with open(kt_path, "wb") as f:
                f.write(kt_bytes)
            parsed = parse_keytab_file(kt_path)
            self.assertEqual(len(parsed), count)

    def test_oversized_11mb_keytab_raises_clear_value_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            big_path = os.path.join(tmpdir, "oversized_11mb.keytab")
            size_11mb = 11 * 1024 * 1024
            with open(big_path, "wb") as f:
                f.seek(size_11mb - 1)
                f.write(b"\x00")

            with self.assertRaises(ValueError) as ctx:
                parse_keytab_file(big_path)
            msg = str(ctx.exception)
            self.assertIn(str(size_11mb), msg)
            self.assertIn("10485760", msg)

    def test_boundary_10mb_plus_one_byte_rejected_and_symlink_checked_first(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            edge_path = os.path.join(tmpdir, "edge.keytab")
            with open(edge_path, "wb") as f:
                f.seek(10485760)
                f.write(b"\x00")
            with self.assertRaises(ValueError) as ctx:
                parse_keytab_file(edge_path)
            self.assertIn("10485761", str(ctx.exception))

        with patch("tanuki.keytab.os.path.islink", return_value=True), \
             patch("tanuki.keytab.os.path.getsize", side_effect=AssertionError("getsize called before islink")):
            with self.assertRaises(ValueError) as sym_ctx:
                parse_keytab_file("/tmp/symlink.keytab")
            self.assertIn("symbolic link", str(sym_ctx.exception))


class TestReviewerRegressionSuite(unittest.TestCase):
    def test_cli_config_and_run_fix_accept_ipv6_kdc_and_emit_structured_error_on_bad_input(self):
        from tanuki.fix import run_fix

        proc = subprocess.run(
            [sys.executable, "-m", "tanuki", "config", "--realm", "TEST.LOCAL", "--kdc", "[2001:db8::1]:88", "--stdout"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("kdc = [2001:db8::1]:88", proc.stdout)
        self.assertIn("admin_server = [2001:db8::1]:88", proc.stdout)

        bad_proc = subprocess.run(
            [
                sys.executable, "-m", "tanuki", "config",
                "--realm", "TEST.LOCAL",
                "--kdc", "[2001:db8::1]:88",
                "--admin-server", "[2001:db8::1]",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(bad_proc.returncode, 0)
        self.assertNotIn("Traceback", bad_proc.stderr)
        err_payload = json.loads(bad_proc.stdout)
        self.assertEqual(err_payload["reason_code"], "INVALID_ARGUMENT")

        rep = run_fix(realm="TEST.LOCAL", kdc="[2001:db8::1]:88", dry_run=True)
        self.assertEqual(rep.status, "SUCCESS")

    def test_probe_tcp_port_ipv6_and_parse_kdc_host_port_variants(self):
        import socket
        from tanuki.auth import _parse_kdc_host_port
        from tanuki.ldap import probe_tcp_port

        self.assertEqual(_parse_kdc_host_port("2001:db8::1"), ("2001:db8::1", 88))
        self.assertEqual(_parse_kdc_host_port("::1"), ("::1", 88))
        self.assertEqual(_parse_kdc_host_port("[2001:db8::1]:8888"), ("2001:db8::1", 8888))
        self.assertEqual(_parse_kdc_host_port("tcp/dc01.lab.local:10088"), ("dc01.lab.local", 10088))
        self.assertEqual(_parse_kdc_host_port("dc01.lab.local:99999"), ("dc01.lab.local", 88))
        self.assertEqual(_parse_kdc_host_port("[::1]:0"), ("::1", 88))

        try:
            srv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv6.bind(("::1", 0))
            srv6.listen(5)
        except OSError as exc:
            self.skipTest(f"IPv6 loopback unavailable: {exc}")
        try:
            port6 = srv6.getsockname()[1]
            ok_raw, err_raw = probe_tcp_port("::1", port6, timeout=1.0)
            self.assertTrue(ok_raw, err_raw)
            conn1, _ = srv6.accept()
            conn1.close()
            ok_bracket, err_bracket = probe_tcp_port("[::1]", port6, timeout=1.0)
            self.assertTrue(ok_bracket, err_bracket)
            conn2, _ = srv6.accept()
            conn2.close()
        finally:
            srv6.close()

    def test_multi_realm_krb5_conf_stanza_isolation_and_srv_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            kt_path = os.path.join(td, "svc.keytab")
            with open(kt_path, "wb") as f:
                f.write(_build_keytab_v2([_build_keytab_v2_entry(realm="LAB.LOCAL")]))
            cc_path = os.path.join(td, "svc.ccache")
            with open(cc_path, "wb") as f:
                f.write(b"\x05\x04")

            multi_conf = os.path.join(td, "multi_krb5.conf")
            with open(multi_conf, "w", encoding="utf-8") as f:
                f.write(
                    "[libdefaults]\n"
                    "    default_realm = ATHENA.MIT.EDU\n"
                    "[realms]\n"
                    "    ATHENA.MIT.EDU = {\n"
                    "        kdc = kerberos.mit.edu:88\n"
                    "        v4_name_convert = {\n"
                    "            host = {\n"
                    "                rcmd = host\n"
                    "            }\n"
                    "        }\n"
                    "    }\n"
                    "    SINGLE.LOCAL = { kdc = dc-single.local:88 }\n"
                    "    LAB.LOCAL = {\n"
                    "        kdc = [2001:db8::10]:8888#lab-dc\n"
                    "    }\n"
                )

            with patch("tanuki.ldap.probe_tcp_port", return_value=(False, "refused")) as mp_tgt:
                res_tgt = acquire_tgt(kt_path, principal="HTTP/srv01.lab.local@LAB.LOCAL", krb5_conf=multi_conf)
                self.assertEqual(res_tgt["reason_code"], "KDC_UNREACHABLE")
                mp_tgt.assert_called_once_with("2001:db8::10", 8888, timeout=0.8)

            with patch("tanuki.ldap.probe_tcp_port", return_value=(False, "refused")) as mp_tgs:
                res_tgs = acquire_tgs("HTTP/srv01.lab.local@LAB.LOCAL", ccache_path=cc_path, krb5_conf=multi_conf)
                self.assertEqual(res_tgs["reason_code"], "KDC_UNREACHABLE")
                mp_tgs.assert_called_once_with("2001:db8::10", 8888, timeout=0.8)

            unrelated_conf = os.path.join(td, "debian_default_krb5.conf")
            with open(unrelated_conf, "w", encoding="utf-8") as f:
                f.write(
                    "[realms]\n"
                    "    ATHENA.MIT.EDU = {\n"
                    "        kdc = kerberos.mit.edu:88\n"
                    "    }\n"
                )

            with patch("tanuki.config.discover_dc_via_srv", return_value=("dc-srv.lab.local", 9088)), \
                 patch("tanuki.ldap.probe_tcp_port", return_value=(False, "refused")) as mp_srv:
                res_srv = acquire_tgt(kt_path, principal="HTTP/srv01.lab.local@LAB.LOCAL", krb5_conf=unrelated_conf)
                self.assertEqual(res_srv["reason_code"], "KDC_UNREACHABLE")
                mp_srv.assert_called_once_with("dc-srv.lab.local", 9088, timeout=0.8)

    def test_kdc_rejects_tab_whitespace_and_malformed_brackets(self):
        for bad in (
            "10.0.0.1\tallow_weak_crypto",
            "10.0.0.1\x0bevil",
            "[libdefaults]",
            "[2001:db8::1",
            "2001:db8::1]",
            "dc01[1].lab.local",
            "[2001:db8::1]:99999",
            "[2001:db8::1]:abc",
        ):
            with self.assertRaises(ValueError, msg=f"Failed to reject KDC token {bad!r}"):
                generate_krb5_conf(realm="TEST.LOCAL", kdc=bad)

    def test_krb5_config_restored_even_when_krb5_free_context_raises(self):
        orig = os.environ.get("KRB5_CONFIG")
        try:
            os.environ["KRB5_CONFIG"] = "/etc/original_krb5.conf"
            fake_krb5 = MagicMock()
            fake_krb5.krb5_init_context.return_value = 0
            fake_krb5.krb5_parse_name.return_value = 99
            fake_krb5.krb5_cc_resolve.return_value = 99
            fake_krb5.krb5_free_context.side_effect = RuntimeError("simulated free_context error")

            with patch("ctypes.CDLL", return_value=fake_krb5):
                with self.assertRaises(RuntimeError):
                    acquire_tgt_via_ctypes(
                        "/tmp/fake.kt",
                        "svc@LAB.LOCAL",
                        "/tmp/fake.cc",
                        lib_path="/usr/lib/libkrb5.so.3",
                        krb5_conf="/tmp/leaked_tgt.conf",
                    )
            self.assertEqual(os.environ.get("KRB5_CONFIG"), "/etc/original_krb5.conf")

            with patch("ctypes.CDLL", return_value=fake_krb5):
                with self.assertRaises(RuntimeError):
                    acquire_tgs_via_ctypes(
                        "HTTP/srv@LAB.LOCAL",
                        "/tmp/fake.cc",
                        lib_path="/usr/lib/libkrb5.so.3",
                        krb5_conf="/tmp/leaked_tgs.conf",
                    )
            self.assertEqual(os.environ.get("KRB5_CONFIG"), "/etc/original_krb5.conf")
        finally:
            if orig is None:
                os.environ.pop("KRB5_CONFIG", None)
            else:
                os.environ["KRB5_CONFIG"] = orig

    def test_cli_auth_terminal_surfaces_unsupported_ccache_warning_and_shadow_modulus_is_odd(self):
        from contextlib import redirect_stdout
        from tanuki.cli import main

        buf = io.StringIO()
        with patch("tanuki.cli.acquire_tgt", return_value={
            "status": "SUCCESS",
            "method": "kinit",
            "principal": "svc@LAB.LOCAL",
            "keytab": "/tmp/a.keytab",
            "ccache": "/tmp/krb5cc_1000",
            "export_command": "export KRB5CCNAME=FILE:/tmp/krb5cc_1000",
            "warning": "KRB5CCNAME was set to 'KCM:1000' (unsupported scheme). Credentials written to FILE: fallback instead: /tmp/krb5cc_1000",
        }):
            with redirect_stdout(buf):
                main(["auth", "--keytab", "/tmp/a.keytab"])
        self.assertIn("KCM:1000", buf.getvalue())

        for _ in range(32):
            blob = build_synthetic_shadow_blob()
            parsed = parse_key_credential_link(blob)
            mod_bytes = bytes.fromhex(parsed["key_material"]["modulus_hex"])
            self.assertEqual(mod_bytes[0] & 0x80, 0x80)
            self.assertEqual(mod_bytes[-1] & 0x01, 0x01)

    def test_install_sh_handles_leading_backslash_from_gnu_sha256sum(self):
        bash_bin = r"C:\Program Files\Git\usr\bin\bash.exe"
        if not os.path.isfile(bash_bin):
            bash_bin = shutil.which("bash") or ""
        if not bash_bin:
            self.skipTest("POSIX bash not available")

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        install_sh = os.path.join(repo_root, "install.sh")
        with open(install_sh, "r", encoding="utf-8") as f:
            script_text = f.read()
        self.assertIn("sub(/^\\\\/, \"\", $1)", script_text)

        snippet = (
            "printf '\\\\80bf7ff0ee1f47784eb265ff6a68ba609ea569deba49aa1e6c9eeaf6a5fbda30 *C:\\\\temp\\\\tanuki.tar.gz\\n' "
            "| awk '{sub(/^\\\\/, \"\", $1); print $1}'\n"
        )
        proc = subprocess.run(
            [bash_bin, "-l", "-s"],
            input=snippet,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "80bf7ff0ee1f47784eb265ff6a68ba609ea569deba49aa1e6c9eeaf6a5fbda30")

    def test_doctor_host_tools_skips_wsl_drvfs_mounts_and_invalidates_path_cache(self):
        from tanuki.doctor import _is_wsl_drvfs_path, check_host_tools

        self.assertTrue(_is_wsl_drvfs_path("/mnt/c"))
        self.assertTrue(_is_wsl_drvfs_path("/mnt/c/Windows/system32"))
        self.assertTrue(_is_wsl_drvfs_path("/mnt/D/tools"))
        self.assertFalse(_is_wsl_drvfs_path("/mnt/cdrom/bin"))
        self.assertFalse(_is_wsl_drvfs_path("/mnt/share"))
        self.assertFalse(_is_wsl_drvfs_path("/usr/bin"))
        self.assertFalse(_is_wsl_drvfs_path(""))

        probed: list[str] = []

        def fake_isfile(path: str) -> bool:
            probed.append(path)
            return False

        with patch("tanuki.doctor.os.name", "posix"), \
             patch("tanuki.doctor.os.pathsep", ":"), \
             patch.dict(os.environ, {
                 "WSL_DISTRO_NAME": "kali-linux",
                 "PATH": "/usr/local/bin:/usr/bin:/mnt/c/Windows/system32:/mnt/c:/mnt/d/tools",
             }, clear=False), \
             patch("tanuki.doctor.os.path.isfile", side_effect=fake_isfile):
            res = check_host_tools()
            self.assertEqual(res["status"], "WARN")
            self.assertFalse(any(p.startswith("/mnt/c") or p.startswith("/mnt/d") for p in probed), probed)

            probed.clear()
            check_host_tools(search_path="/mnt/c/custom_bin")
            self.assertTrue(any(p.startswith("/mnt/c/custom_bin") for p in probed), probed)

        with tempfile.TemporaryDirectory() as empty_dir, tempfile.TemporaryDirectory() as tool_dir:
            bin_name = "kinit.exe" if os.name == "nt" else "kinit"
            kinit_file = os.path.join(tool_dir, bin_name)
            with open(kinit_file, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\nexit 0\n")
            if os.name != "nt":
                os.chmod(kinit_file, 0o755)

            with patch.dict(os.environ, {"PATH": empty_dir}, clear=False):
                r1 = check_host_tools()
                self.assertEqual(r1["status"], "WARN")

            with patch.dict(os.environ, {"PATH": tool_dir}, clear=False):
                r2 = check_host_tools()
                self.assertEqual(r2["status"], "PASS")
                self.assertTrue(r2["kinit_present"])

    def test_write_krb5_conf_file_and_admin_server_metadata_consistency(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            conf1 = os.path.join(tmpdir, "v6_tcp.conf")
            res1 = write_krb5_conf_file(
                conf1,
                realm="CORP.LOCAL",
                kdc="tcp/[2001:db8::1]:88",
                admin_server="   ",
            )
            self.assertEqual(res1["admin_server"], "[2001:db8::1]:88")
            self.assertIn("admin_server = [2001:db8::1]:88", res1["content"])

            conf2 = os.path.join(tmpdir, "comma.conf")
            res2 = write_krb5_conf_file(
                conf2,
                realm="CORP.LOCAL",
                kdc=[",tcp/10.0.0.1:88,10.0.0.2:88"],
            )
            self.assertEqual(res2["kdc"], "tcp/10.0.0.1:88,10.0.0.2:88")
            self.assertEqual(res2["admin_server"], "10.0.0.1:88")
            self.assertIn("admin_server = 10.0.0.1:88", res2["content"])

    def test_handle_config_enforces_o_nofollow_and_strips_transport_prefix_in_admin_server(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json_conf = os.path.join(tmpdir, "valid.conf")
            proc = subprocess.run(
                [
                    sys.executable, "-m", "tanuki", "config",
                    "--realm", "CORP.LOCAL",
                    "--kdc", "tcp/[2001:db8::1]:88",
                    "--out", out_json_conf,
                    "--json",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["admin_server"], "[2001:db8::1]:88")
            with open(out_json_conf, "r", encoding="utf-8") as cf:
                self.assertIn("admin_server = [2001:db8::1]:88", cf.read())

            race_conf = os.path.join(tmpdir, "race_mock.conf")
            observed_flags: list[int] = []

            def fake_open(_path: str, flags: int, _mode: int = 0o644) -> int:
                observed_flags.append(flags)
                raise OSError(errno.ELOOP, "Too many levels of symbolic links")

            err_buf = io.StringIO()
            with patch("sys.stdout", err_buf), \
                 patch.object(os, "O_NOFOLLOW", 0x20000, create=True), \
                 patch("tanuki.cli.os.path.islink", return_value=False), \
                 patch("tanuki.cli.os.open", side_effect=fake_open):
                with self.assertRaises(SystemExit) as ctx:
                    cli.handle_config("CORP.LOCAL", "10.0.0.1", None, race_conf, False, True)
            self.assertNotEqual(ctx.exception.code, 0)
            self.assertEqual(len(observed_flags), 1)
            self.assertTrue(observed_flags[0] & 0x20000)
            err_json = json.loads(err_buf.getvalue())
            self.assertEqual(err_json["reason_code"], "WRITE_ERROR")

            if os.name == "posix":
                victim = os.path.join(tmpdir, "victim.txt")
                with open(victim, "wb") as vf:
                    vf.write(b"IMMUTABLE_VICTIM")
                sym_conf = os.path.join(tmpdir, "real_race.conf")
                os.symlink(victim, sym_conf)
                posix_buf = io.StringIO()
                with patch("sys.stdout", posix_buf), \
                     patch("tanuki.cli.os.path.islink", return_value=False):
                    with self.assertRaises(SystemExit) as pctx:
                        cli.handle_config("CORP.LOCAL", "10.0.0.1", None, sym_conf, False, True)
                self.assertNotEqual(pctx.exception.code, 0)
                self.assertEqual(json.loads(posix_buf.getvalue())["reason_code"], "WRITE_ERROR")
                with open(victim, "rb") as vf:
                    self.assertEqual(vf.read(), b"IMMUTABLE_VICTIM")

    def test_cli_fix_and_run_fix_reject_invalid_kdc_and_realm_without_traceback(self):
        from tanuki.fix import run_fix

        for bad_args in (
            ["--realm", "TEST.LOCAL", "--kdc", "bad;kdc"],
            ["--realm", "[EVIL]", "--kdc", "10.0.0.1"],
            ["--realm", "TEST.LOCAL", "--kdc", "[10.0.0.1:88]"],
        ):
            proc = subprocess.run(
                [sys.executable, "-m", "tanuki", "fix", *bad_args, "--dry-run", "--json"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            err_data = json.loads(proc.stdout)
            self.assertEqual(err_data["status"], "ERROR")
            self.assertEqual(err_data["reason_code"], "INVALID_ARGUMENT")

        rep = run_fix(realm="TEST.LOCAL", kdc="bad;kdc", dry_run=True)
        self.assertEqual(rep.status, "ERROR")
        self.assertTrue(any(a.get("status") == "ERROR" for a in rep.actions))

    def test_find_krb5_library_resolves_trusted_soname_symlinks_and_rejects_untrusted_targets(self):
        soname = "/usr/lib/x86_64-linux-gnu/libkrb5.so.3"
        real_trusted = "/usr/lib/x86_64-linux-gnu/libkrb5.so.3.3"

        with patch("ctypes.util.find_library", return_value=None), \
             patch("tanuki.auth.os.path.isfile", side_effect=lambda p: p in (soname, real_trusted)), \
             patch("tanuki.auth.os.path.realpath", side_effect=lambda p: real_trusted if p == soname else p), \
             patch("ctypes.CDLL", return_value=MagicMock()) as mock_cdll:
            found = find_krb5_library()
        self.assertEqual(found, real_trusted)
        mock_cdll.assert_called_once_with(real_trusted)

        for untrusted_target in ("/tmp/evil_libkrb5.so", "/usr/lib_attacker/libkrb5.so.3.3"):
            with patch("ctypes.util.find_library", return_value=None), \
                 patch("tanuki.auth.os.path.isfile", side_effect=lambda p, u=untrusted_target: p in (soname, u)), \
                 patch("tanuki.auth.os.path.realpath", side_effect=lambda p, u=untrusted_target: u if p == soname else p), \
                 patch("ctypes.CDLL", return_value=MagicMock()) as mock_cdll_bad:
                rejected = find_krb5_library()
            self.assertIsNone(rejected)
            mock_cdll_bad.assert_not_called()

        if os.name == "posix" and os.path.isfile(soname):
            with patch("ctypes.util.find_library", return_value=None):
                live_found = find_krb5_library()
            self.assertIsNotNone(live_found)
            self.assertEqual(live_found, os.path.realpath(soname))


if __name__ == "__main__":
    unittest.main()
