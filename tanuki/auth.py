"""Zero-Dependency Unprivileged Kerberos Ticket Acquisition Engine.

Provides TGT acquisition using either system kinit or dynamic C library bindings
(libkrb5.so.3 / libgssapi_krb5.so.2) via standard library ctypes without requiring
external dependencies or root privileges.
"""

import ctypes
import ctypes.util
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

from .keytab import parse_keytab_file


def find_krb5_library() -> Optional[str]:
    """Locate libkrb5 or libgssapi_krb5 shared library on the host."""
    candidates = [
        "libkrb5.so.3",
        "libkrb5.so",
        "libgssapi_krb5.so.2",
        "/usr/lib/x86_64-linux-gnu/libkrb5.so.3",
        "/usr/lib/aarch64-linux-gnu/libkrb5.so.3",
        "/usr/lib64/libkrb5.so.3",
        "/usr/lib/libkrb5.so.3",
    ]
    for cand in candidates:
        try:
            lib = ctypes.CDLL(cand)
            return cand
        except OSError:
            pass

    found = ctypes.util.find_library("krb5")
    if found:
        try:
            ctypes.CDLL(found)
            return found
        except OSError:
            pass

    found_gss = ctypes.util.find_library("gssapi_krb5")
    if found_gss:
        try:
            ctypes.CDLL(found_gss)
            return found_gss
        except OSError:
            pass

    return None


def find_static_binary() -> Optional[str]:
    """Check if static binary tanuki-cli or tanuki is accessible on PATH or local locations."""
    for name in ("tanuki-cli", "tanuki"):
        found = shutil.which(name)
        if found:
            return found
    local_candidates = [
        "./tanuki-cli",
        "./tanuki",
        "/usr/local/bin/tanuki-cli",
        "/usr/local/bin/tanuki",
        os.path.expanduser("~/.local/bin/tanuki-cli"),
        os.path.expanduser("~/.local/bin/tanuki"),
    ]
    for cand in local_candidates:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def get_distro_guidance() -> str:
    """Inspect /etc/os-release (if present) and return actionable distro-specific guidance."""
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read().lower()
                if "alpine" in content:
                    return "Alpine: apk add krb5-libs"
                if any(x in content for x in ("debian", "ubuntu", "kali")):
                    return "Debian/Ubuntu/Kali: apt install libkrb5-3"
                if any(x in content for x in ("rhel", "centos", "fedora", "rocky", "alma")):
                    return "RHEL/CentOS/Fedora: dnf install krb5-libs"
                break
            except OSError:
                pass
    return "Standalone: Use the self-contained static musl binary."


def acquire_tgt_via_ctypes(
    keytab_path: str,
    principal: str,
    ccache_path: str,
    lib_path: Optional[str] = None,
    krb5_conf: Optional[str] = None,
    fast: bool = False,
    armor_cache: Optional[str] = None,
) -> Dict[str, Any]:
    """Acquire TGT using standard library ctypes bound to libkrb5 C runtime."""
    if krb5_conf:
        os.environ["KRB5_CONFIG"] = os.path.abspath(krb5_conf)

    target_lib = lib_path or find_krb5_library()
    krb5 = None
    if target_lib:
        try:
            krb5 = ctypes.CDLL(target_lib)
        except OSError:
            krb5 = None

    if krb5 is None:
        static_bin = find_static_binary()
        if static_bin:
            cmd = [static_bin, "auth", "--keytab", os.path.abspath(keytab_path), "--principal", principal]
            if ccache_path:
                cmd.extend(["--ccache", os.path.abspath(ccache_path)])
            if fast:
                cmd.append("--fast")
            if armor_cache:
                cmd.extend(["--armor-cache", os.path.abspath(armor_cache)])
            env = dict(os.environ)
            if krb5_conf:
                env["KRB5_CONFIG"] = os.path.abspath(krb5_conf)
            try:
                proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
                if proc.returncode == 0:
                    res_dict = {
                        "status": "SUCCESS",
                        "method": "static-binary",
                        "principal": principal,
                        "keytab": os.path.abspath(keytab_path),
                        "ccache": os.path.abspath(ccache_path),
                        "export_command": f"export KRB5CCNAME={os.path.abspath(ccache_path)}",
                    }
                    if fast:
                        res_dict["fast"] = True
                    if armor_cache:
                        res_dict["armor_cache"] = os.path.abspath(armor_cache)
                    return res_dict
            except (subprocess.SubprocessError, OSError):
                pass

        guidance = get_distro_guidance()
        return {
            "status": "ERROR",
            "reason_code": "MISSING_GSSAPI_LIBRARY",
            "category": "DEPENDENCY_ERROR",
            "exit_code": 3,
            "message": f"libkrb5/libgssapi_krb5 shared library not found on host. {guidance}",
            "details": guidance,
            "recommendation": guidance,
        }

    # Initialize Kerberos context
    ctx = ctypes.c_void_p()
    krb5.krb5_init_context.restype = ctypes.c_int32
    krb5.krb5_init_context.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    ret = krb5.krb5_init_context(ctypes.byref(ctx))
    if ret != 0:
        return {
            "status": "ERROR",
            "reason_code": "INIT_CONTEXT_FAILED",
            "category": "PROTOCOL_ERROR",
            "message": f"krb5_init_context failed with error code {ret}",
        }

    try:
        # Parse principal string
        princ = ctypes.c_void_p()
        krb5.krb5_parse_name.restype = ctypes.c_int32
        krb5.krb5_parse_name.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        ret = krb5.krb5_parse_name(ctx, principal.encode("utf-8"), ctypes.byref(princ))
        if ret != 0:
            return {
                "status": "ERROR",
                "reason_code": "PARSE_PRINCIPAL_FAILED",
                "category": "PROTOCOL_ERROR",
                "message": f"krb5_parse_name failed for principal '{principal}' (code {ret})",
            }

        try:
            # Resolve keytab file
            kt = ctypes.c_void_p()
            krb5.krb5_kt_resolve.restype = ctypes.c_int32
            krb5.krb5_kt_resolve.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            kt_spec = f"FILE:{os.path.abspath(keytab_path)}".encode("utf-8")
            ret = krb5.krb5_kt_resolve(ctx, kt_spec, ctypes.byref(kt))
            if ret != 0:
                return {
                    "status": "ERROR",
                    "reason_code": "KEYTAB_RESOLVE_FAILED",
                    "category": "RESOURCE_MISSING",
                    "message": f"krb5_kt_resolve failed for keytab '{keytab_path}' (code {ret})",
                }

            try:
                # Resolve destination credential cache
                cc = ctypes.c_void_p()
                krb5.krb5_cc_resolve.restype = ctypes.c_int32
                krb5.krb5_cc_resolve.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_char_p,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                cc_spec = f"FILE:{os.path.abspath(ccache_path)}".encode("utf-8")
                ret = krb5.krb5_cc_resolve(ctx, cc_spec, ctypes.byref(cc))
                if ret != 0:
                    return {
                        "status": "ERROR",
                        "reason_code": "CCACHE_RESOLVE_FAILED",
                        "category": "RESOURCE_MISSING",
                        "message": f"krb5_cc_resolve failed for ccache '{ccache_path}' (code {ret})",
                    }

                try:
                    # Initialize destination ccache with target principal
                    krb5.krb5_cc_initialize.restype = ctypes.c_int32
                    krb5.krb5_cc_initialize.argtypes = [
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                    ]
                    ret = krb5.krb5_cc_initialize(ctx, cc, princ)
                    if ret != 0:
                        return {
                            "status": "ERROR",
                            "reason_code": "CCACHE_INIT_FAILED",
                            "category": "PROTOCOL_ERROR",
                            "message": f"krb5_cc_initialize failed (code {ret})",
                        }

                    # Allocate initialization options if supported
                    opt = ctypes.c_void_p()
                    has_opt_alloc = hasattr(krb5, "krb5_get_init_creds_opt_alloc")
                    if has_opt_alloc:
                        krb5.krb5_get_init_creds_opt_alloc.restype = ctypes.c_int32
                        krb5.krb5_get_init_creds_opt_alloc.argtypes = [
                            ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_void_p),
                        ]
                        krb5.krb5_get_init_creds_opt_alloc(ctx, ctypes.byref(opt))
                        if opt:
                            if armor_cache and hasattr(krb5, "krb5_get_init_creds_opt_set_fast_ccache_name"):
                                try:
                                    krb5.krb5_get_init_creds_opt_set_fast_ccache_name.restype = ctypes.c_int32
                                    krb5.krb5_get_init_creds_opt_set_fast_ccache_name.argtypes = [
                                        ctypes.c_void_p,
                                        ctypes.c_void_p,
                                        ctypes.c_char_p,
                                    ]
                                    krb5.krb5_get_init_creds_opt_set_fast_ccache_name(ctx, opt, os.path.abspath(armor_cache).encode("utf-8"))
                                except Exception:
                                    pass
                            if fast and hasattr(krb5, "krb5_get_init_creds_opt_set_fast_flags"):
                                try:
                                    krb5.krb5_get_init_creds_opt_set_fast_flags.restype = ctypes.c_int32
                                    krb5.krb5_get_init_creds_opt_set_fast_flags.argtypes = [
                                        ctypes.c_void_p,
                                        ctypes.c_void_p,
                                        ctypes.c_uint32,
                                    ]
                                    krb5.krb5_get_init_creds_opt_set_fast_flags(ctx, opt, 1)
                                except Exception:
                                    pass

                    # Buffer for krb5_creds structure (expanded to 4096 bytes for safe struct alignment)
                    creds_buf = ctypes.create_string_buffer(4096)

                    krb5.krb5_get_init_creds_keytab.restype = ctypes.c_int32
                    krb5.krb5_get_init_creds_keytab.argtypes = [
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_int32,
                        ctypes.c_char_p,
                        ctypes.c_void_p,
                    ]
                    def _get_err(code: int, default: str) -> str:
                        if hasattr(krb5, "krb5_get_error_message"):
                            try:
                                krb5.krb5_get_error_message.restype = ctypes.c_void_p
                                krb5.krb5_get_error_message.argtypes = [
                                    ctypes.c_void_p,
                                    ctypes.c_int32,
                                ]
                                msg_ptr = krb5.krb5_get_error_message(ctx, code)
                                if msg_ptr:
                                    try:
                                        return ctypes.string_at(msg_ptr).decode("utf-8", errors="replace")
                                    finally:
                                        if hasattr(krb5, "krb5_free_error_message"):
                                            krb5.krb5_free_error_message.restype = None
                                            krb5.krb5_free_error_message.argtypes = [
                                                ctypes.c_void_p,
                                                ctypes.c_void_p,
                                            ]
                                            krb5.krb5_free_error_message(ctx, msg_ptr)
                            except Exception:
                                pass
                        return default

                    try:
                        ret = krb5.krb5_get_init_creds_keytab(
                            ctx,
                            ctypes.byref(creds_buf),
                            princ,
                            kt,
                            0,
                            None,
                            opt if opt.value else None,
                        )

                        if ret != 0:
                            err_msg = _get_err(ret, f"krb5_get_init_creds_keytab failed (code {ret})")
                            return {
                                "status": "ERROR",
                                "reason_code": "AUTH_FAILED",
                                "category": "PROTOCOL_ERROR",
                                "message": err_msg,
                            }

                        try:
                            # Store acquired credentials into the ccache
                            krb5.krb5_cc_store_cred.restype = ctypes.c_int32
                            krb5.krb5_cc_store_cred.argtypes = [
                                ctypes.c_void_p,
                                ctypes.c_void_p,
                                ctypes.c_void_p,
                            ]
                            ret = krb5.krb5_cc_store_cred(ctx, cc, ctypes.byref(creds_buf))
                            if ret != 0:
                                return {
                                    "status": "ERROR",
                                    "reason_code": "STORE_CRED_FAILED",
                                    "category": "PROTOCOL_ERROR",
                                    "message": f"krb5_cc_store_cred failed (code {ret})",
                                }
                        finally:
                            if hasattr(krb5, "krb5_free_cred_contents"):
                                krb5.krb5_free_cred_contents.restype = None
                                krb5.krb5_free_cred_contents.argtypes = [
                                    ctypes.c_void_p,
                                    ctypes.c_void_p,
                                ]
                                krb5.krb5_free_cred_contents(ctx, ctypes.byref(creds_buf))
                    finally:
                        if has_opt_alloc and opt.value:
                            if hasattr(krb5, "krb5_get_init_creds_opt_free"):
                                krb5.krb5_get_init_creds_opt_free.restype = ctypes.c_int32
                                krb5.krb5_get_init_creds_opt_free.argtypes = [
                                    ctypes.c_void_p,
                                    ctypes.c_void_p,
                                ]
                                krb5.krb5_get_init_creds_opt_free(ctx, opt)

                    if hasattr(os, "chmod") and os.path.exists(ccache_path):
                        try:
                            os.chmod(ccache_path, 0o600)
                        except OSError:
                            pass

                    res_dict = {
                        "status": "SUCCESS",
                        "method": "ctypes",
                        "principal": principal,
                        "keytab": os.path.abspath(keytab_path),
                        "ccache": os.path.abspath(ccache_path),
                        "export_command": f"export KRB5CCNAME={os.path.abspath(ccache_path)}",
                    }
                    if fast:
                        res_dict["fast"] = True
                    if armor_cache:
                        res_dict["armor_cache"] = os.path.abspath(armor_cache)
                    return res_dict
                finally:
                    if hasattr(krb5, "krb5_cc_close"):
                        krb5.krb5_cc_close.restype = ctypes.c_int32
                        krb5.krb5_cc_close.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                        krb5.krb5_cc_close(ctx, cc)
            finally:
                if hasattr(krb5, "krb5_kt_close"):
                    krb5.krb5_kt_close.restype = ctypes.c_int32
                    krb5.krb5_kt_close.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                    krb5.krb5_kt_close(ctx, kt)
        finally:
            if hasattr(krb5, "krb5_free_principal"):
                krb5.krb5_free_principal.restype = None
                krb5.krb5_free_principal.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                krb5.krb5_free_principal(ctx, princ)
    finally:
        if hasattr(krb5, "krb5_free_context"):
            krb5.krb5_free_context.restype = None
            krb5.krb5_free_context.argtypes = [ctypes.c_void_p]
            krb5.krb5_free_context(ctx)


def acquire_tgt(
    keytab_path: str,
    principal: Optional[str] = None,
    ccache_path: Optional[str] = None,
    force_ctypes: bool = False,
    krb5_conf: Optional[str] = None,
    kdc: Optional[str] = None,
    fast: bool = False,
    armor_cache: Optional[str] = None,
) -> Dict[str, Any]:
    """Acquire TGT using keytab via host kinit or fallback ctypes C library bridge."""
    if not os.path.exists(keytab_path):
        return {
            "status": "ERROR",
            "reason_code": "MISSING_KEYTAB",
            "category": "RESOURCE_MISSING",
            "message": f"Keytab file not found: '{keytab_path}'",
            "target": keytab_path,
        }

    # Extract principals from keytab for resolution and helpful guidance
    found_principals: List[str] = []
    try:
        entries = parse_keytab_file(keytab_path)
        found_principals = list(dict.fromkeys(e.get("principal") for e in entries if e.get("principal")))
    except Exception as exc:
        return {
            "status": "ERROR",
            "reason_code": "CORRUPT_KEYTAB",
            "category": "PARSE_FAILURE",
            "message": f"Error parsing keytab to determine principal: {exc}",
            "target": keytab_path,
        }

    target_princ = principal
    if not target_princ or not target_princ.strip():
        if found_principals:
            target_princ = found_principals[0]
        else:
            return {
                "status": "ERROR",
                "reason_code": "MISSING_PRINCIPAL",
                "category": "USAGE_ERROR",
                "message": "No valid principal specified or found within keytab file.",
                "target": keytab_path,
            }

    target_princ = target_princ.strip()

    # Determine destination credential cache path
    target_ccache = ccache_path
    if not target_ccache:
        env_cc = os.environ.get("KRB5CCNAME")
        if env_cc:
            if env_cc.startswith("FILE:"):
                target_ccache = env_cc[5:]
            elif env_cc.startswith("/"):
                target_ccache = env_cc
    if not target_ccache:
        uid = getattr(os, "getuid", lambda: 1000)()
        if os.name != "nt":
            target_ccache = f"/tmp/krb5cc_{uid}"
        else:
            target_ccache = os.path.join(tempfile.gettempdir(), f"krb5cc_{uid}")

    abs_ccache = os.path.abspath(target_ccache)
    abs_keytab = os.path.abspath(keytab_path)

    parent_dir = os.path.dirname(abs_ccache)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    # Fast non-blocking socket probe (<800ms) before initiating Kerberos auth over live wire
    target_kdc_host = kdc.split(",")[0].strip().split(":")[0].strip() if kdc else None
    if not target_kdc_host:
        conf_to_check = krb5_conf or os.environ.get("KRB5_CONFIG") or "/etc/krb5.conf"
        if os.path.isfile(conf_to_check):
            try:
                with open(conf_to_check, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line_s = line.strip()
                        if line_s.startswith("kdc") and "=" in line_s:
                            target_kdc_host = line_s.split("=")[1].strip().split()[0].split(",")[0].split(":")[0]
                            break
            except OSError:
                pass
    if not target_kdc_host and target_princ and "@" in target_princ:
        realm = target_princ.split("@")[-1].strip()
        try:
            from .config import discover_dc_via_srv
            discovered = discover_dc_via_srv(realm, timeout=0.8)
            if discovered:
                target_kdc_host = discovered[0]
        except Exception:
            pass

    if target_kdc_host:
        from .ldap import probe_tcp_port
        reachable, err_msg = probe_tcp_port(target_kdc_host, 88, timeout=0.8)
        if not reachable:
            remediation = f"ssh -L 8888:{target_kdc_host}:88 user@pivot -N"
            return {
                "status": "ERROR",
                "reason_code": "KDC_UNREACHABLE",
                "category": "NETWORK_ERROR",
                "exit_code": 3,
                "message": f"KDC port 88 unreachable on host '{target_kdc_host}' ({err_msg}). Tactical remediation: Verify network route/firewall or configure SSH port-forwarding pivot: {remediation}",
                "recommendation": f"Configure SSH port-forwarding pivot: {remediation}",
                "details": remediation,
                "target": abs_keytab,
            }

    # 1. Try host kinit if available and not explicitly forcing ctypes
    kinit_bin = shutil.which("kinit")
    kinit_err: Optional[str] = None
    if kinit_bin and not force_ctypes:
        cmd = [kinit_bin, "-k", "-t", abs_keytab, target_princ]
        if armor_cache:
            cmd.extend(["-T", os.path.abspath(armor_cache)])
        env = dict(os.environ)
        if krb5_conf:
            env["KRB5_CONFIG"] = os.path.abspath(krb5_conf)
        env["KRB5CCNAME"] = f"FILE:{abs_ccache}"
        try:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                if hasattr(os, "chmod") and os.path.exists(abs_ccache):
                    try:
                        os.chmod(abs_ccache, 0o600)
                    except OSError:
                        pass
                success_dict = {
                    "status": "SUCCESS",
                    "method": "kinit",
                    "principal": target_princ,
                    "keytab": abs_keytab,
                    "ccache": abs_ccache,
                    "export_command": f"export KRB5CCNAME={abs_ccache}",
                }
                if fast:
                    success_dict["fast"] = True
                if armor_cache:
                    success_dict["armor_cache"] = os.path.abspath(armor_cache)
                return success_dict
            else:
                kinit_err = (proc.stderr or proc.stdout or "").strip()
        except (subprocess.SubprocessError, OSError) as exc:
            kinit_err = str(exc)

    # 2. Fallback to ctypes bridge loading libkrb5.so.3
    ctypes_res = acquire_tgt_via_ctypes(
        keytab_path=abs_keytab,
        principal=target_princ,
        ccache_path=abs_ccache,
        krb5_conf=krb5_conf,
        fast=fast,
        armor_cache=armor_cache,
    )
    if ctypes_res.get("status") == "SUCCESS":
        return ctypes_res

    # 3. Clean fallback when neither kinit nor libkrb5.so is available
    if not kinit_bin and ctypes_res.get("reason_code") in ("MISSING_GSSAPI_LIBRARY", "LIBRARY_NOT_FOUND", "LIBRARY_LOAD_FAILED"):
        return ctypes_res

    # If kinit was attempted and failed, and ctypes failed because libkrb5 was not found,
    # report kinit's error rather than masking it with LIBRARY_NOT_FOUND
    res = ctypes_res
    if kinit_bin and not force_ctypes and ctypes_res.get("reason_code") in ("MISSING_GSSAPI_LIBRARY", "LIBRARY_NOT_FOUND", "LIBRARY_LOAD_FAILED"):
        res = {
            "status": "ERROR",
            "reason_code": "AUTH_FAILED",
            "category": "PROTOCOL_ERROR",
            "message": f"kinit authentication failed: {kinit_err or 'unknown error'}",
            "principal": target_princ,
            "keytab": abs_keytab,
        }

    if res.get("status") == "ERROR" and found_principals and target_princ not in found_principals:
        cur_msg = res.get("message", "")
        hint_text = f" (Principal '{target_princ}' was not found in keytab. Available in keytab: {', '.join(found_principals)}. If mapped via ktpass, use the SPN as --principal)"
        res["message"] = cur_msg + hint_text
        res["available_principals"] = found_principals

    return res


def inject_ticket_to_keyring(
    ccache_bytes_or_path: Any,
    key_name: str = "krb5cc",
    keyring_id: int = -3,  # KEY_SPEC_SESSION_KEYRING
) -> Dict[str, Any]:
    """Inject credential cache directly into Linux Kernel Keyring via add_key syscall."""
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return {
            "status": "UNSUPPORTED_PLATFORM",
            "message": "Linux Kernel Keyring injection requires Linux OS with keyctl syscall support.",
        }

    data: bytes = b""
    if isinstance(ccache_bytes_or_path, str):
        if not os.path.isfile(ccache_bytes_or_path):
            return {
                "status": "FILE_NOT_FOUND",
                "target": ccache_bytes_or_path,
                "message": f"Ccache file not found: {ccache_bytes_or_path}",
            }
        with open(ccache_bytes_or_path, "rb") as f:
            data = f.read()
    elif isinstance(ccache_bytes_or_path, (bytes, bytearray)):
        data = bytes(ccache_bytes_or_path)

    if not data:
        return {"status": "EMPTY_PAYLOAD", "message": "Cannot inject empty ticket payload."}

    import platform
    machine = platform.machine().lower()
    # Syscall numbers for __NR_add_key
    syscall_nr = 248  # x86_64 default
    if "aarch64" in machine or "arm64" in machine:
        syscall_nr = 217
    elif "i386" in machine or "i686" in machine:
        syscall_nr = 286

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        key_type = b"user"
        key_desc = key_name.encode("utf-8")
        payload_buf = ctypes.c_char_p(data)
        payload_len = ctypes.c_size_t(len(data))
        target_ring = ctypes.c_int32(keyring_id)

        res_id = libc.syscall(
            ctypes.c_long(syscall_nr),
            key_type,
            key_desc,
            payload_buf,
            payload_len,
            target_ring,
        )

        if res_id >= 0:
            return {
                "status": "SUCCESS",
                "key_id": res_id,
                "key_name": key_name,
                "keyring": "KEYRING:session" if keyring_id == -3 else f"KEYRING:{keyring_id}",
                "bytes_injected": len(data),
            }
        else:
            errno_val = ctypes.get_errno()
            return {
                "status": "ERROR",
                "errno": errno_val,
                "message": f"Syscall add_key failed with errno {errno_val}",
            }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"Kernel keyring injection failed: {exc}",
        }

