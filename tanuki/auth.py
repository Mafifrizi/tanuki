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


def acquire_tgt_via_ctypes(
    keytab_path: str,
    principal: str,
    ccache_path: str,
    lib_path: Optional[str] = None,
    krb5_conf: Optional[str] = None,
) -> Dict[str, Any]:
    """Acquire TGT using standard library ctypes bound to libkrb5 C runtime."""
    if krb5_conf:
        os.environ["KRB5_CONFIG"] = os.path.abspath(krb5_conf)

    target_lib = lib_path or find_krb5_library()
    if not target_lib:
        return {
            "status": "ERROR",
            "reason_code": "LIBRARY_NOT_FOUND",
            "category": "RESOURCE_MISSING",
            "message": "libkrb5 shared library not found on host filesystem.",
            "recommendation": "Install krb5-user/libkrb53 or make libkrb5.so.3 available in library path.",
        }

    try:
        krb5 = ctypes.CDLL(target_lib)
    except OSError as exc:
        return {
            "status": "ERROR",
            "reason_code": "LIBRARY_LOAD_FAILED",
            "category": "RESOURCE_MISSING",
            "message": f"Failed to load shared library '{target_lib}': {exc}",
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

                    # Buffer for krb5_creds structure
                    creds_buf = ctypes.create_string_buffer(1024)

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

                    return {
                        "status": "SUCCESS",
                        "method": "ctypes",
                        "principal": principal,
                        "keytab": os.path.abspath(keytab_path),
                        "ccache": os.path.abspath(ccache_path),
                        "export_command": f"export KRB5CCNAME={os.path.abspath(ccache_path)}",
                    }
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

    # Extract principal from keytab if omitted
    target_princ = principal
    if not target_princ or not target_princ.strip():
        try:
            entries = parse_keytab_file(keytab_path)
            for e in entries:
                p = (e.get("principal") or "").strip()
                if p:
                    target_princ = p
                    break
        except Exception as exc:
            return {
                "status": "ERROR",
                "reason_code": "CORRUPT_KEYTAB",
                "category": "PARSE_FAILURE",
                "message": f"Error parsing keytab to determine principal: {exc}",
                "target": keytab_path,
            }

    if not target_princ:
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

    # 1. Try host kinit if available and not explicitly forcing ctypes
    kinit_bin = shutil.which("kinit")
    kinit_err: Optional[str] = None
    if kinit_bin and not force_ctypes:
        cmd = [kinit_bin, "-k", "-t", abs_keytab, target_princ]
        env = dict(os.environ)
        if krb5_conf:
            env["KRB5_CONFIG"] = os.path.abspath(krb5_conf)
        env["KRB5CCNAME"] = f"FILE:{abs_ccache}"
        try:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                return {
                    "status": "SUCCESS",
                    "method": "kinit",
                    "principal": target_princ,
                    "keytab": abs_keytab,
                    "ccache": abs_ccache,
                    "export_command": f"export KRB5CCNAME={abs_ccache}",
                }
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
    )
    if ctypes_res.get("status") == "SUCCESS":
        return ctypes_res

    # 3. Clean fallback when neither kinit nor libkrb5.so is available
    if not kinit_bin and ctypes_res.get("reason_code") in ("LIBRARY_NOT_FOUND", "LIBRARY_LOAD_FAILED"):
        return {
            "status": "ERROR",
            "reason_code": "NO_AUTHENTICATION_BACKEND",
            "category": "RESOURCE_MISSING",
            "message": "'kinit' utility not found on PATH and libkrb5 shared runtime not available.",
            "recommendation": "Install krb5-user (Debian/Ubuntu/Kali) or ensure libkrb5.so.3 is present on host.",
            "principal": target_princ,
            "keytab": abs_keytab,
        }

    # If kinit was attempted and failed, and ctypes failed because libkrb5 was not found,
    # report kinit's error rather than masking it with LIBRARY_NOT_FOUND
    if kinit_bin and not force_ctypes and ctypes_res.get("reason_code") in ("LIBRARY_NOT_FOUND", "LIBRARY_LOAD_FAILED"):
        return {
            "status": "ERROR",
            "reason_code": "AUTH_FAILED",
            "category": "PROTOCOL_ERROR",
            "message": f"kinit authentication failed: {kinit_err or 'unknown error'}",
            "principal": target_princ,
            "keytab": abs_keytab,
        }

    return ctypes_res


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

