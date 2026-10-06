"""Tanuki: Protocol-First Linux Active Directory & Kerberos Triage Engine."""

__version__ = "1.2.1"
__author__ = "Mafifrizi"
__all__ = [
    "parse_keytab_bytes",
    "parse_keytab_stream",
    "parse_keytab_file",
    "scan_for_ccache_blobs",
    "try_parse_default_principal",
    "find_error_resolution",
    "ERROR_DICTIONARY",
    "DECISION_LADDER",
    "diagnose_system",
    "DoctorReport",
    "check_host_tools",
    "generate_krb5_conf",
    "format_telemetry_terminal",
    "validate_jwt_workload",
    "validate_token_exchange",
    "acquire_tgt",
    "acquire_tgt_via_ctypes",
    "parse_windows_sid",
    "parse_rbcd_security_descriptor",
    "parse_nt_security_descriptor",
]

from .keytab import parse_keytab_bytes, parse_keytab_stream, parse_keytab_file
from .kcm import scan_for_ccache_blobs, try_parse_default_principal
from .protocol import find_error_resolution, ERROR_DICTIONARY, DECISION_LADDER
from .doctor import diagnose_system, DoctorReport, check_host_tools
from .config import generate_krb5_conf
from .telemetry import format_telemetry_terminal
from .nhi import validate_jwt_workload, validate_token_exchange
from .auth import acquire_tgt, acquire_tgt_via_ctypes
from .pac import parse_windows_sid, parse_rbcd_security_descriptor, parse_nt_security_descriptor

