"""Tanuki: Protocol-First Linux Active Directory & Kerberos Triage Engine."""

__version__ = "1.2.0"
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
    "format_telemetry_terminal",
    "validate_jwt_workload",
    "validate_token_exchange",
]

from .keytab import parse_keytab_bytes, parse_keytab_stream, parse_keytab_file
from .kcm import scan_for_ccache_blobs, try_parse_default_principal
from .protocol import find_error_resolution, ERROR_DICTIONARY, DECISION_LADDER
from .doctor import diagnose_system, DoctorReport
from .telemetry import format_telemetry_terminal
from .nhi import validate_jwt_workload, validate_token_exchange

