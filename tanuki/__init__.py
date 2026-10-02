"""Tanuki: Protocol-First Linux Active Directory & Kerberos Triage Engine."""

__version__ = "1.1.0"
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
]

from .keytab import parse_keytab_bytes, parse_keytab_stream, parse_keytab_file
from .kcm import scan_for_ccache_blobs, try_parse_default_principal
from .protocol import find_error_resolution, ERROR_DICTIONARY, DECISION_LADDER
