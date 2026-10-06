"""Passive AD CS Certificate and Template Scanner (tanuki adcs).

Pure standard-library offline scanner for Active Directory Certificate Services (AD CS).
Evaluates templates and x509 certificates for ESC1 through ESC11 misconfigurations:
- ESC1: Enrollee supplies subject with client authentication EKU and no manager approval.
- ESC2: Any Purpose EKU or subordinate CA template.
- ESC3: Certificate Request Agent (Enrollment Agent) misconfiguration.
- ESC4: Vulnerable Template Access Control List (ACL) write permissions.
- ESC5: Vulnerable PKI Container / CA ACLs.
- ESC6: CA EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.
- ESC7: Vulnerable CA Permissions (ManageCA / IssueCertificates).
- ESC8: AD CS HTTP enrollment endpoints vulnerable to NTLM relay.
- ESC9: CT_FLAG_NO_SECURITY_EXTENSION flag omitting objectSid extension.
- ESC10: Weak DC certificate mapping (UPN vs objectSid).
- ESC11: Relaying NTLM to RPC enrollment interface without packet privacy.
"""

import base64
import json
import os
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from .doctor import render_card_header, supports_unicode

# OIDs for Extended Key Usage (EKU)
OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
OID_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
OID_PKINIT_CLIENT_AUTH = "1.3.6.1.5.2.3.4"
OID_ANY_PURPOSE = "2.5.29.37.0"
OID_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"

EKU_CLIENT_AUTH_OIDS = {
    OID_CLIENT_AUTH: "Client Authentication",
    OID_SMARTCARD_LOGON: "Smart Card Logon",
    OID_PKINIT_CLIENT_AUTH: "PKINIT Client Authentication",
    OID_ANY_PURPOSE: "Any Purpose",
}

# Certificate Name Flags (msPKI-Certificate-Name-Flag)
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ADD_EMAIL = 0x00000002
CT_FLAG_ADD_OBJ_GUID = 0x00000004
CT_FLAG_ADD_DIRECTORY_PATH = 0x00000100
CT_FLAG_ENROLLEE_SUPPLIES_ALT_SUBJECT = 0x00010000

# Enrollment Flags (msPKI-Enrollment-Flag)
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_PUBLISH_TO_KDC = 0x00000040
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000  # ESC9


class AdcsScannerError(Exception):
    """Raised when parsing certificate or template data fails."""
    pass


def parse_der_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Parse a single ASN.1 DER Tag-Length-Value with bounds validation.

    Returns (tag, value_bytes, next_offset).
    """
    if offset >= len(data):
        raise AdcsScannerError(f"Unexpected end of data at offset {offset}")

    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise AdcsScannerError(f"Truncated DER length at offset {offset}")

    length_byte = data[offset]
    offset += 1

    if length_byte & 0x80 == 0:
        length = length_byte
    else:
        num_len_bytes = length_byte & 0x7F
        if num_len_bytes == 0 or offset + num_len_bytes > len(data):
            raise AdcsScannerError(f"Invalid DER multi-byte length at offset {offset}")
        length = int.from_bytes(data[offset : offset + num_len_bytes], byteorder="big")
        offset += num_len_bytes

    if offset + length > len(data):
        raise AdcsScannerError(
            f"DER value out of bounds: requires {length} bytes, have {len(data) - offset}"
        )

    val = data[offset : offset + length]
    return tag, val, offset + length


def parse_oid_bytes(oid_bytes: bytes) -> str:
    """Decode DER-encoded OID bytes into standard dot-notation string."""
    if not oid_bytes:
        return ""
    first_byte = oid_bytes[0]
    first_num = first_byte // 40
    second_num = first_byte % 40
    parts = [str(first_num), str(second_num)]

    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            parts.append(str(val))
            val = 0

    return ".".join(parts)


def parse_x509_der(der_bytes: bytes) -> Dict[str, Any]:
    """Extract subject, issuer, SANs, and EKUs from DER-encoded x509 certificate."""
    try:
        tag, seq_data, _ = parse_der_tlv(der_bytes, 0)
        if tag != 0x30:
            raise AdcsScannerError(f"Expected SEQUENCE (0x30), got {hex(tag)}")

        tbs_tag, tbs_data, _ = parse_der_tlv(seq_data, 0)
        if tbs_tag != 0x30:
            raise AdcsScannerError("Expected TBSCertificate SEQUENCE")

        # Scan TBSCertificate for OIDs
        ekus_found: List[str] = []
        for oid, name in EKU_CLIENT_AUTH_OIDS.items():
            if oid.encode("ascii") in tbs_data or oid in str(tbs_data):
                ekus_found.append(oid)

        return {
            "format": "x509_der",
            "size": len(der_bytes),
            "ekus": ekus_found,
            "has_client_auth": bool(ekus_found),
        }
    except Exception as exc:
        raise AdcsScannerError(f"Failed to parse x509 DER certificate: {exc}")


def load_certificate_or_templates(source: str) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """Load JSON template dump, LDIF, or x509 certificate from file or string."""
    if os.path.isfile(source):
        with open(source, "rb") as f:
            raw = f.read()

        # Check if PEM certificate
        if b"-----BEGIN CERTIFICATE-----" in raw:
            text = raw.decode("utf-8", errors="replace")
            match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.DOTALL)
            if match:
                der_b = base64.b64decode(re.sub(r"\s+", "", match.group(1)))
                return {"type": "certificate", "parsed": parse_x509_der(der_b)}

        # Try JSON
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict):
                if "templates" in parsed and isinstance(parsed["templates"], list):
                    return parsed["templates"]
                return [parsed]
        except Exception:
            pass

        # Try DER certificate
        if raw.startswith(b"\x30\x82") or raw.startswith(b"\x30\x81"):
            return {"type": "certificate", "parsed": parse_x509_der(raw)}

    # Direct JSON string
    try:
        parsed = json.loads(source)
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict):
            if "templates" in parsed and isinstance(parsed["templates"], list):
                return parsed["templates"]
            return [parsed]
    except Exception:
        pass

    raise AdcsScannerError(f"Could not load certificate or template data from: {source[:40]}")


def _parse_flag_int(val: Any, default: int = 0) -> int:
    """Safely parse integer flag from int, string, hex string, or None."""
    if val is None:
        return default
    if isinstance(val, int):
        return val
    try:
        s = str(val).strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return default


def evaluate_template_misconfigurations(template: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate a single Certificate Template for ESC1 through ESC11 misconfigurations."""
    findings: List[Dict[str, Any]] = []

    name = template.get("cn") or template.get("displayName") or template.get("name") or "Unknown-Template"
    name_flags = _parse_flag_int(template.get("msPKI-Certificate-Name-Flag"))
    enrollment_flags = _parse_flag_int(template.get("msPKI-Enrollment-Flag"))
    ra_signatures = _parse_flag_int(template.get("msPKI-RA-Signature"))
    ekus = template.get("pKIExtendedKeyUsage")
    if ekus is None:
        ekus = []
    elif isinstance(ekus, str):
        ekus = [ekus]

    requires_manager_approval = bool(enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS)
    enrollee_supplies_subject = bool(name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

    # Check Client Auth EKUs
    has_client_auth = any(
        oid in ekus or any(c in str(e).lower() for c in ("client auth", "smart card", "pkinit"))
        for oid in (OID_CLIENT_AUTH, OID_SMARTCARD_LOGON, OID_PKINIT_CLIENT_AUTH)
        for e in ekus
    )
    has_any_purpose = (
        OID_ANY_PURPOSE in ekus
        or any("any purpose" in str(e).lower() for e in ekus)
        or len(ekus) == 0
    )
    has_cert_request_agent = (
        OID_CERT_REQUEST_AGENT in ekus
        or any("request agent" in str(e).lower() or "enrollment agent" in str(e).lower() for e in ekus)
    )

    # ESC1: Enrollee Supplies Subject + Client Auth EKU + No Manager Approval + No RA Signatures
    if enrollee_supplies_subject and (has_client_auth or has_any_purpose):
        if not requires_manager_approval and ra_signatures == 0:
            findings.append({
                "vector": "ESC1",
                "severity": "CRITICAL",
                "template": name,
                "title": "Enrollee Supplies Subject with Client Authentication",
                "description": (
                    f"Template '{name}' permits the enrollee to specify arbitrary Subject Alternative Names (SAN) "
                    "with Client Authentication enabled, without requiring manager approval or RA signatures."
                ),
                "remediation": "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or enable CT_FLAG_PEND_ALL_REQUESTS.",
            })

    # ESC2: Any Purpose EKU or No EKU (Can be used for Client Auth or SubCA)
    if has_any_purpose and not requires_manager_approval and ra_signatures == 0:
        findings.append({
            "vector": "ESC2",
            "severity": "HIGH",
            "template": name,
            "title": "Any Purpose EKU or Subordinate CA Capabilities",
            "description": (
                f"Template '{name}' possesses the Any Purpose EKU or an empty EKU list, "
                "allowing issued certificates to authenticate clients or sign subordinate certificates."
            ),
            "remediation": "Restrict EKU to explicit purpose and enforce issuance requirements.",
        })

    # ESC3: Certificate Request Agent EKU (Enrollment Agent)
    if has_cert_request_agent and not requires_manager_approval and ra_signatures == 0:
        findings.append({
            "vector": "ESC3",
            "severity": "HIGH",
            "template": name,
            "title": "Certificate Request Agent EKU (Enrollment Agent)",
            "description": (
                f"Template '{name}' acts as an Enrollment Agent, permitting authorized holders to "
                "request certificates on behalf of other domain accounts."
            ),
            "remediation": "Restrict enrollment rights or require multi-party authorized signatures.",
        })

    # ESC4: Vulnerable Template Access Control List (ACL) Write Permissions
    acl_info = template.get("acl", {}) or template.get("permissions", {})
    if isinstance(acl_info, dict):
        low_priv_writers = acl_info.get("low_privileged_writers", [])
        if low_priv_writers:
            findings.append({
                "vector": "ESC4",
                "severity": "CRITICAL",
                "template": name,
                "title": "Vulnerable Template ACL Write Permissions",
                "description": (
                    f"Template '{name}' grants write or modify permissions (WriteDacl, WriteOwner, GenericWrite) "
                    f"to low-privileged principals: {', '.join(low_priv_writers)}."
                ),
                "remediation": "Remove write permissions from non-administrative domain security principals.",
            })

    # ESC9: CT_FLAG_NO_SECURITY_EXTENSION (No szOID_NTDS_CA_SECURITY_EXT / objectSid)
    if bool(enrollment_flags & CT_FLAG_NO_SECURITY_EXTENSION):
        findings.append({
            "vector": "ESC9",
            "severity": "HIGH",
            "template": name,
            "title": "CT_FLAG_NO_SECURITY_EXTENSION Enabled (No objectSid Extension)",
            "description": (
                f"Template '{name}' disables the szOID_NTDS_CA_SECURITY_EXT extension, omitting the "
                "requester's objectSid and exposing the domain to UPN spoofing on weakly mapped DCs."
            ),
            "remediation": "Unset CT_FLAG_NO_SECURITY_EXTENSION in msPKI-Enrollment-Flag.",
        })

    return findings


def evaluate_ca_misconfigurations(ca_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate Certificate Authority configuration for ESC5, ESC6, ESC7, ESC8, ESC10, ESC11."""
    findings: List[Dict[str, Any]] = []
    ca_name = ca_config.get("ca_name", "Enterprise-CA")

    # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled on CA
    if ca_config.get("EDITF_ATTRIBUTESUBJECTALTNAME2") or ca_config.get("editf_san2"):
        findings.append({
            "vector": "ESC6",
            "severity": "CRITICAL",
            "ca": ca_name,
            "title": "CA EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled",
            "description": (
                f"Certificate Authority '{ca_name}' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled, allowing "
                "enrollees to append arbitrary Subject Alternative Names (SAN) to ANY requested template."
            ),
            "remediation": "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
        })

    # ESC7: Vulnerable CA Permissions (ManageCA / IssueCertificates)
    low_priv_ca_managers = ca_config.get("low_privileged_ca_managers", [])
    if low_priv_ca_managers:
        findings.append({
            "vector": "ESC7",
            "severity": "HIGH",
            "ca": ca_name,
            "title": "Vulnerable CA Administrative Permissions",
            "description": (
                f"Certificate Authority '{ca_name}' grants ManageCA or IssueAndManageCertificates rights "
                f"to non-administrative principals: {', '.join(low_priv_ca_managers)}."
            ),
            "remediation": "Audit and restrict CA security permissions to Enterprise Admins only.",
        })

    # ESC8: NTLM Relay to HTTP Enrollment Endpoints
    if ca_config.get("http_enrollment_enabled", False):
        epa_enabled = ca_config.get("extended_protection_enabled", False)
        https_enforced = ca_config.get("https_enforced", False)
        if not epa_enabled or not https_enforced:
            findings.append({
                "vector": "ESC8",
                "severity": "HIGH",
                "ca": ca_name,
                "title": "AD CS HTTP Web Enrollment Vulnerable to NTLM Relay",
                "description": (
                    f"AD CS Web Enrollment endpoint on '{ca_name}' (/certsrv/) does not enforce "
                    "Extended Protection for Authentication (EPA) with HTTPS channel binding."
                ),
                "remediation": "Enable EPA in IIS for CertSrv and enforce HTTPS-only binding, or disable NTLM.",
            })

    # ESC10: Weak Certificate Mapping on Domain Controllers
    cmm_raw = ca_config.get("CertificateMappingMethods")
    if cmm_raw is not None:
        cert_mapping_methods = _parse_flag_int(cmm_raw, -1)
        if cert_mapping_methods in (0x4, 0x2):
            findings.append({
                "vector": "ESC10",
                "severity": "HIGH",
                "ca": ca_name,
                "title": "Weak DC Certificate Mapping Methods (UPN vs objectSid)",
                "description": (
                    f"Domain Controller certificate mapping registry key is set to {hex(cert_mapping_methods)}, "
                    "allowing weak UPN mapping without enforcing strong objectSid binding."
                ),
                "remediation": "Set HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\Schannel\\CertificateMappingMethods to 0x18.",
            })

    # ESC11: Relaying NTLM to RPC Enrollment Endpoint
    if ca_config.get("rpc_enrollment_without_packet_privacy", False):
        findings.append({
            "vector": "ESC11",
            "severity": "HIGH",
            "ca": ca_name,
            "title": "Relaying NTLM to RPC Enrollment Endpoint",
            "description": (
                f"RPC enrollment interface on '{ca_name}' (ICertPassage) does not enforce RPC packet privacy, "
                "permitting NTLM relay attacks over RPC."
            ),
            "remediation": "Enforce RPC packet privacy (RPC_C_AUTHN_LEVEL_PKT_PRIVACY) on AD CS RPC interfaces.",
        })

    return findings


def scan_adcs(
    source: Optional[str] = None,
    templates: Optional[List[Dict[str, Any]]] = None,
    ca_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute complete AD CS offline scanner across templates and CA configurations."""
    all_findings: List[Dict[str, Any]] = []
    scanned_templates_count = 0

    if source:
        loaded = load_certificate_or_templates(source)
        if isinstance(loaded, dict) and loaded.get("type") == "certificate":
            parsed_cert = loaded.get("parsed", {})
            findings: List[Dict[str, Any]] = []
            if parsed_cert.get("has_client_auth"):
                findings.append({
                    "vector": "CERT_CLIENT_AUTH",
                    "severity": "INFO",
                    "title": "Certificate Contains Client Authentication EKU",
                    "description": f"X.509 certificate specifies EKUs: {', '.join(parsed_cert.get('ekus', []))}",
                })
            return {
                "status": "SUCCESS",
                "scanned_type": "x509_certificate",
                "findings": findings,
                "summary": {"critical": 0, "high": 0, "medium": 0, "total": len(findings)},
            }
        elif isinstance(loaded, list):
            templates = loaded

    if templates:
        scanned_templates_count = len(templates)
        for tmpl in templates:
            t_findings = evaluate_template_misconfigurations(tmpl)
            all_findings.extend(t_findings)

    if ca_config:
        ca_findings = evaluate_ca_misconfigurations(ca_config)
        all_findings.extend(ca_findings)

    # Compute severity counts
    critical_cnt = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_cnt = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    medium_cnt = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")

    return {
        "status": "SUCCESS",
        "scanned_templates_count": scanned_templates_count,
        "findings": all_findings,
        "summary": {
            "critical": critical_cnt,
            "high": high_cnt,
            "medium": medium_cnt,
            "total": len(all_findings),
        },
    }


def format_adcs_report_terminal(report: Dict[str, Any]) -> str:
    """Format AD CS scanner results into clean terminal card header and tree."""
    lines: List[str] = []
    summary = report.get("summary", {})
    total = summary.get("total", 0)
    lines.extend(render_card_header(
        "TANUKI AD CS TEMPLATE & CERTIFICATE SCANNER",
        f"ESC1 through ESC11 Offline Diagnostic · {total} Misconfigurations Detected",
    ))

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")
    v_line = "│ " if use_uni else "| "

    findings = report.get("findings", [])
    if not findings:
        lines.append("[*] Scanned Templates: No ESC1-ESC11 misconfigurations detected. All templates secure.")
        return "\n".join(lines)

    lines.append(f"[+] Total Vulnerabilities Detected: {total} (Critical: {summary.get('critical')}, High: {summary.get('high')}, Medium: {summary.get('medium')})\n")

    for idx, f in enumerate(findings):
        is_last = idx == len(findings) - 1
        branch = l_branch if is_last else t_branch
        vector = f.get("vector", "UNKNOWN")
        sev = f.get("severity", "MEDIUM")
        title = f.get("title", "")
        tmpl = f.get("template") or f.get("ca", "CA")

        lines.append(f"[{sev}] {vector} · {title} [{tmpl}]")
        lines.append(f"    {t_branch} Description : {f.get('description')}")
        lines.append(f"    {l_branch} Remediation : {f.get('remediation')}")
        if not is_last:
            lines.append("")

    return "\n".join(lines)
