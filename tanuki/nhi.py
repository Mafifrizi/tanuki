"""Non-Human Identity (NHI) Cloud-to-AD Token Validator (RFC 8693).

Zero-dependency parser and security analyzer for workload identity JWTs
and OAuth 2.0 Token Exchange parameters.
"""

import base64
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

RFC8693_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

SUPPORTED_TOKEN_TYPES = {
    "urn:ietf:params:oauth:token-type:jwt",
    "urn:ietf:params:oauth:token-type:access_token",
    "urn:ietf:params:oauth:token-type:refresh_token",
    "urn:ietf:params:oauth:token-type:id_token",
    "urn:ietf:params:oauth:token-type:saml1",
    "urn:ietf:params:oauth:token-type:saml2",
}


def b64url_decode(segment: str) -> bytes:
    clean = segment.strip().rstrip("=")
    mod = len(clean) % 4
    if mod == 1:
        raise ValueError("Invalid Base64URL encoding (data character length cannot be 1 mod 4)")
    padding = "=" * ((4 - mod) % 4)
    return base64.urlsafe_b64decode(clean + padding)


def decode_jwt_segment(segment: str) -> Dict[str, Any]:
    raw_bytes = b64url_decode(segment)
    try:
        decoded_str = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Invalid UTF-8 encoding in JWT segment: {exc}") from exc
    try:
        parsed = json.loads(decoded_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in JWT segment: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Decoded JWT segment must be a JSON object")
    return parsed


def parse_workload_jwt(token_str: str) -> Dict[str, Any]:
    clean = token_str.strip()
    if not clean:
        raise ValueError("Token string is empty")
    parts = clean.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 period-delimited segments, got {len(parts)}")
    header = decode_jwt_segment(parts[0])
    payload = decode_jwt_segment(parts[1])
    return {
        "header": header,
        "payload": payload,
        "signature_raw": parts[2],
    }


def detect_identity_type(claims: Dict[str, Any]) -> str:
    iss = str(claims.get("iss", "")).lower()
    sub = str(claims.get("sub", ""))

    if "kubernetes" in iss or sub.startswith("system:serviceaccount:"):
        return "Kubernetes ServiceAccount Token"
    if "actions.githubusercontent.com" in iss or sub.startswith("repo:"):
        return "GitHub Actions OIDC Token"
    if sub.startswith("spiffe://") or iss.startswith("spiffe://"):
        return "SPIFFE SVID"
    if "amazonaws.com" in iss or "aws" in iss:
        return "AWS IAM Workload Identity"
    return "Workload Identity Token"


class JwtValidationReport(dict):
    """Dictionary representing a workload JWT validation report."""

    def to_json(self) -> str:
        return json.dumps(self, indent=2)

    def format_terminal(self) -> str:
        return format_token_report_terminal(self)


class TokenValidationReport(dict):
    """Dictionary representing an RFC 8693 token exchange validation report."""

    def to_json(self) -> str:
        return json.dumps(self, indent=2)

    def format_terminal(self) -> str:
        return format_exchange_report_terminal(self)


def validate_jwt_workload(
    token: str,
    expected_aud: Optional[str] = None,
    now: Optional[int] = None,
) -> JwtValidationReport:
    """Validate a workload identity JWT with zero external dependencies."""
    if now is None:
        now = int(time.time())

    parsed = parse_workload_jwt(token)
    header = parsed["header"]
    claims = parsed["payload"]

    identity_type = detect_identity_type(claims)

    exp_val = claims.get("exp")
    iat_val = claims.get("iat")
    nbf_val = claims.get("nbf")

    is_expired: Optional[bool] = None
    remaining_seconds: Optional[int] = None
    remaining_human = "No Expiration"
    lifetime_seconds: Optional[int] = None
    is_ephemeral = True

    if exp_val is not None:
        try:
            exp_int = int(exp_val)
            remaining_seconds = exp_int - now
            is_expired = remaining_seconds <= 0
            if is_expired:
                remaining_human = "Expired"
            else:
                hrs = remaining_seconds // 3600
                mins = (remaining_seconds % 3600) // 60
                secs = remaining_seconds % 60
                if hrs > 0:
                    remaining_human = f"{hrs}h {mins}m {secs}s"
                elif mins > 0:
                    remaining_human = f"{mins}m {secs}s"
                else:
                    remaining_human = f"{secs}s"
        except (ValueError, TypeError):
            pass

    if iat_val is not None and exp_val is not None:
        try:
            lifetime_seconds = int(exp_val) - int(iat_val)
            is_ephemeral = lifetime_seconds <= 86400
        except (ValueError, TypeError):
            pass

    findings: List[Dict[str, str]] = []
    security_warnings: List[str] = []

    has_wildcard_audience = False
    aud_val = claims.get("aud")

    if aud_val is None or aud_val == "" or aud_val == []:
        has_wildcard_audience = True
        msg = "Audience claim is missing or empty"
        findings.append({"severity": "HIGH", "code": "MISSING_AUDIENCE", "message": msg})
        security_warnings.append(f"MISSING_AUDIENCE: {msg}")
    elif aud_val == "*" or (isinstance(aud_val, list) and "*" in aud_val):
        has_wildcard_audience = True
        msg = "Dangerous wildcard audience detected: '*'"
        findings.append({"severity": "CRITICAL", "code": "WILDCARD_AUDIENCE", "message": msg})
        security_warnings.append(f"WILDCARD_AUDIENCE: {msg}")
    elif isinstance(aud_val, str) and "*" in aud_val:
        has_wildcard_audience = True
        msg = f"Wildcard pattern in audience: {aud_val}"
        findings.append({"severity": "HIGH", "code": "WILDCARD_AUDIENCE", "message": msg})
        security_warnings.append(f"WILDCARD_AUDIENCE: {msg}")
    elif expected_aud is not None:
        aud_list = [aud_val] if isinstance(aud_val, str) else (aud_val if isinstance(aud_val, list) else [])
        if expected_aud not in aud_list:
            msg = f"Token audience does not match expected audience '{expected_aud}'"
            findings.append({"severity": "HIGH", "code": "AUDIENCE_MISMATCH", "message": msg})
            security_warnings.append(f"AUDIENCE_MISMATCH: {msg}")

    has_broad_subject_scope = False
    sub_val = claims.get("sub")
    if sub_val is not None:
        sub_str = str(sub_val)
        if sub_str.startswith("system:serviceaccount:"):
            parts = sub_str.split(":")
            if len(parts) >= 4 and parts[2] == "*":
                has_broad_subject_scope = True
                msg = f"Wildcard namespace in Kubernetes ServiceAccount: {sub_str}"
                findings.append({"severity": "CRITICAL", "code": "OVERLY_BROAD_SUBJECT", "message": msg})
                security_warnings.append(f"OVERLY_BROAD_SUBJECT: {msg}")
            elif len(parts) >= 4 and parts[3] == "*":
                has_broad_subject_scope = True
                msg = f"Wildcard service account name: {sub_str}"
                findings.append({"severity": "HIGH", "code": "OVERLY_BROAD_SUBJECT", "message": msg})
                security_warnings.append(f"OVERLY_BROAD_SUBJECT: {msg}")
            elif "*" in sub_str:
                has_broad_subject_scope = True
                msg = f"Wildcard pattern in Kubernetes ServiceAccount: {sub_str}"
                findings.append({"severity": "HIGH", "code": "OVERLY_BROAD_SUBJECT", "message": msg})
                security_warnings.append(f"OVERLY_BROAD_SUBJECT: {msg}")
        elif sub_str.startswith("repo:"):
            if "*" in sub_str:
                has_broad_subject_scope = True
                msg = f"Wildcard repository pattern in GitHub OIDC subject: {sub_str}"
                findings.append({"severity": "HIGH", "code": "OVERLY_BROAD_SUBJECT", "message": msg})
                security_warnings.append(f"OVERLY_BROAD_SUBJECT: {msg}")
        elif sub_str.startswith("spiffe://"):
            if "*" in sub_str:
                has_broad_subject_scope = True
                msg = f"Wildcard pattern in SPIFFE ID: {sub_str}"
                findings.append({"severity": "CRITICAL", "code": "OVERLY_BROAD_SUBJECT", "message": msg})
                security_warnings.append(f"OVERLY_BROAD_SUBJECT: {msg}")
        elif "*" in sub_str:
            has_broad_subject_scope = True
            msg = f"Wildcard pattern in subject scope: {sub_str}"
            findings.append({"severity": "HIGH", "code": "OVERLY_BROAD_SUBJECT", "message": msg})
            security_warnings.append(f"OVERLY_BROAD_SUBJECT: {msg}")

    alg_val = header.get("alg")
    insecure_algorithm = False
    if alg_val is None or str(alg_val).lower() == "none":
        insecure_algorithm = True
        msg = "Unsecured JWT (alg=none) detected"
        findings.append({"severity": "CRITICAL", "code": "INSECURE_ALGORITHM", "message": msg})
        security_warnings.append(f"INSECURE_ALGORITHM: {msg}")
    elif str(alg_val).upper().startswith("HS"):
        msg = f"Symmetric algorithm {alg_val} used instead of asymmetric for workload identity"
        findings.append({"severity": "MEDIUM", "code": "SYMMETRIC_ALGORITHM", "message": msg})
        security_warnings.append(f"SYMMETRIC_ALGORITHM: {msg}")

    if exp_val is None:
        msg = "Token has no expiration (exp) claim"
        findings.append({"severity": "HIGH", "code": "MISSING_EXPIRATION", "message": msg})
        security_warnings.append(f"MISSING_EXPIRATION: {msg}")
    elif is_expired:
        msg = "Token has expired"
        findings.append({"severity": "CRITICAL", "code": "TOKEN_EXPIRED", "message": msg})
        security_warnings.append(f"TOKEN_EXPIRED: {msg}")

    if nbf_val is not None:
        try:
            if now < int(nbf_val):
                msg = f"Token is not yet valid (nbf={nbf_val} in future)"
                findings.append({"severity": "HIGH", "code": "TOKEN_NOT_YET_VALID", "message": msg})
                security_warnings.append(f"TOKEN_NOT_YET_VALID: {msg}")
        except (ValueError, TypeError):
            pass

    if lifetime_seconds is not None and lifetime_seconds > 86400:
        msg = f"Token lifetime ({lifetime_seconds}s) exceeds 24h threshold for ephemeral workloads"
        findings.append({"severity": "MEDIUM", "code": "EXCESSIVE_LIFETIME", "message": msg})
        security_warnings.append(f"EXCESSIVE_LIFETIME: {msg}")

    if any(f["severity"] == "CRITICAL" for f in findings):
        risk_level = "CRITICAL"
    elif any(f["severity"] == "HIGH" for f in findings):
        risk_level = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        findings.append({
            "severity": "LOW",
            "code": "SAFE_TOKEN",
            "message": "Token claims and security boundaries are valid",
        })

    is_valid = True
    if is_expired or is_expired is None:
        is_valid = False
    if insecure_algorithm:
        is_valid = False
    if has_wildcard_audience:
        is_valid = False
    if has_broad_subject_scope:
        is_valid = False
    if expected_aud is not None and any(f["code"] == "AUDIENCE_MISMATCH" for f in findings):
        is_valid = False
    if nbf_val is not None:
        try:
            if now < int(nbf_val):
                is_valid = False
        except (ValueError, TypeError):
            pass

    temporal_data: Dict[str, Any] = {
        "is_expired": is_expired,
        "remaining_seconds": remaining_seconds,
        "remaining_human": remaining_human,
        "lifetime_seconds": lifetime_seconds,
        "is_ephemeral": is_ephemeral,
    }

    security_eval_data: Dict[str, Any] = {
        "has_wildcard_audience": has_wildcard_audience,
        "has_broad_subject_scope": has_broad_subject_scope,
        "insecure_algorithm": insecure_algorithm,
        "risk_level": risk_level,
        "findings": findings,
    }

    report = JwtValidationReport({
        "valid": is_valid,
        "identity_type": identity_type,
        "header": header,
        "claims": claims,
        "temporal": temporal_data,
        "security_evaluation": security_eval_data,
        "security_warnings": security_warnings,
    })
    return report


def validate_token_exchange(params: Dict[str, Any]) -> TokenValidationReport:
    """Validate RFC 8693 OAuth 2.0 Token Exchange parameters."""
    if not isinstance(params, dict):
        return TokenValidationReport({
            "valid": False,
            "exchange_valid": False,
            "error": "invalid_request",
            "error_description": "Request parameters must be a dictionary",
            "security_warnings": ["INVALID_REQUEST: Request parameters must be a dictionary"],
        })

    grant_type = params.get("grant_type")
    if not grant_type:
        return TokenValidationReport({
            "valid": False,
            "exchange_valid": False,
            "error": "invalid_request",
            "error_description": "Missing required parameter 'grant_type'",
            "security_warnings": ["INVALID_REQUEST: Missing required parameter 'grant_type'"],
        })

    if grant_type != RFC8693_TOKEN_EXCHANGE_GRANT:
        return TokenValidationReport({
            "valid": False,
            "exchange_valid": False,
            "error": "unsupported_grant_type",
            "error_description": f"Unsupported grant_type '{grant_type}'. Expected '{RFC8693_TOKEN_EXCHANGE_GRANT}'",
            "security_warnings": ["UNSUPPORTED_GRANT_TYPE: Grant type is not RFC 8693 token exchange"],
        })

    subject_token = params.get("subject_token")
    if not subject_token:
        return TokenValidationReport({
            "valid": False,
            "exchange_valid": False,
            "error": "invalid_request",
            "error_description": "Missing required parameter 'subject_token'",
            "security_warnings": ["INVALID_REQUEST: Missing required parameter 'subject_token'"],
        })

    subject_token_type = params.get("subject_token_type")
    if not subject_token_type:
        return TokenValidationReport({
            "valid": False,
            "exchange_valid": False,
            "error": "invalid_request",
            "error_description": "Missing required parameter 'subject_token_type'",
            "security_warnings": ["INVALID_REQUEST: Missing required parameter 'subject_token_type'"],
        })

    if subject_token_type not in SUPPORTED_TOKEN_TYPES:
        return TokenValidationReport({
            "valid": False,
            "exchange_valid": False,
            "error": "invalid_request",
            "error_description": f"Unsupported subject_token_type '{subject_token_type}'",
            "security_warnings": [f"INVALID_REQUEST: Unsupported subject_token_type '{subject_token_type}'"],
        })

    requested_token_type = params.get("requested_token_type")
    if requested_token_type and requested_token_type not in SUPPORTED_TOKEN_TYPES:
        return TokenValidationReport({
            "valid": False,
            "exchange_valid": False,
            "error": "invalid_request",
            "error_description": f"Unsupported requested_token_type '{requested_token_type}'",
            "security_warnings": [f"INVALID_REQUEST: Unsupported requested_token_type '{requested_token_type}'"],
        })

    security_warnings: List[str] = []
    aud = params.get("audience")
    if aud == "*":
        security_warnings.append("WILDCARD_AUDIENCE: Dangerous wildcard audience detected: '*'")
    elif aud and "*" in str(aud):
        security_warnings.append(f"WILDCARD_AUDIENCE: Wildcard pattern in exchange audience: '{aud}'")

    subject_report: Optional[JwtValidationReport] = None
    if subject_token_type == "urn:ietf:params:oauth:token-type:jwt":
        try:
            subject_report = validate_jwt_workload(str(subject_token))
            for warning in subject_report.get("security_warnings", []):
                if warning not in security_warnings:
                    security_warnings.append(warning)
            if subject_report.get("temporal", {}).get("is_expired"):
                return TokenValidationReport({
                    "valid": False,
                    "exchange_valid": False,
                    "error": "invalid_grant",
                    "error_description": "The provided subject_token has expired",
                    "security_warnings": security_warnings,
                    "subject_token_report": subject_report,
                })
        except Exception as exc:
            return TokenValidationReport({
                "valid": False,
                "exchange_valid": False,
                "error": "invalid_request",
                "error_description": f"Failed to parse subject_token JWT: {exc}",
                "security_warnings": [f"INVALID_REQUEST: Malformed subject_token JWT: {exc}"],
            })

    return TokenValidationReport({
        "valid": True,
        "exchange_valid": True,
        "error": None,
        "error_description": None,
        "parameters": dict(params),
        "security_warnings": security_warnings,
        "subject_token_report": subject_report,
    })


def format_token_report_terminal(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(" TANUKI WORKLOAD IDENTITY VALIDATOR (RFC 8693 / NHI)")
    lines.append("=" * 72)

    id_type = report.get("identity_type", "Workload Identity Token")
    claims = report.get("claims", {})
    header = report.get("header", {})
    temporal = report.get("temporal", {})
    eval_sec = report.get("security_evaluation", {})

    lines.append(f"Identity Type    : {id_type}")
    if "iss" in claims:
        lines.append(f"Issuer (iss)     : {claims['iss']}")
    if "sub" in claims:
        lines.append(f"Subject (sub)    : {claims['sub']}")
    if "aud" in claims:
        lines.append(f"Audience (aud)   : {claims['aud']}")

    alg = header.get("alg", "unknown")
    kid = header.get("kid")
    key_info = f" | Key ID: {kid}" if kid else ""
    lines.append(f"Algorithm (alg)  : {alg}{key_info}")
    lines.append("")

    lines.append("TEMPORAL STATUS:")
    if "iat" in claims:
        lines.append(f"Issued At (iat)  : {claims['iat']}")
    if "exp" in claims:
        lines.append(f"Expires At (exp) : {claims['exp']}")
    rem_human = temporal.get("remaining_human", "N/A")
    status_str = "EXPIRED" if temporal.get("is_expired") else "ACTIVE"
    lines.append(f"Remaining Time   : {rem_human} ({status_str})")
    if temporal.get("lifetime_seconds") is not None:
        lines.append(f"Lifetime Span    : {temporal['lifetime_seconds']}s")
    lines.append("")

    lines.append("SECURITY POLICY EVALUATION:")
    findings = eval_sec.get("findings", [])
    if findings:
        for f in findings:
            tag = "SAFE" if f.get("severity") == "LOW" else ("WARN" if f.get("severity") == "MEDIUM" else "CRITICAL")
            lines.append(f"[{tag}] {f.get('code')} : {f.get('message')}")
    else:
        lines.append("[SAFE] All security policies satisfied")
    lines.append("")

    assessment = "VALID & SECURE" if report.get("valid") else "INVALID OR HIGH RISK"
    lines.append(f"OVERALL ASSESSMENT: {assessment}")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_exchange_report_terminal(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(" TANUKI RFC 8693 TOKEN EXCHANGE VALIDATION REPORT")
    lines.append("=" * 72)

    status = "VALID" if report.get("valid") else "FAILED"
    lines.append(f"Exchange Status   : {status}")
    if report.get("error"):
        lines.append(f"Error Code        : {report['error']}")
    if report.get("error_description"):
        lines.append(f"Description       : {report['error_description']}")

    warnings = report.get("security_warnings", [])
    if warnings:
        lines.append("\nSecurity Warnings:")
        for w in warnings:
            lines.append(f"  [!] {w}")

    lines.append("=" * 72)
    return "\n".join(lines)
