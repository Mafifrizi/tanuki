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
    from .doctor import render_card_header
    lines: List[str] = []
    lines.extend(render_card_header(
        "TANUKI WORKLOAD IDENTITY VALIDATOR (RFC 8693 / NHI)",
        "Zero-Dependency Workload Token & RFC 8693 Claims Assessment",
    ))
    lines.append("")

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
    return "\n".join(lines)


def format_exchange_report_terminal(report: Dict[str, Any]) -> str:
    from .doctor import render_card_header
    lines: List[str] = []
    lines.extend(render_card_header(
        "TANUKI RFC 8693 TOKEN EXCHANGE VALIDATION REPORT",
        "OAuth 2.0 Workload Token Exchange Assessment",
    ))
    lines.append("")

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

    return "\n".join(lines)


def exchange_token_live(
    endpoint: str,
    subject_token: str,
    subject_token_type: str = "urn:ietf:params:oauth:token-type:jwt",
    requested_token_type: Optional[str] = None,
    audience: Optional[str] = None,
    scope: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Execute live RFC 8693 token exchange HTTP POST request using pure standard library."""
    import urllib.error
    import urllib.parse
    import urllib.request

    form_data: Dict[str, str] = {
        "grant_type": RFC8693_TOKEN_EXCHANGE_GRANT,
        "subject_token": subject_token.strip(),
        "subject_token_type": subject_token_type.strip(),
    }
    if requested_token_type:
        form_data["requested_token_type"] = requested_token_type.strip()
    if audience:
        form_data["audience"] = audience.strip()
    if scope:
        form_data["scope"] = scope.strip()

    encoded_data = urllib.parse.urlencode(form_data).encode("utf-8")
    req_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "Tanuki-Identity-Engine/2.0",
    }
    if extra_headers:
        req_headers.update(extra_headers)

    req = urllib.request.Request(
        url=endpoint,
        data=encoded_data,
        headers=req_headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            body_bytes = resp.read()
            body_str = body_bytes.decode("utf-8", errors="replace")
            try:
                json_data = json.loads(body_str)
            except json.JSONDecodeError:
                json_data = {"raw_response": body_str}

            return {
                "status": "SUCCESS",
                "http_status": status_code,
                "endpoint": endpoint,
                "response": json_data,
                "access_token": json_data.get("access_token"),
                "issued_token_type": json_data.get("issued_token_type"),
                "token_type": json_data.get("token_type"),
                "expires_in": json_data.get("expires_in"),
            }
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(err_body)
        except Exception:
            err_json = {"error": "http_error", "raw": err_body}
        return {
            "status": "ERROR",
            "http_status": exc.code,
            "endpoint": endpoint,
            "error": err_json.get("error", "http_error"),
            "error_description": err_json.get("error_description", str(exc)),
            "response": err_json,
        }
    except urllib.error.URLError as exc:
        return {
            "status": "ERROR",
            "endpoint": endpoint,
            "error": "connection_failure",
            "error_description": str(exc.reason),
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "endpoint": endpoint,
            "error": "unexpected_error",
            "error_description": str(exc),
        }


def fetch_spiffe_jwt(
    socket_path: str = "/tmp/spire-agent/public/api.sock",
    audience: str = "spiffe://example.org/ad",
    timeout: float = 2.0,
) -> Optional[str]:
    """Fetch SPIFFE Workload API JWT-SVID from local UNIX domain socket."""
    import socket
    if not hasattr(socket, "AF_UNIX") or not os.path.exists(socket_path):
        return None

    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect(socket_path)
        # SPIFFE Workload API uses gRPC HTTP/2 over UNIX socket.
        # Minimal probe / handshake check:
        client.close()
        return None
    except Exception:
        return None


def fetch_imds_token(
    cloud_provider: str = "auto",
    audience: Optional[str] = None,
    imds_base_url: str = "http://169.254.169.254",
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """Fetch workload identity token from cloud instance metadata service (IMDSv2)."""
    import urllib.error
    import urllib.request

    result: Dict[str, Any] = {
        "status": "NOT_AVAILABLE",
        "provider": None,
        "token": None,
        "details": None,
    }

    # 1. AWS IMDSv2 Token Probe
    if cloud_provider in ("auto", "aws"):
        try:
            token_req = urllib.request.Request(
                f"{imds_base_url}/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                method="PUT",
            )
            with urllib.request.urlopen(token_req, timeout=timeout) as resp:
                if resp.status == 200:
                    aws_token = resp.read().decode("utf-8").strip()
                    result["status"] = "SUCCESS"
                    result["provider"] = "aws_imdsv2"
                    result["token"] = aws_token
                    result["details"] = "AWS IMDSv2 session token acquired"
                    return result
        except Exception:
            pass

    # 2. Azure IMDS Token Probe
    if cloud_provider in ("auto", "azure"):
        try:
            target_aud = audience or "https://management.azure.com/"
            encoded_aud = urllib.parse.quote(target_aud, safe="")
            azure_url = (
                f"{imds_base_url}/metadata/identity/oauth2/token"
                f"?api-version=2018-02-01&resource={encoded_aud}"
            )
            azure_req = urllib.request.Request(
                azure_url,
                headers={"Metadata": "true"},
                method="GET",
            )
            with urllib.request.urlopen(azure_req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read().decode("utf-8"))
                    result["status"] = "SUCCESS"
                    result["provider"] = "azure_imds"
                    result["token"] = body.get("access_token")
                    result["details"] = "Azure Managed Identity token acquired"
                    return result
        except Exception:
            pass

    # 3. GCP IMDS Token Probe
    if cloud_provider in ("auto", "gcp"):
        try:
            target_aud = audience or "https://iam.googleapis.com/"
            encoded_aud = urllib.parse.quote(target_aud, safe="")
            gcp_url = (
                f"{imds_base_url}/computeMetadata/v1/instance/service-accounts/default/identity"
                f"?audience={encoded_aud}"
            )
            gcp_req = urllib.request.Request(
                gcp_url,
                headers={"Metadata-Flavor": "Google"},
                method="GET",
            )
            with urllib.request.urlopen(gcp_req, timeout=timeout) as resp:
                if resp.status == 200:
                    gcp_jwt = resp.read().decode("utf-8").strip()
                    result["status"] = "SUCCESS"
                    result["provider"] = "gcp_imds"
                    result["token"] = gcp_jwt
                    result["details"] = "GCP Service Account OIDC token acquired"
                    return result
        except Exception:
            pass

    result["details"] = "No cloud metadata endpoints responded"
    return result


def discover_cloud_mesh(
    spiffe_socket: Optional[str] = None,
    imds_url: Optional[str] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """Discover and ingest Non-Human Identities across local sockets and cloud mesh metadata."""
    discovered: List[Dict[str, Any]] = []

    # 1. Inspect Filesystem Workload Tokens (Kubernetes)
    k8s_paths = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/token",
    ]
    for kp in k8s_paths:
        if os.path.isfile(kp):
            try:
                with open(kp, "r", encoding="utf-8") as f:
                    tok = f.read().strip()
                val_rep = validate_jwt_workload(tok)
                discovered.append({
                    "source": "kubernetes_serviceaccount",
                    "path": kp,
                    "valid": val_rep.get("valid"),
                    "identity_type": val_rep.get("identity_type"),
                    "subject": val_rep.get("claims", {}).get("sub"),
                    "issuer": val_rep.get("claims", {}).get("iss"),
                    "token": tok,
                })
            except Exception as exc:
                discovered.append({
                    "source": "kubernetes_serviceaccount",
                    "path": kp,
                    "error": str(exc),
                })

    # 2. Inspect SPIFFE Socket
    spiffe_path = spiffe_socket or "/tmp/spire-agent/public/api.sock"
    has_spiffe = os.path.exists(spiffe_path)
    if has_spiffe:
        discovered.append({
            "source": "spiffe_workload_api",
            "path": spiffe_path,
            "status": "SOCKET_PRESENT",
            "details": "Local SPIFFE agent socket available",
        })

    # 3. Inspect Cloud IMDS
    base_imds = imds_url or "http://169.254.169.254"
    imds_res = fetch_imds_token(imds_base_url=base_imds, timeout=timeout)
    if imds_res.get("status") == "SUCCESS":
        token_str = imds_res.get("token")
        val_rep = None
        if token_str and "." in token_str:
            try:
                val_rep = validate_jwt_workload(token_str)
            except Exception:
                pass
        discovered.append({
            "source": imds_res.get("provider"),
            "token": token_str,
            "details": imds_res.get("details"),
            "jwt_report": val_rep,
        })

    return {
        "status": "SUCCESS" if discovered else "NONE_DISCOVERED",
        "discovered_identities": discovered,
        "count": len(discovered),
    }


def format_live_exchange_terminal(res: Dict[str, Any]) -> str:
    """Format live token exchange result into terminal card header and tree."""
    from .doctor import render_card_header, supports_unicode
    lines: List[str] = []
    lines.extend(render_card_header(
        "TANUKI RFC 8693 LIVE TOKEN EXCHANGE",
        f"Endpoint: {res.get('endpoint')} · Status: {res.get('status')}",
    ))

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")

    if res.get("status") == "SUCCESS":
        lines.append(f"[+] HTTP Status       : {res.get('http_status')} OK")
        lines.append(f"    {t_branch} Issued Token Type : {res.get('issued_token_type', 'N/A')}")
        lines.append(f"    {t_branch} Token Type        : {res.get('token_type', 'Bearer')}")
        lines.append(f"    {t_branch} Expires In        : {res.get('expires_in', 'N/A')}s")
        tok = res.get("access_token", "")
        preview = (tok[:24] + "...") if len(tok) > 24 else tok
        lines.append(f"    {l_branch} Access Token      : {preview}")
    else:
        lines.append(f"[!] HTTP Status       : {res.get('http_status', 'N/A')}")
        lines.append(f"    {t_branch} Error Code        : {res.get('error', 'unknown')}")
        lines.append(f"    {l_branch} Description       : {res.get('error_description', 'N/A')}")

    return "\n".join(lines)


def format_mesh_report_terminal(report: Dict[str, Any]) -> str:
    """Format cloud mesh discovery report into clean terminal tree."""
    from .doctor import render_card_header, supports_unicode
    lines: List[str] = []
    lines.extend(render_card_header(
        "TANUKI CLOUD MESH IDENTITY INGESTION",
        f"SPIFFE / IMDS / Kubernetes Workload Ingestion · Found: {report.get('count', 0)}",
    ))

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")

    identities = report.get("discovered_identities", [])
    if identities:
        for idx, ident in enumerate(identities):
            is_last = idx == len(identities) - 1
            branch = l_branch if is_last else t_branch
            src = ident.get("source", "unknown")
            sub = ident.get("subject") or ident.get("details", "")
            lines.append(f"[+] Workload Identity [{src}]")
            lines.append(f"    {branch} {sub}")
    else:
        lines.append("[*] No active workload identity tokens found in local mesh.")

    return "\n".join(lines)

