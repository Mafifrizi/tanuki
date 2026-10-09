#!/usr/bin/env python3
"""KitPloit Submission Utility for Tanuki.

Verifies repository reachability and formats the canonical KitPloit tool
submission payload for https://www.kitploit.com/submit.
"""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional
import urllib.error
import urllib.request


DEFAULT_REPO_URL = "https://github.com/Mafifrizi/tanuki"
DEFAULT_PYPI_URL = "https://pypi.org/project/tanuki-ad/"
DEFAULT_TOOL_NAME = "Tanuki (tanuki-ad)"
DEFAULT_VERSION = "1.2.1"
DEFAULT_AUTHOR = "Mafifrizi"
DEFAULT_EMAIL = "hazama3321@gmail.com"
KITPLOIT_SUBMISSION_URL = "https://www.kitploit.com/submit"


def verify_repository_reachability(
    repo_url: str,
    timeout: float = 10.0,
    skip_network: bool = False,
) -> Dict[str, Any]:
    """Verify repository reachability via HTTP request."""
    if skip_network:
        return {
            "reachable": None,
            "status_code": None,
            "url": repo_url,
            "skipped": True,
            "message": "Network verification skipped via --skip-network",
        }

    req = urllib.request.Request(
        repo_url,
        headers={"User-Agent": f"Tanuki-Verification/{DEFAULT_VERSION} (Python urllib)"},
        method="HEAD",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.getcode()
            is_ok = 200 <= status < 400
            return {
                "reachable": is_ok,
                "status_code": status,
                "url": repo_url,
                "skipped": False,
                "message": f"Repository reachable (HTTP {status})",
            }
    except urllib.error.HTTPError as exc:
        # Fall back to GET if HEAD method is disallowed by server
        if exc.code == 405:
            try:
                get_req = urllib.request.Request(
                    repo_url,
                    headers={"User-Agent": f"Tanuki-Verification/{DEFAULT_VERSION} (Python urllib)"},
                    method="GET",
                )
                with urllib.request.urlopen(get_req, timeout=timeout) as response:
                    status = response.getcode()
                    is_ok = 200 <= status < 400
                    return {
                        "reachable": is_ok,
                        "status_code": status,
                        "url": repo_url,
                        "skipped": False,
                        "message": f"Repository reachable via GET (HTTP {status})",
                    }
            except Exception as inner_exc:
                return {
                    "reachable": False,
                    "status_code": getattr(inner_exc, "code", None),
                    "url": repo_url,
                    "skipped": False,
                    "message": f"HTTP request failed: {inner_exc}",
                }

        return {
            "reachable": False,
            "status_code": exc.code,
            "url": repo_url,
            "skipped": False,
            "message": f"HTTP error {exc.code}: {exc.reason}",
        }
    except Exception as exc:
        return {
            "reachable": False,
            "status_code": None,
            "url": repo_url,
            "skipped": False,
            "message": f"Connection check failed: {exc}",
        }


def format_kitploit_markdown(
    name: str = DEFAULT_TOOL_NAME,
    version: str = DEFAULT_VERSION,
    author: str = DEFAULT_AUTHOR,
    email: str = DEFAULT_EMAIL,
    repo_url: str = DEFAULT_REPO_URL,
    pypi_url: str = DEFAULT_PYPI_URL,
) -> str:
    """Format canonical submission markdown text for KitPloit editor."""
    return f"""# {name} v{version}

**Author**: {author} ({email})
**GitHub Repository**: {repo_url}
**PyPI Package**: {pypi_url}
**License**: MIT OR Apache-2.0
**Target Categories**: Active Directory, Kerberos, Linux Post-Exploitation, Blue Team Triage, Non-Human Identity (NHI)

---

### What is Tanuki?

Tanuki is a deterministic Linux Active Directory and Kerberos protocol triage engine.
Built specifically for security professionals, red teams, and sysadmins operating in
hybrid Linux-to-AD domains, Tanuki cuts through diagnostic noise with zero external runtime dependencies.

### Key Capabilities

1. **Sub-Millisecond Pre-Flight Diagnostic (`tanuki doctor`)**:
   Immediately inspects host state, keytabs, credential caches, time synchronization,
   and Active Directory domain controller availability.

2. **Autonomous Protocol Triage with Blue Telemetry (`tanuki triage <CODE>`)**:
   Decodes cryptic Kerberos and ASN.1 error codes (such as `KDC_ERR_PREAUTH_FAILED`,
   `KDC_ERR_C_PRINCIPAL_UNKNOWN`, `KDC_ERR_SKEW`), pairing every protocol breakdown
   with defensive Blue Telemetry and Sigma/Falco detection rules.

3. **Binary Keytab Inspector (`tanuki keytab <PATH>`)**:
   Parses raw RFC 4120 keytab structures, reveals KVNOs, principal mappings, encryption
   types, and identifies weak or misconfigured credentials.

4. **SSSD KCM Credential Extractor (`tanuki kcm`)**:
   Parses raw SSSD Secrets LDB databases without invoking external binaries, safely
   recovering cached Kerberos CCache credentials.

5. **MS-PAC NDR Decoder (`tanuki pac <PAYLOAD>`)**:
   Dissects MS-PAC structures to extract Domain SIDs, Group Memberships, and User Account
   Control flags for privilege verification.

6. **Workload Token & NHI Verification (`tanuki token <JWT>`)**:
   Validates RFC 8693 Non-Human Identity workload identity tokens air-gapped.

7. **Cryptographic Zero-Trace Purge (`tanuki purge`)**:
   Overwrites and shreds sensitive forensic traces, in-memory keys, and temporary artifacts.

### Quickstart & Installation

Install via PyPI:
```bash
pip install tanuki-ad
```

Or clone directly from GitHub:
```bash
git clone {repo_url}.git
cd tanuki
python -m pip install .
```

### Usage Examples

```bash
# Run pre-flight health diagnostic
tanuki doctor

# Investigate authentication failure with Blue Telemetry
tanuki triage KDC_ERR_PREAUTH_FAILED

# Inspect Active Directory service keytab
tanuki keytab /etc/krb5.keytab --json

# Synthesize minimal krb5.conf without root access
tanuki config --realm CORP.LOCAL --kdc 192.168.1.10 -o ./krb5.conf
```

### Architecture Highlights

- Zero external runtime dependencies: uses pure Python standard library for maximum portability.
- Memory-safe core: optional Rust binary compiled with strict memory safety (`#![forbid(unsafe_code)]`).
- Deterministic exit codes and full JSON output compatibility for scriptability.
"""


def compile_submission_payload(
    name: str = DEFAULT_TOOL_NAME,
    version: str = DEFAULT_VERSION,
    author: str = DEFAULT_AUTHOR,
    email: str = DEFAULT_EMAIL,
    repo_url: str = DEFAULT_REPO_URL,
    pypi_url: str = DEFAULT_PYPI_URL,
    skip_network: bool = False,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Compile the complete submission data payload."""
    reachability = verify_repository_reachability(
        repo_url=repo_url,
        timeout=timeout,
        skip_network=skip_network,
    )

    markdown_body = format_kitploit_markdown(
        name=name,
        version=version,
        author=author,
        email=email,
        repo_url=repo_url,
        pypi_url=pypi_url,
    )

    tags = [
        "active-directory",
        "kerberos",
        "keytab",
        "sssd",
        "security-audit",
        "triage",
        "nhi",
        "linux",
        "blue-team",
    ]

    return {
        "submission_target": KITPLOIT_SUBMISSION_URL,
        "tool_name": name,
        "version": version,
        "author": author,
        "author_email": email,
        "repository_url": repo_url,
        "pypi_url": pypi_url,
        "license": "MIT OR Apache-2.0",
        "short_description": "Deterministic Linux Active Directory & Kerberos Protocol Triage Engine",
        "category": "Active Directory / Kerberos / Security Assessment",
        "tags": tags,
        "reachability_check": reachability,
        "markdown_payload": markdown_body,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Format canonical KitPloit tool submission payload and verify repository reachability"
    )
    parser.add_argument("--repo", default=DEFAULT_REPO_URL, help=f"Repository URL (default: {DEFAULT_REPO_URL})")
    parser.add_argument("--name", default=DEFAULT_TOOL_NAME, help="Tool name")
    parser.add_argument("--version", default=DEFAULT_VERSION, help=f"Version (default: {DEFAULT_VERSION})")
    parser.add_argument("--author", default=DEFAULT_AUTHOR, help=f"Author name (default: {DEFAULT_AUTHOR})")
    parser.add_argument("--email", default=DEFAULT_EMAIL, help=f"Author email (default: {DEFAULT_EMAIL})")
    parser.add_argument("--pypi-url", default=DEFAULT_PYPI_URL, help=f"PyPI URL (default: {DEFAULT_PYPI_URL})")
    parser.add_argument("-o", "--output", default="dist/kitploit_submission.md", help="Output Markdown file")
    parser.add_argument("--out-json", default="dist/kitploit_submission.json", help="Output JSON file")
    parser.add_argument("--skip-network", action="store_true", help="Skip remote network reachability probe")
    parser.add_argument("--strict", action="store_true", help="Fail with non-zero exit code if repository reachability verification fails")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)")
    parser.add_argument("--json", action="store_true", help="Print structured JSON to stdout")

    args = parser.parse_args()

    payload = compile_submission_payload(
        name=args.name,
        version=args.version,
        author=args.author,
        email=args.email,
        repo_url=args.repo,
        pypi_url=args.pypi_url,
        skip_network=args.skip_network,
        timeout=args.timeout,
    )

    # Save Markdown deliverable
    md_path = Path(args.output).resolve()
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(payload["markdown_payload"], encoding="utf-8")

    # Save JSON deliverable
    json_path = Path(args.out_json).resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    reachability = payload["reachability_check"]
    is_failed_reachability = (reachability["reachable"] is False) and not reachability.get("skipped", False)

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        if is_failed_reachability:
            print("[WARNING] KitPloit payload generated, but repository reachability verification failed")
        else:
            print("[OK] KitPloit tool submission payload generated successfully")
        print(f"     Target Portal : {payload['submission_target']}")
        print(f"     Repository    : {args.repo}")
        print(f"     PyPI URL      : {payload['pypi_url']}")
        print(f"     Reachability  : {reachability['message']}")
        print(f"     Markdown File : {md_path}")
        print(f"     JSON File     : {json_path}")

    if args.strict and is_failed_reachability:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
