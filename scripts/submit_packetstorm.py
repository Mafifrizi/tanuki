#!/usr/bin/env python3
"""Packet Storm Security Submission Utility for Tanuki.

Compiles the canonical RFC-822 formatted submission email payload for
submissions@packetstormsecurity.com. Can optionally deliver via SMTP
when credentials/host are configured, or save as an .eml message for
mail client import.
"""

import argparse
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
import json
import os
from pathlib import Path
import smtplib
import sys
from typing import Dict, Optional, Tuple


DEFAULT_TO = "submissions@packetstormsecurity.com"
DEFAULT_FROM = "Mafifrizi <hazama3321@gmail.com>"
DEFAULT_SUBJECT = "[TOOL] tanuki-ad 1.2.1 - Linux Active Directory & Kerberos Protocol Triage Engine"
DEFAULT_VERSION = "1.2.1"
DEFAULT_HOMEPAGE = "https://github.com/Mafifrizi/tanuki"
DEFAULT_PYPI_URL = "https://pypi.org/project/tanuki-ad/"


def build_submission_body(
    version: str = DEFAULT_VERSION,
    homepage: str = DEFAULT_HOMEPAGE,
    pypi_url: str = DEFAULT_PYPI_URL,
    author: str = DEFAULT_FROM,
) -> str:
    """Build the canonical plaintext body for Packet Storm Security curators."""
    lines = [
        f"Title: Tanuki (tanuki-ad) v{version}",
        f"Author: {author}",
        f"Homepage: {homepage}",
        f"PyPI: {pypi_url}",
        "License: MIT OR Apache-2.0",
        "Category: Security Auditing / Active Directory / Kerberos",
        "Platform: Linux / POSIX (pure Python portable client + Rust core)",
        f"Version: {version}",
        "",
        "SYNOPSIS:",
        "Tanuki is a deterministic Linux Active Directory and Kerberos protocol triage",
        "engine designed for security operations, red teams, and systems administration.",
        "Operating with zero external runtime dependencies in pure Python alongside a",
        "hardened Rust core, Tanuki eliminates diagnostic ambiguity in hybrid identity",
        "failures and non-human identity (NHI) infrastructure.",
        "",
        "KEY CAPABILITIES:",
        "- Deterministic pre-flight diagnostic engine with sub-millisecond triage (tanuki doctor)",
        "- Unprivileged krb5.conf synthesis and clock-skew compensation",
        "- Binary keytab inspection (RFC 4120) with integrity auditing",
        "- SSSD KCM credential cache extraction and analysis",
        "- Autonomous Kerberos protocol error triage enriched with Blue Telemetry",
        "- Unprivileged ticket acquisition and fast-path armoring",
        "- MS-PAC NDR structure decoding and authorization validation",
        "- NHI workload token verification and policy conformance (RFC 8693)",
        "- Cryptographic zero-trace memory purge for OPSEC hygiene",
        "",
        "DISTRIBUTION & VERIFICATION:",
        f"Official PyPI Package: pip install tanuki-ad",
        f"Upstream Repository: {homepage}",
        f"Signed releases and tarballs: {homepage}/releases",
        "",
        "Regards,",
        "Mafifrizi (Maintainer)",
    ]
    return "\n".join(lines) + "\n"


def create_rfc822_message(
    to_addr: str = DEFAULT_TO,
    from_addr: str = DEFAULT_FROM,
    subject: str = DEFAULT_SUBJECT,
    version: str = DEFAULT_VERSION,
    attachment_path: Optional[str] = None,
    homepage: str = DEFAULT_HOMEPAGE,
    pypi_url: str = DEFAULT_PYPI_URL,
) -> EmailMessage:
    """Compile canonical RFC-822 EmailMessage structure."""
    msg = EmailMessage()
    msg["To"] = to_addr
    msg["From"] = from_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg["User-Agent"] = f"Tanuki-Syndication/{version}"
    msg["MIME-Version"] = "1.0"

    body = build_submission_body(
        version=version,
        homepage=homepage,
        pypi_url=pypi_url,
        author=from_addr,
    )
    msg.set_content(body)

    if attachment_path and os.path.isfile(attachment_path):
        attach_p = Path(attachment_path)
        with open(attach_p, "rb") as f:
            data = f.read()

        filename = attach_p.name
        if filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            maintype = "application"
            subtype = "gzip"
        elif filename.endswith(".zip"):
            maintype = "application"
            subtype = "zip"
        else:
            maintype = "application"
            subtype = "octet-stream"

        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    return msg


def save_eml_file(msg: EmailMessage, output_path: str) -> Path:
    """Save RFC-822 message to .eml file."""
    dest = Path(output_path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(msg.as_bytes())
    return dest


def send_via_smtp(
    msg: EmailMessage,
    smtp_host: str,
    smtp_port: int = 587,
    smtp_user: Optional[str] = None,
    smtp_pass: Optional[str] = None,
    use_tls: bool = True,
    use_ssl: bool = False,
    timeout: float = 15.0,
) -> Tuple[bool, str]:
    """Optionally send compiled message via SMTP."""
    server = None
    try:
        if use_ssl or smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=timeout)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=timeout)
            if use_tls:
                server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        return True, "Email successfully sent via SMTP"
    except Exception as exc:
        return False, f"SMTP delivery failed: {exc}"
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def find_default_distribution_archive(base_dir: Optional[Path] = None) -> Optional[str]:
    """Locate distribution tarball or wheel in dist directory."""
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent.parent

    dist_dir = base_dir / "dist"
    if not dist_dir.is_dir():
        return None

    # Prefer sdist tar.gz for packetstorm, selecting latest version first
    candidates = sorted(dist_dir.glob("tanuki_ad*.tar.gz"), reverse=True)
    if candidates:
        return str(candidates[0])

    candidates = sorted(dist_dir.glob("tanuki-*.tar.gz"), reverse=True)
    if candidates:
        return str(candidates[0])

    candidates = sorted(dist_dir.glob("tanuki_ad*.whl"), reverse=True)
    if candidates:
        return str(candidates[0])

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compile RFC-822 submission email for Packet Storm Security"
    )
    parser.add_argument("--to", default=DEFAULT_TO, help=f"Recipient (default: {DEFAULT_TO})")
    parser.add_argument("--from", dest="from_addr", default=DEFAULT_FROM, help=f"Sender (default: {DEFAULT_FROM})")
    parser.add_argument("--subject", default=None, help="Email subject (default: formatted with version)")
    parser.add_argument("--version", default=DEFAULT_VERSION, help=f"Version (default: {DEFAULT_VERSION})")
    parser.add_argument("-o", "--output", default="dist/packetstorm_submission.eml", help="Output .eml file path")
    parser.add_argument("--attach", default=None, help="Explicit archive file to attach")
    parser.add_argument("--no-attach", action="store_true", help="Do not attach distribution archive")
    parser.add_argument("--smtp-host", default=os.getenv("SMTP_HOST"), help="SMTP server host")
    parser.add_argument("--smtp-port", type=int, default=int(os.getenv("SMTP_PORT", "587")), help="SMTP server port")
    parser.add_argument("--smtp-user", default=os.getenv("SMTP_USER"), help="SMTP username")
    parser.add_argument("--smtp-pass", default=os.getenv("SMTP_PASS"), help="SMTP password")
    parser.add_argument("--smtp-tls", dest="smtp_tls", action="store_true", default=True, help="Enable STARTTLS for SMTP (default: True)")
    parser.add_argument("--no-smtp-tls", "--no-tls", dest="smtp_tls", action="store_false", help="Disable STARTTLS for unencrypted SMTP")
    parser.add_argument("--smtp-ssl", action="store_true", default=False, help="Use direct SSL connection (SMTPS, default on port 465)")
    parser.add_argument("--send", action="store_true", help="Attempt immediate delivery via configured SMTP server")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON output")

    args = parser.parse_args()

    # Determine attachment
    attachment_path = None
    if not args.no_attach:
        if args.attach:
            if not os.path.isfile(args.attach):
                err_msg = f"Specified attachment file does not exist: {args.attach}"
                if args.json:
                    print(json.dumps({"status": "ERROR", "error": err_msg}))
                else:
                    print(f"[ERROR] {err_msg}", file=sys.stderr)
                sys.exit(1)
            attachment_path = str(Path(args.attach).resolve())
        else:
            attachment_path = find_default_distribution_archive()

    subject = args.subject or f"[TOOL] tanuki-ad {args.version} - Linux Active Directory & Kerberos Protocol Triage Engine"

    msg = create_rfc822_message(
        to_addr=args.to,
        from_addr=args.from_addr,
        subject=subject,
        version=args.version,
        attachment_path=attachment_path,
    )

    eml_path = save_eml_file(msg, args.output)

    smtp_sent = False
    smtp_message = "SMTP delivery skipped (no --send flag or SMTP host unconfigured)"
    if args.send and args.smtp_host:
        smtp_sent, smtp_message = send_via_smtp(
            msg=msg,
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            smtp_user=args.smtp_user,
            smtp_pass=args.smtp_pass,
            use_tls=args.smtp_tls,
            use_ssl=args.smtp_ssl,
        )

    result = {
        "status": "SUCCESS" if (not args.send or smtp_sent) else "SMTP_ERROR",
        "output_file": str(eml_path),
        "recipient": args.to,
        "sender": args.from_addr,
        "subject": subject,
        "version": args.version,
        "attached_file": attachment_path if (attachment_path and os.path.isfile(attachment_path)) else None,
        "smtp_sent": smtp_sent,
        "smtp_status": smtp_message,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("[OK] Packet Storm submission compiled successfully")
        print(f"     Output EML  : {eml_path}")
        print(f"     Recipient   : {args.to}")
        print(f"     Subject     : {subject}")
        if attachment_path:
            print(f"     Attached    : {attachment_path}")
        print(f"     SMTP Status : {smtp_message}")

    if args.send and not smtp_sent:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
