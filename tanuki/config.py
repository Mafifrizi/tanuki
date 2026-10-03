"""Unprivileged Kerberos Configuration Generator for Linux Active Directory."""

import os
from typing import Dict, Optional


def generate_krb5_conf(
    realm: str,
    kdc: str,
    admin_server: Optional[str] = None,
    dns_lookup_realm: bool = False,
    dns_lookup_kdc: bool = False,
    ticket_lifetime: str = "24h",
    renew_lifetime: str = "7d",
    forwardable: bool = True,
) -> str:
    """Generate an RFC 4120-compliant Kerberos configuration with uppercase realm."""
    if not realm or not realm.strip():
        raise ValueError("Realm cannot be empty")
    if not kdc or not kdc.strip():
        raise ValueError("KDC cannot be empty")

    clean_realm = realm.strip().upper()
    domain = clean_realm.lower()
    kdc_target = kdc.strip()
    admin_target = admin_server.strip() if admin_server else kdc_target

    dns_realm_str = "true" if dns_lookup_realm else "false"
    dns_kdc_str = "true" if dns_lookup_kdc else "false"
    forwardable_str = "true" if forwardable else "false"

    return f"""[libdefaults]
    default_realm = {clean_realm}
    dns_lookup_realm = {dns_realm_str}
    dns_lookup_kdc = {dns_kdc_str}
    ticket_lifetime = {ticket_lifetime}
    renew_lifetime = {renew_lifetime}
    forwardable = {forwardable_str}

[realms]
    {clean_realm} = {{
        kdc = {kdc_target}
        admin_server = {admin_target}
    }}

[domain_realm]
    .{domain} = {clean_realm}
    {domain} = {clean_realm}
"""


def write_krb5_conf_file(
    filepath: str,
    realm: str,
    kdc: str,
    admin_server: Optional[str] = None,
) -> Dict[str, str]:
    """Write generated Kerberos configuration to target filepath."""
    content = generate_krb5_conf(realm, kdc, admin_server)
    abs_path = os.path.abspath(filepath)
    parent_dir = os.path.dirname(abs_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)

    return {
        "status": "SUCCESS",
        "realm": realm.strip().upper(),
        "kdc": kdc.strip(),
        "admin_server": admin_server.strip() if admin_server else kdc.strip(),
        "config_path": abs_path,
        "export_command": f"export KRB5_CONFIG={abs_path}",
        "content": content,
    }
