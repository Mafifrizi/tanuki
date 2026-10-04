"""Unprivileged Kerberos Configuration Generator for Linux Active Directory."""

import os
from typing import Dict, List, Optional, Union


def generate_krb5_conf(
    realm: str,
    kdc: Union[str, List[str]],
    admin_server: Optional[str] = None,
    dns_lookup_realm: bool = False,
    dns_lookup_kdc: bool = False,
    ticket_lifetime: str = "24h",
    renew_lifetime: str = "7d",
    forwardable: bool = True,
    rdns: bool = False,
    udp_preference_limit: int = 0,
    clockskew: Optional[int] = None,
    enforce_aes: bool = False,
) -> str:
    """Generate an RFC 4120-compliant Kerberos configuration with uppercase realm."""
    if not realm or not realm.strip():
        raise ValueError("Realm cannot be empty")
    if not kdc:
        raise ValueError("KDC cannot be empty")

    clean_realm = realm.strip().upper()
    domain = clean_realm.lower()

    if isinstance(kdc, str):
        kdc_candidates = [k.strip() for k in kdc.split(",") if k.strip()]
    elif isinstance(kdc, (list, tuple)):
        kdc_candidates = []
        for item in kdc:
            for k in item.split(","):
                k_clean = k.strip()
                if k_clean and k_clean not in kdc_candidates:
                    kdc_candidates.append(k_clean)
    else:
        kdc_candidates = [str(kdc).strip()]

    if not kdc_candidates:
        raise ValueError("KDC cannot be empty")

    admin_target = admin_server.strip() if admin_server else kdc_candidates[0]

    dns_realm_str = "true" if dns_lookup_realm else "false"
    dns_kdc_str = "true" if dns_lookup_kdc else "false"
    rdns_str = "true" if rdns else "false"
    forwardable_str = "true" if forwardable else "false"

    libdefaults_lines = [
        "[libdefaults]",
        f"    default_realm = {clean_realm}",
        f"    dns_lookup_realm = {dns_realm_str}",
        f"    dns_lookup_kdc = {dns_kdc_str}",
        f"    rdns = {rdns_str}",
        f"    udp_preference_limit = {udp_preference_limit}",
        f"    ticket_lifetime = {ticket_lifetime}",
        f"    renew_lifetime = {renew_lifetime}",
        f"    forwardable = {forwardable_str}",
    ]

    if clockskew is not None:
        libdefaults_lines.append(f"    clockskew = {clockskew}")

    if enforce_aes:
        libdefaults_lines.append("    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96")
        libdefaults_lines.append("    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96")

    libdefaults_block = "\n".join(libdefaults_lines)
    kdc_lines = "\n".join(f"        kdc = {k}" for k in kdc_candidates)

    return f"""{libdefaults_block}

[realms]
    {clean_realm} = {{
{kdc_lines}
        admin_server = {admin_target}
    }}

[domain_realm]
    .{domain} = {clean_realm}
    {domain} = {clean_realm}
"""


def write_krb5_conf_file(
    filepath: str,
    realm: str,
    kdc: Union[str, List[str]],
    admin_server: Optional[str] = None,
    clockskew: Optional[int] = None,
    enforce_aes: bool = False,
) -> Dict[str, str]:
    """Write generated Kerberos configuration to target filepath."""
    content = generate_krb5_conf(
        realm=realm,
        kdc=kdc,
        admin_server=admin_server,
        clockskew=clockskew,
        enforce_aes=enforce_aes,
    )
    abs_path = os.path.abspath(filepath)
    parent_dir = os.path.dirname(abs_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)

    kdc_str = kdc if isinstance(kdc, str) else ",".join(kdc)

    return {
        "status": "SUCCESS",
        "realm": realm.strip().upper(),
        "kdc": kdc_str,
        "admin_server": admin_server.strip() if admin_server else (kdc.split(",")[0].strip() if isinstance(kdc, str) else kdc[0]),
        "config_path": abs_path,
        "export_command": f"export KRB5_CONFIG={abs_path}",
        "content": content,
    }
