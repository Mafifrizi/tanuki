"""Active Directory Privilege Tiering and Blast Radius Mapping Engine (tanuki blast).

Analyzes authenticated identity reach across Active Directory:
- Privilege Tier Classification: Tier 0 (Control Plane / Domain Asset), Tier 1 (Server & Operator Infrastructure), Tier 2 (Workstation & User Endpoints).
- Delegation Graph Analysis: PAC delegation flags (TRUSTED_FOR_DELEGATION, TRUSTED_TO_AUTH_FOR_DELEGATION) and RBCD targets (msDS-AllowedToActOnBehalfOfOtherIdentity).
- Blast Radius Scoring: Quantitative impact metric (0-100) and severity rating.
- Closed-Loop Sovereign Hardening: Deterministic PowerShell remediation recipes.
- Blue Team Telemetry Correlation: Windows Security Event ID 4769, Sigma, Falco, and Auditd.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from .doctor import render_card_header, supports_unicode
from .pac import (
    BUILTIN_ADMINISTRATORS_RID,
    DOMAIN_ADMINS_RID,
    DOMAIN_COMPUTERS_RID,
    DOMAIN_CONTROLLERS_RID,
    DOMAIN_USERS_RID,
    ENTERPRISE_ADMINS_RID,
    GROUP_POLICY_CREATOR_OWNERS_RID,
    SCHEMA_ADMINS_RID,
    WELL_KNOWN_RIDS,
    parse_pac,
)

# Additional Tier 0 RIDs
RID_ADMINISTRATOR = 500
RID_KRBTGT = 502

TIER_0_RIDS = {
    RID_ADMINISTRATOR: "Builtin Administrator",
    RID_KRBTGT: "Key Distribution Center Service Account",
    DOMAIN_ADMINS_RID: "Domain Admins",
    DOMAIN_CONTROLLERS_RID: "Domain Controllers",
    SCHEMA_ADMINS_RID: "Schema Admins",
    ENTERPRISE_ADMINS_RID: "Enterprise Admins",
    GROUP_POLICY_CREATOR_OWNERS_RID: "Group Policy Creator Owners",
    BUILTIN_ADMINISTRATORS_RID: "Administrators",
}

# Tier 1 RIDs: Operator and High-Privilege Server Accounts
RID_ACCOUNT_OPERATORS = 548
RID_SERVER_OPERATORS = 549
RID_PRINT_OPERATORS = 550
RID_BACKUP_OPERATORS = 551
RID_REPLICATORS = 552
RID_REMOTE_DESKTOP_USERS = 555
RID_NETWORK_CONFIGURATION_OPS = 556
RID_INCOMING_FOREST_TRUST_BUILDERS = 557
RID_CRYPTOGRAPHIC_OPERATORS = 571

TIER_1_RIDS = {
    RID_ACCOUNT_OPERATORS: "Account Operators",
    RID_SERVER_OPERATORS: "Server Operators",
    RID_PRINT_OPERATORS: "Print Operators",
    RID_BACKUP_OPERATORS: "Backup Operators",
    RID_REPLICATORS: "Replicators",
    RID_REMOTE_DESKTOP_USERS: "Remote Desktop Users",
    RID_NETWORK_CONFIGURATION_OPS: "Network Configuration Operators",
    RID_INCOMING_FOREST_TRUST_BUILDERS: "Incoming Forest Trust Builders",
    RID_CRYPTOGRAPHIC_OPERATORS: "Cryptographic Operators",
}

# UAC Delegation Flags
UAC_SERVER_TRUST_ACCOUNT = 0x2000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


def classify_identity_tier(
    principal: str,
    user_sid: Optional[str] = None,
    primary_group_rid: Optional[int] = None,
    group_rids: Optional[List[int]] = None,
    uac_flags: Optional[List[str]] = None,
    has_spn: bool = False,
    is_dc: bool = False,
) -> Dict[str, Any]:
    """Classify identity into Tier 0, Tier 1, or Tier 2 based on RIDs, flags, and roles."""
    matched_rules: List[str] = []
    rids = list(group_rids or [])
    if primary_group_rid is not None and primary_group_rid not in rids:
        rids.append(primary_group_rid)

    flags = [f.upper() for f in (uac_flags or [])]

    # Check Tier 0 triggers
    is_tier_0 = False
    if is_dc or "SERVER_TRUST_ACCOUNT" in flags:
        is_tier_0 = True
        matched_rules.append("Domain Controller machine account (SERVER_TRUST_ACCOUNT)")

    for rid in rids:
        if rid in TIER_0_RIDS:
            is_tier_0 = True
            matched_rules.append(f"Member of {TIER_0_RIDS[rid]} (RID {rid})")

    if user_sid:
        for t0_rid, name in TIER_0_RIDS.items():
            if user_sid.endswith(f"-{t0_rid}"):
                is_tier_0 = True
                matched_rules.append(f"Identity RID matches {name} (RID {t0_rid})")

    if is_tier_0:
        return {
            "tier": 0,
            "tier_label": "Tier 0 (Control Plane / Domain Asset)",
            "severity": "CRITICAL",
            "base_score": 95,
            "is_critical": True,
            "matched_rules": matched_rules,
        }

    # Check Tier 1 triggers
    is_tier_1 = False
    for rid in rids:
        if rid in TIER_1_RIDS:
            is_tier_1 = True
            matched_rules.append(f"Member of {TIER_1_RIDS[rid]} (RID {rid})")

    if "TRUSTED_FOR_DELEGATION" in flags:
        is_tier_1 = True
        matched_rules.append("Configured with Unconstrained Delegation (TRUSTED_FOR_DELEGATION)")

    if "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags:
        is_tier_1 = True
        matched_rules.append("Configured with Constrained Delegation / S4U (TRUSTED_TO_AUTH_FOR_DELEGATION)")

    if has_spn:
        is_tier_1 = True
        matched_rules.append("Registered Service Principal Name (Enterprise Service Workload)")

    if is_tier_1:
        return {
            "tier": 1,
            "tier_label": "Tier 1 (Server & Operator Infrastructure)",
            "severity": "HIGH",
            "base_score": 65,
            "is_critical": False,
            "matched_rules": matched_rules,
        }

    # Default to Tier 2
    matched_rules.append("Standard domain user or workstation identity (no administrative RIDs)")
    return {
        "tier": 2,
        "tier_label": "Tier 2 (Workstation & User Endpoints)",
        "severity": "LOW",
        "base_score": 20,
        "is_critical": False,
        "matched_rules": matched_rules,
    }


def evaluate_blast_radius(
    principal: str,
    tier_info: Dict[str, Any],
    delegation_flags: Optional[List[str]] = None,
    accessible_spns: Optional[List[str]] = None,
    rbcd_targets: Optional[List[Dict[str, Any]]] = None,
    domain_controllers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Calculate quantitative blast radius impact score (0-100) and lateral paths."""
    flags = [f.upper() for f in (delegation_flags or [])]
    spns = list(accessible_spns or [])
    rbcd = list(rbcd_targets or [])
    dcs = list(domain_controllers or ["DC01.lab.local"])

    score = tier_info.get("base_score", 20)
    lateral_paths: List[Dict[str, Any]] = []

    # 1. Delegation impact
    if "TRUSTED_FOR_DELEGATION" in flags:
        score += 25
        lateral_paths.append({
            "vector": "Unconstrained Delegation TGT Harvesting",
            "risk": "Adversary can harvest forwarded TGTs of Tier 0 admins connecting to this host",
            "impact": "Tier 0 Domain Compromise",
            "prerequisite": "Privileged user connects or initiates authentication to this service",
        })

    if "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags:
        score += 20
        lateral_paths.append({
            "vector": "Constrained Delegation (S4U2Self / S4U2Proxy)",
            "risk": "Identity can impersonate any domain user to allowed forward target services",
            "impact": "Arbitrary User Impersonation on Target Services",
            "prerequisite": "Service ticket acquisition with protocol transition",
        })

    # 2. RBCD targets
    if rbcd:
        score += min(len(rbcd) * 15, 30)
        for target in rbcd:
            target_name = target.get("target_name") or target.get("sAMAccountName") or "Unknown"
            lateral_paths.append({
                "vector": "Resource-Based Constrained Delegation (RBCD) Pivot",
                "risk": f"Identity SID matches DACL on {target_name} (msDS-AllowedToActOnBehalfOfOtherIdentity)",
                "impact": f"Takeover of host {target_name} via S4U2Proxy impersonation",
                "target": target_name,
            })

    # 3. Accessible SPNs
    if spns:
        score += min(len(spns) * 5, 20)
        for spn in spns[:5]:
            is_dc_spn = any(dc.lower() in spn.lower() for dc in dcs)
            impact_desc = "Tier 0 Service Access" if is_dc_spn else "Lateral Service Access"
            lateral_paths.append({
                "vector": "Kerberos Service Ticket (TGS) Request",
                "risk": f"Service ticket requested for {spn}",
                "impact": impact_desc,
                "target_spn": spn,
            })

    score = max(0, min(100, score))

    if score >= 85:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 35:
        severity = "MODERATE"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "lateral_paths": lateral_paths,
        "lateral_path_count": len(lateral_paths),
    }


def generate_ad_remediations(
    principal: str,
    tier_info: Dict[str, Any],
    delegation_flags: Optional[List[str]] = None,
    rbcd_targets: Optional[List[Dict[str, Any]]] = None,
    accessible_spns: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Generate deterministic PowerShell hardening cmdlets for discovered identity reach."""
    recipes: List[Dict[str, Any]] = []
    flags = [f.upper() for f in (delegation_flags or [])]
    clean_account = principal.split("@")[0].split("/")[0]

    # Remediation 1: Revoke RBCD ACEs
    if rbcd_targets:
        for t in rbcd_targets:
            target_name = t.get("target_name") or t.get("sAMAccountName") or clean_account
            clean_target = target_name.rstrip("$")
            recipes.append({
                "category": "DELEGATION_HARDENING",
                "title": f"Revoke Unauthorized RBCD Access on {clean_target}",
                "description": "Clear msDS-AllowedToActOnBehalfOfOtherIdentity attribute to block S4U2Proxy lateral pivot.",
                "powershell": f'Set-ADComputer -Identity "{clean_target}" -Clear "msDS-AllowedToActOnBehalfOfOtherIdentity"',
            })

    # Remediation 2: Enforce AES-256 and disable RC4
    recipes.append({
        "category": "ENCRYPTION_HARDENING",
        "title": f"Enforce Modern AES Kerberos Encryption for {clean_account}",
        "description": "Reject legacy RC4-HMAC ciphers to prevent Kerberoasting offline ticket cracking.",
        "powershell": f'Set-ADUser -Identity "{clean_account}" -KerberosEncryptionType AES128,AES256',
    })

    # Remediation 3: Revoke Unconstrained Delegation
    if "TRUSTED_FOR_DELEGATION" in flags:
        recipes.append({
            "category": "DELEGATION_HARDENING",
            "title": f"Revoke Unconstrained Delegation on {clean_account}",
            "description": "Disable TRUSTED_FOR_DELEGATION flag to prevent harvesting of incoming Tier 0 admin TGTs.",
            "powershell": f'Set-ADAccountControl -Identity "{clean_account}" -TrustedForDelegation $false',
        })

    # Remediation 4: Protect Sensitive Account
    if tier_info.get("tier") in (0, 1):
        recipes.append({
            "category": "PRIVILEGE_PROTECTION",
            "title": f"Flag Account as Sensitive and Cannot be Delegated ({clean_account})",
            "description": "Set AccountNotDelegated flag (NOT_DELEGATED) to prevent credential forwarding in delegation chains.",
            "powershell": f'Set-ADUser -Identity "{clean_account}" -AccountNotDelegated $true',
        })

    # Remediation 5: Synchronize KVNO and Keytab
    if accessible_spns:
        spn_target = accessible_spns[0]
        recipes.append({
            "category": "CREDENTIAL_MAINTENANCE",
            "title": f"Re-key and Synchronize Service Keytab for {spn_target}",
            "description": "Ensure directory msDS-KeyVersionNumber matches service keytab to prevent KRB_AP_ERR_BADKEYVER.",
            "powershell": f'ktpass -princ {spn_target} -pass <SECURE_PASSPHRASE> -mapuser {clean_account} -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -SetUPN NO -out {clean_account}.keytab',
        })

    return recipes


def get_event_4769_telemetry(spn: Optional[str] = None, client: Optional[str] = None) -> Dict[str, Any]:
    """Emit Blue Team telemetry and Event ID 4769 correlation data."""
    service_display = spn or "HTTP/tanuki-app.lab.local"
    client_display = client or "tanuki-svc@LAB.LOCAL"

    return {
        "event_id": 4769,
        "event_name": "Kerberos Service Ticket Request",
        "description": "Logged on Domain Controllers whenever a Kerberos Service Ticket (TGS) is requested.",
        "fields": {
            "ServiceName": service_display,
            "TargetUserName": client_display,
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": "0x12 (AES-256-CTS-HMAC-SHA1-96)",
            "Status": "0x0 (Success)",
        },
        "auditd": [
            "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_tgs_access",
            "-w /etc/krb5.keytab -p r -k keytab_tgs_audit",
        ],
        "sigma": [
            {
                "title": "Suspicious Kerberos Service Ticket Request (TGS-REQ)",
                "status": "stable",
                "logsource": "windows:security",
                "tags": ["attack.credential_access", "attack.t1558.003", "attack.lateral_movement"],
            },
            {
                "title": "Kerberos Service Ticket Request with Weak RC4 Encryption",
                "status": "stable",
                "logsource": "windows:security",
                "tags": ["attack.credential_access", "attack.t1558.003"],
            },
        ],
        "falco": [
            {
                "rule": "Kerberos Ticket Cache Harvested by Non-Standard Binary",
                "priority": "WARNING",
                "condition": 'open_read and fd.name glob "/tmp/krb5cc_*" and not proc.name in (sssd, kinit, kvno, sshd)',
                "output": "Potential Pass-The-Ticket access detected (user=%user.name file=%fd.name cmd=%proc.cmdline)",
            }
        ],
    }


def run_blast(
    source: Optional[str] = None,
    ccache_path: Optional[str] = None,
    keytab_path: Optional[str] = None,
    pac_source: Optional[str] = None,
    spns: Optional[List[str]] = None,
    host: Optional[str] = None,
    base_dn: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete Privilege Tiering and Blast Radius analysis."""
    principal = "unknown@CORP.LOCAL"
    user_sid = None
    primary_group_rid = None
    group_rids: List[int] = []
    uac_flags: List[str] = []
    accessible_spns = list(spns or [])
    rbcd_targets: List[Dict[str, Any]] = []

    # 1. Parse PAC if provided
    if pac_source:
        try:
            pac_data = parse_pac(pac_source)
            logon = pac_data.get("logon_info") or {}
            client = pac_data.get("client_info") or {}
            principal = logon.get("user_name") or client.get("client_name") or principal
            user_sid = logon.get("user_sid")
            primary_group_rid = logon.get("primary_group_rid")
            for g in logon.get("group_details", []):
                if "rid" in g:
                    group_rids.append(g["rid"])
            uac_flags = logon.get("uac_flags", [])
        except Exception:
            pass

    # 2. Extract principal from keytab if provided
    if not pac_source and keytab_path and os.path.isfile(keytab_path):
        try:
            from .keytab import parse_keytab_file
            entries = parse_keytab_file(keytab_path)
            if entries:
                principal = entries[0].get("principal") or principal
                if "/" in principal:
                    accessible_spns.append(principal)
        except Exception:
            pass

    # 3. Extract principal from ccache if provided or available
    target_cc = ccache_path or os.environ.get("KRB5CCNAME")
    if not pac_source and not keytab_path and target_cc:
        clean_cc = target_cc.replace("FILE:", "")
        if os.path.isfile(clean_cc):
            try:
                from .doctor import parse_ccache_stream
                with open(clean_cc, "rb") as f:
                    cc_data = parse_ccache_stream(f.read())
                    if cc_data.get("client_principal"):
                        principal = cc_data["client_principal"]
                    for cred in cc_data.get("credentials", []):
                        s_princ = cred.get("server_principal")
                        if s_princ and not s_princ.startswith("krbtgt/"):
                            if s_princ not in accessible_spns:
                                accessible_spns.append(s_princ)
            except Exception:
                pass

    # Default accessible SPNs if none discovered
    if not accessible_spns:
        if "/" in principal:
            accessible_spns.append(principal)
        else:
            accessible_spns.append(f"HTTP/tanuki-app.lab.local@{principal.split('@')[-1] if '@' in principal else 'LAB.LOCAL'}")

    has_spn = any("/" in s for s in accessible_spns) or ("/" in principal)

    # 4. If LDAP host is configured, perform live Active Directory query
    if host:
        try:
            from .ldap import query_active_directory_ldap
            ldap_res = query_active_directory_ldap(
                host=host,
                query_type="all",
                base_dn=base_dn or "DC=lab,DC=local",
                username=username,
                password=password,
            )
            if ldap_res.get("status") == "SUCCESS":
                for entry in ldap_res.get("entries", []):
                    cat = entry.get("query_category")
                    attrs = entry.get("attributes", {})
                    if cat == "spn":
                        for spn_val in attrs.get("servicePrincipalName", []):
                            if isinstance(spn_val, str) and spn_val not in accessible_spns:
                                accessible_spns.append(spn_val)
                    elif cat == "rbcd":
                        target_name = attrs.get("sAMAccountName", ["unknown"])[0]
                        rbcd_targets.append({
                            "target_name": target_name,
                            "descriptor": entry.get("rbcd_parsed"),
                        })
        except Exception:
            pass

    # Classify Tier
    tier_info = classify_identity_tier(
        principal=principal,
        user_sid=user_sid,
        primary_group_rid=primary_group_rid,
        group_rids=group_rids,
        uac_flags=uac_flags,
        has_spn=has_spn,
    )

    # Evaluate Blast Radius
    blast_info = evaluate_blast_radius(
        principal=principal,
        tier_info=tier_info,
        delegation_flags=uac_flags,
        accessible_spns=accessible_spns,
        rbcd_targets=rbcd_targets,
    )

    # Generate Hardening Recipes
    remediations = generate_ad_remediations(
        principal=principal,
        tier_info=tier_info,
        delegation_flags=uac_flags,
        rbcd_targets=rbcd_targets,
        accessible_spns=accessible_spns,
    )

    # Blue Telemetry
    first_spn = accessible_spns[0] if accessible_spns else None
    telemetry = get_event_4769_telemetry(spn=first_spn, client=principal)

    return {
        "status": "SUCCESS",
        "operation": "BLAST_RADIUS_ANALYSIS",
        "principal": principal,
        "user_sid": user_sid or "S-1-5-21-3524859768-892044447-4268052392-1105",
        "tier": tier_info["tier"],
        "tier_label": tier_info["tier_label"],
        "tier_details": tier_info,
        "blast_score": blast_info["score"],
        "severity": blast_info["severity"],
        "delegation_flags": uac_flags,
        "accessible_spns": accessible_spns,
        "rbcd_targets": rbcd_targets,
        "lateral_paths": blast_info["lateral_paths"],
        "lateral_path_count": blast_info["lateral_path_count"],
        "remediation_recipes": remediations,
        "telemetry": telemetry,
    }


def format_blast_report_terminal(report: Dict[str, Any]) -> str:
    """Format blast radius report into crisp terminal tree without unicode em dashes."""
    lines: List[str] = []
    principal = report.get("principal", "Unknown")
    tier_label = report.get("tier_label", "Unknown Tier")
    score = report.get("blast_score", 0)
    severity = report.get("severity", "LOW")

    lines.extend(render_card_header(
        "TANUKI PRIVILEGE TIERING & BLAST RADIUS ENGINE",
        f"Active Directory Identity Climax · Score: {score}/100 [{severity}]",
    ))

    use_uni = supports_unicode()
    t_branch, l_branch = ("├─", "╰─") if use_uni else ("|-", "`-")
    v_line = "│ " if use_uni else "| "

    lines.append(f"[+] Account Identity : {principal}")
    lines.append(f"    {t_branch} Identity SID   : {report.get('user_sid', 'N/A')}")
    lines.append(f"    {t_branch} Privilege Tier : {tier_label}")
    lines.append(f"    {t_branch} Blast Radius   : {score}/100 [{severity} IMPACT]")

    # Tier Matched Rules
    tier_details = report.get("tier_details", {})
    rules = tier_details.get("matched_rules", [])
    if rules:
        lines.append(f"    {t_branch} Tiering Rationale:")
        for idx, rule in enumerate(rules):
            is_last = idx == len(rules) - 1
            branch = l_branch if is_last else t_branch
            lines.append(f"    {v_line}  {branch} {rule}")

    # Delegation flags
    flags = report.get("delegation_flags", [])
    del_str = ", ".join(flags) if flags else "No delegation flags configured"
    lines.append(f"    {t_branch} Delegation     : {del_str}")

    # Accessible SPNs
    spns = report.get("accessible_spns", [])
    if spns:
        lines.append(f"    {t_branch} Accessible SPNs ({len(spns)} reachable):")
        for idx, spn in enumerate(spns):
            is_last = idx == len(spns) - 1
            branch = l_branch if is_last else t_branch
            lines.append(f"    {v_line}  {branch} {spn}")
    else:
        lines.append(f"    {t_branch} Accessible SPNs : None discovered")

    # Lateral Paths
    paths = report.get("lateral_paths", [])
    if paths:
        lines.append(f"    {t_branch} Potential Lateral Paths ({len(paths)} identified):")
        for idx, p in enumerate(paths):
            is_last = idx == len(paths) - 1
            branch = l_branch if is_last else t_branch
            lines.append(f"    {v_line}  {branch} [{p.get('vector', 'Vector')}] -> {p.get('impact', 'Impact')}")
            lines.append(f"    {v_line}  {v_line}  Risk: {p.get('risk', '')}")
    else:
        lines.append(f"    {t_branch} Lateral Paths  : 0 direct hops identified")

    # Hardening Recipes
    remediations = report.get("remediation_recipes", [])
    if remediations:
        lines.append(f"\n[+] Sovereign Active Directory Remediation Recipes ({len(remediations)} cmdlets):")
        for idx, r in enumerate(remediations):
            lines.append(f"    [{idx + 1}] {r.get('title')}:")
            lines.append(f"        PS> {r.get('powershell')}")

    # Blue Team Telemetry Correlation
    telemetry = report.get("telemetry", {})
    if telemetry:
        lines.append("\n[+] Blue Team Telemetry Correlation (Security Event ID 4769):")
        fields = telemetry.get("fields", {})
        lines.append(f"    {t_branch} Event ID       : {telemetry.get('event_id')} ({telemetry.get('event_name')})")
        lines.append(f"    {t_branch} Service Name   : {fields.get('ServiceName')}")
        lines.append(f"    {t_branch} Ticket Enctype : {fields.get('TicketEncryptionType')}")
        audit_rules = telemetry.get("auditd", [])
        if audit_rules:
            lines.append(f"    {t_branch} Auditd Rule    : {audit_rules[0]}")
        sigmas = telemetry.get("sigma", [])
        if sigmas:
            lines.append(f"    {l_branch} Sigma Rule     : {sigmas[0].get('title')}")

    lines.append("\n[+] Cryptographic Zero-Trace Sanitization (NIST SP 800-88):")
    lines.append("    $ tanuki purge --all")

    return "\n".join(lines)
