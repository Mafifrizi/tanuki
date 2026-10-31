use std::collections::HashSet;
use crate::util::escape_json;

pub const RID_ADMINISTRATOR: u32 = 500;
pub const RID_KRBTGT: u32 = 502;
pub const RID_DOMAIN_ADMINS: u32 = 512;
pub const RID_DOMAIN_CONTROLLERS: u32 = 516;
pub const RID_SCHEMA_ADMINS: u32 = 518;
pub const RID_ENTERPRISE_ADMINS: u32 = 519;
pub const RID_GROUP_POLICY_CREATOR_OWNERS: u32 = 520;
pub const RID_BUILTIN_ADMINISTRATORS: u32 = 544;

pub const RID_ACCOUNT_OPERATORS: u32 = 548;
pub const RID_SERVER_OPERATORS: u32 = 549;
pub const RID_PRINT_OPERATORS: u32 = 550;
pub const RID_BACKUP_OPERATORS: u32 = 551;
pub const RID_REPLICATORS: u32 = 552;
pub const RID_REMOTE_DESKTOP_USERS: u32 = 555;
pub const RID_NETWORK_CONFIGURATION_OPS: u32 = 556;
pub const RID_INCOMING_FOREST_TRUST_BUILDERS: u32 = 557;
pub const RID_CRYPTOGRAPHIC_OPERATORS: u32 = 571;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierInfo {
    pub tier: u8,
    pub tier_label: String,
    pub severity: String,
    pub base_score: u32,
    pub is_critical: bool,
    pub matched_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateralPath {
    pub vector: String,
    pub risk: String,
    pub impact: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationRecipe {
    pub category: String,
    pub title: String,
    pub description: String,
    pub powershell: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlastReport {
    pub principal: String,
    pub user_sid: String,
    pub tier_info: TierInfo,
    pub blast_score: u32,
    pub severity: String,
    pub delegation_flags: Vec<String>,
    pub accessible_spns: Vec<String>,
    pub lateral_paths: Vec<LateralPath>,
    pub remediation_recipes: Vec<RemediationRecipe>,
}

pub fn classify_identity_tier(
    _principal: &str,
    user_sid: Option<&str>,
    primary_group_rid: Option<u32>,
    group_rids: &[u32],
    uac_flags: &[String],
    has_spn: bool,
    is_dc: bool,
) -> TierInfo {
    let mut matched_rules = Vec::new();
    let mut rids: HashSet<u32> = group_rids.iter().copied().collect();
    if let Some(p_rid) = primary_group_rid {
        rids.insert(p_rid);
    }

    let upper_flags: Vec<String> = uac_flags.iter().map(|f| f.to_ascii_uppercase()).collect();

    let mut is_tier_0 = false;
    if is_dc || upper_flags.iter().any(|f| f == "SERVER_TRUST_ACCOUNT") {
        is_tier_0 = true;
        matched_rules.push("Domain Controller machine account (SERVER_TRUST_ACCOUNT)".to_string());
    }

    let t0_defs = [
        (RID_ADMINISTRATOR, "Builtin Administrator"),
        (RID_KRBTGT, "Key Distribution Center Service Account"),
        (RID_DOMAIN_ADMINS, "Domain Admins"),
        (RID_DOMAIN_CONTROLLERS, "Domain Controllers"),
        (RID_SCHEMA_ADMINS, "Schema Admins"),
        (RID_ENTERPRISE_ADMINS, "Enterprise Admins"),
        (RID_GROUP_POLICY_CREATOR_OWNERS, "Group Policy Creator Owners"),
        (RID_BUILTIN_ADMINISTRATORS, "Administrators"),
    ];

    for (rid, name) in &t0_defs {
        if rids.contains(rid) {
            is_tier_0 = true;
            matched_rules.push(format!("Member of {} (RID {})", name, rid));
        }
    }

    if let Some(sid) = user_sid {
        for (rid, name) in &t0_defs {
            let suffix = format!("-{}", rid);
            if sid.ends_with(&suffix) {
                is_tier_0 = true;
                matched_rules.push(format!("Identity RID matches {} (RID {})", name, rid));
            }
        }
    }

    if is_tier_0 {
        return TierInfo {
            tier: 0,
            tier_label: "Tier 0 (Control Plane / Domain Asset)".to_string(),
            severity: "CRITICAL".to_string(),
            base_score: 95,
            is_critical: true,
            matched_rules,
        };
    }

    let mut is_tier_1 = false;
    let t1_defs = [
        (RID_ACCOUNT_OPERATORS, "Account Operators"),
        (RID_SERVER_OPERATORS, "Server Operators"),
        (RID_PRINT_OPERATORS, "Print Operators"),
        (RID_BACKUP_OPERATORS, "Backup Operators"),
        (RID_REPLICATORS, "Replicators"),
        (RID_REMOTE_DESKTOP_USERS, "Remote Desktop Users"),
        (RID_NETWORK_CONFIGURATION_OPS, "Network Configuration Operators"),
        (RID_INCOMING_FOREST_TRUST_BUILDERS, "Incoming Forest Trust Builders"),
        (RID_CRYPTOGRAPHIC_OPERATORS, "Cryptographic Operators"),
    ];

    for (rid, name) in &t1_defs {
        if rids.contains(rid) {
            is_tier_1 = true;
            matched_rules.push(format!("Member of {} (RID {})", name, rid));
        }
    }

    if upper_flags.iter().any(|f| f == "TRUSTED_FOR_DELEGATION") {
        is_tier_1 = true;
        matched_rules.push("Configured with Unconstrained Delegation (TRUSTED_FOR_DELEGATION)".to_string());
    }

    if upper_flags.iter().any(|f| f == "TRUSTED_TO_AUTH_FOR_DELEGATION") {
        is_tier_1 = true;
        matched_rules.push("Configured with Constrained Delegation / S4U (TRUSTED_TO_AUTH_FOR_DELEGATION)".to_string());
    }

    if has_spn {
        is_tier_1 = true;
        matched_rules.push("Registered Service Principal Name (Enterprise Service Workload)".to_string());
    }

    if is_tier_1 {
        return TierInfo {
            tier: 1,
            tier_label: "Tier 1 (Server & Operator Infrastructure)".to_string(),
            severity: "HIGH".to_string(),
            base_score: 65,
            is_critical: false,
            matched_rules,
        };
    }

    matched_rules.push("Standard domain user or workstation identity (no administrative RIDs)".to_string());
    TierInfo {
        tier: 2,
        tier_label: "Tier 2 (Workstation & User Endpoints)".to_string(),
        severity: "LOW".to_string(),
        base_score: 20,
        is_critical: false,
        matched_rules,
    }
}

pub fn evaluate_blast_radius(
    tier_info: &TierInfo,
    delegation_flags: &[String],
    accessible_spns: &[String],
    rbcd_targets: &[String],
) -> (u32, String, Vec<LateralPath>) {
    let upper_flags: Vec<String> = delegation_flags.iter().map(|f| f.to_ascii_uppercase()).collect();
    let mut score = tier_info.base_score;
    let mut lateral_paths = Vec::new();

    if upper_flags.iter().any(|f| f == "TRUSTED_FOR_DELEGATION") {
        score += 25;
        lateral_paths.push(LateralPath {
            vector: "Unconstrained Delegation TGT Harvesting".to_string(),
            risk: "Adversary can harvest forwarded TGTs of Tier 0 admins connecting to this host".to_string(),
            impact: "Tier 0 Domain Compromise".to_string(),
            target: None,
        });
    }

    if upper_flags.iter().any(|f| f == "TRUSTED_TO_AUTH_FOR_DELEGATION") {
        score += 20;
        lateral_paths.push(LateralPath {
            vector: "Constrained Delegation (S4U2Self / S4U2Proxy)".to_string(),
            risk: "Identity can impersonate any domain user to allowed forward target services".to_string(),
            impact: "Arbitrary User Impersonation on Target Services".to_string(),
            target: None,
        });
    }

    if !rbcd_targets.is_empty() {
        score += std::cmp::min((rbcd_targets.len() as u32) * 15, 30);
        for t in rbcd_targets {
            lateral_paths.push(LateralPath {
                vector: "Resource-Based Constrained Delegation (RBCD) Pivot".to_string(),
                risk: format!("Identity SID matches DACL on {} (msDS-AllowedToActOnBehalfOfOtherIdentity)", t),
                impact: format!("Takeover of host {} via S4U2Proxy impersonation", t),
                target: Some(t.clone()),
            });
        }
    }

    if !accessible_spns.is_empty() {
        score += std::cmp::min((accessible_spns.len() as u32) * 5, 20);
        for spn in accessible_spns.iter().take(5) {
            lateral_paths.push(LateralPath {
                vector: "Kerberos Service Ticket (TGS) Request".to_string(),
                risk: format!("Service ticket requested for {}", spn),
                impact: "Lateral Service Access".to_string(),
                target: Some(spn.clone()),
            });
        }
    }

    if score > 100 {
        score = 100;
    }

    let severity = if score >= 85 {
        "CRITICAL"
    } else if score >= 60 {
        "HIGH"
    } else if score >= 35 {
        "MODERATE"
    } else {
        "LOW"
    };

    (score, severity.to_string(), lateral_paths)
}

pub fn extract_ad_account_name(principal: &str) -> String {
    let raw = principal.split('@').next().unwrap_or(principal);
    let candidate = if raw.contains('/') {
        let mut parts = raw.splitn(2, '/');
        let _service = parts.next();
        let target = parts.next().unwrap_or(raw);
        let host_or_account = target.split(':').next().unwrap_or(target);
        let netbios = host_or_account.split('.').next().unwrap_or(host_or_account);
        if !netbios.is_empty() {
            netbios
        } else {
            raw
        }
    } else {
        raw
    };
    candidate
        .chars()
        .filter(|&c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '$'))
        .collect()
}

pub fn generate_ad_remediations(
    principal: &str,
    tier_info: &TierInfo,
    delegation_flags: &[String],
    rbcd_targets: &[String],
    accessible_spns: &[String],
) -> Vec<RemediationRecipe> {
    let mut recipes = Vec::new();
    let upper_flags: Vec<String> = delegation_flags.iter().map(|f| f.to_ascii_uppercase()).collect();
    let clean_account = extract_ad_account_name(principal);

    for t in rbcd_targets {
        recipes.push(RemediationRecipe {
            category: "DELEGATION_HARDENING".to_string(),
            title: format!("Revoke Unauthorized RBCD Access on {}", t),
            description: "Clear msDS-AllowedToActOnBehalfOfOtherIdentity attribute to block S4U2Proxy lateral pivot.".to_string(),
            powershell: format!("Set-ADComputer -Identity \"{}\" -Clear \"msDS-AllowedToActOnBehalfOfOtherIdentity\"", t),
        });
    }

    recipes.push(RemediationRecipe {
        category: "ENCRYPTION_HARDENING".to_string(),
        title: format!("Enforce Modern AES Kerberos Encryption for {}", clean_account),
        description: "Reject legacy RC4-HMAC ciphers to prevent Kerberoasting offline ticket cracking.".to_string(),
        powershell: format!("Set-ADUser -Identity \"{}\" -KerberosEncryptionType AES128,AES256", clean_account),
    });

    if upper_flags.iter().any(|f| f == "TRUSTED_FOR_DELEGATION") {
        recipes.push(RemediationRecipe {
            category: "DELEGATION_HARDENING".to_string(),
            title: format!("Revoke Unconstrained Delegation on {}", clean_account),
            description: "Disable TRUSTED_FOR_DELEGATION flag to prevent harvesting of incoming Tier 0 admin TGTs.".to_string(),
            powershell: format!("Set-ADAccountControl -Identity \"{}\" -TrustedForDelegation $false", clean_account),
        });
    }

    if tier_info.tier <= 1 {
        recipes.push(RemediationRecipe {
            category: "PRIVILEGE_PROTECTION".to_string(),
            title: format!("Flag Account as Sensitive and Cannot be Delegated ({})", clean_account),
            description: "Set AccountNotDelegated flag (NOT_DELEGATED) to prevent credential forwarding in delegation chains.".to_string(),
            powershell: format!("Set-ADUser -Identity \"{}\" -AccountNotDelegated $true", clean_account),
        });
    }

    if let Some(spn) = accessible_spns.first() {
        recipes.push(RemediationRecipe {
            category: "CREDENTIAL_MAINTENANCE".to_string(),
            title: format!("Re-key and Synchronize Service Keytab for {}", spn),
            description: "Ensure directory msDS-KeyVersionNumber matches service keytab to prevent KRB_AP_ERR_BADKEYVER.".to_string(),
            powershell: format!("ktpass -princ {} -pass <SECURE_PASSPHRASE> -mapuser {} -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -SetUPN NO -out {}.keytab", spn, clean_account, clean_account),
        });
    }

    recipes
}

pub fn format_blast_report_terminal(report: &BlastReport) -> String {
    let mut out = String::new();
    out.push_str("[TANUKI PRIVILEGE TIERING & BLAST RADIUS ENGINE]\n");
    out.push_str(&format!(" Active Directory Identity Climax | Score: {}/100 [{}]\n", report.blast_score, report.severity));
    out.push_str(&format!("[+] Account Identity : {}\n", report.principal));
    out.push_str(&format!("    |- Identity SID   : {}\n", report.user_sid));
    out.push_str(&format!("    |- Privilege Tier : {}\n", report.tier_info.tier_label));
    out.push_str(&format!("    |- Blast Radius   : {}/100 [{} IMPACT]\n", report.blast_score, report.severity));

    out.push_str("    |- Tiering Rationale:\n");
    for (idx, r) in report.tier_info.matched_rules.iter().enumerate() {
        let is_last = idx == report.tier_info.matched_rules.len() - 1;
        let branch = if is_last { "`-" } else { "|-" };
        out.push_str(&format!("    |   {} {}\n", branch, r));
    }

    let del_str = if report.delegation_flags.is_empty() {
        "No delegation flags configured".to_string()
    } else {
        report.delegation_flags.join(", ")
    };
    out.push_str(&format!("    |- Delegation     : {}\n", del_str));

    if report.accessible_spns.is_empty() {
        out.push_str("    |- Accessible SPNs : None discovered\n");
    } else {
        out.push_str(&format!("    |- Accessible SPNs ({} reachable):\n", report.accessible_spns.len()));
        for (idx, spn) in report.accessible_spns.iter().enumerate() {
            let is_last = idx == report.accessible_spns.len() - 1;
            let branch = if is_last { "`-" } else { "|-" };
            out.push_str(&format!("    |   {} {}\n", branch, spn));
        }
    }

    if report.lateral_paths.is_empty() {
        out.push_str("    |- Lateral Paths  : 0 direct hops identified\n");
    } else {
        out.push_str(&format!("    |- Potential Lateral Paths ({} identified):\n", report.lateral_paths.len()));
        for (idx, p) in report.lateral_paths.iter().enumerate() {
            let is_last = idx == report.lateral_paths.len() - 1;
            let branch = if is_last { "`-" } else { "|-" };
            out.push_str(&format!("    |   {} [{}] -> {}\n", branch, p.vector, p.impact));
            out.push_str(&format!("    |   |   Risk: {}\n", p.risk));
        }
    }

    if !report.remediation_recipes.is_empty() {
        out.push_str(&format!("\n[+] Sovereign Active Directory Remediation Recipes ({} cmdlets):\n", report.remediation_recipes.len()));
        for (idx, r) in report.remediation_recipes.iter().enumerate() {
            out.push_str(&format!("    [{}] {}:\n", idx + 1, r.title));
            out.push_str(&format!("        PS> {}\n", r.powershell));
        }
    }

    out.push_str("\n[+] Blue Team Telemetry Correlation (Security Event ID 4769):\n");
    out.push_str("    |- Event ID       : 4769 (Kerberos Service Ticket Request)\n");
    let spn_display = report.accessible_spns.first().map(|s| s.as_str()).unwrap_or("HTTP/tanuki-app.lab.local");
    out.push_str(&format!("    |- Service Name   : {}\n", spn_display));
    out.push_str("    |- Ticket Enctype : 0x12 (AES-256-CTS-HMAC-SHA1-96)\n");
    out.push_str("    |- Auditd Rule    : -w /tmp/krb5cc_* -p rwa -k krb5_ccache_tgs_access\n");
    out.push_str("    `- Sigma Rule     : Suspicious Kerberos Service Ticket Request (TGS-REQ)\n");

    out.push_str("\n[+] Cryptographic Zero-Trace Sanitization (NIST SP 800-88):\n");
    out.push_str("    $ tanuki purge --all\n");

    out
}

pub fn blast_report_to_json(report: &BlastReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"status\": \"SUCCESS\",\n");
    out.push_str("  \"operation\": \"BLAST_RADIUS_ANALYSIS\",\n");
    out.push_str(&format!("  \"principal\": \"{}\",\n", escape_json(&report.principal)));
    out.push_str(&format!("  \"user_sid\": \"{}\",\n", escape_json(&report.user_sid)));
    out.push_str(&format!("  \"tier\": {},\n", report.tier_info.tier));
    out.push_str(&format!("  \"tier_label\": \"{}\",\n", escape_json(&report.tier_info.tier_label)));
    out.push_str(&format!("  \"blast_score\": {},\n", report.blast_score));
    out.push_str(&format!("  \"severity\": \"{}\",\n", escape_json(&report.severity)));
    
    // Tier details
    out.push_str("  \"tier_details\": {\n");
    out.push_str(&format!("    \"tier\": {},\n", report.tier_info.tier));
    out.push_str(&format!("    \"tier_label\": \"{}\",\n", escape_json(&report.tier_info.tier_label)));
    out.push_str(&format!("    \"severity\": \"{}\",\n", escape_json(&report.tier_info.severity)));
    out.push_str(&format!("    \"base_score\": {},\n", report.tier_info.base_score));
    out.push_str(&format!("    \"is_critical\": {},\n", report.tier_info.is_critical));
    out.push_str("    \"matched_rules\": [\n");
    for (idx, r) in report.tier_info.matched_rules.iter().enumerate() {
        let comma = if idx + 1 < report.tier_info.matched_rules.len() { "," } else { "" };
        out.push_str(&format!("      \"{}\"{}\n", escape_json(r), comma));
    }
    out.push_str("    ]\n");
    out.push_str("  },\n");

    // Accessible SPNs
    out.push_str("  \"accessible_spns\": [\n");
    for (idx, s) in report.accessible_spns.iter().enumerate() {
        let comma = if idx + 1 < report.accessible_spns.len() { "," } else { "" };
        out.push_str(&format!("    \"{}\"{}\n", escape_json(s), comma));
    }
    out.push_str("  ],\n");

    // Lateral paths
    out.push_str("  \"lateral_paths\": [\n");
    for (idx, p) in report.lateral_paths.iter().enumerate() {
        let comma = if idx + 1 < report.lateral_paths.len() { "," } else { "" };
        out.push_str("    {\n");
        out.push_str(&format!("      \"vector\": \"{}\",\n", escape_json(&p.vector)));
        out.push_str(&format!("      \"risk\": \"{}\",\n", escape_json(&p.risk)));
        out.push_str(&format!("      \"impact\": \"{}\"\n", escape_json(&p.impact)));
        out.push_str(&format!("    }}{}\n", comma));
    }
    out.push_str("  ],\n");

    // Remediation recipes
    out.push_str("  \"remediation_recipes\": [\n");
    for (idx, r) in report.remediation_recipes.iter().enumerate() {
        let comma = if idx + 1 < report.remediation_recipes.len() { "," } else { "" };
        out.push_str("    {\n");
        out.push_str(&format!("      \"category\": \"{}\",\n", escape_json(&r.category)));
        out.push_str(&format!("      \"title\": \"{}\",\n", escape_json(&r.title)));
        out.push_str(&format!("      \"description\": \"{}\",\n", escape_json(&r.description)));
        out.push_str(&format!("      \"powershell\": \"{}\"\n", escape_json(&r.powershell)));
        out.push_str(&format!("    }}{}\n", comma));
    }
    out.push_str("  ],\n");

    // Telemetry block
    let spn_first = report.accessible_spns.first().map(|s| s.as_str()).unwrap_or("HTTP/tanuki-app.lab.local");
    out.push_str("  \"telemetry\": {\n");
    out.push_str("    \"event_id\": 4769,\n");
    out.push_str("    \"event_name\": \"Kerberos Service Ticket Request\",\n");
    out.push_str("    \"fields\": {\n");
    out.push_str(&format!("      \"ServiceName\": \"{}\",\n", escape_json(spn_first)));
    out.push_str(&format!("      \"TargetUserName\": \"{}\",\n", escape_json(&report.principal)));
    out.push_str("      \"TicketOptions\": \"0x40810000\",\n");
    out.push_str("      \"TicketEncryptionType\": \"0x12 (AES-256-CTS-HMAC-SHA1-96)\",\n");
    out.push_str("      \"Status\": \"0x0 (Success)\"\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("}\n");

    out
}
