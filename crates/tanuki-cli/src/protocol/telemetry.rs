use crate::util::escape_json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigmaRuleRef {
    pub title: &'static str,
    pub status: &'static str,
    pub logsource: &'static str,
    pub tags: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalcoRuleRef {
    pub rule: &'static str,
    pub priority: &'static str,
    pub condition: &'static str,
    pub output: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryData {
    pub auditd: &'static [&'static str],
    pub event_ids: &'static [u32],
    pub sigma: &'static [SigmaRuleRef],
    pub falco: &'static [FalcoRuleRef],
}

impl TelemetryData {
    pub fn to_json(&self) -> String {
        let auditd_items: Vec<String> = self
            .auditd
            .iter()
            .map(|s| format!("\"{}\"", escape_json(s)))
            .collect();
        let auditd_json = format!("[{}]", auditd_items.join(", "));

        let event_id_items: Vec<String> = self
            .event_ids
            .iter()
            .map(|id| id.to_string())
            .collect();
        let event_ids_json = format!("[{}]", event_id_items.join(", "));

        let sigma_items: Vec<String> = self
            .sigma
            .iter()
            .map(|s| {
                let tags: Vec<String> = s
                    .tags
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json(t)))
                    .collect();
                format!(
                    "        {{\n          \"title\": \"{}\",\n          \"status\": \"{}\",\n          \"logsource\": \"{}\",\n          \"tags\": [{}]\n        }}",
                    escape_json(s.title),
                    escape_json(s.status),
                    escape_json(s.logsource),
                    tags.join(", ")
                )
            })
            .collect();
        let sigma_json = if sigma_items.is_empty() {
            "[]".to_string()
        } else {
            format!("[\n{}\n      ]", sigma_items.join(",\n"))
        };

        let falco_items: Vec<String> = self
            .falco
            .iter()
            .map(|f| {
                format!(
                    "        {{\n          \"rule\": \"{}\",\n          \"priority\": \"{}\",\n          \"condition\": \"{}\",\n          \"output\": \"{}\"\n        }}",
                    escape_json(f.rule),
                    escape_json(f.priority),
                    escape_json(f.condition),
                    escape_json(f.output)
                )
            })
            .collect();
        let falco_json = if falco_items.is_empty() {
            "[]".to_string()
        } else {
            format!("[\n{}\n      ]", falco_items.join(",\n"))
        };

        format!(
            "{{\n      \"auditd\": {},\n      \"event_ids\": {},\n      \"sigma\": {},\n      \"falco\": {}\n    }}",
            auditd_json, event_ids_json, sigma_json, falco_json
        )
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::from("[BLUE TELEMETRY]\n");
        if !self.auditd.is_empty() {
            out.push_str("    Auditd Rules:\n");
            for r in self.auditd {
                out.push_str(&format!("      {}\n", r));
            }
        }
        if !self.event_ids.is_empty() {
            out.push_str("    Windows Event IDs:\n");
            for id in self.event_ids {
                let desc = get_event_description(*id);
                out.push_str(&format!("      - {} ({})\n", id, desc));
            }
        }
        if !self.sigma.is_empty() {
            out.push_str("    Sigma Rules:\n");
            for s in self.sigma {
                let tag_str = if s.tags.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", s.tags.join(", "))
                };
                out.push_str(&format!("      - {} [{}]{}\n", s.title, s.logsource, tag_str));
            }
        }
        if !self.falco.is_empty() {
            out.push_str("    Falco Signatures:\n");
            for f in self.falco {
                out.push_str(&format!("      - {} [{}]: {}\n", f.rule, f.priority, f.condition));
            }
        }
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }

    pub fn format_inline(&self) -> String {
        let mut parts = Vec::new();
        if let Some(first_audit) = self.auditd.first() {
            parts.push(format!("Auditd: {}", first_audit));
        }
        if !self.event_ids.is_empty() {
            let ids_str: Vec<String> = self.event_ids.iter().map(|id| id.to_string()).collect();
            parts.push(format!("Event IDs: {}", ids_str.join(", ")));
        }
        if let Some(first_sig) = self.sigma.first() {
            parts.push(format!("Sigma: {}", first_sig.title));
        }
        if let Some(first_fal) = self.falco.first() {
            parts.push(format!("Falco: {}", first_fal.rule));
        }
        parts.join(" | ")
    }
}

pub fn get_event_description(event_id: u32) -> &'static str {
    match event_id {
        4624 => "Successful Logon",
        4625 => "Failed Logon",
        4662 => "Operation Performed on Object",
        4672 => "Special Privileges Assigned",
        4738 => "User Account Modified",
        4740 => "User Account Locked Out",
        4768 => "Kerberos TGT Request",
        4769 => "Kerberos Service Ticket Request",
        4771 => "Kerberos Pre-authentication Failed",
        4886 => "Certificate Request Received",
        4887 => "Certificate Issued",
        5136 => "Directory Service Object Modified",
        _ => "Security Audit Event",
    }
}

pub const TELEMETRY_KRB_AP_ERR_SKEW: TelemetryData = TelemetryData {
    auditd: &[
        "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k system_time_change",
        "-w /etc/chrony.conf -p wa -k time_config_modify",
        "-w /etc/ntp.conf -p wa -k time_config_modify",
    ],
    event_ids: &[4768, 4771],
    sigma: &[SigmaRuleRef {
        title: "System Time Modification Detected",
        status: "stable",
        logsource: "linux:auditd",
        tags: &["attack.defense_evasion", "attack.t1070.006"],
    }],
    falco: &[FalcoRuleRef {
        rule: "System Time Modification",
        priority: "WARNING",
        condition: "evt.type in (clock_settime, settimeofday, adjtimex) and not proc.name in (chronyd, ntpd, systemd-timesyncd)",
        output: "System time adjusted by unauthorized process (user=%user.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_KDC_ERR_ETYPE_NOSUPP: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.conf -p wa -k krb5_conf_modify",
        "-w /etc/krb5.conf.d/ -p wa -k krb5_conf_modify",
    ],
    event_ids: &[4768, 4769],
    sigma: &[SigmaRuleRef {
        title: "Kerberos TGT Request With Weak RC4 Encryption",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1558.003"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Modify Kerberos Configuration",
        priority: "WARNING",
        condition: "open_write and fd.name in (/etc/krb5.conf, /etc/krb5.conf.d) and not proc.name in (dpkg, rpm, yum, apt, puppet, ansible)",
        output: "Kerberos configuration modified (user=%user.name file=%fd.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_KDC_ERR_C_PRINCIPAL_UNKNOWN: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.keytab -p r -k keytab_read",
        "-w /etc/krb5.conf -p r -k krb5_conf_read",
    ],
    event_ids: &[4768, 4771, 4625],
    sigma: &[SigmaRuleRef {
        title: "Kerberos TGT Request For Unknown Principal",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.reconnaissance", "attack.t1087.002"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Read Kerberos Keytab File",
        priority: "NOTICE",
        condition: "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, kinit, adcli, realm, gssd)",
        output: "Kerberos keytab accessed by non-standard process (user=%user.name command=%proc.cmdline file=%fd.name)",
    }],
};

pub const TELEMETRY_KDC_ERR_PREAUTH_FAILED: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.keytab -p r -k keytab_read",
        "-w /etc/krb5.keytab -p wa -k keytab_modify",
    ],
    event_ids: &[4771, 4768, 4625],
    sigma: &[SigmaRuleRef {
        title: "Potential Kerberos Password Spraying or Pre-Authentication Failure Spikes",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1110.003"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Repeated Keytab Read Untrusted Process",
        priority: "WARNING",
        condition: "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, kinit, adcli)",
        output: "Repeated keytab reads detected on host (user=%user.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_STATUS_MORE_PROCESSING_REQUIRED: TelemetryData = TelemetryData {
    auditd: &[
        "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access",
        "-w /var/lib/sss/pipes/kcm -p rw -k sssd_kcm_pipe_access",
    ],
    event_ids: &[4624, 4625],
    sigma: &[SigmaRuleRef {
        title: "Anomalous Kerberos SPNEGO Token Negotiation Failure",
        status: "experimental",
        logsource: "windows:security",
        tags: &["attack.defense_evasion", "attack.t1550.002"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Read Kerberos Credential Cache",
        priority: "WARNING",
        condition: "(evt.type in (open, openat) and fd.name glob \"/tmp/krb5cc_*\" and not proc.name in (sssd, sshd, systemd, login, su, sudo, kinit))",
        output: "Kerberos credential cache accessed by untrusted process (user=%user.name proc=%proc.cmdline ccache=%fd.name)",
    }],
};

pub const TELEMETRY_KDC_ERR_S_PRINCIPAL_UNKNOWN: TelemetryData = TelemetryData {
    auditd: &[
        "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
        "-w /etc/resolv.conf -p r -k dns_resolution_read",
    ],
    event_ids: &[4769, 4768],
    sigma: &[SigmaRuleRef {
        title: "Kerberos Service Ticket Request For Unknown SPN",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.discovery", "attack.t1069.002", "attack.credential_access", "attack.t1558"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Outbound LDAP Probe Detected",
        priority: "NOTICE",
        condition: "(evt.type in (connect, sendto) and fd.rip != \"127.0.0.1\" and fd.rport in (389, 636, 3268, 3269) and proc.name in (ldapsearch, impacket, netexec))",
        output: "Outbound LDAP directory probe detected (user=%user.name proc=%proc.cmdline dest=%fd.rip:%fd.rport)",
    }],
};

pub const TELEMETRY_KDC_ERR_CLIENT_REVOKED: TelemetryData = TelemetryData {
    auditd: &[
        "-w /var/log/secure -p r -k auth_log_read",
        "-w /var/log/audit/audit.log -p r -k audit_log_read",
    ],
    event_ids: &[4771, 4740, 4625],
    sigma: &[SigmaRuleRef {
        title: "Authentication Attempt With Revoked Or Disabled Account",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.initial_access", "attack.t1078"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Security Audit Log Inspection",
        priority: "WARNING",
        condition: "open_read and fd.name in (/var/log/secure, /var/log/auth.log, /var/log/audit/audit.log) and not proc.name in (auditd, rsyslogd, journald, logrotate)",
        output: "Security audit logs inspected by non-logging process (user=%user.name proc=%proc.cmdline file=%fd.name)",
    }],
};

pub const TELEMETRY_KDC_ERR_KEY_EXPIRED: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.keytab -p wa -k keytab_modify",
        "-w /etc/security/pam_env.conf -p r -k pam_env_read",
    ],
    event_ids: &[4771, 4768, 4625, 4738],
    sigma: &[SigmaRuleRef {
        title: "Kerberos Pre-Authentication Failure - Expired Key/Password",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.persistence", "attack.t1078"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Keytab Password Rotation Execution",
        priority: "NOTICE",
        condition: "open_write and fd.name = \"/etc/krb5.keytab\" and proc.name in (adcli, net, realm)",
        output: "Keytab rotation performed on host (user=%user.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_KDC_ERR_NAME_EXP: TelemetryData = TelemetryData {
    auditd: &[
        "-w /var/lib/sss/db/cache_default.ldb -p r -k sssd_cache_read",
        "-w /etc/sssd/sssd.conf -p r -k sssd_conf_read",
    ],
    event_ids: &[4768, 4771, 4625],
    sigma: &[SigmaRuleRef {
        title: "Logon Attempt By Expired Active Directory Account",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.initial_access", "attack.t1078"],
    }],
    falco: &[FalcoRuleRef {
        rule: "SSSD Cache Database Read",
        priority: "WARNING",
        condition: "open_read and fd.name startswith \"/var/lib/sss/db/\" and not proc.name in (sssd, sssd_be, sssd_nss, sssd_pam)",
        output: "SSSD local database directly read by user space process (user=%user.name command=%proc.cmdline file=%fd.name)",
    }],
};

pub const TELEMETRY_KDC_ERR_PADATA_TYPE_NOSUPP: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/pki/tls/certs/ -p r -k pki_certs_read",
        "-w /etc/ssl/certs/ -p r -k ssl_certs_read",
    ],
    event_ids: &[4768, 4886, 4887],
    sigma: &[SigmaRuleRef {
        title: "Kerberos PKINIT Pre-Authentication Type Unsupported or Probed",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1558.004"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Read PKI Store by Untrusted Process",
        priority: "NOTICE",
        condition: "open_read and fd.name startswith \"/etc/pki/\" and not proc.name in (sssd, certmonger, openssl, curl, ca-certificates)",
        output: "System PKI trust store read by external process (user=%user.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_KRB_AP_ERR_BADKEYVER: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.keytab -p r -k keytab_read",
        "-w /etc/krb5.conf -p r -k krb5_conf_read",
    ],
    event_ids: &[4769],
    sigma: &[SigmaRuleRef {
        title: "Kerberos Service Ticket Request With Key Version Mismatch (0x1f)",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1558.003"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Kerberos Keytab Desynchronization Detected",
        priority: "WARNING",
        condition: "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, kinit, adcli, realm, gssd)",
        output: "Kerberos keytab accessed during service ticket key version mismatch (user=%user.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_KDC_ERR_PREAUTH_REQUIRED_FOR_FAST: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.conf -p wa -k krb5_fast_modify",
        "-w /etc/krb5.conf.d/ -p wa -k krb5_fast_modify",
    ],
    event_ids: &[4771, 4768],
    sigma: &[SigmaRuleRef {
        title: "Kerberos FAST Armoring Required Failure",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1558"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Kerberos FAST Armoring Configuration Update",
        priority: "NOTICE",
        condition: "open_write and fd.name in (/etc/krb5.conf, /etc/krb5.conf.d) and not proc.name in (dpkg, rpm, yum, apt, puppet, ansible)",
        output: "Kerberos configuration updated for FAST armoring (user=%user.name file=%fd.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_EVENT_4768: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.keytab -p r -k keytab_read",
        "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
    ],
    event_ids: &[4768],
    sigma: &[SigmaRuleRef {
        title: "Kerberos TGT Request (Event 4768)",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1558"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Kerberos TGT Request Observed",
        priority: "NOTICE",
        condition: "open_read and fd.name startswith \"/tmp/krb5cc_\" and not proc.name in (sssd, sshd, systemd)",
        output: "Kerberos ticket requested or accessed (user=%user.name ccache=%fd.name)",
    }],
};

pub const TELEMETRY_EVENT_4769: TelemetryData = TelemetryData {
    auditd: &[
        "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
    ],
    event_ids: &[4769],
    sigma: &[SigmaRuleRef {
        title: "Kerberos Service Ticket Request (Event 4769)",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1558.003"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Kerberos Service Ticket Accessed",
        priority: "NOTICE",
        condition: "open_read and fd.name startswith \"/tmp/krb5cc_\"",
        output: "Kerberos TGS accessed (user=%user.name ccache=%fd.name)",
    }],
};

pub const TELEMETRY_EVENT_4771: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.keytab -p r -k keytab_read",
    ],
    event_ids: &[4771],
    sigma: &[SigmaRuleRef {
        title: "Kerberos Pre-Authentication Failure (Event 4771)",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.credential_access", "attack.t1110"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Kerberos Pre-Authentication Failure Observed",
        priority: "WARNING",
        condition: "open_read and fd.name = \"/etc/krb5.keytab\"",
        output: "Kerberos preauth failed keytab inspected (user=%user.name file=%fd.name)",
    }],
};

pub const TELEMETRY_LADDER_RUNG_1: TelemetryData = TelemetryData {
    auditd: &[
        "-w /etc/krb5.keytab -p r -k keytab_read",
        "-w /etc/krb5.conf -p r -k krb5_conf_read",
        "-w /var/lib/sss/secrets/secrets.ldb -p r -k sssd_secrets_read",
        "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
    ],
    event_ids: &[4624, 4672],
    sigma: &[SigmaRuleRef {
        title: "Local Kerberos Configuration and Keytab Read",
        status: "stable",
        logsource: "linux:auditd",
        tags: &["attack.discovery", "attack.t1083", "attack.t1552.004"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Read Kerberos Sensitive Files",
        priority: "NOTICE",
        condition: "open_read and fd.name in (/etc/krb5.keytab, /var/lib/sss/secrets/secrets.ldb) and not proc.name in (sssd, kinit, adcli)",
        output: "Local Kerberos credential store inspected (user=%user.name file=%fd.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_LADDER_RUNG_2: TelemetryData = TelemetryData {
    auditd: &["-w /etc/krb5.conf -p wa -k krb5_conf_modify"],
    event_ids: &[4768, 4771, 4625],
    sigma: &[
        SigmaRuleRef {
            title: "Kerberos TGT Request With Weak RC4 Encryption",
            status: "stable",
            logsource: "windows:security",
            tags: &["attack.credential_access", "attack.t1558.003"],
        },
        SigmaRuleRef {
            title: "Kerberos Password Spraying Detection",
            status: "stable",
            logsource: "windows:security",
            tags: &["attack.credential_access", "attack.t1110.003"],
        },
    ],
    falco: &[FalcoRuleRef {
        rule: "Network Port Scan Detected",
        priority: "WARNING",
        condition: "inbound and evt.type = connect and count() > 50",
        output: "High frequency outbound network scan detected (proc=%proc.cmdline)",
    }],
};

pub const TELEMETRY_LADDER_RUNG_3: TelemetryData = TelemetryData {
    auditd: &["-w /etc/krb5.keytab -p r -k keytab_read"],
    event_ids: &[4768, 4624],
    sigma: &[SigmaRuleRef {
        title: "Machine Account TGT Request From Linux Host",
        status: "stable",
        logsource: "windows:security",
        tags: &["attack.initial_access", "attack.t1078"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Keytab Machine Identity Ingestion",
        priority: "NOTICE",
        condition: "open_read and fd.name = \"/etc/krb5.keytab\" and proc.name = \"kinit\"",
        output: "Machine account TGT requested using host keytab (user=%user.name command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_LADDER_RUNG_4: TelemetryData = TelemetryData {
    auditd: &[
        "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access",
        "-w /etc/pki/ -p r -k pki_access",
    ],
    event_ids: &[5136, 4662, 4886, 4887, 4769],
    sigma: &[
        SigmaRuleRef {
            title: "Directory Service Object Modified - Shadow Credentials",
            status: "stable",
            logsource: "windows:security",
            tags: &["attack.persistence", "attack.t1556"],
        },
        SigmaRuleRef {
            title: "Certificate Services Certificate Request and Issuance",
            status: "stable",
            logsource: "windows:security",
            tags: &["attack.credential_access", "attack.t1558.004"],
        },
    ],
    falco: &[FalcoRuleRef {
        rule: "Outbound Active Directory Traversal",
        priority: "NOTICE",
        condition: "evt.type in (connect, sendto) and fd.rport in (389, 636, 88)",
        output: "Surgical directory traversal query initiated (dest=%fd.rip:%fd.rport command=%proc.cmdline)",
    }],
};

pub const TELEMETRY_LADDER_RUNG_5: TelemetryData = TelemetryData {
    auditd: &["-a always,exit -F arch=b64 -S openat,open -k krb5_access"],
    event_ids: &[4768, 4769],
    sigma: &[SigmaRuleRef {
        title: "Coupled Remediation and Telemetry Output Validation",
        status: "stable",
        logsource: "linux:auditd",
        tags: &["attack.defense_evasion", "attack.t1562"],
    }],
    falco: &[FalcoRuleRef {
        rule: "Remediation Command Executed",
        priority: "INFO",
        condition: "evt.type = execve and proc.name in (chronyc, ntpdate, kinit, adcli)",
        output: "Remediation command triggered on host (user=%user.name command=%proc.cmdline)",
    }],
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalRemediationRef {
    pub key: &'static str,
    pub title: &'static str,
    pub tactical_cmd: &'static str,
    pub telemetry: TelemetryData,
}

pub const OPERATIONAL_REMEDIATIONS: &[OperationalRemediationRef] = &[
    OperationalRemediationRef {
        key: "keytab_machine_extraction",
        title: "Keytab Machine Account Extraction (LotD)",
        tactical_cmd: "kinit -k -t /etc/krb5.keytab $(klist -k /etc/krb5.keytab | awk 'NR==4 {print $2}')",
        telemetry: TelemetryData {
            auditd: &[
                "-w /etc/krb5.keytab -p r -k keytab_read",
                "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access",
            ],
            event_ids: &[4768, 4624, 4672],
            sigma: &[SigmaRuleRef {
                title: "Suspicious Machine Account TGT Request From Linux Host",
                status: "stable",
                logsource: "windows:security",
                tags: &["attack.initial_access", "attack.t1078", "attack.t1558"],
            }],
            falco: &[FalcoRuleRef {
                rule: "Keytab Read by Non-Service Process",
                priority: "NOTICE",
                condition: "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, adcli)",
                output: "Keytab read by non-service process (user=%user.name command=%proc.cmdline)",
            }],
        },
    },
    OperationalRemediationRef {
        key: "sssd_kcm_stream_access",
        title: "SSSD KCM Credential Cache Stream Access",
        tactical_cmd: "tanuki kcm -o ./extracted_ccache && export KRB5CCNAME=./extracted_ccache/ticket_1.ccache",
        telemetry: TelemetryData {
            auditd: &[
                "-w /var/lib/sss/secrets/secrets.ldb -p rwa -k sssd_secrets_access",
                "-w /var/lib/sss/pipes/kcm -p rw -k sssd_kcm_pipe_access",
            ],
            event_ids: &[4769, 4624],
            sigma: &[SigmaRuleRef {
                title: "Direct Access to SSSD KCM Secrets Database",
                status: "stable",
                logsource: "linux:auditd",
                tags: &["attack.credential_access", "attack.t1555"],
            }],
            falco: &[FalcoRuleRef {
                rule: "SSSD Secrets Database Direct Access",
                priority: "WARNING",
                condition: "open_read and fd.name = \"/var/lib/sss/secrets/secrets.ldb\" and proc.name != \"sssd\"",
                output: "SSSD secrets database accessed directly (user=%user.name command=%proc.cmdline)",
            }],
        },
    },
    OperationalRemediationRef {
        key: "pass_the_ticket",
        title: "Pass-The-Ticket / Credential Cache Injection",
        tactical_cmd: "export KRB5CCNAME=/tmp/krb5cc_$(id -u) && klist",
        telemetry: TelemetryData {
            auditd: &["-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access"],
            event_ids: &[4769, 4624],
            sigma: &[SigmaRuleRef {
                title: "Anomalous Kerberos Ticket Injection",
                status: "stable",
                logsource: "windows:security",
                tags: &["attack.lateral_movement", "attack.t1550.002"],
            }],
            falco: &[FalcoRuleRef {
                rule: "Unauthorized Credential Cache Read",
                priority: "WARNING",
                condition: "open_read and fd.name glob \"/tmp/krb5cc_*\" and not proc.name in (sssd, sshd, systemd)",
                output: "Unauthorized process read credential cache (user=%user.name command=%proc.cmdline)",
            }],
        },
    },
    OperationalRemediationRef {
        key: "delegation_triage",
        title: "Unconstrained / Constrained Delegation Triage",
        tactical_cmd: "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' sAMAccountName",
        telemetry: TelemetryData {
            auditd: &["-w /tmp/krb5cc_* -p r -k krb5_ccache_read"],
            event_ids: &[4769, 4738],
            sigma: &[SigmaRuleRef {
                title: "Kerberos Ticket Request with Delegation Option",
                status: "stable",
                logsource: "windows:security",
                tags: &["attack.privilege_escalation", "attack.t1558"],
            }],
            falco: &[FalcoRuleRef {
                rule: "LDAP Query for Unconstrained Delegation",
                priority: "NOTICE",
                condition: "connect to port 389/636 and send query for userAccountControl:524288",
                output: "LDAP query scanning unconstrained delegation objects (user=%user.name proc=%proc.cmdline)",
            }],
        },
    },
    OperationalRemediationRef {
        key: "shadow_credentials",
        title: "Shadow Credentials (msDS-KeyCredentialLink)",
        tactical_cmd: "certipy shadow auto -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -account '<TARGET>'",
        telemetry: TelemetryData {
            auditd: &["-w /etc/pki/ -p r -k pki_access"],
            event_ids: &[5136, 4662, 4768],
            sigma: &[SigmaRuleRef {
                title: "Shadow Credentials Attribute Modification",
                status: "stable",
                logsource: "windows:security",
                tags: &["attack.persistence", "attack.t1556"],
            }],
            falco: &[FalcoRuleRef {
                rule: "Outbound LDAP Shadow Credential Modification",
                priority: "WARNING",
                condition: "sendto on LDAP port with msDS-KeyCredentialLink write",
                output: "Directory object msDS-KeyCredentialLink written (user=%user.name proc=%proc.cmdline)",
            }],
        },
    },
    OperationalRemediationRef {
        key: "rbcd",
        title: "Resource-Based Constrained Delegation (RBCD)",
        tactical_cmd: "impacket-rbcd -action write -delegatee '<MACHINE>$' -target '<TARGET>$' '<DOMAIN>/<USER>:<PASS>'",
        telemetry: TelemetryData {
            auditd: &["-w /tmp/krb5cc_* -p r -k krb5_ccache_read"],
            event_ids: &[5136, 4769],
            sigma: &[SigmaRuleRef {
                title: "RBCD msDS-AllowedToActOnBehalfOfOtherIdentity Modification",
                status: "stable",
                logsource: "windows:security",
                tags: &["attack.persistence", "attack.t1558"],
            }],
            falco: &[FalcoRuleRef {
                rule: "LDAP RBCD Attribute Modification",
                priority: "WARNING",
                condition: "sendto on LDAP port with msDS-AllowedToAct write",
                output: "Directory object msDS-AllowedToActOnBehalfOfOtherIdentity written (user=%user.name proc=%proc.cmdline)",
            }],
        },
    },
];
