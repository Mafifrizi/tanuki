"""Dual-use detection telemetry database and formatters for Linux Active Directory operations."""

from typing import Any, Dict, List, Optional


EVENT_DESCRIPTIONS: Dict[int, str] = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4662: "Operation Performed on Object",
    4672: "Special Privileges Assigned",
    4738: "User Account Modified",
    4740: "User Account Locked Out",
    4768: "Kerberos TGT Request",
    4769: "Kerberos Service Ticket Request",
    4771: "Kerberos Pre-authentication Failed",
    4886: "Certificate Request Received",
    4887: "Certificate Issued",
    5136: "Directory Service Object Modified",
}

ERROR_TELEMETRY: Dict[str, Dict[str, Any]] = {
    "KRB_AP_ERR_SKEW": {
        "tactical_cmd": "chronyc -q 'server <DC_IP> iburst' || ntpdate <DC_IP>",
        "telemetry": {
            "auditd": [
                "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k system_time_change",
                "-w /etc/chrony.conf -p wa -k time_config_modify",
                "-w /etc/ntp.conf -p wa -k time_config_modify",
            ],
            "event_ids": [4768, 4771],
            "sigma": [
                {
                    "title": "System Time Modification Detected",
                    "status": "stable",
                    "logsource": "linux:auditd",
                    "tags": ["attack.defense_evasion", "attack.t1070.006"],
                }
            ],
            "falco": [
                {
                    "rule": "System Time Modification",
                    "priority": "WARNING",
                    "condition": "evt.type in (clock_settime, settimeofday, adjtimex) and not proc.name in (chronyd, ntpd, systemd-timesyncd)",
                    "output": "System time adjusted by unauthorized process (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "KDC_ERR_ETYPE_NOSUPP": {
        "tactical_cmd": "sed -i '/\\[libdefaults\\]/a \\    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96' /etc/krb5.conf",
        "telemetry": {
            "auditd": [
                "-w /etc/krb5.conf -p wa -k krb5_conf_modify",
                "-w /etc/krb5.conf.d/ -p wa -k krb5_conf_modify",
            ],
            "event_ids": [4768, 4769],
            "sigma": [
                {
                    "title": "Kerberos TGT Request With Weak RC4 Encryption",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.credential_access", "attack.t1558.003"],
                }
            ],
            "falco": [
                {
                    "rule": "Modify Kerberos Configuration",
                    "priority": "WARNING",
                    "condition": "open_write and fd.name in (/etc/krb5.conf, /etc/krb5.conf.d) and not proc.name in (dpkg, rpm, yum, apt, puppet, ansible)",
                    "output": "Kerberos configuration modified (user=%user.name file=%fd.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "KDC_ERR_C_PRINCIPAL_UNKNOWN": {
        "tactical_cmd": "klist -k -t /etc/krb5.keytab && realm list",
        "telemetry": {
            "auditd": [
                "-w /etc/krb5.keytab -p r -k keytab_read",
                "-w /etc/krb5.conf -p r -k krb5_conf_read",
            ],
            "event_ids": [4768, 4771, 4625],
            "sigma": [
                {
                    "title": "Kerberos TGT Request For Unknown Principal",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.reconnaissance", "attack.t1087.002"],
                }
            ],
            "falco": [
                {
                    "rule": "Read Kerberos Keytab File",
                    "priority": "NOTICE",
                    "condition": "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, kinit, adcli, realm, gssd)",
                    "output": "Kerberos keytab accessed by non-standard process (user=%user.name command=%proc.cmdline file=%fd.name)",
                }
            ],
        },
    },
    "KDC_ERR_PREAUTH_FAILED": {
        "tactical_cmd": "kvno -k /etc/krb5.keytab <principal> || adcli testjoin",
        "telemetry": {
            "auditd": [
                "-w /etc/krb5.keytab -p r -k keytab_read",
                "-w /etc/krb5.keytab -p wa -k keytab_modify",
            ],
            "event_ids": [4771, 4768, 4625],
            "sigma": [
                {
                    "title": "Potential Kerberos Password Spraying or Pre-Authentication Failure Spikes",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.credential_access", "attack.t1110.003"],
                }
            ],
            "falco": [
                {
                    "rule": "Repeated Keytab Read Untrusted Process",
                    "priority": "WARNING",
                    "condition": "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, kinit, adcli)",
                    "output": "Repeated keytab reads detected on host (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "STATUS_MORE_PROCESSING_REQUIRED": {
        "tactical_cmd": "export KRB5CCNAME=/tmp/krb5cc_$(id -u) && klist -s || kinit -k -t /etc/krb5.keytab",
        "telemetry": {
            "auditd": [
                "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access",
                "-w /var/lib/sss/pipes/kcm -p rw -k sssd_kcm_pipe_access",
            ],
            "event_ids": [4624, 4625],
            "sigma": [
                {
                    "title": "Anomalous Kerberos SPNEGO Token Negotiation Failure",
                    "status": "experimental",
                    "logsource": "windows:security",
                    "tags": ["attack.defense_evasion", "attack.t1550.002"],
                }
            ],
            "falco": [
                {
                    "rule": "Read Kerberos Credential Cache",
                    "priority": "WARNING",
                    "condition": "(evt.type in (open, openat) and fd.name glob \"/tmp/krb5cc_*\" and not proc.name in (sssd, sshd, systemd, login, su, sudo, kinit))",
                    "output": "Kerberos credential cache accessed by untrusted process (user=%user.name proc=%proc.cmdline ccache=%fd.name)",
                }
            ],
        },
    },
    "KDC_ERR_S_PRINCIPAL_UNKNOWN": {
        "tactical_cmd": "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName",
        "telemetry": {
            "auditd": [
                "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
                "-w /etc/resolv.conf -p r -k dns_resolution_read",
            ],
            "event_ids": [4769, 4768],
            "sigma": [
                {
                    "title": "Kerberos Service Ticket Request For Unknown SPN",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.discovery", "attack.t1069.002", "attack.credential_access", "attack.t1558"],
                }
            ],
            "falco": [
                {
                    "rule": "Outbound LDAP Probe Detected",
                    "priority": "NOTICE",
                    "condition": "(evt.type in (connect, sendto) and fd.rip != \"127.0.0.1\" and fd.rport in (389, 636, 3268, 3269) and proc.name in (ldapsearch, impacket, netexec))",
                    "output": "Outbound LDAP directory probe detected (user=%user.name proc=%proc.cmdline dest=%fd.rip:%fd.rport)",
                }
            ],
        },
    },
    "KDC_ERR_CLIENT_REVOKED": {
        "tactical_cmd": "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(sAMAccountName=<USER>)' userAccountControl lockoutTime badPwdCount",
        "telemetry": {
            "auditd": [
                "-w /var/log/secure -p r -k auth_log_read",
                "-w /var/log/audit/audit.log -p r -k audit_log_read",
            ],
            "event_ids": [4771, 4740, 4625],
            "sigma": [
                {
                    "title": "Authentication Attempt With Revoked Or Disabled Account",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.initial_access", "attack.t1078"],
                }
            ],
            "falco": [
                {
                    "rule": "Security Audit Log Inspection",
                    "priority": "WARNING",
                    "condition": "open_read and fd.name in (/var/log/secure, /var/log/auth.log, /var/log/audit/audit.log) and not proc.name in (auditd, rsyslogd, journald, logrotate)",
                    "output": "Security audit logs inspected by non-logging process (user=%user.name proc=%proc.cmdline file=%fd.name)",
                }
            ],
        },
    },
    "KDC_ERR_KEY_EXPIRED": {
        "tactical_cmd": "adcli update --domain=<DOMAIN> --computer-password-lifetime=30 || net ads changetrustpw",
        "telemetry": {
            "auditd": [
                "-w /etc/krb5.keytab -p wa -k keytab_modify",
                "-w /etc/security/pam_env.conf -p r -k pam_env_read",
            ],
            "event_ids": [4771, 4768, 4625, 4738],
            "sigma": [
                {
                    "title": "Kerberos Pre-Authentication Failure - Expired Key/Password",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.persistence", "attack.t1078"],
                }
            ],
            "falco": [
                {
                    "rule": "Keytab Password Rotation Execution",
                    "priority": "NOTICE",
                    "condition": "open_write and fd.name = \"/etc/krb5.keytab\" and proc.name in (adcli, net, realm)",
                    "output": "Keytab rotation performed on host (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "KDC_ERR_NAME_EXP": {
        "tactical_cmd": "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(sAMAccountName=<USER>)' accountExpires",
        "telemetry": {
            "auditd": [
                "-w /var/lib/sss/db/cache_default.ldb -p r -k sssd_cache_read",
                "-w /etc/sssd/sssd.conf -p r -k sssd_conf_read",
            ],
            "event_ids": [4768, 4771, 4625],
            "sigma": [
                {
                    "title": "Logon Attempt By Expired Active Directory Account",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.initial_access", "attack.t1078"],
                }
            ],
            "falco": [
                {
                    "rule": "SSSD Cache Database Read",
                    "priority": "WARNING",
                    "condition": "open_read and fd.name startswith \"/var/lib/sss/db/\" and not proc.name in (sssd, sssd_be, sssd_nss, sssd_pam)",
                    "output": "SSSD local database directly read by user space process (user=%user.name command=%proc.cmdline file=%fd.name)",
                }
            ],
        },
    },
    "KDC_ERR_PADATA_TYPE_NOSUPP": {
        "tactical_cmd": "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable",
        "telemetry": {
            "auditd": [
                "-w /etc/pki/tls/certs/ -p r -k pki_certs_read",
                "-w /etc/ssl/certs/ -p r -k ssl_certs_read",
            ],
            "event_ids": [4768, 4886, 4887],
            "sigma": [
                {
                    "title": "Kerberos PKINIT Pre-Authentication Type Unsupported or Probed",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.credential_access", "attack.t1558.004"],
                }
            ],
            "falco": [
                {
                    "rule": "Read PKI Store by Untrusted Process",
                    "priority": "NOTICE",
                    "condition": "open_read and fd.name startswith \"/etc/pki/\" and not proc.name in (sssd, certmonger, openssl, curl, ca-certificates)",
                    "output": "System PKI trust store read by external process (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "KRB_AP_ERR_BADKEYVER": {
        "tactical_cmd": "kvno <SPN> && klist -k -t /etc/krb5.keytab || Set-ADUser -Identity <SVC_ACCOUNT> -KerberosEncryptionType AES128,AES256",
        "telemetry": {
            "auditd": [
                "-w /etc/krb5.keytab -p r -k keytab_read",
                "-w /etc/krb5.conf -p r -k krb5_conf_read",
            ],
            "event_ids": [4769],
            "sigma": [
                {
                    "title": "Kerberos Service Ticket Request With Key Version Mismatch (0x1f)",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.credential_access", "attack.t1558.003"],
                }
            ],
            "falco": [
                {
                    "rule": "Kerberos Keytab Desynchronization Detected",
                    "priority": "WARNING",
                    "condition": "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, kinit, adcli, realm, gssd)",
                    "output": "Kerberos keytab accessed during service ticket key version mismatch (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
}

LADDER_TELEMETRY: Dict[int, Dict[str, Any]] = {
    1: {
        "auditd": [
            "-w /etc/krb5.keytab -p r -k keytab_read",
            "-w /etc/krb5.conf -p r -k krb5_conf_read",
            "-w /var/lib/sss/secrets/secrets.ldb -p r -k sssd_secrets_read",
            "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
        ],
        "event_ids": [4624, 4672],
        "sigma": [
            {
                "title": "Local Kerberos Configuration and Keytab Read",
                "status": "stable",
                "logsource": "linux:auditd",
                "tags": ["attack.discovery", "attack.t1083", "attack.t1552.004"],
            }
        ],
        "falco": [
            {
                "rule": "Read Kerberos Sensitive Files",
                "priority": "NOTICE",
                "condition": "open_read and fd.name in (/etc/krb5.keytab, /var/lib/sss/secrets/secrets.ldb) and not proc.name in (sssd, kinit, adcli)",
                "output": "Local Kerberos credential store inspected (user=%user.name file=%fd.name command=%proc.cmdline)",
            }
        ],
    },
    2: {
        "auditd": [
            "-w /etc/krb5.conf -p wa -k krb5_conf_modify",
        ],
        "event_ids": [4768, 4771, 4625],
        "sigma": [
            {
                "title": "Kerberos TGT Request With Weak RC4 Encryption",
                "status": "stable",
                "logsource": "windows:security",
                "tags": ["attack.credential_access", "attack.t1558.003"],
            },
            {
                "title": "Kerberos Password Spraying Detection",
                "status": "stable",
                "logsource": "windows:security",
                "tags": ["attack.credential_access", "attack.t1110.003"],
            },
        ],
        "falco": [
            {
                "rule": "Network Port Scan Detected",
                "priority": "WARNING",
                "condition": "inbound and evt.type = connect and count() > 50",
                "output": "High frequency outbound network scan detected (proc=%proc.cmdline)",
            }
        ],
    },
    3: {
        "auditd": [
            "-w /etc/krb5.keytab -p r -k keytab_read",
        ],
        "event_ids": [4768, 4624],
        "sigma": [
            {
                "title": "Machine Account TGT Request From Linux Host",
                "status": "stable",
                "logsource": "windows:security",
                "tags": ["attack.initial_access", "attack.t1078"],
            }
        ],
        "falco": [
            {
                "rule": "Keytab Machine Identity Ingestion",
                "priority": "NOTICE",
                "condition": "open_read and fd.name = \"/etc/krb5.keytab\" and proc.name = \"kinit\"",
                "output": "Machine account TGT requested using host keytab (user=%user.name command=%proc.cmdline)",
            }
        ],
    },
    4: {
        "auditd": [
            "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access",
            "-w /etc/pki/ -p r -k pki_access",
        ],
        "event_ids": [5136, 4662, 4886, 4887, 4769],
        "sigma": [
            {
                "title": "Directory Service Object Modified - Shadow Credentials",
                "status": "stable",
                "logsource": "windows:security",
                "tags": ["attack.persistence", "attack.t1556"],
            },
            {
                "title": "Certificate Services Certificate Request and Issuance",
                "status": "stable",
                "logsource": "windows:security",
                "tags": ["attack.credential_access", "attack.t1558.004"],
            },
        ],
        "falco": [
            {
                "rule": "Outbound Active Directory Traversal",
                "priority": "NOTICE",
                "condition": "evt.type in (connect, sendto) and fd.rport in (389, 636, 88)",
                "output": "Surgical directory traversal query initiated (dest=%fd.rip:%fd.rport command=%proc.cmdline)",
            }
        ],
    },
    5: {
        "auditd": [
            "-a always,exit -F arch=b64 -S openat,open -k krb5_access",
        ],
        "event_ids": [4768, 4769],
        "sigma": [
            {
                "title": "Coupled Remediation and Telemetry Output Validation",
                "status": "stable",
                "logsource": "linux:auditd",
                "tags": ["attack.defense_evasion", "attack.t1562"],
            }
        ],
        "falco": [
            {
                "rule": "Remediation Command Executed",
                "priority": "INFO",
                "condition": "evt.type = execve and proc.name in (chronyc, ntpdate, kinit, adcli)",
                "output": "Remediation command triggered on host (user=%user.name command=%proc.cmdline)",
            }
        ],
    },
}

OPERATIONAL_REMEDIATIONS: Dict[str, Dict[str, Any]] = {
    "keytab_machine_extraction": {
        "title": "Keytab Machine Account Extraction (LotD)",
        "tactical_cmd": "kinit -k -t /etc/krb5.keytab $(klist -k /etc/krb5.keytab | awk 'NR==4 {print $2}')",
        "telemetry": {
            "auditd": [
                "-w /etc/krb5.keytab -p r -k keytab_read",
                "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access",
            ],
            "event_ids": [4768, 4624, 4672],
            "sigma": [
                {
                    "title": "Suspicious Machine Account TGT Request From Linux Host",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.initial_access", "attack.t1078", "attack.t1558"],
                }
            ],
            "falco": [
                {
                    "rule": "Keytab Read by Non-Service Process",
                    "priority": "NOTICE",
                    "condition": "open_read and fd.name = \"/etc/krb5.keytab\" and not proc.name in (sssd, adcli)",
                    "output": "Keytab read by non-service process (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "sssd_kcm_stream_access": {
        "title": "SSSD KCM Credential Cache Stream Access",
        "tactical_cmd": "tanuki kcm -o ./extracted_ccache && export KRB5CCNAME=./extracted_ccache/ticket_1.ccache",
        "telemetry": {
            "auditd": [
                "-w /var/lib/sss/secrets/secrets.ldb -p rwa -k sssd_secrets_access",
                "-w /var/lib/sss/pipes/kcm -p rw -k sssd_kcm_pipe_access",
            ],
            "event_ids": [4769, 4624],
            "sigma": [
                {
                    "title": "Direct Access to SSSD KCM Secrets Database",
                    "status": "stable",
                    "logsource": "linux:auditd",
                    "tags": ["attack.credential_access", "attack.t1555"],
                }
            ],
            "falco": [
                {
                    "rule": "SSSD Secrets Database Direct Access",
                    "priority": "WARNING",
                    "condition": "open_read and fd.name = \"/var/lib/sss/secrets/secrets.ldb\" and proc.name != \"sssd\"",
                    "output": "SSSD secrets database accessed directly (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "pass_the_ticket": {
        "title": "Pass-The-Ticket / Credential Cache Injection",
        "tactical_cmd": "export KRB5CCNAME=/tmp/krb5cc_$(id -u) && klist",
        "telemetry": {
            "auditd": [
                "-w /tmp/krb5cc_* -p rwa -k krb5_ccache_access",
            ],
            "event_ids": [4769, 4624],
            "sigma": [
                {
                    "title": "Anomalous Kerberos Ticket Injection",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.lateral_movement", "attack.t1550.002"],
                }
            ],
            "falco": [
                {
                    "rule": "Unauthorized Credential Cache Read",
                    "priority": "WARNING",
                    "condition": "open_read and fd.name glob \"/tmp/krb5cc_*\" and not proc.name in (sssd, sshd, systemd)",
                    "output": "Unauthorized process read credential cache (user=%user.name command=%proc.cmdline)",
                }
            ],
        },
    },
    "delegation_triage": {
        "title": "Unconstrained / Constrained Delegation Triage",
        "tactical_cmd": "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' sAMAccountName",
        "telemetry": {
            "auditd": [
                "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
            ],
            "event_ids": [4769, 4738],
            "sigma": [
                {
                    "title": "Kerberos Ticket Request with Delegation Option",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.privilege_escalation", "attack.t1558"],
                }
            ],
            "falco": [
                {
                    "rule": "LDAP Query for Unconstrained Delegation",
                    "priority": "NOTICE",
                    "condition": "connect to port 389/636 and send query for userAccountControl:524288",
                    "output": "LDAP query scanning unconstrained delegation objects (user=%user.name proc=%proc.cmdline)",
                }
            ],
        },
    },
    "shadow_credentials": {
        "title": "Shadow Credentials (msDS-KeyCredentialLink)",
        "tactical_cmd": "certipy shadow auto -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -account '<TARGET>'",
        "telemetry": {
            "auditd": [
                "-w /etc/pki/ -p r -k pki_access",
            ],
            "event_ids": [5136, 4662, 4768],
            "sigma": [
                {
                    "title": "Shadow Credentials Attribute Modification",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.persistence", "attack.t1556"],
                }
            ],
            "falco": [
                {
                    "rule": "Outbound LDAP Shadow Credential Modification",
                    "priority": "WARNING",
                    "condition": "sendto on LDAP port with msDS-KeyCredentialLink write",
                    "output": "Directory object msDS-KeyCredentialLink written (user=%user.name proc=%proc.cmdline)",
                }
            ],
        },
    },
    "rbcd": {
        "title": "Resource-Based Constrained Delegation (RBCD)",
        "tactical_cmd": "impacket-rbcd -action write -delegatee '<MACHINE>$' -target '<TARGET>$' '<DOMAIN>/<USER>:<PASS>'",
        "telemetry": {
            "auditd": [
                "-w /tmp/krb5cc_* -p r -k krb5_ccache_read",
            ],
            "event_ids": [5136, 4769],
            "sigma": [
                {
                    "title": "RBCD msDS-AllowedToActOnBehalfOfOtherIdentity Modification",
                    "status": "stable",
                    "logsource": "windows:security",
                    "tags": ["attack.persistence", "attack.t1558"],
                }
            ],
            "falco": [
                {
                    "rule": "LDAP RBCD Attribute Modification",
                    "priority": "WARNING",
                    "condition": "sendto on LDAP port with msDS-AllowedToAct write",
                    "output": "Directory object msDS-AllowedToActOnBehalfOfOtherIdentity written (user=%user.name proc=%proc.cmdline)",
                }
            ],
        },
    },
}


def format_telemetry_terminal(telemetry: Dict[str, Any]) -> str:
    lines = ["[BLUE TELEMETRY]"]

    audit_rules = telemetry.get("auditd", [])
    if audit_rules:
        lines.append("    Auditd Rules:")
        for rule in audit_rules:
            lines.append(f"      {rule}")

    event_ids = telemetry.get("event_ids", [])
    if event_ids:
        lines.append("    Windows Event IDs:")
        for eid in event_ids:
            desc = EVENT_DESCRIPTIONS.get(eid, "Security Audit Event")
            lines.append(f"      - {eid} ({desc})")

    sigma_rules = telemetry.get("sigma", [])
    if sigma_rules:
        lines.append("    Sigma Rules:")
        for sig in sigma_rules:
            tags = ", ".join(sig.get("tags", []))
            tag_str = f" ({tags})" if tags else ""
            lines.append(f"      - {sig['title']} [{sig['logsource']}]{tag_str}")

    falco_rules = telemetry.get("falco", [])
    if falco_rules:
        lines.append("    Falco Signatures:")
        for fal in falco_rules:
            lines.append(f"      - {fal['rule']} [{fal['priority']}]: {fal['condition']}")

    return "\n".join(lines)


def format_telemetry_inline(telemetry: Dict[str, Any]) -> str:
    parts = []
    audit_rules = telemetry.get("auditd", [])
    if audit_rules:
        parts.append(f"Auditd: {audit_rules[0]}")

    event_ids = telemetry.get("event_ids", [])
    if event_ids:
        parts.append(f"Event IDs: {', '.join(str(e) for e in event_ids)}")

    sigma_rules = telemetry.get("sigma", [])
    if sigma_rules:
        parts.append(f"Sigma: {sigma_rules[0]['title']}")

    falco_rules = telemetry.get("falco", [])
    if falco_rules:
        parts.append(f"Falco: {falco_rules[0]['rule']}")

    return " | ".join(parts)
