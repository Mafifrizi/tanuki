use super::telemetry::*;
use crate::util::escape_json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResolution {
    pub code: &'static str,
    pub event_id: Option<u32>,
    pub root_cause: &'static str,
    pub resolution: &'static str,
    pub tactical_cmd: &'static str,
    pub telemetry: TelemetryData,
}

impl ErrorResolution {
    pub fn to_json(&self) -> String {
        let event_json = match self.event_id {
            Some(id) => id.to_string(),
            None => "null".to_string(),
        };

        format!(
            "  {{\n    \"code\": \"{}\",\n    \"event_id\": {},\n    \"root_cause\": \"{}\",\n    \"resolution\": \"{}\",\n    \"tactical_cmd\": \"{}\",\n    \"telemetry\": {}\n  }}",
            escape_json(self.code),
            event_json,
            escape_json(self.root_cause),
            escape_json(self.resolution),
            escape_json(self.tactical_cmd),
            self.telemetry.to_json()
        )
    }
}

pub fn errors_to_json(errors: &[ErrorResolution]) -> String {
    if errors.is_empty() {
        return "[]".to_string();
    }
    let body = errors
        .iter()
        .map(|e| e.to_json())
        .collect::<Vec<_>>()
        .join(",\n");
    format!("[\n{}\n]", body)
}

pub const ERROR_DICTIONARY: &[ErrorResolution] = &[
    ErrorResolution {
        code: "KRB_AP_ERR_SKEW",
        event_id: Some(37),
        root_cause: "Clock skew between Linux host and KDC exceeds threshold (default 300s).",
        resolution: "Synchronize clock against Domain Controller:\n$ ntpdate <DC_IP> or $ chronyc -q 'server <DC_IP> iburst'",
        tactical_cmd: "chronyc -q 'server <DC_IP> iburst' || ntpdate <DC_IP>",
        telemetry: TELEMETRY_KRB_AP_ERR_SKEW,
    },
    ErrorResolution {
        code: "KDC_ERR_ETYPE_NOSUPP",
        event_id: Some(14),
        root_cause: "Requested encryption type (usually RC4-HMAC) is not supported or explicitly disabled on the KDC.",
        resolution: "Enforce AES encryption in request or /etc/krb5.conf:\ndefault_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
        tactical_cmd: "sed -i '/\\[libdefaults\\]/a \\    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96' /etc/krb5.conf",
        telemetry: TELEMETRY_KDC_ERR_ETYPE_NOSUPP,
    },
    ErrorResolution {
        code: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        event_id: Some(6),
        root_cause: "Client principal does not exist in KDC database or realm name is mismatched.",
        resolution: "Verify realm capitalization in /etc/krb5.conf (realms must be uppercase):\n$ klist -k -t /etc/krb5.keytab to confirm exact principal name.",
        tactical_cmd: "klist -k -t /etc/krb5.keytab && realm list",
        telemetry: TELEMETRY_KDC_ERR_C_PRINCIPAL_UNKNOWN,
    },
    ErrorResolution {
        code: "KDC_ERR_PREAUTH_FAILED",
        event_id: Some(24),
        root_cause: "Incorrect key, outdated Key Version Number (KVNO), or invalid password.",
        resolution: "Check KVNO on keytab vs KDC:\n$ kvno <principal> vs klist -k -t /etc/krb5.keytab. Re-sync keytab if KVNO is desynchronized.",
        tactical_cmd: "kvno -k /etc/krb5.keytab <principal> || adcli testjoin",
        telemetry: TELEMETRY_KDC_ERR_PREAUTH_FAILED,
    },
    ErrorResolution {
        code: "STATUS_MORE_PROCESSING_REQUIRED",
        event_id: None,
        root_cause: "GSSAPI authentication step requires SPNEGO token exchange continuation.",
        resolution: "Ensure tool has -k -no-pass flags enabled and KRB5CCNAME points to a valid ccache.",
        tactical_cmd: "export KRB5CCNAME=/tmp/krb5cc_$(id -u) && klist -s || kinit -k -t /etc/krb5.keytab",
        telemetry: TELEMETRY_STATUS_MORE_PROCESSING_REQUIRED,
    },
    ErrorResolution {
        code: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        event_id: Some(7),
        root_cause: "Target Service Principal Name (SPN) does not exist in Active Directory.",
        resolution: "Inspect target SPN syntax and verify service registration via LDAP: ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(servicePrincipalName=...)'",
        tactical_cmd: "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName",
        telemetry: TELEMETRY_KDC_ERR_S_PRINCIPAL_UNKNOWN,
    },
    ErrorResolution {
        code: "KDC_ERR_CLIENT_REVOKED",
        event_id: Some(18),
        root_cause: "Client account has been locked out, disabled, or expired in Active Directory.",
        resolution: "Query userAccountControl flag on the account object to verify account status and lockout state.",
        tactical_cmd: "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(sAMAccountName=<USER>)' userAccountControl lockoutTime badPwdCount",
        telemetry: TELEMETRY_KDC_ERR_CLIENT_REVOKED,
    },
    ErrorResolution {
        code: "KDC_ERR_KEY_EXPIRED",
        event_id: Some(23),
        root_cause: "Client account password or key has expired on the Domain Controller.",
        resolution: "Rotate computer account password or re-join realm using adcli / realm to generate a fresh keytab.",
        tactical_cmd: "adcli update --domain=<DOMAIN> --computer-password-lifetime=30 || net ads changetrustpw",
        telemetry: TELEMETRY_KDC_ERR_KEY_EXPIRED,
    },
    ErrorResolution {
        code: "KDC_ERR_NAME_EXP",
        event_id: Some(12),
        root_cause: "Client account has expired in Active Directory.",
        resolution: "Verify accountExpires attribute on client object in Active Directory.",
        tactical_cmd: "ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(sAMAccountName=<USER>)' accountExpires",
        telemetry: TELEMETRY_KDC_ERR_NAME_EXP,
    },
    ErrorResolution {
        code: "KDC_ERR_PADATA_TYPE_NOSUPP",
        event_id: Some(16),
        root_cause: "KDC does not support requested pre-authentication type (e.g. PKINIT or PA-ENC-TIMESTAMP).",
        resolution: "Verify whether Domain Controller has Smart Card / Domain Controller certificates enrolled for PKINIT support.",
        tactical_cmd: "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable",
        telemetry: TELEMETRY_KDC_ERR_PADATA_TYPE_NOSUPP,
    },
    ErrorResolution {
        code: "KRB_AP_ERR_BADKEYVER",
        event_id: Some(44),
        root_cause: "Key Version Number (KVNO) desynchronization between directory object (msDS-KeyVersionNumber) and service keytab. AS-REQ/TGS-REQ succeeds because ticket granting and service ticket issuance use the current KDC master key and user credentials, but AP-REQ to the target service fails during mutual authentication when the service decrypts the ticket using an outdated keytab KVNO.",
        resolution: "Re-synchronize keytab KVNO with Active Directory or update service account key:\n$ kvno <SPN> vs klist -k -t /etc/krb5.keytab\nPowerShell: Set-ADUser -Identity <ACCOUNT> -KerberosEncryptionType AES128,AES256\nktpass -princ <SPN> -pass <PWD> -mapuser <ACCOUNT> -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -SetUPN NO -out <FILE>.keytab",
        tactical_cmd: "kvno <SPN> && klist -k -t /etc/krb5.keytab || Set-ADUser -Identity <ACCOUNT> -KerberosEncryptionType AES128,AES256",
        telemetry: TELEMETRY_KRB_AP_ERR_BADKEYVER,
    },
    ErrorResolution {
        code: "KDC_ERR_PREAUTH_REQUIRED_FOR_FAST",
        event_id: Some(93),
        root_cause: "KDC policy enforces Kerberos FAST armoring (RFC 6113). Unarmored AS-REQ requests are rejected with failure code 0x18.",
        resolution: "Enable Kerberos FAST armoring in request or /etc/krb5.conf:\n[libdefaults]\n    fast_req_armoring = true\nOr supply armor credentials cache: $ kinit -T <ARMOR_CCACHE> <USER>@<REALM>",
        tactical_cmd: "kinit -T <ARMOR_CCACHE> <USER>@<REALM> || sed -i '/\\[libdefaults\\]/a \\    fast_req_armoring = true' /etc/krb5.conf",
        telemetry: TELEMETRY_KDC_ERR_PREAUTH_REQUIRED_FOR_FAST,
    },
    ErrorResolution {
        code: "EVENT_4768",
        event_id: Some(4768),
        root_cause: "A Kerberos authentication ticket (TGT) was requested. Emitted by Active Directory Domain Controllers during AS-REQ evaluation.",
        resolution: "Inspect Result Code in Windows Security Event Log: 0x0 (Success), 0x6 (Client principal unknown), 0x12 (Client revoked/disabled), 0x17 (User key expired), 0x18 (Pre-authentication failed / invalid password), 0x25 (Clock skew too great). Correlate client IP and requested encryption type (0x12 AES256, 0x17 RC4).",
        tactical_cmd: "wevtutil qe Security \"/q:*[System[(EventID=4768)]]\" /f:text /c:5 /rd:true",
        telemetry: TELEMETRY_EVENT_4768,
    },
    ErrorResolution {
        code: "EVENT_4769",
        event_id: Some(4769),
        root_cause: "A Kerberos service ticket (TGS) was requested. Emitted by Active Directory Domain Controllers during TGS-REQ evaluation.",
        resolution: "Inspect Result Code in Windows Security Event Log: 0x0 (Success), 0x1b (Server principal not found in AD), 0x1f (Key version number KVNO desynchronization between keytab and AD), 0x20 (Target service ticket encryption type not supported).",
        tactical_cmd: "wevtutil qe Security \"/q:*[System[(EventID=4769)]]\" /f:text /c:5 /rd:true",
        telemetry: TELEMETRY_EVENT_4769,
    },
    ErrorResolution {
        code: "EVENT_4771",
        event_id: Some(4771),
        root_cause: "Kerberos pre-authentication failed. Emitted by Active Directory Domain Controllers when an account fails pre-authentication.",
        resolution: "Inspect Failure Code: 0x18 (Wrong password or outdated keytab key), 0x17 (Password expired), 0x12 (Account locked or disabled), 0x25 (Clock skew between client and KDC > 300s). For FAST armoring policy, verify armor cache.",
        tactical_cmd: "wevtutil qe Security \"/q:*[System[(EventID=4771)]]\" /f:text /c:5 /rd:true",
        telemetry: TELEMETRY_EVENT_4771,
    },
];

pub fn find_error_resolution(query: &str) -> Option<&'static ErrorResolution> {
    let clean = query.trim().to_uppercase();
    if clean.is_empty() {
        return None;
    }
    let query_int: Option<u32> = if clean.starts_with("0X") {
        u32::from_str_radix(&clean[2..], 16).ok()
    } else {
        clean.parse().ok()
    };

    if let Some(item) = ERROR_DICTIONARY.iter().find(|item| {
        item.code == clean
            || item.event_id.map(|id| id.to_string() == clean).unwrap_or(false)
            || (query_int.is_some() && item.event_id == query_int)
    }) {
        return Some(item);
    }

    if let Some(item) = ERROR_DICTIONARY.iter().find(|item| item.code.contains(&clean)) {
        return Some(item);
    }

    if let Some(qid) = query_int {
        if let Some(item) = ERROR_DICTIONARY.iter().find(|item| {
            item.telemetry.event_ids.contains(&qid)
        }) {
            return Some(item);
        }
    }

    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderRung {
    pub rung: usize,
    pub title: &'static str,
    pub description: &'static str,
    pub telemetry: TelemetryData,
}

impl LadderRung {
    pub fn to_json(&self) -> String {
        format!(
            "  {{\n    \"rung\": {},\n    \"title\": \"{}\",\n    \"description\": \"{}\",\n    \"telemetry\": {}\n  }}",
            self.rung,
            escape_json(self.title),
            escape_json(self.description),
            self.telemetry.to_json()
        )
    }
}

pub const DECISION_LADDER: &[LadderRung] = &[
    LadderRung {
        rung: 1,
        title: "RUNG 1: LOCAL PASSIVE TRIAGE",
        description: "Inspect local system files: /etc/krb5.conf, /var/lib/sss/secrets/, /etc/krb5.keytab before sending packets over the network.",
        telemetry: TELEMETRY_LADDER_RUNG_1,
    },
    LadderRung {
        rung: 2,
        title: "RUNG 2: ZERO-NOISE OPSEC FILTER",
        description: "Strictly ban RC4-HMAC, broad password sprays, and noisy network scans. Enforce Kerberos AES-256 or PKINIT.",
        telemetry: TELEMETRY_LADDER_RUNG_2,
    },
    LadderRung {
        rung: 3,
        title: "RUNG 3: MACHINE IDENTITY REUSE (LOTD)",
        description: "Reuse existing machine tickets (HOST$ / MACHINE$) from /etc/krb5.keytab before searching for human credentials.",
        telemetry: TELEMETRY_LADDER_RUNG_3,
    },
    LadderRung {
        rung: 4,
        title: "RUNG 4: SURGICAL PATHFINDING",
        description: "Prioritize minimal-hop directory vectors: Shadow Credentials (msDS-KeyCredentialLink), AD CS Templates (ESC1/ESC8), and RBCD.",
        telemetry: TELEMETRY_LADDER_RUNG_4,
    },
    LadderRung {
        rung: 5,
        title: "RUNG 5: DETERMINISTIC ONE-LINER",
        description: "Provide direct, concise outputs formatted strictly as: [TARGET] -> [PREREQUISITE] -> [TACTICAL COMMAND] ([TACTICAL CMD]) -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]",
        telemetry: TELEMETRY_LADDER_RUNG_5,
    },
];

pub fn ladder_to_json() -> String {
    let body = DECISION_LADDER
        .iter()
        .map(|r| r.to_json())
        .collect::<Vec<_>>()
        .join(",\n");
    format!("[\n{}\n]", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_by_code() {
        let res = find_error_resolution("KRB_AP_ERR_SKEW").expect("Should find error");
        assert_eq!(res.event_id, Some(37));
        assert_eq!(res.tactical_cmd, "chronyc -q 'server <DC_IP> iburst' || ntpdate <DC_IP>");
        assert_eq!(res.telemetry.event_ids, &[4768, 4771]);
    }

    #[test]
    fn test_lookup_by_event_id() {
        let res = find_error_resolution("14").expect("Should find error by event id");
        assert_eq!(res.code, "KDC_ERR_ETYPE_NOSUPP");
    }

    #[test]
    fn test_lookup_empty_query_returns_none() {
        assert_eq!(find_error_resolution(""), None);
        assert_eq!(find_error_resolution("   "), None);
    }

    #[test]
    fn test_ladder_levels_complete() {
        assert_eq!(DECISION_LADDER.len(), 5);
        assert_eq!(DECISION_LADDER[0].rung, 1);
        assert_eq!(DECISION_LADDER[4].rung, 5);
        assert!(DECISION_LADDER[4].description.contains("[BLUE TELEMETRY]"));
    }

    #[test]
    fn test_json_serialization() {
        let res = &ERROR_DICTIONARY[0];
        let json = res.to_json();
        assert!(json.contains("\"code\": \"KRB_AP_ERR_SKEW\""));
        assert!(json.contains("\"event_id\": 37"));
        assert!(json.contains("\"telemetry\":"));
        assert!(json.contains("\"auditd\":"));

        let ladder_json = ladder_to_json();
        assert!(ladder_json.contains("\"rung\": 1"));
        assert!(ladder_json.contains("LOCAL PASSIVE TRIAGE"));
        assert!(ladder_json.contains("\"telemetry\":"));
    }
}
