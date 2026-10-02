use crate::util::escape_json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResolution {
    pub code: &'static str,
    pub event_id: Option<u32>,
    pub root_cause: &'static str,
    pub resolution: &'static str,
}

impl ErrorResolution {
    pub fn to_json(&self) -> String {
        let event_json = match self.event_id {
            Some(id) => id.to_string(),
            None => "null".to_string(),
        };

        format!(
            "  {{\n    \"code\": \"{}\",\n    \"event_id\": {},\n    \"root_cause\": \"{}\",\n    \"resolution\": \"{}\"\n  }}",
            escape_json(self.code),
            event_json,
            escape_json(self.root_cause),
            escape_json(self.resolution)
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
    },
    ErrorResolution {
        code: "KDC_ERR_ETYPE_NOSUPP",
        event_id: Some(14),
        root_cause: "Requested encryption type (usually RC4-HMAC) is not supported or explicitly disabled on the KDC.",
        resolution: "Enforce AES encryption in request or /etc/krb5.conf:\ndefault_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
    },
    ErrorResolution {
        code: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        event_id: Some(6),
        root_cause: "Client principal does not exist in KDC database or realm name is mismatched.",
        resolution: "Verify realm capitalization in /etc/krb5.conf (realms must be uppercase):\n$ klist -k -t /etc/krb5.keytab to confirm exact principal name.",
    },
    ErrorResolution {
        code: "KDC_ERR_PREAUTH_FAILED",
        event_id: Some(24),
        root_cause: "Incorrect key, outdated Key Version Number (KVNO), or invalid password.",
        resolution: "Check KVNO on keytab vs KDC:\n$ kvno <principal> vs klist -k -t /etc/krb5.keytab. Re-sync keytab if KVNO is desynchronized.",
    },
    ErrorResolution {
        code: "STATUS_MORE_PROCESSING_REQUIRED",
        event_id: None,
        root_cause: "GSSAPI authentication step requires SPNEGO token exchange continuation.",
        resolution: "Ensure tool has -k -no-pass flags enabled and KRB5CCNAME points to a valid ccache.",
    },
    ErrorResolution {
        code: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        event_id: Some(7),
        root_cause: "Target Service Principal Name (SPN) does not exist in Active Directory.",
        resolution: "Inspect target SPN syntax and verify service registration via LDAP: ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(servicePrincipalName=...)'",
    },
    ErrorResolution {
        code: "KDC_ERR_CLIENT_REVOKED",
        event_id: Some(18),
        root_cause: "Client account has been locked out, disabled, or expired in Active Directory.",
        resolution: "Query userAccountControl flag on the account object to verify account status and lockout state.",
    },
    ErrorResolution {
        code: "KDC_ERR_KEY_EXPIRED",
        event_id: Some(23),
        root_cause: "Client account password or key has expired on the Domain Controller.",
        resolution: "Rotate computer account password or re-join realm using adcli / realm to generate a fresh keytab.",
    },
    ErrorResolution {
        code: "KDC_ERR_NAME_EXP",
        event_id: Some(12),
        root_cause: "Client account has expired in Active Directory.",
        resolution: "Verify accountExpires attribute on client object in Active Directory.",
    },
    ErrorResolution {
        code: "KDC_ERR_PADATA_TYPE_NOSUPP",
        event_id: Some(16),
        root_cause: "KDC does not support requested pre-authentication type (e.g. PKINIT or PA-ENC-TIMESTAMP).",
        resolution: "Verify whether Domain Controller has Smart Card / Domain Controller certificates enrolled for PKINIT support.",
    },
];

pub fn find_error_resolution(query: &str) -> Option<&'static ErrorResolution> {
    let clean = query.trim().to_uppercase();
    if clean.is_empty() {
        return None;
    }
    ERROR_DICTIONARY.iter().find(|item| {
        item.code == clean
            || item
                .event_id
                .map(|id| id.to_string() == clean)
                .unwrap_or(false)
            || item.code.contains(&clean)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderRung {
    pub rung: usize,
    pub title: &'static str,
    pub description: &'static str,
}

pub const DECISION_LADDER: &[LadderRung] = &[
    LadderRung {
        rung: 1,
        title: "RUNG 1: LOCAL PASSIVE TRIAGE",
        description: "Inspect local system files: /etc/krb5.conf, /var/lib/sss/secrets/, /etc/krb5.keytab before sending packets over the network.",
    },
    LadderRung {
        rung: 2,
        title: "RUNG 2: ZERO-NOISE OPSEC FILTER",
        description: "Strictly ban RC4-HMAC, broad password sprays, and noisy network scans. Enforce Kerberos AES-256 or PKINIT.",
    },
    LadderRung {
        rung: 3,
        title: "RUNG 3: MACHINE IDENTITY REUSE (LOTD)",
        description: "Reuse existing machine tickets (HOST$ / MACHINE$) from /etc/krb5.keytab before searching for human credentials.",
    },
    LadderRung {
        rung: 4,
        title: "RUNG 4: SURGICAL PATHFINDING",
        description: "Prioritize minimal-hop directory vectors: Shadow Credentials (msDS-KeyCredentialLink), AD CS Templates (ESC1/ESC8), and RBCD.",
    },
    LadderRung {
        rung: 5,
        title: "RUNG 5: DETERMINISTIC ONE-LINER",
        description: "Provide direct, concise outputs formatted strictly as: [TARGET] -> [PREREQUISITE] -> [TACTICAL COMMAND] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]",
    },
];

pub fn ladder_to_json() -> String {
    let body = DECISION_LADDER
        .iter()
        .map(|r| {
            format!(
                "  {{\n    \"rung\": {},\n    \"title\": \"{}\",\n    \"description\": \"{}\"\n  }}",
                r.rung,
                escape_json(r.title),
                escape_json(r.description)
            )
        })
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
    }

    #[test]
    fn test_json_serialization() {
        let res = &ERROR_DICTIONARY[0];
        let json = res.to_json();
        assert!(json.contains("\"code\": \"KRB_AP_ERR_SKEW\""));
        assert!(json.contains("\"event_id\": 37"));

        let ladder_json = ladder_to_json();
        assert!(ladder_json.contains("\"rung\": 1"));
        assert!(ladder_json.contains("LOCAL PASSIVE TRIAGE"));
    }
}
