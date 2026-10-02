#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResolution {
    pub code: &'static str,
    pub event_id: Option<u32>,
    pub root_cause: &'static str,
    pub resolution: &'static str,
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
];

pub fn find_error_resolution(query: &str) -> Option<&'static ErrorResolution> {
    let clean = query.trim().to_uppercase();
    ERROR_DICTIONARY.iter().find(|item| {
        item.code == clean
            || item
                .event_id
                .map(|id| id.to_string() == clean)
                .unwrap_or(false)
            || item.code.contains(&clean)
    })
}

pub const DECISION_LADDER: &[(&str, &str)] = &[
    (
        "Level 1: Local Passive First",
        "Inspect local files (/etc/krb5.keytab, /etc/sssd/sssd.conf, KCM stores) before sending packets over the wire.",
    ),
    (
        "Level 2: OPSEC Guardrails",
        "Enforce AES-256 (aes256-cts-hmac-sha1-96). Strictly forbid RC4 downgrade attacks and account spraying.",
    ),
    (
        "Level 3: Machine Identity (LotD)",
        "Validate host keytabs and managed identities before requesting human user credentials.",
    ),
    (
        "Level 4: Targeted Vectors",
        "Focus triage on specific certificate templates (ADCS), resource-based delegation, and Kerberos error codes.",
    ),
    (
        "Level 5: Deterministic Output",
        "Return exact CLI invocations, target endpoints, and expected artifacts instead of general explanations.",
    ),
];

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
    fn test_ladder_levels_complete() {
        assert_eq!(DECISION_LADDER.len(), 5);
    }
}
