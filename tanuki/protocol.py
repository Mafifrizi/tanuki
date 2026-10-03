"""Kerberos/SSSD Error Resolution Dictionary and 5-Rung Tactical Decision Ladder."""

from typing import Any, Dict, List, Optional
from .telemetry import ERROR_TELEMETRY, LADDER_TELEMETRY

ERROR_DICTIONARY: List[Dict[str, Any]] = [
    {
        "code": "KRB_AP_ERR_SKEW",
        "event_id": 37,
        "root_cause": "Clock skew between Linux host and KDC exceeds threshold (default 300s).",
        "resolution": "Synchronize clock against Domain Controller:\n$ ntpdate <DC_IP> or $ chronyc -q 'server <DC_IP> iburst'",
        "tactical_cmd": ERROR_TELEMETRY["KRB_AP_ERR_SKEW"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KRB_AP_ERR_SKEW"]["telemetry"],
    },
    {
        "code": "KDC_ERR_ETYPE_NOSUPP",
        "event_id": 14,
        "root_cause": "Requested encryption type (usually RC4-HMAC) is not supported or explicitly disabled on the KDC.",
        "resolution": "Enforce AES encryption in request or /etc/krb5.conf:\ndefault_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_ETYPE_NOSUPP"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_ETYPE_NOSUPP"]["telemetry"],
    },
    {
        "code": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        "event_id": 6,
        "root_cause": "Client principal does not exist in KDC database or realm name is mismatched.",
        "resolution": "Verify realm capitalization in /etc/krb5.conf (realms must be uppercase):\n$ klist -k -t /etc/krb5.keytab to confirm exact principal name.",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_C_PRINCIPAL_UNKNOWN"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_C_PRINCIPAL_UNKNOWN"]["telemetry"],
    },
    {
        "code": "KDC_ERR_PREAUTH_FAILED",
        "event_id": 24,
        "root_cause": "Incorrect key, outdated Key Version Number (KVNO), or invalid password.",
        "resolution": "Check KVNO on keytab vs KDC:\n$ kvno <principal> vs klist -k -t /etc/krb5.keytab. Re-sync keytab if KVNO is desynchronized.",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_PREAUTH_FAILED"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_PREAUTH_FAILED"]["telemetry"],
    },
    {
        "code": "STATUS_MORE_PROCESSING_REQUIRED",
        "event_id": None,
        "root_cause": "GSSAPI authentication step requires SPNEGO token exchange continuation.",
        "resolution": "Ensure tool has -k -no-pass flags enabled and KRB5CCNAME points to a valid ccache.",
        "tactical_cmd": ERROR_TELEMETRY["STATUS_MORE_PROCESSING_REQUIRED"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["STATUS_MORE_PROCESSING_REQUIRED"]["telemetry"],
    },
    {
        "code": "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        "event_id": 7,
        "root_cause": "Target Service Principal Name (SPN) does not exist in Active Directory.",
        "resolution": "Inspect target SPN syntax and verify service registration via LDAP: ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(servicePrincipalName=...)'",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_S_PRINCIPAL_UNKNOWN"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_S_PRINCIPAL_UNKNOWN"]["telemetry"],
    },
    {
        "code": "KDC_ERR_CLIENT_REVOKED",
        "event_id": 18,
        "root_cause": "Client account has been locked out, disabled, or expired in Active Directory.",
        "resolution": "Query userAccountControl flag on the account object to verify account status and lockout state.",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_CLIENT_REVOKED"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_CLIENT_REVOKED"]["telemetry"],
    },
    {
        "code": "KDC_ERR_KEY_EXPIRED",
        "event_id": 23,
        "root_cause": "Client account password or key has expired on the Domain Controller.",
        "resolution": "Rotate computer account password or re-join realm using adcli / realm to generate a fresh keytab.",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_KEY_EXPIRED"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_KEY_EXPIRED"]["telemetry"],
    },
    {
        "code": "KDC_ERR_NAME_EXP",
        "event_id": 12,
        "root_cause": "Client account has expired in Active Directory.",
        "resolution": "Verify accountExpires attribute on client object in Active Directory.",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_NAME_EXP"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_NAME_EXP"]["telemetry"],
    },
    {
        "code": "KDC_ERR_PADATA_TYPE_NOSUPP",
        "event_id": 16,
        "root_cause": "KDC does not support requested pre-authentication type (e.g. PKINIT or PA-ENC-TIMESTAMP).",
        "resolution": "Verify whether Domain Controller has Smart Card / Domain Controller certificates enrolled for PKINIT support.",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_PADATA_TYPE_NOSUPP"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_PADATA_TYPE_NOSUPP"]["telemetry"],
    },
]

DECISION_LADDER: List[Dict[str, Any]] = [
    {
        "rung": 1,
        "title": "RUNG 1: LOCAL PASSIVE TRIAGE",
        "description": "Inspect local system files: /etc/krb5.conf, /var/lib/sss/secrets/, /etc/krb5.keytab before sending packets over the network.",
        "telemetry": LADDER_TELEMETRY[1],
    },
    {
        "rung": 2,
        "title": "RUNG 2: ZERO-NOISE OPSEC FILTER",
        "description": "Strictly ban RC4-HMAC, broad password sprays, and noisy network scans. Enforce Kerberos AES-256 or PKINIT.",
        "telemetry": LADDER_TELEMETRY[2],
    },
    {
        "rung": 3,
        "title": "RUNG 3: MACHINE IDENTITY REUSE (LOTD)",
        "description": "Reuse existing machine tickets (HOST$ / MACHINE$) from /etc/krb5.keytab before searching for human credentials.",
        "telemetry": LADDER_TELEMETRY[3],
    },
    {
        "rung": 4,
        "title": "RUNG 4: SURGICAL PATHFINDING",
        "description": "Prioritize minimal-hop directory vectors: Shadow Credentials (msDS-KeyCredentialLink), AD CS Templates (ESC1/ESC8), and RBCD.",
        "telemetry": LADDER_TELEMETRY[4],
    },
    {
        "rung": 5,
        "title": "RUNG 5: DETERMINISTIC ONE-LINER",
        "description": "Provide direct, concise outputs formatted strictly as: [TARGET] -> [PREREQUISITE] -> [TACTICAL COMMAND] ([TACTICAL CMD]) -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]",
        "telemetry": LADDER_TELEMETRY[5],
    },
]


def find_error_resolution(query: str) -> Optional[Dict[str, Any]]:
    """Lookup error resolution by Kerberos error name or Windows Security Event ID."""
    clean = query.strip().upper()
    if not clean:
        return None

    for item in ERROR_DICTIONARY:
        if (
            item["code"] == clean
            or (item["event_id"] is not None and str(item["event_id"]) == clean)
            or clean in item["code"]
        ):
            return item
    return None
