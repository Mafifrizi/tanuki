"""Kerberos/SSSD Error Resolution Dictionary and 5-Rung Tactical Decision Ladder."""

from typing import Any, Dict, List, Optional, Union
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
    {
        "code": "KRB_AP_ERR_BADKEYVER",
        "event_id": 44,
        "root_cause": "Key Version Number (KVNO) desynchronization between directory object (msDS-KeyVersionNumber) and service keytab. AS-REQ/TGS-REQ succeeds because ticket granting and service ticket issuance use the current KDC master key and user credentials, but AP-REQ to the target service fails during mutual authentication when the service decrypts the ticket using an outdated keytab KVNO.",
        "resolution": "Re-synchronize keytab KVNO with Active Directory or update service account key:\n$ kvno <SPN> vs klist -k -t /etc/krb5.keytab\nPowerShell: Set-ADUser -Identity <ACCOUNT> -KerberosEncryptionType AES128,AES256\nktpass -princ <SPN> -pass <PWD> -mapuser <ACCOUNT> -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -SetUPN NO -out <FILE>.keytab",
        "tactical_cmd": ERROR_TELEMETRY["KRB_AP_ERR_BADKEYVER"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KRB_AP_ERR_BADKEYVER"]["telemetry"],
    },
    {
        "code": "KDC_ERR_PREAUTH_REQUIRED_FOR_FAST",
        "event_id": 93,
        "failure_code": "0x18",
        "root_cause": "KDC policy enforces Kerberos FAST armoring (RFC 6113). Unarmored AS-REQ requests are rejected with failure code 0x18.",
        "resolution": "Enable Kerberos FAST armoring in request or /etc/krb5.conf:\n[libdefaults]\n    fast_req_armoring = true\nOr supply armor credentials cache: $ kinit -T <ARMOR_CCACHE> <USER>@<REALM>",
        "tactical_cmd": ERROR_TELEMETRY["KDC_ERR_PREAUTH_REQUIRED_FOR_FAST"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["KDC_ERR_PREAUTH_REQUIRED_FOR_FAST"]["telemetry"],
    },
    {
        "code": "EVENT_4768",
        "event_id": 4768,
        "failure_code": "0x0",
        "root_cause": "A Kerberos authentication ticket (TGT) was requested. Emitted by Active Directory Domain Controllers during AS-REQ evaluation.",
        "resolution": "Inspect Result Code in Windows Security Event Log: 0x0 (Success), 0x6 (Client principal unknown), 0x12 (Client revoked/disabled), 0x17 (User key expired), 0x18 (Pre-authentication failed / invalid password), 0x25 (Clock skew too great). Correlate client IP and requested encryption type (0x12 AES256, 0x17 RC4).",
        "tactical_cmd": ERROR_TELEMETRY["EVENT_4768"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["EVENT_4768"]["telemetry"],
    },
    {
        "code": "EVENT_4769",
        "event_id": 4769,
        "failure_code": "0x0",
        "root_cause": "A Kerberos service ticket (TGS) was requested. Emitted by Active Directory Domain Controllers during TGS-REQ evaluation.",
        "resolution": "Inspect Result Code in Windows Security Event Log: 0x0 (Success), 0x1b (Server principal not found in AD), 0x1f (Key version number KVNO desynchronization between keytab and AD), 0x20 (Target service ticket encryption type not supported).",
        "tactical_cmd": ERROR_TELEMETRY["EVENT_4769"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["EVENT_4769"]["telemetry"],
    },
    {
        "code": "EVENT_4771",
        "event_id": 4771,
        "failure_code": "0x18",
        "root_cause": "Kerberos pre-authentication failed. Emitted by Active Directory Domain Controllers when an account fails pre-authentication.",
        "resolution": "Inspect Failure Code: 0x18 (Wrong password or outdated keytab key), 0x17 (Password expired), 0x12 (Account locked or disabled), 0x25 (Clock skew between client and KDC > 300s). For FAST armoring policy, verify armor cache.",
        "tactical_cmd": ERROR_TELEMETRY["EVENT_4771"]["tactical_cmd"],
        "telemetry": ERROR_TELEMETRY["EVENT_4771"]["telemetry"],
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


def find_error_resolution(query: Union[str, int]) -> Optional[Dict[str, Any]]:
    """Lookup error resolution by Kerberos error name, failure code, or Windows Security Event ID."""
    if isinstance(query, int):
        clean = str(query)
        query_int: Optional[int] = query
    elif isinstance(query, str):
        clean = query.strip().upper()
        if not clean:
            return None
        query_int = None
        try:
            query_int = int(clean, 0)
        except ValueError:
            pass
    else:
        return None

    clean_lower = clean.lower()

    # Pass 1: Exact match on error code, failure code, or event_id equality
    for item in ERROR_DICTIONARY:
        if item["code"] == clean:
            return item
        if item.get("failure_code") and item["failure_code"].lower() == clean_lower:
            return item
        if item.get("event_id") is not None and (
            str(item["event_id"]) == clean or (isinstance(query, int) and item["event_id"] == query)
        ):
            return item

    # Pass 2: Substring match on error code
    for item in ERROR_DICTIONARY:
        if clean in item["code"]:
            return item

    # Pass 3: Fallback match on auxiliary telemetry event_ids
    if query_int is not None:
        for item in ERROR_DICTIONARY:
            event_ids = item.get("telemetry", {}).get("event_ids", [])
            if query_int in event_ids:
                return item

    return None

