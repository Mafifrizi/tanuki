# Kerberos & SSSD Error Triage Dictionary

Comprehensive diagnostic table for resolving cryptic Kerberos, SSSD, and Active Directory authentication failures on Linux hosts, coupled with Blue Team detection telemetry.

---

## 1. Complete Kerberos Protocol Error Resolution Table

| Error Code | Event ID | Root Cause | Operator Tactical Resolution | Blue Telemetry Coupling |
| :--- | :---: | :--- | :--- | :--- |
| `KRB_AP_ERR_SKEW` | 37 | Clock skew between Linux host and KDC exceeds threshold (default 300s). | Synchronize clock against Domain Controller:<br>`$ ntpdate <DC_IP>` or `$ chronyc -q 'server <DC_IP> iburst'` | **Auditd**: `-w /etc/chrony.conf -p wa`<br>**DC Event**: 4768 / 4771<br>**Falco**: System Time Modification |
| `KDC_ERR_ETYPE_NOSUPP` | 14 | Requested encryption type (usually RC4-HMAC) is not supported or explicitly disabled on KDC. | Enforce AES encryption in request or `/etc/krb5.conf`:<br>`default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96` | **Auditd**: `-w /etc/krb5.conf -p wa`<br>**DC Event**: 4768 Failure 0x0e |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 6 | Client principal does not exist in KDC database or realm name is mismatched. | Verify realm capitalization in `/etc/krb5.conf` (Realms MUST be uppercase):<br>`$ klist -k -t /etc/krb5.keytab` to confirm exact principal name. | **Auditd**: `-w /etc/krb5.keytab -p r`<br>**DC Event**: 4768 Failure 0x06 |
| `KDC_ERR_PREAUTH_FAILED` | 24 | Incorrect key, outdated Key Version Number (KVNO), or invalid password. | Check KVNO on keytab vs KDC:<br>`$ kvno <principal>` vs `klist -k -t /etc/krb5.keytab`. Re-sync keytab if KVNO is desynchronized. | **Auditd**: `-w /etc/krb5.keytab -p r`<br>**DC Event**: 4771 Failure 0x18 |
| `KRB_AP_ERR_BADKEYVER` | 44 | KVNO desynchronization between directory object (`msDS-KeyVersionNumber`) and service keytab. AS-REQ/TGS-REQ succeeds but AP-REQ fails on target service. | Re-synchronize keytab KVNO with AD:<br>`Set-ADUser -Identity <ACC> -KerberosEncryptionType AES128,AES256`<br>`ktpass -princ <SPN> -mapuser <ACC> -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out <FILE>.keytab` | **Auditd**: `-w /etc/krb5.keytab -p r`<br>**DC Event**: 4769 Failure 0x1f |
| `KDC_ERR_PREAUTH_REQUIRED_FOR_FAST` | 93 | KDC policy enforces Kerberos FAST armoring (RFC 6113). Unarmored AS-REQ requests rejected with failure code 0x18. | Enable Kerberos FAST armoring in request or `/etc/krb5.conf`:<br>`fast_req_armoring = true`<br>Supply armor cache: `$ kinit -T <ARMOR_CCACHE> <USER>@<REALM>` | **Auditd**: `-w /etc/krb5.conf -p wa`<br>**DC Event**: 4771 Failure 0x18 |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | 7 | Target Service Principal Name (SPN) does not exist in Active Directory. | Inspect target SPN syntax and verify service registration via LDAP:<br>`$ ldapsearch -Y GSSAPI -b 'DC=domain,DC=local' '(servicePrincipalName=...)'` | **Auditd**: `-w /etc/krb5.conf -p r`<br>**DC Event**: 4769 Failure 0x07 |
| `KDC_ERR_CLIENT_REVOKED` | 18 | Client account has been locked out, disabled, or expired in Active Directory. | Query `userAccountControl` flag on the account object to verify account status and lockout state. | **Auditd**: `-w /var/log/secure -p r`<br>**DC Event**: 4768 Failure 0x12 |
| `KDC_ERR_KEY_EXPIRED` | 23 | Client account password or key has expired on the Domain Controller. | Rotate computer account password or re-join realm using `adcli` / `realm` to generate a fresh keytab. | **Auditd**: `-w /etc/krb5.keytab -p wa`<br>**DC Event**: 4768 Failure 0x17 |
| `KDC_ERR_NAME_EXP` | 12 | Client account has expired in Active Directory. | Verify `accountExpires` attribute on client object in Active Directory. | **Auditd**: `-w /var/log/audit/audit.log -p r`<br>**DC Event**: 4768 Failure 0x0c |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | 16 | KDC does not support requested pre-authentication type (e.g. PKINIT or PA-ENC-TIMESTAMP). | Verify whether Domain Controller has Smart Card / Domain Controller certificates enrolled for PKINIT support. | **Auditd**: `-w /etc/krb5.conf -p r`<br>**DC Event**: 4768 Failure 0x10 |
| `STATUS_MORE_PROCESSING_REQUIRED` | N/A | GSSAPI authentication step requires SPNEGO token exchange continuation. | Ensure tool has `-k -no-pass` flags enabled and `KRB5CCNAME` points to a valid ccache. | **Auditd**: `-w /tmp/krb5cc_* -p r`<br>**DC Event**: 4624 / 4625 |

---

## 2. SSSD & Credential Diagnostic Commands

```bash
# Check current domain join status and realm
realm list

# Inspect active SSSD configuration and responder status
cat /etc/sssd/sssd.conf | grep -E "services|domains|default_ccache_name"

# Check active Kerberos credentials in environment
klist -c "$KRB5CCNAME"

# Passive pre-flight health diagnostic (<1ms, 0 network packets)
tanuki doctor

# Fast protocol triage query via unified CLI
tanuki triage KRB_AP_ERR_BADKEYVER
tanuki triage 44 --json
```
