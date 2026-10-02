# Kerberos & SSSD Error Triage Dictionary

Quick-reference diagnostic table for resolving cryptic Kerberos, SSSD, and RPC authentication failures on Linux hosts.

## Common Kerberos Errors

| Error Code | Root Cause | Operator Resolution |
| :--- | :--- | :--- |
| `KRB_AP_ERR_SKEW` (Event 37) | Clock skew between Linux host and KDC exceeds threshold (default 300s). | Synchronize clock against Domain Controller:<br>`$ ntpdate <DC_IP>` or `$ chronyc -q 'server <DC_IP> iburst'` |
| `KDC_ERR_ETYPE_NOSUPP` (Event 14) | Requested encryption type (usually RC4-HMAC) is not supported or explicitly disabled on the KDC. | Enforce AES encryption in request or `/etc/krb5.conf`:<br>`default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96` |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` (Event 6) | Client principal does not exist in KDC database or realm name is mismatched. | Verify realm capitalization in `/etc/krb5.conf` (Realms MUST be uppercase):<br>`$ klist -k -t /etc/krb5.keytab` to confirm exact principal name. |
| `KDC_ERR_PREAUTH_FAILED` (Event 24) | Incorrect key, outdated Key Version Number (KVNO), or invalid password. | Check KVNO on keytab vs KDC:<br>`$ kvno <principal>` vs `klist -k -t /etc/krb5.keytab`. Re-sync keytab if KVNO is desynchronized. |
| `STATUS_MORE_PROCESSING_REQUIRED` | GSSAPI authentication step requires SPNEGO token exchange continuation. | Ensure tool has `-k -no-pass` flags enabled and `KRB5CCNAME` points to a valid ccache. |

## SSSD Diagnostic Checks

```bash
# Check current domain join status and realm
realm list

# Inspect active SSSD configuration and responder status
cat /etc/sssd/sssd.conf | grep -E "services|domains|default_ccache_name"

# Check active Kerberos credentials in environment
klist -c "$KRB5CCNAME"
```
