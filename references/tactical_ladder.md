# The Operator's Tactical Decision Ladder (Tanuki Standard)

The Tanuki Decision Ladder is a prioritized operational filter designed to prevent AI agents from hallucinating noisy commands, over-engineering attacks, or triggering security monitoring alerts during identity assessment workflows.

```text
================================================================================
                    THE OPERATOR'S TACTICAL DECISION LADDER
================================================================================

[ RUNG 1: LOCAL PASSIVE TRIAGE ]
  - Inspect local system files: /etc/krb5.conf, /var/lib/sss/secrets/, /etc/krb5.keytab.
  - Check whether ccache is FILE, KCM, or KEYRING.
  - RULE: Send 0 packets over the network before local host identity is fully triaged.

[ RUNG 2: ZERO-NOISE OPSEC FILTER ]
  - FORBIDDEN: RC4-HMAC encryption types, brute-force password spraying, broad NTLM relays.
  - REQUIRED: Kerberos AES-256/128, PKINIT, or direct LDAP LDAPS queries with legitimate machine principals.
  - RULE: "Never spray if you can steer."

[ RUNG 3: MACHINE IDENTITY REUSE (LOTD) ]
  - Use the machine account (HOST$ / MACHINE$) obtained from the local keytab.
  - Do not search for new human credentials if the machine account has sufficient rights to query LDAP, read AD CS templates, or perform RBCD.

[ RUNG 4: SURGICAL PATHFINDING ]
  - Evaluate paths with minimal hop count:
    1. Shadow Credentials (msDS-KeyCredentialLink via PKINIT)
    2. AD CS Misconfigured Templates (ESC1, ESC8)
    3. Resource-Based Constrained Delegation (RBCD)
  - Prioritize native directory object modification over dropping binaries onto disks.

[ RUNG 5: DETERMINISTIC ONE-LINER ]
  - Output format strictly follows military brevity:
    [TARGET] -> [PREREQUISITE] -> [TACTICAL COMMAND] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]
  - No conversational padding, no multi-page generic essays.
================================================================================
```
