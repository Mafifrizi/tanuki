# Tanuki Command Reference

Full usage for every Tanuki command. Both engines share the same command surface and flags, so these examples work with the Rust binary (tanuki) and the Python engine (python3 -m tanuki).

For a high-level overview, see the [README](../README.md). For the protocol decision model, see [references/tactical_ladder.md](../references/tactical_ladder.md).

## 1. Pre-flight health diagnostics (tanuki doctor)

Runs 10 diagnostic checks across domain configuration, credentials, network connectivity, and OPSEC telemetry (<5ms execution).

```bash
# Terminal checklist output
tanuki doctor

# Structured JSON export for orchestration pipelines
tanuki doctor --json

# Probe active OPSEC endpoint hooks, auditd rules, and eBPF monitors
tanuki doctor --opsec

# Pre-flight audit targeting specific keytab, config, or ccache files
tanuki doctor --keytab /path/to/identity.keytab --krb5-conf /path/to/krb5.conf --ccache /tmp/krb5cc_1000

# Pre-flight audit with Active Directory encryption type and KVNO comparison
tanuki doctor --keytab /path/to/identity.keytab --ad-enctypes 0x18 --ad-kvno 3

# Audit specific SSSD sockets, pid files, and secrets databases
tanuki doctor --sssd-pipe /var/lib/sss/pipes/kcm --sssd-pid /var/run/sssd.pid --secrets-path /var/lib/sss/secrets/secrets.ldb
```

## 2. Unprivileged userspace TGT authentication (tanuki auth)

Acquires a Kerberos Ticket Granting Ticket (TGT) using local keytab credentials, with automatic principal detection, in-memory clock skew healing, and Kerberos Flexible Authentication Secure Tunneling (FAST) armoring per [RFC 6113].

```bash
# Authenticate a machine principal with in-memory clock skew tolerance
tanuki auth --keytab /path/to/identity.keytab

# Explicitly specify principal and export to a custom credential cache
tanuki auth --keytab /path/to/identity.keytab --principal host/srv01.domain.local@DOMAIN.LOCAL --ccache /tmp/krb5cc_custom

# Enable RFC 6113 FAST armoring using an existing credential cache as the armor ticket
tanuki auth --keytab /path/to/identity.keytab --fast --armor-cache /tmp/krb5cc_armor

# Authenticate against a specific KDC override
tanuki auth --keytab /path/to/identity.keytab --kdc 192.168.56.106 --json
```

## 3. Kerberos service ticket acquisition (tanuki tgs)

Requests Kerberos Service Tickets (TGS-REQ) for target Service Principal Names using cached credentials or a direct keytab exchange.

```bash
# Acquire a service ticket using an existing cached TGT
tanuki tgs --spn HTTP/web-service.domain.local

# Combined TGT and TGS acquisition via keytab
tanuki tgs --spn HTTP/web-service.domain.local --keytab /path/to/identity.keytab

# Acquire service ticket and export to a custom ccache
tanuki tgs --spn MSSQLSvc/db01.domain.local:1433 --keytab /path/to/identity.keytab --ccache /tmp/krb5cc_sql
```

## 4. Quantitative blast radius engine (tanuki blast)

Evaluates machine identity blast radius, calculates the risk tier (Tier 0, Tier 1, Tier 2), and emits copy-paste PowerShell remediation recipes.

```bash
# Quantitative risk scoring and privilege tiering
tanuki blast --keytab /path/to/identity.keytab --spn HTTP/app.domain.local

# Identity evaluation from a Kerberos principal or PAC source
tanuki blast jdoe@CORP.LOCAL

# Enriched LDAP blast radius calculation
tanuki blast --keytab /path/to/identity.keytab --host dc01.domain.local --base-dn DC=corp,DC=local

# Structured JSON report with remediation recipes
tanuki blast --keytab /path/to/identity.keytab --spn HTTP/app.domain.local --json
```

## 5. Idempotent closed-loop remediation (tanuki fix)

Applies deterministic self-healing fixes to environment misconfigurations. Synthesized Kerberos clock skew is clamped to the standard 300 second maximum so a drift value can never widen the host replay window.

```bash
# Dry-run preview without modifying disk state
tanuki fix --dry-run

# Execute automated idempotent repair
tanuki fix

# Remediate with target keytab and synthesize isolated krb5.conf
tanuki fix --keytab /path/to/identity.keytab --realm CORP.LOCAL --kdc 192.168.56.106

# Preview fix for a specific Kerberos error code with custom clock skew tolerance
tanuki fix --krb-error KRB_AP_ERR_SKEW --clock-skew 180 --dry-run

# Remediate with target keytab, config, and ccache in dry-run simulation mode
tanuki fix --keytab /path/to/identity.keytab --krb5-conf ./krb5.conf --ccache /tmp/krb5cc_1000 --dry-run
```

## 6. NIST SP 800-88 cryptographic memory purge (tanuki purge)

Executes a multi-pass cryptographic overwrite and zeroization across credential caches and memory buffers in accordance with NIST SP 800-88 Rev. 1 guidelines.

```bash
# Purge all discovered ticket caches and temporary session files
tanuki purge --all

# Purge a specific credential cache file
tanuki purge --target /tmp/krb5cc_1000

# JSON output confirming zeroized files
tanuki purge --all --json
```

## 7. Passive AD CS certificate and template scanner (tanuki adcs)

Audits Active Directory Certificate Services (AD CS) certificate templates for ESC1 through ESC11 misconfigurations.

```bash
# Scan a certificate template definition
tanuki adcs --file /path/to/template.json

# Scan an exported X.509 certificate file
tanuki adcs --file /path/to/cert.pem

# Structured JSON export for vulnerability management
tanuki adcs --file /path/to/template.json --json
```

## 8. Unprivileged and authenticated Active Directory LDAP (tanuki ldap)

Reconnaissance across domain partitions for Kerberos SPNs, AS-REP roasting targets, RBCD delegation, shadow credentials (msDS-KeyCredentialLink per [MS-ADTS] 2.2.20), and unconstrained delegation. Query categories are selected with --query: spn, asreproast, rbcd, shadow, unconstrained, or all.

```bash
# Audit Kerberos Service Principal Names
tanuki ldap --host dc01.domain.local --realm CORP.LOCAL --query spn

# AS-REP roasting detection with cipher negotiation audit (RC4 vs AES-256)
tanuki ldap --host dc01.domain.local --realm CORP.LOCAL --query asreproast

# Resource-Based Constrained Delegation discovery with in-line DACL parsing
tanuki ldap --host dc01.domain.local --realm CORP.LOCAL --query rbcd

# Shadow Credentials discovery auditing msDS-KeyCredentialLink per [MS-ADTS] 2.2.20
tanuki ldap --host dc01.domain.local --realm CORP.LOCAL --query shadow

# Unconstrained delegation audit
tanuki ldap --host dc01.domain.local --realm CORP.LOCAL --query unconstrained

# Comprehensive audit across all categories in JSON
tanuki ldap --host dc01.domain.local --realm CORP.LOCAL --query all --json

# Query targeting specific port (default: 389)
tanuki ldap --host dc01.domain.local --port 389 --realm CORP.LOCAL --query spn
```

### Verified LDAPS (credentialed queries)

Plain LDAP on port 389 sends the simple-bind credentials in cleartext. When you pass a username and password, use a verified LDAPS channel. In the Python engine, --ssl verifies the Domain Controller certificate by default (or pins a CA bundle via --verify-ca), with --insecure available only as an explicit opt-out.

```bash
# Verify the DC certificate against the system trust store (-u/--username, -p/--password)
python3 -m tanuki ldap --host dc01.domain.local --ssl --secure \
  --username svc@DOMAIN.LOCAL --password '<password>' --query rbcd

# Pin a specific DC CA bundle
python3 -m tanuki ldap --host dc01.domain.local --ssl --verify-ca ./dc-ca.pem \
  -u svc@DOMAIN.LOCAL -p '<password>' --query rbcd

# Explicitly opt out of certificate verification on lab self-signed endpoints
python3 -m tanuki ldap --host dc01.domain.local --ssl --insecure \
  -u svc@DOMAIN.LOCAL -p '<password>' --query rbcd
```

The zero-dependency Rust engine has no TLS stack, so tanuki ldap --ssl refuses to run (exit 3) rather than send credentials in cleartext. Use the Python engine for verified LDAPS, or tunnel LDAP over stunnel or SSH.

## 9. Binary keytab inspection (tanuki keytab)

Inspects binary Kerberos keytab files per [RFC 4120], extracting principals, Key Version Numbers (KVNO), encryption types, and key lengths, and generating recommended non-interactive modern AES kinit commands.

```bash
# Inspect keytab entries and view modern AES kinit recommendation
tanuki keytab /path/to/identity.keytab

# Inspect using the -f/--file option
tanuki keytab -f /path/to/identity.keytab
tanuki keytab --file /path/to/identity.keytab

# Structured JSON export of keytab entries
tanuki keytab /path/to/identity.keytab --json
```

## 10. SSSD KCM credential cache extraction (tanuki kcm)

Scans and extracts Kerberos credential cache (ccache) streams from local SSSD Kerberos Credential Manager (KCM) databases (secrets.ldb) or default system cache locations.

```bash
# Triage and extract candidate credential caches from default system locations
tanuki kcm

# Extract ccache streams from a specific SSSD secrets database file (-f or --file)
tanuki kcm -f /var/lib/sss/secrets/secrets.ldb

# Specify a custom output directory for recovered tickets (-o or --out)
tanuki kcm -f /var/lib/sss/secrets/secrets.ldb -o ./extracted_tickets
tanuki kcm --file /var/lib/sss/secrets/secrets.ldb --out ./extracted_tickets

# Extract ccache streams by direct positional database path
tanuki kcm /var/lib/sss/secrets/secrets.ldb --out ./extracted_tickets

# JSON output of candidate ccache streams with offsets and principals
tanuki kcm -f /var/lib/sss/secrets/secrets.ldb --json
```

## 11. MS-PAC authorization data decoding (tanuki pac)

Decodes and audits Microsoft Privilege Attribute Certificate (MS-PAC) binary authorization structures per [MS-PAC] and [MS-DTYP], extracting Logon Information, group SIDs, user RID, domain SID, and user account control flags.

```bash
# Decode a raw PAC binary file
tanuki pac ./ticket.pac

# Decode a PAC from a hex-encoded string
tanuki pac 0100000008000000...

# Decode using the -f/--file option
tanuki pac -f /path/to/pac_blob.bin
tanuki pac --file /path/to/pac_blob.bin

# Structured JSON export of PAC buffers and claims
tanuki pac ./ticket.pac --json
```

## 12. Active Directory Shadow Credentials dissection (tanuki shadow)

Dissects Active Directory Shadow Credentials (msDS-KeyCredentialLink binary structures per [MS-ADTS] 2.2.20), decoding Next Generation Cryptography (NGC) and FIDO credential entries, KeyID, key usage, source flags, and creation timestamps.

```bash
# Dissect a raw binary Shadow Credential file
tanuki shadow /path/to/key_credential.bin

# Dissect using the -f/--file option
tanuki shadow -f /path/to/key_credential.bin
tanuki shadow --file /path/to/key_credential.bin

# Decode a raw hex string or DN-Binary formatted string
tanuki shadow "B:120:00000200..."

# Structured JSON report of shadow credential attributes
tanuki shadow -f /path/to/key_credential.bin --json
```

## 13. Protocol error triage and tactical resolution (tanuki triage)

Queries the pre-compiled Kerberos, Active Directory, and SSSD protocol error resolution dictionary. Provides root causes, tactical remediation commands, Blue Team event detection telemetry, and [RFC 6113] FAST armoring requirements.

```bash
# Display the entire error resolution dictionary
tanuki triage

# Lookup resolution for a specific error code
tanuki triage KDC_ERR_PREAUTH_FAILED

# Lookup Kerberos FAST armoring requirement (code 93 / 0x18 per RFC 6113)
tanuki triage KDC_ERR_PREAUTH_REQUIRED_FOR_FAST

# Lookup clock skew error resolution
tanuki triage KRB_AP_ERR_SKEW

# Structured JSON export of error dictionary or resolution
tanuki triage KDC_ERR_ETYPE_NOSUPP --json
```

## 14. 5-rung Tactical Decision Ladder (tanuki ladder)

Displays the fixed 5-rung Tactical Decision Ladder (Diagnose -> Authenticate -> Authorize -> Assess -> Purge) enforcing disciplined agent Standard Operating Procedures (SOP), zero-noise OPSEC standards, and military-brief command output standards: [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE].

```bash
# Display the 5-rung Tactical Decision Ladder in human-readable format
tanuki ladder

# Export the decision ladder schema as structured JSON
tanuki ladder --json
```

## 15. Workload identity JWT validation (tanuki token)

Parses and validates Non-Human Identity (NHI) workload JSON Web Tokens (JWT) per [RFC 7519] and [RFC 8693] with zero external dependencies. Assesses cryptographic algorithm strength, token expiration, claims validity, and expected audience/issuer constraints.

```bash
# Validate a raw JWT string passed as an argument
tanuki token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# Validate a token from a file (-f or --file)
tanuki token -f /var/run/secrets/kubernetes.io/serviceaccount/token
tanuki token --file /var/run/secrets/kubernetes.io/serviceaccount/token

# Validate with audience and issuer verification (-a or --audience, --issuer)
tanuki token -f ./token.jwt -a api://default --issuer https://accounts.google.com
tanuki token --file ./token.jwt --audience api://default --issuer https://accounts.google.com

# Validate token read from standard input
cat /path/to/token.jwt | tanuki token

# Structured JSON validation report with security findings
tanuki token -f ./token.jwt --json
```

## 16. Non-Human Identity operations suite (tanuki nhi)

Comprehensive Non-Human Identity (NHI) operations suite for inspecting workload JWTs per [RFC 7519], validating OAuth 2.0 Token Exchange parameters per [RFC 8693], performing live token exchange against Security Token Service (STS) endpoints, discovering cloud mesh workload identities (SPIFFE/SPIRE, AWS, GCP, Azure), and scanning local filesystems.

```bash
# Scan local filesystem for Kubernetes service account and standard workload tokens
tanuki nhi scan

# Inspect and audit a workload JWT token (-f or --file, -a or --audience, --issuer)
tanuki nhi inspect -f /path/to/token.jwt -a api://vault --issuer https://kubernetes.default.svc
tanuki nhi inspect --file /path/to/token.jwt --audience api://vault --issuer https://kubernetes.default.svc

# Validate RFC 8693 token exchange parameters locally
tanuki nhi exchange --subject-token eyJ... --subject-token-type urn:ietf:params:oauth:token-type:jwt -a api://ad-bridge

# Validate RFC 8693 token exchange with explicit grant type and requested token type
tanuki nhi exchange \
  --grant-type urn:ietf:params:oauth:grant-type:token-exchange \
  --subject-token eyJ... \
  --subject-token-type urn:ietf:params:oauth:token-type:jwt \
  --requested-token-type urn:ietf:params:oauth:token-type:access_token \
  --audience api://ad-bridge

# Execute live HTTP POST RFC 8693 token exchange against an STS endpoint
tanuki nhi exchange --live --endpoint https://sts.domain.local/oauth/token \
  --subject-token eyJ... --subject-token-type urn:ietf:params:oauth:token-type:jwt \
  -a api://ad-bridge

# Probe SPIFFE/SPIRE workload mesh socket and cloud metadata (optional socket override via -f/--file)
tanuki nhi mesh
tanuki nhi mesh --file /run/spire/sockets/agent.sock

# Output structured JSON report
tanuki nhi inspect -f ./token.jwt --json
```

*Note: Both the Python reference engine and the Rust systems core support workload mesh discovery (tanuki nhi mesh / ingest), live STS exchange (tanuki nhi exchange --live --endpoint), and local filesystem token scanning (tanuki nhi scan, the default when no subcommand is given).*

## 17. Zero-DNS unprivileged Kerberos configuration generator (tanuki config)

Generates an isolated, unprivileged Kerberos configuration (krb5.conf) targeting Domain Controllers directly by IP address without modifying /etc/krb5.conf or requiring root privileges. Supports enforcing modern AES encryption and enabling Kerberos FAST armoring per [RFC 6113].

```bash
# Generate configuration targeting the KDC IP directly
tanuki config --realm DOMAIN.LOCAL --kdc 192.168.56.106 --out ./krb5.conf

# Strictly enforce modern AES-128/256 encryption and reject legacy RC4 ciphers
tanuki config --realm DOMAIN.LOCAL --kdc 192.168.56.106 --enforce-aes --out ./krb5.conf

# Enable RFC 6113 FAST armoring in the configuration
tanuki config --realm DOMAIN.LOCAL --kdc 192.168.56.106 --fast --armor-cache /tmp/krb5cc_armor --out ./krb5.conf

# Derive realm and target KDC automatically from keytab file with clock skew tolerance
tanuki config --keytab /path/to/identity.keytab --kdc 192.168.56.106 --clock-skew 180 --out ./krb5.conf

# Specify an explicit administrative server address for password changes
tanuki config --realm DOMAIN.LOCAL --kdc 192.168.56.106 --admin-server 192.168.56.106 --out ./krb5.conf

# Print generated krb5.conf directly to stdout (or as JSON without writing ./krb5.conf)
tanuki config --realm DOMAIN.LOCAL --kdc 192.168.56.106 --stdout
tanuki config --realm DOMAIN.LOCAL --kdc 192.168.56.106 --stdout --json

# Activate the generated configuration in the current unprivileged shell session
export KRB5_CONFIG=$(pwd)/krb5.conf
```

## 18. Interactive terminal UI wizard (tanuki -i)

Launches a keyboard-navigable terminal interface for guided diagnosis, authentication, and remediation across all operational pillars.

```bash
tanuki -i
# or
tanuki --interactive
```

## 19. AI agent integration (tanuki skill)

Exports structured agent tool declarations and operational schemas for agent-driven developer tools such as Claude Code, Cursor, and Google Antigravity.

```bash
# Human-readable skill manifest
tanuki skill

# Machine-actionable JSON schema for agent tooling
tanuki skill --json
```

## Semantic exit codes

Every command returns a deterministic exit code so orchestrators can branch on the result.

| Code | Meaning |
| :---: | :--- |
| 0 | Success |
| 1 | Usage error |
| 2 | Policy stop |
| 3 | Resource missing |
| 4 | Parse failure |
