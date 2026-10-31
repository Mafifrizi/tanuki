# Tanuki Command Reference

Full usage for every Tanuki command. Both engines share the same command surface and flags, so these examples work with the Rust binary (`tanuki`) and the Python engine (`python3 -m tanuki`).

For a high-level overview, see the [README](../README.md). For the protocol decision model, see [`references/tactical_ladder.md`](../references/tactical_ladder.md).

## 1. Pre-flight health diagnostics (`tanuki doctor`)

Runs 10 diagnostic checks across domain configuration, credentials, network connectivity, and OPSEC telemetry.

```bash
# Terminal checklist output
tanuki doctor

# Structured JSON export for orchestration pipelines
tanuki doctor --json

# Probe active OPSEC endpoint hooks
tanuki doctor --opsec
```

## 2. Unprivileged userspace TGT authentication (`tanuki auth`)

Acquires a Kerberos Ticket Granting Ticket using local keytab credentials, with automatic principal detection and in-memory clock skew healing.

```bash
# Authenticate a machine principal with in-memory clock skew tolerance
tanuki auth --keytab /path/to/identity.keytab --clock-skew

# Export the ticket to a custom credential cache
tanuki auth --keytab /path/to/identity.keytab --ccache /tmp/krb5cc_custom
```

## 3. Kerberos service ticket acquisition (`tanuki tgs`)

Requests Kerberos Service Tickets for target Service Principal Names using cached credentials or a direct keytab exchange.

```bash
# Acquire a service ticket using an existing cached TGT
tanuki tgs --spn HTTP/web-service.domain.local

# Combined TGT and TGS acquisition via keytab
tanuki tgs --spn HTTP/web-service.domain.local --keytab /path/to/identity.keytab
```

## 4. Quantitative blast radius engine (`tanuki blast`)

Evaluates machine identity blast radius, calculates the risk tier, and emits copy-paste PowerShell remediation recipes.

```bash
# Quantitative risk scoring and privilege tiering
tanuki blast --keytab /path/to/identity.keytab --spn HTTP/app.domain.local

# Structured JSON report with remediation recipes
tanuki blast --keytab /path/to/identity.keytab --spn HTTP/app.domain.local --json
```

## 5. Idempotent closed-loop remediation (`tanuki fix`)

Applies deterministic self-healing fixes to environment misconfigurations. Synthesized Kerberos clock skew is clamped to the standard 300 second maximum so a drift value can never widen the host replay window.

```bash
# Dry-run preview without modifying disk state
tanuki fix --dry-run

# Execute automated idempotent repair
tanuki fix
```

## 6. NIST SP 800-88 cryptographic memory purge (`tanuki purge`)

Executes a multi-pass cryptographic overwrite and zeroization across credential caches and memory buffers.

```bash
# Purge all discovered ticket caches and temporary session files
tanuki purge --all

# Purge a specific credential cache file
tanuki purge --target /tmp/krb5cc_1000
```

## 7. Passive AD CS certificate and template scanner (`tanuki adcs`)

Audits Active Directory Certificate Services templates for ESC1 through ESC11 misconfigurations.

```bash
# Scan a certificate template definition
tanuki adcs --template /path/to/template.json

# Structured JSON export for vulnerability management
tanuki adcs --template /path/to/template.json --json
```

## 8. Unprivileged and authenticated Active Directory LDAP (`tanuki ldap`)

Reconnaissance across domain partitions for Kerberos SPNs, AS-REP roasting targets, RBCD delegation, and shadow credentials. Query categories are selected with `--query`: `spn`, `asreproast`, `rbcd`, `shadow`, `unconstrained`, or `all`.

```bash
# Audit Kerberos Service Principal Names
tanuki ldap --host dc01.domain.local --query spn

# AS-REP roasting detection with cipher negotiation audit (RC4 vs AES-256)
tanuki ldap --host dc01.domain.local --query asreproast

# Resource-Based Constrained Delegation discovery with in-line DACL parsing
tanuki ldap --host dc01.domain.local --query rbcd
```

### Verified LDAPS (credentialed queries)

Plain LDAP on port 389 sends the simple-bind credentials in cleartext. When you pass a username and password, use a verified LDAPS channel.

```bash
# Verify the DC certificate against the system trust store
python3 -m tanuki ldap --host dc01.domain.local --ssl --secure \
  -u svc@DOMAIN.LOCAL -p '<password>' --query rbcd

# Pin a specific DC CA bundle
python3 -m tanuki ldap --host dc01.domain.local --ssl --verify-ca ./dc-ca.pem \
  -u svc@DOMAIN.LOCAL -p '<password>' --query rbcd
```

The zero-dependency Rust engine has no TLS stack, so `tanuki ldap --ssl` refuses to run (exit 3) rather than send credentials in cleartext. Use the Python engine for verified LDAPS, or tunnel LDAP over stunnel or SSH.

## 9. Zero-DNS unprivileged Kerberos configuration generator (`tanuki config`)

Generates an isolated, unprivileged Kerberos configuration that targets the Domain Controller directly by IP, without touching `/etc/krb5.conf`.

```bash
# Generate an unprivileged configuration targeting the KDC IP directly
tanuki config --domain domain.local --dc-ip 192.168.56.106 --output ./krb5.conf

# Activate it in the current shell session
export KRB5_CONFIG=$(pwd)/krb5.conf
```

## 10. Interactive terminal UI wizard (`tanuki -i`)

Launches a keyboard-navigable terminal interface for guided diagnosis, authentication, and remediation.

```bash
tanuki -i
# or
tanuki --interactive
```

## 11. AI agent integration (`tanuki skill`)

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
| `0` | Success |
| `1` | Usage error |
| `2` | Policy stop |
| `3` | Resource missing |
| `4` | Parse failure |
