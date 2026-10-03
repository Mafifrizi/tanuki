<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <img src="assets/logo.png" alt="Tanuki Logo" width="220">
  </picture>
</p>

<h1 align="center">Tanuki</h1>

<p align="center">
  <em>Linux Active Directory triage for AI coding agents. Protocol-first, zero noise.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.1-blue.svg" alt="Version 1.2.1">
  <img src="https://img.shields.io/badge/rust-1.75+-dea584.svg" alt="Rust 1.75+">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-zero-success.svg" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/standards-RFC_4120-orange.svg" alt="RFC 4120">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#dual-engine-architecture">Dual-Engine Architecture</a> &bull;
  <a href="#live-lab-empirical-validation">Live Lab Validation</a> &bull;
  <a href="#the-decision-ladder">Decision Ladder</a> &bull;
  <a href="#before--after">Before & After</a> &bull;
  <a href="#tooling--usage">Tooling & Usage</a> &bull;
  <a href="#agent-setup">Agent Setup</a> &bull;
  <a href="#lineage--credits">Lineage & Credits</a>
</p>

---

## Quick Start (1-Line Universal Install)

Tanuki is 100% plug-and-play. One command installs the unified CLI and configures AI Agent Skills for Claude Code, Cursor, and Google Antigravity:

### Linux & macOS

```bash
curl -sSL https://raw.githubusercontent.com/Mafifrizi/tanuki/main/install.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Mafifrizi/tanuki/main/install.ps1 | iex
```

### Via Pipx / Pip / Cargo

```bash
# Pipx (Isolated CLI environment)
pipx install git+https://github.com/Mafifrizi/tanuki.git

# Local repository install
pip install .

# Note for Linux (Kali, Debian, Ubuntu): If ~/.local/bin is not in your PATH:
export PATH="$HOME/.local/bin:$PATH"

# Rust binary install
cargo install --path crates/tanuki-cli
```

Verify your installation:

```bash
# Direct CLI binary or universal Python module
tanuki --version
python3 -m tanuki --version

tanuki doctor
tanuki ladder
tanuki triage KRB_AP_ERR_SKEW
```

## Dual-Engine Architecture

Tanuki ships two complementary implementations:

1. **Rust Systems Core (`crates/tanuki-cli`)**: The primary high-performance engine for operator workstations, CI/CD security validation pipelines, and standalone deployment. It compiles into a single static binary with `#![forbid(unsafe_code)]`, zero external dependencies, and execution times under 2 milliseconds.
2. **Python Fallback Engine (`scripts/`)**: A zero-dependency script suite using only the Python standard library (`struct`, `io`, `sys`). It operates directly on remote target systems where dropping compiled binaries is prohibited or monitored by endpoint detection.

Both engines share an identical JSON schema and parsing specification.

---

## Live Lab Empirical Validation

All protocol parsers, diagnostics, and CLI workflows are empirically validated across live virtualized lab environments:
- **Active Directory Domain Controller**: Windows Server 2022 (`DC01.lab.local`, IP: `192.168.56.106`)
- **Operator Workstation**: Kali Linux 2024 (`kraii@kraiiandreyy`, IP: `192.168.56.105`)

### 1. Active Directory Keytab Export (`ktpass`)

Official RFC 4120 binary keytab export on the Domain Controller for service account `LAB\tanuki-nhi` with modern AES-256 (`aes256-cts-hmac-sha1-96`, KVNO 4):

<p align="center">
  <img src="assets/dc01-ktpass-export-real.png" alt="Windows Server ktpass Export" width="850">
</p>

### 2. Unprivileged Zero-DNS Kerberos Configuration Generator (`tanuki config`)

Generates a local Kerberos configuration file (`lab_krb5.conf`) enforcing RFC 4120 § 6.1 uppercase realm conventions, zero-DNS direct KDC IP routing, and instant unprivileged session activation:

<p align="center">
  <img src="assets/lab-validation-config.png" alt="Unprivileged Kerberos Config Generator" width="850">
</p>

### 3. Pre-Flight Health Diagnostic Audit (`tanuki doctor`)

Passive, zero-packet pre-flight health diagnostic executing in **4.27 ms**:
- Verifies keytab permissions (`0600 (secure)`) and RFC 4120 binary header integrity.
- Audits Kerberos configuration realm syntax (`Default realm: LAB.LOCAL`).
- Validates SSSD daemon and KCM socket availability.
- Evaluates active ticket lifetimes across file caches and kernel keyrings.
- Passively audits host client tooling (`kinit`/`klist`) and provides tailored package manager recommendations.

<p align="center">
  <img src="assets/lab-validation-doctor.png" alt="Pre-Flight Doctor Health Check" width="850">
</p>

### 4. Zero-Root Session Precedence (`KRB5_CONFIG`)

Validates automatic environment variable precedence, enabling unprivileged operators to triage custom realms without `/etc/krb5.conf` root write permissions in **3.53 ms**:

<p align="center">
  <img src="assets/lab-validation-doctor-env.png" alt="Doctor with KRB5_CONFIG Precedence" width="850">
</p>

### 5. RFC 4120 Keytab Ingestion & Dynamic Triage (`tanuki keytab`)

Parses binary keytab structures, extracts AES-256 principals, injects active `KRB5_CONFIG` prefixes into non-interactive `kinit` commands, and flags missing host tooling:

<p align="center">
  <img src="assets/lab-validation-keytab.png" alt="Keytab Triage Report" width="850">
</p>

### 6. Structured Machine Contract (`tanuki keytab --json`)

Emits deterministic, machine-readable JSON schemas for automated AI agent workflows and CI/CD pipelines:

<p align="center">
  <img src="assets/lab-validation-keytab-json.png" alt="Structured JSON Keytab Contract" width="850">
</p>

### 7. Kerberos Protocol Error Triage & Blue Telemetry Coupling (`tanuki triage`)

Couples tactical remediation commands with Blue Team detection telemetry (Auditd watch rules, Windows Event IDs 4771/4768/4625, Sigma rules, and Falco signatures):

<p align="center">
  <img src="assets/lab-validation-triage.png" alt="Protocol Error Triage and Telemetry" width="850">
</p>

### 8. 5-Rung Tactical Decision Ladder (`tanuki ladder`)

Visualizes the complete OPSEC hierarchy in a pristine, zero-noise terminal interface:

<p align="center">
  <img src="assets/lab-validation-ladder.png" alt="5-Rung Tactical Decision Ladder" width="850">
</p>

### 9. AI Agent Skill Manifest (`tanuki skill`)

Exports the autonomous agent skill manifest, intellectual lineage, operational triggers, and deterministic execution standard:

<p align="center">
  <img src="assets/lab-validation-skill.png" alt="AI Agent Skill Manifest" width="850">
</p>

---

## The Decision Ladder

Before proposing any triage command or query, Tanuki follows a 5-level operational ladder:

```text
Level 5  [ Deterministic Output ]  --> [Target] -> [Exact Command] -> [Artifact]
   ▲
Level 4  [ Targeted Vectors    ]  --> ADCS ESC templates, RBCD, Shadow Credentials
   ▲
Level 3  [ Machine Identity    ]  --> Leverage host keytabs and service principals (LotD)
   ▲
Level 2  [ OPSEC Guardrails    ]  --> Enforce AES-256; strictly ban RC4 and password spraying
   ▲
Level 1  [ Local Passive First ]  --> Triage /etc/krb5.keytab & SSSD KCM before network packets
```

1. **Local Passive First**: Inspect local files (`/etc/krb5.keytab`, `/etc/sssd/sssd.conf`, KCM stores) before sending packets over the wire.
2. **OPSEC Guardrails**: Enforce AES-256 (`aes256-cts-hmac-sha1-96`). Strictly forbid RC4 downgrade attacks and account spraying.
3. **Machine Identity (Living off the Domain)**: Validate host keytabs and managed identities before requesting human user credentials.
4. **Targeted Vectors**: Focus triage on specific certificate templates (ADCS), resource-based delegation, and Kerberos error codes.
5. **Deterministic Output**: Return exact CLI invocations, target endpoints, and expected artifacts instead of general explanations.

---

## Before & After

| Scenario | Generic Coding Agent | With Tanuki |
| :--- | :--- | :--- |
| **Service LDAP Query Fails** | Proposes `ldapsearch -x -D "admin@corp" -W` asking operator for cleartext credentials. | Inspects local keytab, acquires machine ticket via AES-256, and issues `ldapsearch -Y GSSAPI` with existing credentials. |
| **Kerberos Error Handling** | Recommends editing `/etc/krb5.conf` to add `allow_weak_crypto = true`. | Diagnoses specific Kerberos error code (`KDC_ERR_ETYPE_NOSUPP` or clock skew) and fixes encryption types without weakening security. |
| **Ticket Cache Extraction** | Searches only for `/tmp/krb5cc_%{uid}`, reports no tickets found when SSSD KCM is active. | Parses `/var/lib/sss/secrets/secrets.ldb` directly to extract active CCACHE v4 streams. |

---

## Tooling & Usage

### 1. Rust Systems Core (`crates/tanuki-cli`)

Build the standalone binary:

```bash
cargo build --release --manifest-path crates/tanuki-cli/Cargo.toml
```

Run proactive pre-flight health diagnostics (<5ms, zero network packets):

`tanuki doctor` runs deterministic, zero-network pre-flight diagnostics across local Active Directory components in under 5 milliseconds:
- Keytab permissions and format: Audits `/etc/krb5.keytab` permissions (flags world-readable `0644`/`0666` permissions vs secure `0600`) and validates RFC 4120 binary header magic (`0x0502`).
- Realm capitalization: Audits `/etc/krb5.conf` for lowercase realm declarations across `[libdefaults]` and `[realms]`, honoring `KRB5_CONFIG` environment variable precedence.
- SSSD daemon and socket status: Validates `/var/lib/sss/pipes/kcm` socket presence and `/var/run/sssd.pid` daemon state.
- Ticket cache lifetimes: Evaluates remaining ticket validity across MIT CCACHE v4 streams (`0x0504`) and Linux Kernel Keyring (`KEYRING:persistent:` / `/proc/keys`).
- Host client tooling: Passively audits availability of `kinit`/`klist` on `$PATH` in <0.5ms and provides package recommendations for Debian/Kali (`krb5-user`) and RHEL (`krb5-workstation`).

```bash
# Terminal checklist output
tanuki doctor

# Structured JSON export for automated agent ingestion
tanuki doctor --json

# Custom target paths
tanuki doctor --keytab /custom/krb5.keytab --krb5-conf /custom/krb5.conf
```

Generate zero-DNS unprivileged Kerberos configuration (RFC 4120):

```bash
# Generate unprivileged configuration directly targeting KDC IP (zero root, zero DNS dependency)
tanuki config --realm CORP.LOCAL --kdc 192.168.56.106 -o ./krb5.conf

# Activate in current unprivileged shell session
export KRB5_CONFIG=$(pwd)/krb5.conf
```

Inspect binary keytabs (RFC 4120):

```bash
# Human-readable report
tanuki keytab /etc/krb5.keytab

# Deterministic JSON schema
tanuki keytab /etc/krb5.keytab --json
```

Extract SSSD KCM credential cache streams:

```bash
# Scan local default SSSD database paths
tanuki kcm

# Parse a specific LDB database and save recovered tickets
tanuki kcm -f /var/lib/sss/secrets/secrets.ldb -o ./extracted_ccache
```

Query the Kerberos error triage dictionary with dual-use SOC detection telemetry:

Tanuki couples every tactical remediation (Rung 5) and all 10 Kerberos error codes with defender detection telemetry:
- Auditd watch rules: Exact audit rules for monitored paths (such as `-w /etc/krb5.keytab -p r -k keytab_read` and `-w /etc/localtime -p wa`).
- Domain Controller Security Event IDs: Windows Event IDs (4768 TGT Request, 4769 TGS Request, 4771 Pre-Authentication Failed, 4624/4625 Logon).
- Sigma rules: Detection rule identifiers (such as `proc_creation_win_susp_kerberos_ticket_request`).
- Falco signatures: Syscall monitoring signatures (such as `read_sensitive_file_untrusted`).
- Terminal display: Emits `[BLUE TELEMETRY]` alongside `[TACTICAL CMD]`.
- Structured JSON: Full `telemetry` schema blocks in `tanuki triage <ERROR> --json` and `tanuki ladder --json`.

```bash
# Lookup resolution with [TACTICAL CMD] and [BLUE TELEMETRY]
tanuki triage KRB_AP_ERR_SKEW

# Lookup by Active Directory Event ID with structured JSON export
tanuki triage 14 --json
```

Validate Non-Human Identity (NHI) workload tokens (RFC 8693):

Tanuki validates modern cloud and workload identity tokens undergoing RFC 8693 OAuth 2.0 Token Exchange to Kerberos tickets:
- Zero external runtime dependencies: Parses and validates JWT claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`) using standard library base64 and JSON without network calls.
- Supported identity classes: Evaluates Kubernetes ServiceAccount tokens, AWS IAM Roles Anywhere credentials, SPIFFE SVIDs, and GitHub Actions OIDC tokens.
- Security policy auditing: Detects dangerous wildcard audience scopes (`aud: "*"` or wildcard array elements) and overly broad subject patterns (`system:serviceaccount:*:*`, `arn:aws:iam::*:role/*`, `spiffe://*`).
- Token exchange parameter validation: Verifies RFC 8693 parameters (`grant_type`, `subject_token`, `subject_token_type`, `requested_token_type`, `audience`).

```bash
# Validate Kubernetes ServiceAccount or cloud workload JWT
tanuki token /var/run/secrets/kubernetes.io/serviceaccount/token

# Validate with audience check and JSON export
tanuki token <JWT> --audience https://sts.corp.local --json

# Inspect workload token claims and detect broad subject patterns
tanuki nhi inspect <JWT>

# Validate RFC 8693 token exchange request parameters
tanuki nhi exchange --subject-token <JWT> --audience https://sts.corp.local
```

Export AI Agent Skill Manifest & Operational Contract (`tanuki skill`):

```bash
# Terminal card manifest for human operators
tanuki skill

# Structured JSON export for autonomous agents (Claude Code, Cursor, Antigravity)
tanuki skill --json
```

### 2. Operator CLI Contract & Semantic Exit Codes

Tanuki guarantees deterministic exit codes and machine-readable error envelopes across both Python and Rust engines. Operators and automated orchestration agents can distinguish missing artifacts from policy refusals without parsing conversational text:

| Exit Code | Constant | Meaning | JSON Reason Code |
| :--- | :--- | :--- | :--- |
| `0` | `EXIT_SUCCESS` | Command completed successfully or pre-flight healthy | `SUCCESS` |
| `1` | `EXIT_USAGE_ERROR` | Syntax error, unknown option, or missing argument | `USAGE_ERROR` |
| `2` | `EXIT_POLICY_STOP` | Refusal due to security guardrail (e.g. insecure keytab 0644, weak ciphers) | `POLICY_STOP` |
| `3` | `EXIT_RESOURCE_MISSING` | Target keytab file, SSSD pipe, or ccache not found | `MISSING_KEYTAB` / `MISSING_RESOURCE` |
| `4` | `EXIT_PARSE_FAILURE` | Corrupted binary magic, truncated bytes, or invalid encoding | `CORRUPT_KEYTAB` / `PARSE_FAILURE` |

When `--json` is supplied, errors emit a structured JSON envelope to standard output:

```json
{
  "status": "ERROR",
  "reason_code": "MISSING_KEYTAB",
  "category": "RESOURCE_MISSING",
  "exit_code": 3,
  "message": "Error reading keytab at '/etc/krb5.keytab': No such file or directory",
  "target": "/etc/krb5.keytab"
}
```

### 3. Python Fallback Scripts (`scripts/`)

Used for remote living-off-the-land workflows where dropping binaries is prohibited. No third-party packages or network access are required.

```bash
# Keytab inspection
python3 scripts/keytab_inspector.py /etc/krb5.keytab
python3 scripts/keytab_inspector.py /etc/krb5.keytab --json

# SSSD KCM cache extraction
python3 scripts/kcm_parser.py -o ./extracted_ccache
```

### 4. Automated Test Suites

Verify both engines:

```bash
# Python test suite
python3 -m unittest discover -s tests -v

# Rust test suite
cargo test --workspace
```

---

## Agent Setup

| Environment | Integration | Configuration Path |
| :--- | :--- | :--- |
| **Google Antigravity** | Native Skill Module | Place repository in active workspace or skills path |
| **Claude Code** | Native Skill Guide | Point to `SKILL.md` or copy to project root |
| **Cursor** | Project Rule | `.cursor/rules/tanuki.mdc` |
| **Cline / Windsurf / Codex** | System Prompt Instructions | Reference `AGENTS.md` |

---

## Repository Architecture & Subsystems

```mermaid
flowchart TD
    subgraph DIST["Distribution & 1-Line Setup"]
        M1["pyproject.toml (PEP 621)"]
        M2["Cargo.toml (Workspace)"]
        I1["install.sh (POSIX)"]
        I2["install.ps1 (Windows)"]
    end

    subgraph ENGINES["Dual Protocol Engines"]
        subgraph RUST_ENGINE["Rust Systems Core (crates/tanuki-cli)"]
            R_LIB["lib.rs (#![forbid(unsafe_code)])"]
            R_DOC["doctor/ (Pre-flight sub-5ms)"]
            R_NHI["nhi/ (RFC 8693 Validator)"]
            R_KT["keytab/ (RFC 4120 Parser)"]
            R_KCM["kcm/ (CCACHE Extractor)"]
            R_TEL["protocol/ (Telemetry & Triage)"]
        end

        subgraph PY_ENGINE["Python Unified Package (tanuki/)"]
            P_CLI["cli.py (Unified CLI Entry)"]
            P_DOC["doctor.py (Pre-flight sub-5ms)"]
            P_NHI["nhi.py (RFC 8693 Validator)"]
            P_TEL["telemetry.py (Auditd & Event IDs)"]
            P_KT["keytab.py (RFC 4120 Parser)"]
            P_KCM["kcm.py (SSSD LDB Parser)"]
        end
    end

    subgraph AGENT_LAYER["Agent Specifications & Lineage"]
        S1["SKILL.md (Claude Code & Antigravity)"]
        S2[".cursor/rules/tanuki.mdc (Cursor)"]
        S3["references/ (Tactical Ladder, AD CS, NHI)"]
    end

    subgraph VERIFICATION["Empirical Verification (310 Tests)"]
        V1["tests/ (Unit Test Suites)"]
        V2["tests/e2e/ (Tiers 1-4 Scenarios)"]
        V3["Tier 5 Adversarial Fuzzing"]
    end

    DIST --> ENGINES
    ENGINES --> AGENT_LAYER
    ENGINES --> VERIFICATION
```

### Subsystem Directory Map

| Subsystem | Primary Location | Key Capabilities & Architecture |
| :--- | :--- | :--- |
| **Rust Systems Core** | `crates/tanuki-cli/` | High-performance binary CLI built with `#![forbid(unsafe_code)]`. Houses sub-5ms `doctor`, RFC 8693 token exchange, RFC 4120 keytab parsing, and SSSD CCACHE extraction. |
| **Python Unified Package** | `tanuki/` | Zero-dependency PEP 621 package providing the `tanuki` entrypoint, pre-flight diagnostics, SOC detection telemetry, and NHI claim validation. |
| **Living-off-the-Land Scripts** | `scripts/` | Standalone Python 3 standard library scripts for air-gapped environments without pip or compiler toolchains. |
| **Agent Skill Definitions** | `SKILL.md`, `.cursor/rules/` | Multi-agent skill manifests auto-linked into Claude Code (`~/.claude/skills`), Cursor, and Google Antigravity. |
| **Technical References** | `references/` | Grounded protocol manuals covering Ponytail decision ladder, AD CS matrix (ESC1-ESC11), error triage, and NHI federation. |
| **Verification Harness** | `tests/`, `tests/e2e/` | 310 automated tests covering unit, boundary, pairwise, real-world scenarios, and adversarial binary fuzzing. |

<details>
<summary><b>View complete directory file tree</b></summary>

```text
tanuki/
├── .github/
│   └── workflows/
│       └── release.yml        # CI/CD test, release asset, and GHCR container packaging
├── Dockerfile                 # Distroless/slim container specification
├── Cargo.toml                 # Root workspace manifest
├── pyproject.toml             # Python PEP 621 package specification (v1.2.1)
├── install.sh                 # 1-line POSIX installer (Linux & macOS)
├── install.ps1                # 1-line PowerShell installer (Windows)
├── crates/
│   └── tanuki-cli/            # Rust systems core
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs         # Library entry point (#![forbid(unsafe_code)])
│       │   ├── main.rs        # CLI entry point and formatters
│       │   ├── doctor/        # Sub-5ms pre-flight health diagnostic probe
│       │   ├── nhi/           # RFC 8693 workload token validator
│       │   ├── keytab/        # RFC 4120 keytab binary parser
│       │   ├── kcm/           # SSSD KCM CCACHE stream extractor
│       │   └── protocol/      # Kerberos constants, error triage & telemetry
│       └── tests/
│           └── integration_tests.rs
├── tanuki/                    # Unified Python package
│   ├── __init__.py            # Library exports (v1.2.1)
│   ├── __main__.py            # python -m tanuki execution
│   ├── cli.py                 # Unified CLI matching Rust commands
│   ├── doctor.py              # Pre-flight health check engine (<5ms, zero packets)
│   ├── nhi.py                 # Non-Human Identity & RFC 8693 token exchange
│   ├── telemetry.py           # Dual-use SOC detection telemetry (Auditd, Event ID, Sigma)
│   ├── keytab.py              # RFC 4120 keytab parser
│   ├── kcm.py                 # SSSD KCM ticket stream parser
│   └── protocol.py            # Error dictionary & decision ladder
├── assets/
│   ├── logo.png               # Project logo (transparent background, light mode)
│   ├── logo-dark.png          # Project logo (transparent background, dark mode)
│   ├── social-preview.png     # Repository social preview banner
│   ├── dc01-ktpass-export-real.png
│   ├── lab-validation-config.png
│   ├── lab-validation-doctor.png
│   ├── lab-validation-doctor-env.png
│   ├── lab-validation-keytab.png
│   ├── lab-validation-keytab-json.png
│   ├── lab-validation-ladder.png
│   ├── lab-validation-skill.png
│   └── lab-validation-triage.png
├── scripts/
│   ├── keytab_inspector.py    # Python Living-off-the-Land keytab parser
│   └── kcm_parser.py          # Python SSSD KCM credential cache parser
├── references/
│   ├── tactical_ladder.md     # 5-step operational ladder reference
│   ├── dual_engine_architecture.md # Technical comparison and threat model
│   ├── adcs_matrix.md         # ADCS certificate templates and PKINIT parameters
│   ├── error_triage.md        # Kerberos and SSSD error resolution table
│   └── nhi_mesh.md            # Workload identity and token exchange reference
├── tests/
│   ├── test_doctor.py         # Pre-flight health check unit tests
│   ├── test_telemetry.py      # Dual-use detection telemetry unit tests
│   ├── test_nhi.py            # RFC 8693 workload token validator tests
│   ├── test_unified_cli.py    # Unified CLI command coverage
│   ├── test_keytab_inspector.py
│   ├── test_kcm_parser.py
│   ├── test_rust_compatibility.py
│   └── test_security_audit.py
├── SKILL.md                   # Universal skill definition
├── AGENTS.md                  # Multi-agent prompt file
├── CLAUDE.md                  # Claude Code project guide
├── .cursor/rules/tanuki.mdc   # Cursor rule definition
├── LICENSE                    # Dual license declaration
├── LICENSE-APACHE             # Apache License 2.0
├── LICENSE-MIT                # MIT License
└── README.md
```

</details>

---

## Technical References

- [`references/tactical_ladder.md`](references/tactical_ladder.md): Detailed mechanics for each rung of the decision ladder.
- [`references/dual_engine_architecture.md`](references/dual_engine_architecture.md): Technical evaluation of Python (LotL) vs Rust (Systems Core).
- [`references/adcs_matrix.md`](references/adcs_matrix.md): Certificate misconfigurations (ESC1 to ESC11) and PKINIT parameters.
- [`references/error_triage.md`](references/error_triage.md): Complete error code matrix for Kerberos, SSSD, and IAKerb.
- [`references/nhi_mesh.md`](references/nhi_mesh.md): Workload identity federation, SPIFFE SVIDs, and RFC 8693 token exchange.

---

## Lineage & Credits

Tanuki draws inspiration and tradecraft from two projects:

- **Tim Brown ([@timb-machine](https://github.com/timb-machine))**: Created [Linikatz](https://github.com/CiscoCXSecurity/linikatz) and pioneered Linux Active Directory assessment techniques, keytab analysis, and credential cache harvesting.
- **Dietrich Gebert ([@dietrichayala](https://github.com/dietrichayala))**: Created [Ponytail](https://github.com/DietrichGebert/ponytail) and demonstrated how a disciplined decision ladder prevents AI agent hallucination and conversational bloat.

---

## License

Tanuki is dual-licensed under either:

- **MIT License** ([`LICENSE-MIT`](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([`LICENSE-APACHE`](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose to use this project under the terms of either license.
