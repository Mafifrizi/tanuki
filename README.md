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
  <img src="https://img.shields.io/badge/rust-1.75+-dea584.svg" alt="Rust 1.75+">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-zero-success.svg" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/standards-RFC_4120-orange.svg" alt="RFC 4120">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#dual-engine-architecture">Dual-Engine Architecture</a> &bull;
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

# Rust binary install
cargo install --path crates/tanuki-cli
```

Verify your installation:

```bash
tanuki --version
tanuki ladder
tanuki triage KRB_AP_ERR_SKEW
```

## Dual-Engine Architecture

Tanuki ships two complementary implementations:

1. **Rust Systems Core (`crates/tanuki-cli`)**: The primary high-performance engine for operator workstations, CI/CD security validation pipelines, and standalone deployment. It compiles into a single static binary with `#![forbid(unsafe_code)]`, zero external dependencies, and execution times under 2 milliseconds.
2. **Python Fallback Engine (`scripts/`)**: A zero-dependency script suite using only the Python standard library (`struct`, `io`, `sys`). It operates directly on remote target systems where dropping compiled binaries is prohibited or monitored by endpoint detection.

Both engines share an identical JSON schema and parsing specification.

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

Inspect binary keytabs:

```bash
# Human-readable report
./target/release/tanuki keytab /etc/krb5.keytab

# Deterministic JSON schema
./target/release/tanuki keytab /etc/krb5.keytab --json
```

Extract SSSD KCM credential cache streams:

```bash
# Scan local default SSSD database paths
./target/release/tanuki kcm

# Parse a specific LDB database and save recovered tickets
./target/release/tanuki kcm -f /var/lib/sss/secrets/secrets.ldb -o ./extracted_ccache
```

Query the Kerberos error triage dictionary:

```bash
# Lookup resolution for clock skew
./target/release/tanuki triage KRB_AP_ERR_SKEW

# Lookup by Active Directory Event ID
./target/release/tanuki triage 14
```

### 2. Python Fallback Scripts (`scripts/`)

Used for remote living-off-the-land workflows where dropping binaries is prohibited. No third-party packages or network access are required.

```bash
# Keytab inspection
python3 scripts/keytab_inspector.py /etc/krb5.keytab
python3 scripts/keytab_inspector.py /etc/krb5.keytab --json

# SSSD KCM cache extraction
python3 scripts/kcm_parser.py -o ./extracted_ccache
```

### 3. Automated Test Suites

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

## Repository Structure

```text
tanuki/
├── Cargo.toml                 # Root workspace manifest
├── pyproject.toml             # Python PEP 621 package specification
├── install.sh                 # 1-line POSIX installer (Linux & macOS)
├── install.ps1                # 1-line PowerShell installer (Windows)
├── crates/
│   └── tanuki-cli/            # Rust systems core
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs         # Library entry point (#![forbid(unsafe_code)])
│       │   ├── main.rs        # CLI entry point and formatters
│       │   ├── keytab/        # RFC 4120 keytab binary parser
│       │   ├── kcm/           # SSSD KCM CCACHE stream extractor
│       │   └── protocol/      # Kerberos constants and error triage dictionary
│       └── tests/
│           └── integration_tests.rs
├── tanuki/                    # Unified Python package
│   ├── __init__.py            # Library exports
│   ├── __main__.py            # python -m tanuki execution
│   ├── cli.py                 # Unified CLI matching Rust commands
│   ├── keytab.py              # RFC 4120 keytab parser
│   ├── kcm.py                 # SSSD KCM ticket stream parser
│   └── protocol.py            # Error dictionary & decision ladder
├── assets/
│   ├── logo.png               # Project logo (transparent background, light mode)
│   └── logo-dark.png          # Project logo (transparent background, dark mode)
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
│   ├── test_unified_cli.py
│   ├── test_keytab_inspector.py
│   ├── test_kcm_parser.py
│   ├── test_rust_compatibility.py
│   └── test_security_audit.py
├── SKILL.md                   # Universal skill definition
├── AGENTS.md                  # Multi-agent prompt file
├── CLAUDE.md                  # Claude Code project guide
├── .cursor/rules/tanuki.mdc   # Cursor rule definition
├── LICENSE                    # MIT License
└── README.md
```

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

This project is licensed under the [MIT License](LICENSE).
