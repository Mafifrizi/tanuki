<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <img src="assets/logo.png" alt="Tanuki Logo" width="220">
  </picture>
</p>

<h1 align="center">Tanuki</h1>

<p align="center">
  <strong>Non-Human Identity & Hybrid Active Directory Operator for Linux Workloads</strong><br>
  <em>Protocol-first, zero root privileges, zero host configuration footprint, zero noise.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version 2.0.0">
  <img src="https://img.shields.io/badge/rust-1.75+%20(1.8MB%20musl)-dea584.svg?logo=rust&logoColor=white" alt="Rust Systems Core">
  <img src="https://img.shields.io/badge/python-3.10+%20(zero--dep)-3776ab.svg?logo=python&logoColor=white" alt="Python Reference Engine">
  <img src="https://img.shields.io/badge/standards-RFC_4120%20%7C%20RFC_8693-orange.svg" alt="RFC Standards">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0">
</p>

<p align="center">
  <a href="#overview">Overview</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#commands">Commands</a> &bull;
  <a href="docs/ARCHITECTURE.md">Architecture</a> &bull;
  <a href="docs/VALIDATION.md">Validation</a> &bull;
  <a href="#lineage--credits">Lineage & Credits</a>
</p>

---

## Overview

Modern cloud-native and on-premise environments increasingly run Linux workloads (Kubernetes pods, AI coding agents, CI/CD runners, containerized batch workers) that must authenticate to enterprise Active Directory domains without a full domain join, Kerberos daemons (`sssd` / `winbind`), or root privileges.

Tanuki is a protocol-first Active Directory operator built for unprivileged Linux userspace. It runs the full Purple Team lifecycle under human-in-the-loop control: pre-flight triage, cryptographic ticket negotiation, quantitative privilege tiering, closed-loop self-healing, and forensic audit telemetry. It is also agent-operable, exposing a structured skill manifest so tools like Claude Code, Cursor, and Google Antigravity can drive it one deterministic step at a time.

**Highlights:**

- **Living off the domain.** The Python engine uses only the 3.10+ standard library. Zero pip dependencies. The Rust core is a 1.8 MB static binary built with `#![forbid(unsafe_code)]`.
- **Strictly unprivileged (UID 1000).** No `sudo`, no root, no `CAP_SYS_TIME`, and no mutation of `/etc/krb5.conf` or system files.
- **Quantitative blast radius.** Scores identity risk (0-100), classifies Active Directory tiers, and emits deterministic PowerShell remediation recipes.
- **Deterministic and auditable.** Military-brief output, semantic exit codes, and in-memory clock skew healing clamped to the Kerberos standard 300 second maximum.

For the full engine comparison and subsystem map, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

<p align="center">
  <img src="assets/04_tanuki_blast_radius.png" alt="Tanuki blast radius and privilege tiering" width="850">
</p>

---

## Quick Start

### 1-line universal install

```bash
# Detects the Rust musl binary or falls back to the Python standard engine
curl -sSfL https://raw.githubusercontent.com/Mafifrizi/tanuki/main/install.sh | bash
```

### Manual installation

```bash
# Rust systems core
cargo install --path crates/tanuki-cli

# Python reference engine
pipx install git+https://github.com/Mafifrizi/tanuki.git
```

### Zero-install direct execution

```bash
git clone https://github.com/Mafifrizi/tanuki.git
cd tanuki
python3 -m tanuki doctor --json
```

---

## Commands

Both engines share the same command surface and flags. Full usage, every flag, and verified LDAPS examples are in [docs/USAGE.md](docs/USAGE.md).

| Command | Purpose |
| :--- | :--- |
| `tanuki doctor` | Pre-flight diagnostics across domain config, credentials, network, and OPSEC telemetry |
| `tanuki auth` | Unprivileged userspace TGT acquisition with in-memory clock skew healing |
| `tanuki tgs` | Kerberos service ticket acquisition for a target SPN |
| `tanuki blast` | Quantitative blast radius scoring, privilege tiering, and PowerShell remediation recipes |
| `tanuki ldap` | Unprivileged LDAP recon (`--query spn \| asreproast \| rbcd \| shadow \| unconstrained \| all`) |
| `tanuki adcs` | Passive AD CS template scanner for ESC1 through ESC11 |
| `tanuki config` | Zero-DNS unprivileged `krb5.conf` generator targeting the KDC by IP |
| `tanuki fix` | Idempotent closed-loop remediation (`--dry-run` to preview) |
| `tanuki purge` | NIST SP 800-88 cryptographic memory and credential-cache zeroization |
| `tanuki skill` | Export the agent skill manifest (`--json` for machine-actionable schema) |

Add `--json` to any command for structured output. Run `tanuki -i` for the interactive wizard.

### The decision ladder

Tanuki follows a fixed 5-rung tactical decision ladder to prevent privilege escalation loops, reduce authentication noise, and keep every action forensically defensible. The model is documented in [references/tactical_ladder.md](references/tactical_ladder.md).

| Rung | Action | Description |
| :---: | :--- | :--- |
| **0** | `DIAGNOSE` | Pre-flight audit of credentials, enctypes, and network paths |
| **1** | `AUTHENTICATE` | Userspace AS-REQ TGT negotiation with clock skew tolerance |
| **2** | `AUTHORIZE` | TGS service ticket acquisition for verified SPN endpoints |
| **3** | `ASSESS` | Quantitative blast radius calculation and tier scoring |
| **4** | `PURGE` | Cryptographic memory zeroization (NIST SP 800-88) |

---

## Validation

Tanuki is validated against live hybrid infrastructure: an unprivileged Kali workstation (UID 1000) connecting directly to a Windows Server 2022 Domain Controller (`DC01.lab.local`), proving each rung end to end through to Blue Team forensic telemetry on the DC. It also ships 500+ Python unit tests and 39 Rust tests (library plus integration), all green.

See the full milestone walkthrough with terminal proofs in [docs/VALIDATION.md](docs/VALIDATION.md).

---

## Lineage & Credits

Tanuki is engineered by **Muhammad Afif Rizi** ([@Mafifrizi](https://github.com/Mafifrizi)) and **Muhamad Dian Alvito**.

Tanuki draws inspiration and tradecraft from two foundational projects:

- **Tim Brown ([@timb-machine](https://github.com/timb-machine))**: Created [Linikatz](https://github.com/CiscoCXSecurity/linikatz) and pioneered Linux Active Directory assessment techniques, keytab analysis, and credential cache harvesting.
- **Dietrich Gebert ([@dietrichayala](https://github.com/dietrichayala))**: Created [Ponytail](https://github.com/DietrichGebert/ponytail) and demonstrated how a disciplined decision ladder prevents AI agent hallucination and conversational bloat.

### Technical Specifications Implemented

- **[RFC 4120]**: The Kerberos Network Authentication Service (V5)
- **[RFC 4511]**: Lightweight Directory Access Protocol (LDAP): The Protocol
- **[RFC 8693]**: OAuth 2.0 Token Exchange
- **[MS-KILE]**: Kerberos Protocol Extensions
- **[MS-PAC]**: Privilege Attribute Certificate Data Structure
- **[MS-DTYP]**: Windows Data Types & Security Descriptor Structures
- **[NIST SP 800-88]**: Guidelines for Media Sanitization (Rev. 1)

---

## Contributing

We welcome contributions from protocol researchers, systems engineers, and toolmakers. Tanuki enforces two hard invariants: zero external dependencies in the Python core, and `#![forbid(unsafe_code)]` in the Rust core.

- **Developer guide**: see [`CONTRIBUTING.md`](CONTRIBUTING.md) for local setup, testing commands, and PR guidelines.
- **Good first issues**: shell autocompletion (`bash` / `zsh` / `fish`), error dictionary expansion in `tanuki triage`, and SARIF or Markdown export formatters.
- **Reporting issues**: use the structured [issue templates](https://github.com/Mafifrizi/tanuki/issues/new/choose).

---

## License

Tanuki is dual-licensed under either:

- **MIT License** ([`LICENSE-MIT`](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([`LICENSE-APACHE`](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license.
