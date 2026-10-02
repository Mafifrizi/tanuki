<p align="center">
  <img src="assets/logo.jpg" alt="Tanuki Logo" width="240" />
</p>

<h1 align="center">TANUKI</h1>

<p align="center">
  <strong>Tactical Identity Operator for Linux & Hybrid Active Directory (2026–2030)</strong><br />
  <em>A protocol-first, anti-slop AI Agent Skill for surgical, zero-noise identity operations.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#the-decision-ladder">Decision Ladder</a> •
  <a href="#universal-compatibility">Compatibility</a> •
  <a href="#lineage--acknowledgements">Lineage & Credits</a> •
  <a href="#license">License</a>
</p>

---

## What is Tanuki?

Most security guides and AI coding assistants assume an operator sits at a Windows workstation running PowerShell and Mimikatz. In reality, modern enterprise infrastructure runs on **Linux**—cloud virtual machines, container workloads, Kubernetes nodes, and CI/CD runners integrated into Active Directory via SSSD and Kerberos.

When standard AI agents try to assist on Linux, they fail predictably:
1. They search for tickets in `/tmp/` (ignoring modern SSSD KCM databases).
2. They suggest deprecated RC4-HMAC ciphers that trigger Kerberos error alerts.
3. They propose noisy brute-force password sprays that lock domain accounts.
4. They dump pages of generic AI slop instead of deterministic commands.

**Tanuki** is an AI Agent Skill that fixes this. Built on protocol-first mechanics and a strict 5-rung decision ladder, Tanuki transforms your AI coding agent into a razor-sharp, stealthy identity operator.

---

## The Decision Ladder

Before suggesting any command or triage action, Tanuki walks a strict 5-rung operational ladder:

```text
[5] DETERMINISTIC ONE-LINER  ──► Output only: [TARGET] -> [COMMAND] -> [ARTIFACT]
           ▲
[4] SURGICAL PATHFINDING    ──► Prioritize minimal-hop vectors (AD CS, Shadow Credentials, RBCD)
           ▲
[3] MACHINE REUSE (LotD)    ──► Leverage existing machine keytabs before hunting user creds
           ▲
[2] ZERO-NOISE OPSEC        ──► Enforce AES-256; strictly ban RC4 and password spraying
           ▲
[1] LOCAL PASSIVE TRIAGE    ──► Triage /etc/krb5.keytab & SSSD KCM before sending network packets
```

---

## Universal Compatibility

Tanuki is engineered to run seamlessly across all major AI agent platforms:

| Platform | Integration Method | Configuration Path |
| :--- | :--- | :--- |
| **Google Antigravity** | Native Skill Module | Placed in `scratch/tanuki` or skills directory |
| **Anthropic Claude Code** | Native Skill / Guidelines | Reads `SKILL.md` and `CLAUDE.md` automatically |
| **Cursor** | Custom Project Rule | `.cursor/rules/tanuki.mdc` |
| **Cline / Windsurf / Codex** | Universal System Prompt | `AGENTS.md` |

---

## Repository Structure

```text
tanuki/
├── assets/
│   └── logo.jpg               # Official Tanuki logo (floating head, unmasking smirk)
├── scripts/
│   ├── keytab_inspector.py    # Standalone RFC 4120 binary keytab triage tool
│   └── kcm_parser.py          # Standalone SSSD KCM secrets.ldb CCACHE extractor
├── references/
│   ├── tactical_ladder.md     # Detailed 5-Rung Operator Decision Ladder
│   ├── adcs_matrix.md         # Certipy ESC1-ESC11 cheatsheet and PKINIT parameters
│   ├── error_triage.md        # Kerberos/SSSD error resolution matrix
│   └── nhi_mesh.md            # Non-Human Identity & Workload Federation (2026-2030)
├── tests/
│   ├── test_keytab_inspector.py
│   └── test_kcm_parser.py
├── SKILL.md                   # Universal Skill specification
├── AGENTS.md                  # Standard multi-agent instructions
├── CLAUDE.md                  # Claude Code project guide
├── .cursor/rules/tanuki.mdc   # Cursor rule format
├── LICENSE                    # MIT License
└── README.md
```

---

## Quick Start

### 1. Test Keytab Triage
Inspect a binary keytab without external Python dependencies:
```bash
python3 scripts/keytab_inspector.py /etc/krb5.keytab
```

### 2. Extract SSSD KCM Credential Caches
Scan local SSSD KCM database stores for unencrypted CCACHE v4 streams:
```bash
python3 scripts/kcm_parser.py -o ./extracted_tickets
```

### 3. Run Self-Verification Tests
```bash
python3 -m unittest discover -s tests -v
```

---

## Lineage & Acknowledgements

Tanuki is an independent project that proudly honors the foundational work of two pioneers:

* **Tim Brown ([@timb-machine](https://github.com/timb-machine))**: For pioneering UNIX/Linux Active Directory post-exploitation, keytab analysis, and credential cache harvesting through [Linikatz](https://github.com/CiscoCXSecurity/linikatz) and `unix-privesc-check`.
* **Dietrich Gebert ([@dietrichayala](https://github.com/dietrichayala))**: For creating [Ponytail](https://github.com/DietrichGebert/ponytail) and demonstrating how a disciplined "Decision Ladder" eliminates AI agent bloat and over-engineering.

---

## License

This project is licensed under the [MIT License](LICENSE).
