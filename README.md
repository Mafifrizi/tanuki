<p align="center">
  <img src="assets/logo.jpg" alt="Tanuki Logo" width="220" />
</p>

# Tanuki

Linux and Active Directory authentication triage skill for AI coding agents.

## Overview

Tanuki provides operational knowledge and helper scripts for inspecting Active Directory authentication on Linux systems. It covers Kerberos keytabs, SSSD credential caches, certificate-based authentication, and non-human identity federation.

Standard agent prompts often assume Active Directory triage happens on Windows with PowerShell. When working on Linux hosts, agents need different tools, file paths, and protocol defaults. Tanuki defines those steps so agents can diagnose authentication issues and audit permissions without guesswork or destructive commands.

## Decision Ladder

Tanuki uses a 5-step ladder to order triage actions:

1. **Local passive triage**: Inspect `/etc/krb5.keytab` and local SSSD caches before sending traffic over the network.
2. **Safe protocol defaults**: Use AES-256 for Kerberos requests. Avoid deprecated ciphers like RC4 and do not use password spraying.
3. **Machine credentials first**: Check host keytabs and service accounts before requesting human user credentials.
4. **Targeted identity vectors**: Evaluate Active Directory Certificate Services (ADCS) templates, resource-based constrained delegation, and shadow credentials.
5. **Deterministic output**: Return specific commands with targets and expected artifacts rather than open-ended explanations.

## Usage

### Inspect a Keytab
Inspect encryption types and principal names in an existing keytab file without external dependencies:

```bash
python3 scripts/keytab_inspector.py /etc/krb5.keytab
```

### Extract SSSD KCM Credential Caches
Parse local SSSD KCM database files (`secrets.ldb`) to extract ticket caches:

```bash
python3 scripts/kcm_parser.py -o ./extracted_tickets
```

### Run Tests
Verify helper scripts using the standard Python test runner:

```bash
python3 -m unittest discover -s tests -v
```

## Agent Setup

| Agent | Location |
| :--- | :--- |
| Antigravity | Place repository in skills directory or active workspace |
| Claude Code | Add `SKILL.md` to project root or reference in prompt |
| Cursor | `.cursor/rules/tanuki.mdc` |
| Cline, Windsurf, Codex | Reference `AGENTS.md` in system prompt |

## Repository Structure

```text
tanuki/
├── assets/
│   └── logo.jpg               # Project logo
├── scripts/
│   ├── keytab_inspector.py    # Binary keytab inspection script
│   └── kcm_parser.py          # SSSD KCM credential cache parser
├── references/
│   ├── tactical_ladder.md     # Detailed 5-step operational ladder
│   ├── adcs_matrix.md         # ADCS certificate templates and PKINIT parameters
│   ├── error_triage.md        # Kerberos and SSSD error resolution table
│   └── nhi_mesh.md            # Workload identity and token exchange reference
├── tests/
│   ├── test_keytab_inspector.py
│   └── test_kcm_parser.py
├── SKILL.md                   # Universal skill definition
├── AGENTS.md                  # Multi-agent prompt file
├── CLAUDE.md                  # Claude Code project guide
├── .cursor/rules/tanuki.mdc   # Cursor rule definition
├── LICENSE                    # MIT License
└── README.md
```

## References

- `references/tactical_ladder.md`: Technical rationale for each step in the decision ladder.
- `references/adcs_matrix.md`: Common ADCS misconfigurations (ESC1 to ESC11) and PKINIT parameters.
- `references/error_triage.md`: Error codes for Kerberos and SSSD with diagnostic steps.
- `references/nhi_mesh.md`: Token exchange and workload identity federation patterns.

## Acknowledgements

Tanuki builds on ideas from two projects:

- **Tim Brown ([@timb-machine](https://github.com/timb-machine))**: Created [Linikatz](https://github.com/CiscoCXSecurity/linikatz) and documented Linux Active Directory post-exploitation techniques, keytab analysis, and credential cache harvesting.
- **Dietrich Gebert ([@dietrichayala](https://github.com/dietrichayala))**: Created [Ponytail](https://github.com/DietrichGebert/ponytail) and introduced the decision ladder concept to keep AI agent workflows structured and concise.

## License

MIT License. See [LICENSE](LICENSE) for details.
