# Tanuki for Claude Code

This repository contains **Tanuki**, an open-source, vendor-agnostic AI Agent Skill specialized in Non-Human Identity (NHI) and Linux-to-Active-Directory operations.

## Commands
- Run unit tests: `python3 -m unittest discover -s tests -v`
- Inspect a binary keytab: `python3 scripts/keytab_inspector.py /etc/krb5.keytab`
- Dump SSSD KCM caches: `python3 scripts/kcm_parser.py -f /var/lib/sss/secrets/secrets.ldb -o ./extracted_ccache`

## Code Standards
- Zero external pip dependencies for core helpers; use standard Python library only (`struct`, `io`, `sys`, `os`, `json`).
- Strictly adhere to the Tanuki 5-Rung Tactical Decision Ladder detailed in `references/tactical_ladder.md`.
- No verbose AI slop; outputs must be deterministic, military-brief, and OPSEC-conscious.
