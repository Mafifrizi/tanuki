# Tanuki for Claude Code

This repository contains **Tanuki**, an open-source, vendor-agnostic AI Agent Skill specialized in Non-Human Identity (NHI) and Linux-to-Active-Directory operations.

## Commands
- Run unit tests: `python3 -m unittest discover -s tests -v` and `cargo test --workspace`
- Build Rust engine: `cargo build --release --manifest-path crates/tanuki-cli/Cargo.toml`
- Inspect a binary keytab: `./target/release/tanuki keytab /etc/krb5.keytab` (Rust) or `python3 scripts/keytab_inspector.py /etc/krb5.keytab` (Python)
- Dump SSSD KCM caches: `./target/release/tanuki kcm -f /var/lib/sss/secrets/secrets.ldb -o ./extracted_ccache` (Rust) or `python3 scripts/kcm_parser.py -f /var/lib/sss/secrets/secrets.ldb -o ./extracted_ccache` (Python)
- Query Kerberos errors: `./target/release/tanuki triage <ERROR_CODE>`

## Code Standards
- Zero external dependencies: pure Rust standard library for `crates/tanuki-cli` with `#![forbid(unsafe_code)]`, and standard Python library only (`struct`, `io`, `sys`, `os`, `json`) for `scripts/`.
- Strictly adhere to the Tanuki 5-Rung Tactical Decision Ladder detailed in `references/tactical_ladder.md`.
- No verbose AI slop: outputs must be deterministic, military-brief, and OPSEC-conscious.
