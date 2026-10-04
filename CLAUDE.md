# Tanuki for Claude Code

This repository contains **Tanuki**, an open-source, vendor-agnostic AI Agent Skill specialized in Non-Human Identity (NHI) and Linux-to-Active-Directory operations.

## Commands
- Run unit tests: `python3 -m unittest discover -s tests -v` and `cargo test --workspace`
- Build Rust engine: `cargo build --release --manifest-path crates/tanuki-cli/Cargo.toml`
- Pre-flight diagnostic (<1ms): `tanuki doctor [--json]`
- Unprivileged config synthesis: `tanuki config --realm REALM --kdc DC_IP [--clock-skew SEC] [--enforce-aes] -o ./krb5.conf`
- Inspect binary keytab (RFC 4120): `tanuki keytab /etc/krb5.keytab [--json]`
- Dump SSSD KCM caches: `tanuki kcm [-f /var/lib/sss/secrets/secrets.ldb] [-o ./extracted_ccache]`
- Query Kerberos errors & Blue Telemetry: `tanuki triage <ERROR_CODE>`
- Unprivileged ticket acquisition: `tanuki auth --keytab <KEYTAB> --principal <PRINCIPAL> [-o <CCACHE>]`
- Decode MS-PAC NDR structures: `tanuki pac <PAC_BINARY_OR_HEX>`
- Validate NHI workload token (RFC 8693): `tanuki token <JWT>`
- Idempotent self-healing: `tanuki fix [--keytab <KEYTAB>] [--realm <REALM>] [--kdc <DC_IP>]`
- Cryptographic zero-trace purge: `tanuki purge [--all]`
- Export AI Agent Skill manifest: `tanuki skill [--json]`

## Code Standards
- Zero external dependencies: pure standard library in Python (`struct`, `ctypes`, `socket`, `json`, `base64`) and `#![forbid(unsafe_code)]` in Rust `crates/tanuki-cli`.
- Strictly adhere to the Tanuki 5-Rung Tactical Decision Ladder detailed in `references/tactical_ladder.md`.
- No verbose AI slop: outputs must be deterministic, military-brief, and OPSEC-conscious.
- Semantic exit codes (0: success, 1: usage, 2: policy stop, 3: resource missing, 4: parse failure).
