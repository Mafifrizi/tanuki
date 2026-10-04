# AGENTS.md: Tanuki System Instructions

## Project Summary
Tanuki is a universal AI Agent Skill providing deterministic triage for Linux-to-Active-Directory hybrid identity environments.

## Operating Principles
1. **Never Guess Command Flags**: Consult `crates/tanuki-cli` or `tanuki/` and `references/` for exact parameters.
2. **Prioritize Local Artifacts**: Always check `/etc/krb5.keytab` and `/var/lib/sss/secrets/secrets.ldb` before advising network scans.
3. **Enforce Clean Brevity**: Provide actionable one-liners. Strip conversational disclaimers, decorative lines, and boilerplate.
4. **Follow the Decision Ladder**: Triage -> Zero-Noise -> Machine LotD -> Surgical Hop -> One-Liner with Blue Telemetry.
5. **Parse Deterministic Exit Codes**: Use `--json` to inspect structured error envelopes and semantic return codes (0: success, 1: usage, 2: policy stop, 3: resource missing, 4: parse failure).
