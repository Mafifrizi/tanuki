# AGENTS.md: Tanuki System Instructions

## Project Summary
Tanuki is a universal AI Agent Skill providing deterministic triage for Linux-to-Active-Directory hybrid identity environments.

## Operating Principles
1. **Never Guess Command Flags**: Consult `scripts/` and `references/` for exact parameters.
2. **Prioritize Local Artifacts**: Always check `/etc/krb5.keytab` and `/var/lib/sss/secrets/secrets.ldb` before advising network scans.
3. **Enforce Clean Brevity**: Provide actionable one-liners. Strip disclaimers and boilerplate.
4. **Follow the Decision Ladder**: Triage -> Zero-Noise -> Machine LotD -> Surgical Hop -> One-Liner.
