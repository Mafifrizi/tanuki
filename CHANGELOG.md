# Changelog

## v2.1.5 (2026-11-22)

- Hardened Rust file I/O with O_NOFOLLOW + (st_dev, st_ino) regular-file pinning across keytab, krb5.conf, SSSD, /dev/urandom, and NIST SP 800-88 purge pre-unlink verification.
- Enforced ccache symlink rejection in `tanuki tgs` even without `--keytab`, and propagated `generate_krb5_conf` errors in `tanuki fix`.
- Replaced substring AD CS JSON extraction with AST-backed `parse_json` evaluation, hardened RFC 8693 exchange URL parsing against `userinfo@host` and query/fragment confusion, and made `sAMAccountName` matching case-insensitive in LDAP output.
- Added Kerberos enctype 16 (`des3-cbc-sha1`) to weak-enctype checks in both Python and Rust engines, synced `--help` option parity, and surfaced explicit Rust behavior for `--use-ctypes` and `--ssl`.
- Resolved all mypy type errors and ruff unused-import/f-string issues, and reconciled the 5-rung Tactical Decision Ladder numbering in documentation.

## v2.1.4 (2026-11-21)

- Synchronized Python and Rust CLI parity across all 18 subcommands, added `O_NOFOLLOW` guards, keytab SHA-256 fingerprints, and documentation hygiene updates.
