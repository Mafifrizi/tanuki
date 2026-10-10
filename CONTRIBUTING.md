# Contributing to Tanuki

Thank you for your interest in contributing to Tanuki. Tanuki is an autonomous Non-Human Identity (NHI) and Active Directory operator for Linux workloads, built around dual-engine architecture: a pure Python standard library core and a memory-safe static Rust binary.

We welcome contributions ranging from protocol parsing enhancements and triage dictionary expansions to documentation, tests, and shell autocompletion.

---

## Architectural Invariants

Before writing code, please review these core technical invariants. Every pull request is validated against them:

1. **Zero External Dependencies in Python Core**:
   The runtime dependencies list in `pyproject.toml` must remain empty. Tanuki parses Kerberos keytabs, ASN.1 structures, PAC data, and JWT tokens using only the Python standard library. Do not add third-party runtime dependencies.

2. **Memory Safety in Rust Core**:
   All Rust code in `crates/tanuki-cli` strictly enforces `#![forbid(unsafe_code)]`. Pull requests containing `unsafe` blocks will not be merged.

3. **Dual-Engine Parity**:
   Any new flag, subcommand, or output structure added to the Python CLI must also be implemented in the Rust CLI, and vice versa. Both engines must produce equivalent terminal output and JSON schemas.

4. **Unprivileged Execution by Default**:
   Tanuki commands must operate safely without `root` privileges wherever possible. Commands must degrade gracefully with actionable remediation when unprivileged permissions are insufficient.

5. **Strict Zero Em Dash Policy**:
   Em dash characters are forbidden across all source code, docstrings, comments, test assertions, and documentation. Use colons, commas, periods, or parentheses instead.

---

## Where to Start: Good First Issues

Looking for a place to get involved? Here are curated areas that deliver immediate value:

### 1. Shell Autocompletion
Add tab-completion scripts for `bash`, `zsh`, and `fish` to auto-complete subcommands (`doctor`, `config`, `keytab`, `auth`, `triage`, `token`, `purge`, `ladder`, `ldap`) and flags.

### 2. Protocol Error Dictionary Expansion
Expand `tanuki/triage.py` and `crates/tanuki-cli/src/telemetry.rs` with additional RFC 4120 error codes (such as `KRB_AP_ERR_BAD_INTEGRITY` [Code 31], `KDC_ERR_CANNOT_POSTDATE` [Code 13]) or Windows Security Event IDs (e.g., Event ID 4776 for NTLM credential validation).

### 3. Alternative Output Formatters
Add output formats such as `--format sarif` or `--format markdown` to `tanuki triage` or `tanuki doctor` so security teams can feed results directly into GitHub Code Scanning or pull request summaries.

### 4. Protocol Parser Edge-Case Tests
Add synthetic test vectors to `tests/test_pac.py` or `tests/test_protocol.py` that fuzz ASN.1 DER/BER boundaries, malformed keytab entries, or truncated PAC buffers.

### 5. Packaging and Distribution
Contribute distribution recipes (such as PKGBUILD for Arch Linux AUR, Alpine APKBUILD, or Homebrew formula) for the standalone static musl binary.

---

## Local Development Setup

### Python Core Setup

Requirements: Python 3.9 or newer.

```bash
# Clone the repository
git clone https://github.com/Mafifrizi/tanuki.git
cd tanuki

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode
pip install -e .
```

Verify your local installation:

```bash
tanuki --version
tanuki doctor
```

### Rust Core Setup

Requirements: Rust 1.70 or newer (`rustup`).

```bash
# Build the release binary
cargo build --release

# Run the compiled binary
./target/release/tanuki-cli doctor
```

---

## Running Tests

All pull requests must pass the test suites before merging.

### Python Test Suite

Run the full Python test suite with verbose output:

```bash
python -m unittest discover -s tests -v
```

To run a specific test module:

```bash
python -m unittest tests/test_unified_cli.py -v
```

### Rust Test Suite

Run the Rust unit and integration tests:

```bash
cargo test
```

### Em Dash and Linter Check

Verify that no forbidden em dashes exist in your changes:

```bash
python -c "
import glob, sys
bad = []
for ext in ('*.py', '*.rs', '*.md', '*.yml', '*.toml'):
    for p in glob.glob('**/' + ext, recursive=True):
        if '.venv' in p or 'target' in p or '.git' in p:
            continue
        try:
            with open(p, 'r', encoding='utf-8') as f:
                if chr(8212) in f.read():
                    bad.append(p)
        except Exception:
            pass
if bad:
    print('Forbidden em dashes found in:', bad)
    sys.exit(1)
print('Zero em dashes verified.')
"
```

---

## Pull Request Lifecycle

1. **Fork and Branch**: Create a focused branch off `main` with a descriptive name (`git checkout -b feat/shell-autocompletion` or `git checkout -b fix/keytab-overflow`).
2. **Make Targeted Changes**: Keep your changes focused. Do not mix unrelated refactors with bug fixes.
3. **Commit Messages**: Follow Conventional Commits format:
   - `feat(scope): add bash autocompletion generator`
   - `fix(triage): add RFC 4120 code 31 definition`
   - `docs(readme): update quickstart examples`
   - `test(pac): add truncated buffer test vector`
4. **Push and Open PR**: Push to your fork and submit a PR to `main`. Complete the PR checklist.
5. **CI Review**: GitHub Actions will automatically verify unit tests, Rust compilation, and binary builds. Maintainers will review your PR and provide technical feedback.

---

## Community Etiquette

- Provide reproduction steps and environment details when reporting issues.
- Keep discussions technical, constructive, and respectful.
- If you discover a sensitive security vulnerability, please report it privately via GitHub Security Advisories instead of opening a public issue.
