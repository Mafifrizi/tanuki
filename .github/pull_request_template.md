## Description

<!-- Provide a concise description of the change, bug fix, or new capability. -->

## Type of Change

- [ ] Bug fix (`fix:`)
- [ ] New feature (`feat:`)
- [ ] Documentation update (`docs:`)
- [ ] Performance or refactoring (`refactor:`)
- [ ] Test suite enhancement (`test:`)

## Architecture and Quality Checklist

- [ ] **Zero External Dependencies**: Python code introduces zero external runtime dependencies into `pyproject.toml` (pure standard library only).
- [ ] **Rust Memory Safety**: Any Rust code adheres strictly to `#![forbid(unsafe_code)]` with zero `unsafe` blocks.
- [ ] **Dual-Engine Parity**: CLI flags and features have been reviewed for parity between Python and Rust engines.
- [ ] **Unprivileged Safety**: All operations run unprivileged without requiring root permissions wherever possible.
- [ ] **Code Hygiene**: Verified that changes adhere to project formatting standards with no residual debug code.
- [ ] **Tests Added and Passing**: New tests are included, and the full test suite passes (`python -m unittest discover -s tests -v` and `cargo test`).
