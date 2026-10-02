# Dual-Engine Architecture: Python vs Rust Evaluation (2026-2030)

This document outlines the architectural rationale, security evaluation, and multi-language roadmap for Tanuki.

---

## 1. Executive Summary

Tanuki adopts a **Dual-Engine Architecture**:

1. **Lightweight Fallback (Pure Python 3)**: Retained for "Living off the Land" (LotL) triage on remote targets where dropping binaries is prohibited or monitored by endpoint detection systems.
2. **High-Performance Core (Rust - Planned `crates/tanuki-cli`)**: Designed for security pipelines, container sidecars, and standalone operator workstations requiring sub-millisecond execution, zero glibc dependencies, and mathematically verified memory safety.

---

## 2. Technical Comparison Matrix

| Architectural Dimension | Pure Python Standard Library | Rust (`crates/tanuki-cli`) | Go (`gokrb5` / Tooling) |
| :--- | :--- | :--- | :--- |
| **Execution Model** | Interpreted (CPython VM) | Native Machine Code | Compiled with Go Runtime |
| **Startup Latency** | 30 to 80 ms | **0.5 to 2 ms** | 5 to 15 ms |
| **Memory Footprint (RSS)** | 25 to 40 MB | **< 5 MB** | 15 to 25 MB |
| **Binary Output Size** | None (uses system interpreter) | **2 to 5 MB** (stripped static) | 15 to 25 MB |
| **Portability** | Requires target Python 3.10+ | **100% Standalone** (`musl` target) | Standalone static binary |
| **Memory Safety** | Safe in VM, manual byte parsing | **Compile-time Memory Safety** | Memory-safe via Garbage Collector |
| **EDR / Telemetry Footprint** | Low disk noise (in-memory execution) | Drops executable binary to disk | Drops executable binary to disk |
| **Container / Distroless Fit** | Poor (requires Python runtime) | **Ideal** (single static file) | Good (single static file) |

---

## 3. Threat Modeling & Security Analysis

### A. Binary Parser Vulnerabilities
Parsing binary structures such as RFC 4120 Keytabs and SSSD KCM database records requires pointer arithmetic and length-prefixed slice extraction. Historically, C-based tools have suffered from vulnerabilities such as:
- Out-of-bounds reads on corrupted record lengths.
- Integer overflows during buffer allocation.
- Type confusion when interpreting ASN.1 DER elements.

**Rust Mitigation**:
Rust's ownership model and safe slice indexing (`&[u8]`) prevent buffer over-reads and memory corruption at compile time without runtime garbage collection pauses.

**Python Mitigation**:
Python's interpreter abstracts raw memory management, preventing memory corruption. However, malformed binary files can lead to unhandled exceptions, infinite loops, or high memory allocation if length prefixes are not strictly bounded.

### B. Operational Security (OPSEC) on Enterprise Endpoints
When an operator or automated agent audits a Linux host joined to Active Directory:
- Dropping a newly compiled binary (`/tmp/tanuki`) frequently triggers Endpoint Detection and Response (EDR) alerts, especially if the binary is unsigned or marked executable in non-standard paths.
- Running a zero-dependency script via the existing `/usr/bin/python3` binary mimics standard administrative maintenance, avoiding binary-drop detection rules.

Therefore, the pure Python implementation remains a critical operational tool for remote target triage.

---

## 4. Implementation Blueprint: Rust Core (`crates/tanuki-cli`)

The planned Rust implementation will be structured as follows:

```text
crates/
└── tanuki-cli/
    ├── Cargo.toml
    └── src/
        ├── main.rs            # CLI interface and deterministic output formatter
        ├── keytab/
        │   ├── mod.rs
        │   ├── parser.rs      # Zero-copy RFC 4120 binary keytab parser
        │   └── types.rs       # Principal, KVNO, EncType representations
        ├── kcm/
        │   ├── mod.rs
        │   └── ldb.rs         # Direct SSSD KCM CCACHE stream extractor
        └── protocol/
            ├── mod.rs
            └── kerberos.rs    # Protocol constants and error triage dictionary
```

### Key Technical Specifications for Rust Engine:
1. **Target**: `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` to guarantee glibc independence.
2. **Zero Unsafe**: Enforce `#![forbid(unsafe_code)]` across all parser modules.
3. **Zero Third-Party Network Dependencies**: Pure protocol parsing using only audited crates (`nom` for parser combinators or standard library byte slices).
4. **Deterministic JSON Output**: Support `--json` flag matching the Python tool output schema exactly for cross-engine compatibility.

---

## 5. Decision Summary

- **Keep Python**: Essential for remote, agent-driven Living off the Land workflows without disk artifacts.
- **Add Rust**: Optimal for standalone auditing, fast automated CI/CD checks, and production Kubernetes workloads where static binaries are preferred.
