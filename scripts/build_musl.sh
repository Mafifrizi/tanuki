#!/usr/bin/env bash
# Tanuki 2.0 Static Musl Binary Build Script
# Compiles zero-dependency statically linked Linux binaries via Musl libc.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/dist/bin"

TARGET="${1:-x86_64-unknown-linux-musl}"

echo "[*] Tanuki 2.0 Static Musl Build Pipeline"
echo "    Target Architecture: ${TARGET}"
echo "    Repository Root:     ${REPO_ROOT}"
echo "    Output Directory:    ${OUTPUT_DIR}"

mkdir -p "${OUTPUT_DIR}"

if command -v cargo &>/dev/null; then
    echo "[*] Host cargo detected. Installing target ${TARGET}..."
    rustup target add "${TARGET}" || true
    echo "[*] Compiling static release binary..."
    cd "${REPO_ROOT}"
    cargo build --release --target "${TARGET}"
    
    BIN_SRC="${REPO_ROOT}/target/${TARGET}/release/tanuki"
    BIN_DEST="${OUTPUT_DIR}/tanuki-${TARGET}"
    
    echo "[*] Stripping symbols for zero-trace footprint..."
    if command -v strip &>/dev/null; then
        strip "${BIN_SRC}" || true
    fi
    
    cp "${BIN_SRC}" "${BIN_DEST}"
    chmod +x "${BIN_DEST}"
    echo "[+] Static Musl binary built successfully: ${BIN_DEST}"
elif command -v docker &>/dev/null; then
    echo "[*] Host cargo not detected. Utilizing containerized Alpine Musl build..."
    docker run --rm \
        -v "${REPO_ROOT}:/volume" \
        -w /volume \
        rust:alpine \
        sh -c "apk add --no-cache musl-dev && cargo build --release --target ${TARGET} && strip target/${TARGET}/release/tanuki"
        
    BIN_SRC="${REPO_ROOT}/target/${TARGET}/release/tanuki"
    BIN_DEST="${OUTPUT_DIR}/tanuki-${TARGET}"
    cp "${BIN_SRC}" "${BIN_DEST}"
    chmod +x "${BIN_DEST}"
    echo "[+] Containerized Musl binary built successfully: ${BIN_DEST}"
else
    echo "[!] Error: Neither cargo nor docker is available in PATH." >&2
    exit 1
fi

echo "[*] Verifying static binary properties..."
if command -v file &>/dev/null; then
    file "${BIN_DEST}"
fi
echo "[+] Build complete."
