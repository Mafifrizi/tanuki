#!/usr/bin/env bash
# Tanuki Universal 1-Line Installer (Linux & macOS)
# Works both inside a local clone and directly via:
# curl -sSL https://raw.githubusercontent.com/Mafifrizi/tanuki/main/install.sh | bash
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}[*] Initializing Tanuki Universal Installer...${NC}"

# Detect if running from local clone or piped via curl
LOCAL_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

REPO_URL="https://github.com/Mafifrizi/tanuki.git"
CLEANUP_TEMP=false
TEMP_DIR=""

if [ -n "${LOCAL_DIR}" ] && [ -f "${LOCAL_DIR}/pyproject.toml" ] && [ -f "${LOCAL_DIR}/SKILL.md" ]; then
    SRC_DIR="${LOCAL_DIR}"
    echo -e "  [+] Detected local repository source at ${SRC_DIR}"
elif [ -f "./pyproject.toml" ] && [ -f "./SKILL.md" ]; then
    SRC_DIR="$(pwd)"
    echo -e "  [+] Detected current working directory source at ${SRC_DIR}"
else
    TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'tanuki-install')"
    SRC_DIR="${TEMP_DIR}"
    CLEANUP_TEMP=true
    echo -e "  [+] Remote execution detected. Fetching Tanuki repository from GitHub..."
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 "${REPO_URL}" "${SRC_DIR}" --quiet
    else
        curl -sSL "https://github.com/Mafifrizi/tanuki/archive/refs/heads/main.tar.gz" | tar -xz -C "${SRC_DIR}" --strip-components=1
    fi
fi

cleanup() {
    if [ "${CLEANUP_TEMP}" = true ] && [ -d "${TEMP_DIR}" ]; then
        rm -rf "${TEMP_DIR}"
    fi
}
trap cleanup EXIT

# Detect Python 3
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo -e "${RED}[!] Error: Python 3 runtime is required to install Tanuki.${NC}" >&2
    exit 1
fi

BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"

# 1. Install Python package
echo -e "  [+] Installing Tanuki CLI package..."
if command -v pipx >/dev/null 2>&1; then
    pipx install --force "${SRC_DIR}"
elif command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    "${PYTHON_BIN}" -m pip install --user "${SRC_DIR}" 2>/dev/null || \
    "${PYTHON_BIN}" -m pip install --break-system-packages --user "${SRC_DIR}" 2>/dev/null || \
    "${PYTHON_BIN}" -m pip install "${SRC_DIR}" 2>/dev/null || true
fi

# Fallback standalone shim to ensure ~/.local/bin/tanuki always works
SHIM_PATH="${BIN_DIR}/tanuki"
cat <<EOF > "${SHIM_PATH}"
#!/usr/bin/env bash
if command -v python3 >/dev/null 2>&1; then
    exec python3 -m tanuki "\$@"
elif command -v python >/dev/null 2>&1; then
    exec python -m tanuki "\$@"
else
    echo "Error: Python 3 runtime is required to execute Tanuki." >&2
    exit 1
fi
EOF
chmod +x "${SHIM_PATH}"
echo -e "  [+] Configured CLI launcher at ${SHIM_PATH}"

# Check PATH
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo -e "  ${YELLOW}[!] Note: Add ${BIN_DIR} to your PATH to run 'tanuki' from any directory:${NC}"
    echo "      export PATH=\"${BIN_DIR}:\$PATH\""
fi

# 2. Configure AI Agent Skills
echo -e "\n${BOLD}${BLUE}[*] Configuring AI Agent Skill integrations...${NC}"

# Claude Code
CLAUDE_SKILL_DIR="${HOME}/.claude/skills/tanuki"
mkdir -p "${CLAUDE_SKILL_DIR}"
cp -r "${SRC_DIR}/SKILL.md" "${SRC_DIR}/references" "${SRC_DIR}/scripts" "${CLAUDE_SKILL_DIR}/" 2>/dev/null || true
echo -e "  [+] Claude Code skill linked -> ${CLAUDE_SKILL_DIR}"

# Google Antigravity
AGY_SKILL_DIR="${HOME}/.gemini/antigravity/skills/tanuki"
mkdir -p "${AGY_SKILL_DIR}"
cp -r "${SRC_DIR}/SKILL.md" "${SRC_DIR}/references" "${SRC_DIR}/scripts" "${AGY_SKILL_DIR}/" 2>/dev/null || true
echo -e "  [+] Google Antigravity skill linked -> ${AGY_SKILL_DIR}"

# Cursor
CURSOR_RULES_DIR="${HOME}/.cursor/rules"
mkdir -p "${CURSOR_RULES_DIR}"
cat <<'EOF' > "${CURSOR_RULES_DIR}/tanuki.mdc"
---
description: Tanuki Protocol-First Linux AD & Kerberos Triage Skill
globs: ["**/*"]
---
Always consult the 5-Rung Tactical Decision Ladder before issuing AD/Kerberos commands:
1. Local Passive Triage (/etc/krb5.keytab, /var/lib/sss/secrets/)
2. Zero-Noise OPSEC (Ban RC4-HMAC, enforce AES-256)
3. Machine Identity Reuse (HOST$)
4. Surgical Pathfinding (Shadow Credentials, AD CS ESC1/ESC8, RBCD)
5. Deterministic One-Liners: [TARGET] -> [PREREQUISITE] -> [TACTICAL COMMAND] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]
EOF
echo -e "  [+] Cursor rule linked -> ${CURSOR_RULES_DIR}/tanuki.mdc"

echo -e "\n${BOLD}${GREEN}[+] Tanuki successfully installed & integrated!${NC}"
echo "Quick Verification:"
echo "  $ tanuki --version"
echo "  $ tanuki ladder"
echo "  $ tanuki triage KRB_AP_ERR_SKEW"
