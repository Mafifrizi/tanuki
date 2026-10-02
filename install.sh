#!/usr/bin/env bash
# Tanuki Universal One-Line Installer (Linux & macOS)
# Installs Tanuki CLI and links AI Agent Skills into Claude Code, Cursor, and Antigravity.
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}[*] Initializing Tanuki Universal Installer...${NC}"

# Detect repository directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"

# 1. Install CLI
INSTALLED=false

if command -v pipx >/dev/null 2>&1; then
    echo -e "  [+] Installing via pipx..."
    pipx install --force "${SCRIPT_DIR}"
    INSTALLED=true
elif command -v pip3 >/dev/null 2>&1; then
    echo -e "  [+] Installing via pip3..."
    pip3 install --user "${SCRIPT_DIR}" || pip3 install --break-system-packages --user "${SCRIPT_DIR}" || true
    INSTALLED=true
elif command -v pip >/dev/null 2>&1; then
    echo -e "  [+] Installing via pip..."
    pip install --user "${SCRIPT_DIR}" || true
    INSTALLED=true
fi

# Fallback standalone shim to ensure ~/.local/bin/tanuki always works
SHIM_PATH="${BIN_DIR}/tanuki"
cat <<'EOF' > "${SHIM_PATH}"
#!/usr/bin/env bash
if command -v python3 >/dev/null 2>&1; then
    exec python3 -m tanuki "$@"
elif command -v python >/dev/null 2>&1; then
    exec python -m tanuki "$@"
else
    echo "Error: Python 3 runtime is required to execute Tanuki." >&2
    exit 1
fi
EOF
chmod +x "${SHIM_PATH}"
echo -e "  [+] Created standalone CLI shim at ${SHIM_PATH}"

# Check PATH
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo -e "  [!] Note: Add ${BIN_DIR} to your PATH to run 'tanuki' directly:"
    echo "      export PATH=\"${BIN_DIR}:\$PATH\""
fi

# 2. Link AI Agent Skills
echo -e "\n${BOLD}${BLUE}[*] Configuring AI Agent Skill integrations...${NC}"

# Claude Code
CLAUDE_SKILL_DIR="${HOME}/.claude/skills/tanuki"
mkdir -p "${CLAUDE_SKILL_DIR}"
cp -r "${SCRIPT_DIR}/SKILL.md" "${SCRIPT_DIR}/references" "${SCRIPT_DIR}/scripts" "${CLAUDE_SKILL_DIR}/" 2>/dev/null || true
echo -e "  [+] Claude Code skill linked -> ${CLAUDE_SKILL_DIR}"

# Antigravity
AGY_SKILL_DIR="${HOME}/.gemini/antigravity/skills/tanuki"
mkdir -p "${AGY_SKILL_DIR}"
cp -r "${SCRIPT_DIR}/SKILL.md" "${SCRIPT_DIR}/references" "${SCRIPT_DIR}/scripts" "${AGY_SKILL_DIR}/" 2>/dev/null || true
echo -e "  [+] Antigravity skill linked -> ${AGY_SKILL_DIR}"

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
