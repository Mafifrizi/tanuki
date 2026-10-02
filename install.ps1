# Tanuki Universal One-Line Installer (Windows PowerShell)
# Installs Tanuki CLI and links AI Agent Skills into Claude Code, Cursor, and Antigravity.
$ErrorActionPreference = "Stop"

Write-Host "`n[*] Initializing Tanuki Universal Installer for Windows..." -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) {
    $ScriptDir = Get-Location
}

# 1. Install Python package
Write-Host "  [+] Installing Tanuki CLI package..." -ForegroundColor Gray
try {
    & python -m pip install --quiet "$ScriptDir"
    Write-Host "  [+] Python package installed successfully." -ForegroundColor Green
} catch {
    Write-Warning "Direct pip install encountered an issue: $_. Falling back to development install."
    & python -m pip install -e "$ScriptDir"
}

# 2. Configure AI Agent Skills
Write-Host "`n[*] Configuring AI Agent Skill integrations..." -ForegroundColor Cyan

# Claude Code
$ClaudeDir = Join-Path $HOME ".claude\skills\tanuki"
New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null
Copy-Item -Path (Join-Path $ScriptDir "SKILL.md") -Destination $ClaudeDir -Force
Copy-Item -Path (Join-Path $ScriptDir "references") -Destination $ClaudeDir -Recurse -Force
Copy-Item -Path (Join-Path $ScriptDir "scripts") -Destination $ClaudeDir -Recurse -Force
Write-Host "  [+] Claude Code skill linked -> $ClaudeDir" -ForegroundColor Green

# Antigravity
$AgyDir = Join-Path $HOME ".gemini\antigravity\skills\tanuki"
New-Item -ItemType Directory -Path $AgyDir -Force | Out-Null
Copy-Item -Path (Join-Path $ScriptDir "SKILL.md") -Destination $AgyDir -Force
Copy-Item -Path (Join-Path $ScriptDir "references") -Destination $AgyDir -Recurse -Force
Copy-Item -Path (Join-Path $ScriptDir "scripts") -Destination $AgyDir -Recurse -Force
Write-Host "  [+] Antigravity skill linked -> $AgyDir" -ForegroundColor Green

# Cursor
$CursorDir = Join-Path $HOME ".cursor\rules"
New-Item -ItemType Directory -Path $CursorDir -Force | Out-Null
$CursorRule = @"
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
"@
Set-Content -Path (Join-Path $CursorDir "tanuki.mdc") -Value $CursorRule -Encoding UTF8
Write-Host "  [+] Cursor rule linked -> $(Join-Path $CursorDir "tanuki.mdc")" -ForegroundColor Green

Write-Host "`n[+] Tanuki successfully installed & integrated!" -ForegroundColor Green
Write-Host "Quick Verification:"
Write-Host "  PS> tanuki --version"
Write-Host "  PS> tanuki ladder"
Write-Host "  PS> tanuki triage KRB_AP_ERR_SKEW`n"
