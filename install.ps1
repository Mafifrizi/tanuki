# Tanuki Universal 1-Line Installer (Windows PowerShell)
# Works both inside a local clone and directly via:
# irm https://raw.githubusercontent.com/Mafifrizi/tanuki/main/install.ps1 | iex
$ErrorActionPreference = "Stop"

Write-Host "`n[*] Initializing Tanuki Universal Installer for Windows..." -ForegroundColor Cyan

# 1. Resolve source repository (local clone vs remote bootstrap)
$ScriptDir = ""
try {
    if ($MyInvocation.MyCommand.Path) {
        $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
} catch {}

$SourceDir = ""
$TempDir = ""
$CleanupTemp = $false

if ($ScriptDir -and (Test-Path (Join-Path $ScriptDir "pyproject.toml")) -and (Test-Path (Join-Path $ScriptDir "SKILL.md"))) {
    $SourceDir = $ScriptDir
    Write-Host "  [+] Detected local repository source at $SourceDir" -ForegroundColor Gray
} elseif ((Test-Path ".\pyproject.toml") -and (Test-Path ".\SKILL.md")) {
    $SourceDir = (Get-Location).Path
    Write-Host "  [+] Detected working directory source at $SourceDir" -ForegroundColor Gray
} else {
    $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tanuki_install_" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    Write-Host "  [+] Remote execution detected. Fetching Tanuki repository from GitHub..." -ForegroundColor Gray
    
    if (Get-Command git -ErrorAction SilentlyContinue) {
        & git clone --depth 1 https://github.com/Mafifrizi/tanuki.git $TempDir --quiet
    } else {
        $ZipPath = Join-Path $TempDir "tanuki.zip"
        Invoke-WebRequest -Uri "https://github.com/Mafifrizi/tanuki/archive/refs/heads/main.zip" -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force
        $Extracted = Join-Path $TempDir "tanuki-main"
        if (Test-Path $Extracted) {
            Get-ChildItem -Path $Extracted | Move-Item -Destination $TempDir -Force
        }
    }
    $SourceDir = $TempDir
    $CleanupTemp = $true
}

# 2. Install Python package
Write-Host "  [+] Installing Tanuki CLI package via pip..." -ForegroundColor Gray
try {
    & python -m pip install --quiet "$SourceDir"
    Write-Host "  [+] Python package installed successfully." -ForegroundColor Green
} catch {
    Write-Warning "Standard pip install encountered an issue: $_. Falling back to development install."
    & python -m pip install -e "$SourceDir"
}

# 3. Configure AI Agent Skills
Write-Host "`n[*] Configuring AI Agent Skill integrations..." -ForegroundColor Cyan

# Claude Code
$ClaudeDir = Join-Path $HOME ".claude\skills\tanuki"
New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null
Copy-Item -Path (Join-Path $SourceDir "SKILL.md") -Destination $ClaudeDir -Force
Copy-Item -Path (Join-Path $SourceDir "references") -Destination $ClaudeDir -Recurse -Force
Copy-Item -Path (Join-Path $SourceDir "scripts") -Destination $ClaudeDir -Recurse -Force
Write-Host "  [+] Claude Code skill linked -> $ClaudeDir" -ForegroundColor Green

# Google Antigravity
$AgyDir = Join-Path $HOME ".gemini\antigravity\skills\tanuki"
New-Item -ItemType Directory -Path $AgyDir -Force | Out-Null
Copy-Item -Path (Join-Path $SourceDir "SKILL.md") -Destination $AgyDir -Force
Copy-Item -Path (Join-Path $SourceDir "references") -Destination $AgyDir -Recurse -Force
Copy-Item -Path (Join-Path $SourceDir "scripts") -Destination $AgyDir -Recurse -Force
Write-Host "  [+] Google Antigravity skill linked -> $AgyDir" -ForegroundColor Green

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

# 4. Clean temporary download if remote
if ($CleanupTemp -and (Test-Path $TempDir)) {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n[+] Tanuki successfully installed & integrated!" -ForegroundColor Green
Write-Host "Quick Verification:"
Write-Host "  PS> tanuki --version"
Write-Host "  PS> tanuki ladder"
Write-Host "  PS> tanuki triage KRB_AP_ERR_SKEW`n"
