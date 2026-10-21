<#
.SYNOPSIS
    Installs NIGHTWATCH Forwarder Agent as a native Windows Service.
.DESCRIPTION
    Creates configuration directory, sets ACL permissions, registers
    service with Service Control Manager, and configures auto-restart.
#>

[CmdletBinding()]
param (
    [string]$ConfigPath = "C:\ProgramData\Nightwatch\agent.json",
    [string]$InstallDir = "C:\Program Files\Nightwatch",
    [string]$PythonExe = "python.exe"
)

# 1. Elevate check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please re-run from an elevated PowerShell prompt."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  NIGHTWATCH Forwarder Agent Windows Service Installer   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. Setup ProgramData directories with strict ACLs
$ProgramDataDir = "C:\ProgramData\Nightwatch"
$DataDir = "$ProgramDataDir\data"
$CertsDir = "$ProgramDataDir\certs"

foreach ($dir in @($ProgramDataDir, $DataDir, $CertsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[+] Created directory: $dir" -ForegroundColor Green
    }
}

# 3. Harden Permissions (Administrators and SYSTEM only)
Write-Host "[*] Hardening directory permissions..." -ForegroundColor Yellow
$acl = Get-Acl $ProgramDataDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
Set-Acl $ProgramDataDir $acl

# 4. Set Environment Variable for default config
[System.Environment]::SetEnvironmentVariable("NIGHTWATCH_CONFIG", $ConfigPath, "Machine")
Write-Host "[+] Set NIGHTWATCH_CONFIG to $ConfigPath" -ForegroundColor Green

# 5. Register Service using python win32serviceutil
Write-Host "[*] Registering NightwatchAgent Windows Service..." -ForegroundColor Yellow
$scriptPath = Join-Path $PSScriptRoot "windows_service.py"

& $PythonExe $scriptPath --startup auto install
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Windows Service registered successfully!" -ForegroundColor Green

    # Configure Failure Actions: restart service after 5s, 10s, 30s
    & sc.exe failure NightwatchAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000
    Write-Host "[+] Configured automatic recovery restart actions." -ForegroundColor Green
    Write-Host "`nTo start the service now, run: Start-Service NightwatchAgent" -ForegroundColor Cyan
} else {
    Write-Error "Service installation failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
