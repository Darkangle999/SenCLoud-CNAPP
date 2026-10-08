<#
.SYNOPSIS
Run Odineyes API natively from Windows PowerShell.

.DESCRIPTION
Uses a Windows virtual environment, a Windows-native SQLite path, and the AWS
CLI profile already configured on Windows. It does not invoke WSL, Docker, or
Linux-only runtime tooling. Tetragon/eBPF and Linux package inspection remain
remote Linux workload features, not local API requirements.
#>
[CmdletBinding()]
param(
    [int]$Port = 8000,
    [string]$BindAddress = '127.0.0.1',
    [string]$AwsProfile = '',
    [string]$DatabasePath = '',
    [switch]$Install,
    [switch]$NoReload
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    if (-not $Install) {
        throw "Windows virtual environment missing. Re-run with -Install."
    }
    & py -3 -m venv (Join-Path $projectRoot '.venv')
}

if ($Install) {
    & $python -m pip install --upgrade pip
    & $python -m pip install -e '.[aws,db,dev]'
}

if (-not (Test-Path -LiteralPath $python)) {
    throw "Python executable missing: $python"
}

if (-not $DatabasePath) {
    $dataRoot = Join-Path $env:LOCALAPPDATA 'Odineyes'
    New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
    $DatabasePath = Join-Path $dataRoot 'odineyes.db'
}

$dbFullPath = [System.IO.Path]::GetFullPath($DatabasePath)
$dbUriPath = $dbFullPath.Replace('\', '/')
$env:ODINEYES_DATABASE_URL = "sqlite:///$dbUriPath"
$env:PYTHONPATH = Join-Path $projectRoot 'src'
$env:AWS_SDK_LOAD_CONFIG = '1'

# Deployment settings that carry a secret (the onboarding token signing key)
# live in a gitignored .env.local rather than in this tracked script. Already
# exported values win, so CI and container runs are unaffected.
$envFile = Join-Path $projectRoot '.env.local'
if (Test-Path -LiteralPath $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $name, $value = $trimmed -split '=', 2
        $name = $name.Trim()
        if (-not $name -or -not $value) { continue }
        if (-not [Environment]::GetEnvironmentVariable($name)) {
            Set-Item -Path "env:$name" -Value $value.Trim().Trim('"')
        }
    }
    Write-Host "Loaded $envFile"
}

# Prefer an explicit command-line value, then a local environment value. The
# AWS CLI's default profile is a safe final fallback; the old hard-coded
# cloudsentinel-dev profile often points at deleted or expired credentials.
if (-not $AwsProfile) {
    $AwsProfile = if ($env:AWS_PROFILE) { $env:AWS_PROFILE } else { 'default' }
}

if ($AwsProfile) {
    $env:AWS_PROFILE = $AwsProfile

    # Resolve the exact AWS account from the selected shared-config profile
    # before starting the API. This lets onboarding generate a safe trust
    # template locally without requiring a separately copied account ID.
    try {
        $awsCommand = Get-Command aws -ErrorAction Stop
        $identityJson = & $awsCommand.Source sts get-caller-identity `
            --profile $AwsProfile --output json 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "AWS CLI could not authenticate profile '$AwsProfile'."
        }
        $callerIdentity = $identityJson | ConvertFrom-Json
        $callerAccountId = [string]$callerIdentity.Account
        if ($callerAccountId -notmatch '^\d{12}$') {
            throw "AWS STS did not return a valid 12-digit account ID."
        }
        if (
            $env:ODINEYES_AWS_ACCOUNT_ID -and
            $env:ODINEYES_AWS_ACCOUNT_ID -ne $callerAccountId
        ) {
            throw (
                "ODINEYES_AWS_ACCOUNT_ID does not match AWS profile '$AwsProfile'. " +
                "Profile resolved to $callerAccountId."
            )
        }
        $env:ODINEYES_AWS_ACCOUNT_ID = $callerAccountId
    }
    catch {
        throw (
            "Unable to use AWS profile '$AwsProfile'. Configure it locally with " +
            "'aws configure --profile $AwsProfile', then verify it with " +
            "'aws sts get-caller-identity --profile $AwsProfile'. $($_.Exception.Message)"
        )
    }
}

Push-Location $projectRoot
try {
    $arguments = @('-m', 'uvicorn', 'odineyes.api.server:app', '--host', $BindAddress, '--port', $Port.ToString())
    if (-not $NoReload) {
        $arguments += '--reload'
    }

    Write-Host "Odineyes API: http://${BindAddress}:$Port"
    Write-Host "SQLite DB: $dbFullPath"
    Write-Host "AWS profile: $($env:AWS_PROFILE)"
    Write-Host "Scanner AWS account: $($env:ODINEYES_AWS_ACCOUNT_ID)"
    & $python @arguments
}
finally {
    Pop-Location
}
