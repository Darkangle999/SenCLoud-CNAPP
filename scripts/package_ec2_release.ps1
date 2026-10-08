param(
  [Parameter(Mandatory = $true)]
  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$required = @(
  (Join-Path $repoRoot 'src'),
  (Join-Path $repoRoot 'frontend\dist'),
  (Join-Path $repoRoot 'deploy\aws'),
  (Join-Path $repoRoot 'scripts\install-trivy.sh'),
  (Join-Path $repoRoot 'scanner-go\go.mod'),
  (Join-Path $repoRoot 'scanner-go\go.sum'),
  (Join-Path $repoRoot 'pyproject.toml'),
  (Join-Path $repoRoot 'requirements.txt')
)

foreach ($path in $required) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw "Required deployment input is missing: $path"
  }
}

# Linux release scripts must not carry Windows CRLF bytes. A CRLF installer
# passes ZIP presence checks but Bash reads `pipefail\r` and the host build
# fails before container replacement.
foreach ($shellScript in @(
  (Join-Path $repoRoot 'scripts\install-trivy.sh'),
  (Join-Path $repoRoot 'deploy\aws\deploy-release.sh')
)) {
  $bytes = [System.IO.File]::ReadAllBytes($shellScript)
  for ($i = 0; $i -lt ($bytes.Length - 1); $i++) {
    if ($bytes[$i] -eq 13 -and $bytes[$i + 1] -eq 10) {
      throw "Linux release script contains CRLF line endings: $shellScript"
    }
  }
}

$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) {
  Remove-Item -LiteralPath $destination -Force
}

# Build the scanner on the developer/CI machine rather than on the free-tier
# t3.micro host. The AWS SDK's EC2 module is large enough to make an on-host
# compile slow and memory-sensitive. The scanner is pure Go, so this static
# cross-build needs no Linux toolchain or CGO.
$scannerModule = Join-Path $repoRoot 'scanner-go'
$scannerOutputDirectory = Join-Path $scannerModule 'bin'
$scannerOutput = Join-Path $scannerOutputDirectory 'odineyes-scanner-linux-amd64'
$graphOutput = Join-Path $scannerOutputDirectory 'odineyes-graph-linux-amd64'
$realtimeOutput = Join-Path $scannerOutputDirectory 'odineyes-realtime-linux-amd64'
New-Item -ItemType Directory -Force -Path $scannerOutputDirectory | Out-Null
$previousGoos = $env:GOOS
$previousGoarch = $env:GOARCH
$previousCgo = $env:CGO_ENABLED
try {
  $env:GOOS = 'linux'
  $env:GOARCH = 'amd64'
  $env:CGO_ENABLED = '0'
  Push-Location $scannerModule
  try {
    & go build -trimpath -ldflags '-s -w' -o $scannerOutput ./cmd/odineyes-scanner
    if ($LASTEXITCODE -ne 0) {
      throw "Unable to build the Go AWS scanner."
    }
    & go build -trimpath -ldflags '-s -w' -o $graphOutput ./cmd/odineyes-graph
    if ($LASTEXITCODE -ne 0) {
      throw "Unable to build the Go attack-path engine."
    }
    & go build -trimpath -ldflags '-s -w' -o $realtimeOutput ./cmd/odineyes-realtime
    if ($LASTEXITCODE -ne 0) {
      throw "Unable to build the Go real-time worker."
    }
  }
  finally {
    Pop-Location
  }
}
finally {
  $env:GOOS = $previousGoos
  $env:GOARCH = $previousGoarch
  $env:CGO_ENABLED = $previousCgo
}

# Compress-Archive can be prohibitively slow on Windows when the workspace is
# watched by IDE/antivirus processes. The Windows tar utility creates the same
# ZIP artifact while preserving the directory layout expected by the EC2 host.
& tar.exe -a -c -f $destination `
  --exclude='src/odineyes/tests' `
  --exclude='src/__pycache__' `
  --exclude='src/**/__pycache__' `
  --exclude='src/*.pyc' `
  --exclude='src/**/*.pyc' `
  --exclude='src/cloudsentinel.egg-info' `
  --exclude='src/odineyes.egg-info' `
  -C $repoRoot src frontend/dist deploy/aws scripts/install-trivy.sh `
  scanner-go/bin/odineyes-scanner-linux-amd64 `
  scanner-go/bin/odineyes-graph-linux-amd64 `
  scanner-go/bin/odineyes-realtime-linux-amd64 pyproject.toml requirements.txt
if ($LASTEXITCODE -ne 0) {
  throw "Unable to create deployment archive: $destination"
}
Write-Output $destination
