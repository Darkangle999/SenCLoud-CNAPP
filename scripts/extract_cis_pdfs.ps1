# Extract the three CIS AWS benchmark PDFs (user's Downloads folder) into the
# gitignored .cis-extract/ directory as plain text, ready for
# scripts/generate_cis_catalogs.py. Requires pdftotext (poppler).
param(
  [string]$DownloadsPath = (Join-Path $env:USERPROFILE 'Downloads')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$extract = Join-Path $repoRoot '.cis-extract'
New-Item -ItemType Directory -Force -Path $extract | Out-Null

if (-not (Get-Command pdftotext -ErrorAction SilentlyContinue)) {
  throw "pdftotext not found. Install poppler (e.g. 'choco install poppler' or 'winget install --id=oschwartz10612.Poppler'), or extract the PDFs manually into $extract."
}

$pdfs = [ordered]@{
  'compute-v2.txt' = 'CIS AWS Compute Services Benchmark v2.0.0 - PDF.pdf'
  'storage-v1.txt' = 'CIS_AWS_Storage_Services_Benchmark_v1.0.0.pdf'
  'euc-v1.2.txt'   = 'CIS_AWS_End_User_Compute_Services_Benchmark_v1.2.0.pdf'
}

foreach ($target in $pdfs.Keys) {
  $pdf = Join-Path $DownloadsPath $pdfs[$target]
  if (-not (Test-Path -LiteralPath $pdf)) {
    throw "Benchmark PDF missing: $pdf"
  }
  & pdftotext -layout $pdf (Join-Path $extract $target)
  if ($LASTEXITCODE -ne 0) {
    throw "pdftotext failed for $pdf"
  }
  Write-Output "extracted $target"
}

Write-Output 'Next: python scripts/generate_cis_catalogs.py'