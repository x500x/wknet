param(
    [string]$Destination = (Join-Path $PSScriptRoot '..\certs\cacert.pem')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$certifiPath = python -c 'import certifi; print(certifi.where())'
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($certifiPath)) {
    throw 'Unable to locate certifi cacert.pem. Install or update the Python certifi package first.'
}

$resolvedSource = (Resolve-Path -LiteralPath $certifiPath.Trim()).Path
$destinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
$destinationDir = Split-Path -Parent $destinationPath

New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
Copy-Item -LiteralPath $resolvedSource -Destination $destinationPath -Force

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $destinationPath
Write-Host "Updated $destinationPath"
Write-Host "Source: $resolvedSource"
Write-Host "SHA256: $($hash.Hash)"
