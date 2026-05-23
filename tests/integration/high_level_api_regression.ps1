param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64', 'ARM64')]
    [string]$Platform = 'x64',

    [switch]$SkipDriverBuild,
    [switch]$VmSmoke,
    [switch]$KeepService,

    [int]$HttpsPort = 8443,
    [string]$ServiceName = 'KernelHttp',
    [string]$DriverPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$scriptPath = Join-Path $PSScriptRoot 'https_smoke.ps1'
$arguments = @{
    Configuration = $Configuration
    Platform = $Platform
    HttpsPort = $HttpsPort
    ServiceName = $ServiceName
}

if ($SkipDriverBuild) {
    $arguments.SkipDriverBuild = $true
}

if ($VmSmoke) {
    $arguments.VmSmoke = $true
}

if ($KeepService) {
    $arguments.KeepService = $true
}

if (-not [string]::IsNullOrWhiteSpace($DriverPath)) {
    $arguments.DriverPath = $DriverPath
}

function Invoke-StaticStackCleanupCheck {
    Write-Host '[kernel-http] checking high-risk files for large local stack buffers'

    $checks = @(
        @{
            Path = 'src\KernelHttp\tls\TlsConnection.cpp'
            Patterns = @(
                'UCHAR\s+\w+\s*\[\s*(?:[2-9]\d{2,}|\d{4,})\s*\]',
                'new\s+UCHAR\s*\[\s*TlsHandshakeBufferLength\s*\]'
            )
        },
        @{
            Path = 'src\KernelHttp\tls\CertificateValidator.cpp'
            Patterns = @(
                'ParsedCertificate\s+\w+\s*\[\s*CertificateMaxChainLength\s*\]',
                'new\s+UCHAR\s*\[\s*CertificateMaxAuthorityDerLength\s*\]'
            )
        },
        @{
            Path = 'src\KernelHttp\client\HttpsClient.cpp'
            Patterns = @(
                'http::HttpHeader\s+\w+\s*\[\s*Http2MaxRequestHeaders\s*\]',
                'char\s+\w+\s*\[\s*Http2MaxRequestHeaders\s*\]\s*\[\s*Http2MaxHeaderNameLength\s*\]',
                'char\s+\w+\s*\[\s*Http2ContentLengthBufferLength\s*\]'
            )
        }
    )

    foreach ($check in $checks) {
        $path = Join-Path $script:Root $check['Path']
        $content = Get-Content -LiteralPath $path -Raw
        foreach ($pattern in $check['Patterns']) {
            if ($content -match $pattern) {
                throw "Large local stack scratch matched '$pattern' in $($check['Path']). Use KhWorkspace scratch storage instead."
            }
        }
    }
}

Invoke-StaticStackCleanupCheck
& $scriptPath @arguments
