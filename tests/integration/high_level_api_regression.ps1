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

& $scriptPath @arguments
