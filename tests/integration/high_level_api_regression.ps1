param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64', 'ARM64')]
    [string]$Platform = 'x64',

    [switch]$SkipDriverBuild,
    [switch]$VmSmoke,
    [switch]$TestDriverScenarios,
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

if ($TestDriverScenarios -or (-not $SkipDriverBuild -and -not $VmSmoke)) {
    $arguments.TestDriverScenarios = $true
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

function Invoke-MainDriverSamplePathCheck {
    Write-Host '[kernel-http] checking main driver sample path uses high-level API'

    $driverEntryPath = Join-Path $script:Root 'src\KernelHttp\DriverEntry.cpp'
    $driverEntry = Get-Content -LiteralPath $driverEntryPath -Raw
    if ($driverEntry -notmatch 'samples/HighLevelApiSamples\.h') {
        throw 'DriverEntry must include HighLevelApiSamples.h for load-time samples.'
    }
    if ($driverEntry -match 'samples/HttpVerbSamples\.h' -or
        $driverEntry -match 'RunHttpVerbSamples' -or
        $driverEntry -match 'RunHttp2VerbSamples') {
        throw 'DriverEntry must not route main-driver samples through legacy low-level sample matrices.'
    }
    if ($driverEntry -notmatch 'KhSessionCreate' -or $driverEntry -notmatch 'KhSessionClose') {
        throw 'DriverEntry must create and close a high-level API session around samples.'
    }
    if ($driverEntry -notmatch 'KERNEL_HTTP_TEST_DRIVER_SCENARIOS') {
        throw 'DriverEntry must expose the explicit test-driver scenario matrix build switch.'
    }

    $highLevelSamplesPath = Join-Path $script:Root 'src\KernelHttp\samples\HighLevelApiSamples.cpp'
    $highLevelSamples = Get-Content -LiteralPath $highLevelSamplesPath -Raw
    if ($highLevelSamples -match 'client/HttpsClient\.h' -or
        $highLevelSamples -match 'client/WebSocketClient\.h' -or
        $highLevelSamples -match 'tls/TlsConnection\.h') {
        throw 'HighLevelApiSamples must use KernelHttp::api entrypoints, not direct low-level clients.'
    }
    if ($highLevelSamples -notmatch 'samples/ExternalTrustStore\.h' -or
        $highLevelSamples -notmatch 'InitializeExternalTrustStore') {
        throw 'Verified high-level HTTPS/WebSocket samples must initialize external trust data.'
    }
    if ($highLevelSamples -match 'echo\.websocket\.org' -or
        $highLevelSamples -notmatch 'wss://ws\.postman-echo\.com/raw') {
        throw 'HighLevelApiSamples must use the live Postman WebSocket echo endpoint instead of deprecated echo.websocket.org.'
    }
    if ($highLevelSamples -notmatch 'tlsOptions\.MinVersion\s*=\s*api::KhTlsVersion::Tls12' -or
        $highLevelSamples -notmatch 'tlsOptions\.MaxVersion\s*=\s*api::KhTlsVersion::Tls12') {
        throw 'HighLevelApiSamples must pin the live WebSocket echo sample to TLS 1.2 until the TLS 1.3 WebSocket path is validated.'
    }
    if ($highLevelSamples -match 'NgHttp2LeafSpkiSha256' -or
        $highLevelSamples -match 'NgHttp2LetsEncrypt' -or
        $highLevelSamples -match 'WebSocketEchoLeafSpkiSha256' -or
        $highLevelSamples -match 'WebSocketEchoLetsEncrypt') {
        throw 'Verified public-site samples must use the external CA bundle instead of hard-coded site certificate SPKI data.'
    }
}

Invoke-StaticStackCleanupCheck
Invoke-MainDriverSamplePathCheck
& $scriptPath @arguments
