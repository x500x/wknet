param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64', 'ARM64')]
    [string]$Platform = 'x64',

    [switch]$SkipDriverBuild,
    [switch]$VmSmoke,
    [switch]$TestDriverScenarios,
    [switch]$KeepService,

    [string]$ServiceName = 'KernelHttp',
    [string]$DriverPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:OutDir = Join-Path $script:Root 'tests\out'
$script:BinDir = Join-Path $script:OutDir 'bin'
$script:TestDataDir = Join-Path $script:Root 'tests\testdata'
$script:HttpsDir = Join-Path $script:OutDir 'https-smoke'

function Write-Step {
    param([string]$Message)
    Write-Host "[kernel-http] $Message"
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory = $script:Root
    )

    Write-Step "$FilePath $($ArgumentList -join ' ')"
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory `
        -NoNewWindow `
        -Wait `
        -PassThru

    if ($process.ExitCode -ne 0) {
        throw "Command failed with exit code $($process.ExitCode): $FilePath $($ArgumentList -join ' ')"
    }
}

function Get-VsInstallationPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "vswhere.exe not found at $vswhere"
    }

    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($path)) {
        throw 'Visual Studio with VC tools was not found.'
    }

    return $path.Trim()
}

function Import-VsDevShell {
    $vsPath = Get-VsInstallationPath
    $devShell = Join-Path $vsPath 'Common7\Tools\Launch-VsDevShell.ps1'
    if (-not (Test-Path -LiteralPath $devShell)) {
        throw "Launch-VsDevShell.ps1 not found at $devShell"
    }

    $arch = if ($Platform -eq 'ARM64') { 'arm64' } else { 'amd64' }
    Write-Step "loading Visual Studio developer shell for $arch"
    & $devShell -Arch $arch -HostArch amd64 -SkipAutomaticLocation | Out-Null

    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        throw 'cl.exe is not available after loading the Visual Studio developer shell.'
    }

    if (-not (Get-Command msbuild.exe -ErrorAction SilentlyContinue)) {
        throw 'msbuild.exe is not available after loading the Visual Studio developer shell.'
    }
}

function Compile-UserModeTest {
    param(
        [string]$Name,
        [string]$Source,
        [string[]]$ProjectSources
    )

    New-Item -ItemType Directory -Force $script:BinDir | Out-Null
    $output = Join-Path $script:BinDir "$Name.exe"
    $objectDir = Join-Path $script:OutDir "obj\$Name"
    New-Item -ItemType Directory -Force $objectDir | Out-Null

    $arguments = @(
        '/nologo',
        '/std:c++17',
        '/EHsc-',
        '/GR-',
        '/W4',
        '/WX',
        '/wd4100',
        '/wd4127',
        '/D', 'KERNEL_HTTP_USER_MODE_TEST=1',
        '/I', (Join-Path $script:Root 'src\KernelHttp'),
        '/I', (Join-Path $script:Root 'third_party\brotli\c\include'),
        ('/Fe:' + $output),
        ('/Fo' + $objectDir + '\'),
        (Join-Path $script:Root $Source)
    )

    foreach ($projectSource in $ProjectSources) {
        $arguments += (Join-Path $script:Root $projectSource)
    }

    Invoke-Checked -FilePath 'cl.exe' -ArgumentList $arguments
    Invoke-Checked -FilePath $output
}

function Invoke-HostRegression {
    Import-VsDevShell

    Compile-UserModeTest `
        -Name 'http_parser_tests' `
        -Source 'tests\http_parser_tests.cpp' `
        -ProjectSources @(
            'src\KernelHttp\http\HttpTypes.cpp',
            'src\KernelHttp\http\HttpRequest.cpp',
            'src\KernelHttp\http\HttpResponse.cpp',
            'src\KernelHttp\http\HttpContentEncoding.cpp',
            'src\KernelHttp\http\HttpParser.cpp',
            'third_party\brotli\c\common\constants.c',
            'third_party\brotli\c\common\context.c',
            'third_party\brotli\c\common\dictionary.c',
            'third_party\brotli\c\common\platform.c',
            'third_party\brotli\c\common\shared_dictionary.c',
            'third_party\brotli\c\common\transform.c',
            'third_party\brotli\c\dec\bit_reader.c',
            'third_party\brotli\c\dec\decode.c',
            'third_party\brotli\c\dec\huffman.c',
            'third_party\brotli\c\dec\prefix.c',
            'third_party\brotli\c\dec\state.c',
            'third_party\brotli\c\dec\static_init.c'
        )

    Compile-UserModeTest `
        -Name 'tls_record_tests' `
        -Source 'tests\tls_record_tests.cpp' `
        -ProjectSources @(
            'src\KernelHttp\http\HttpTypes.cpp',
            'src\KernelHttp\crypto\CngProvider.cpp',
            'src\KernelHttp\crypto\CngProviderCache.cpp',
            'src\KernelHttp\tls\CertificateStore.cpp',
            'src\KernelHttp\tls\CertificateValidator.cpp',
            'src\KernelHttp\tls\TlsContext.cpp',
            'src\KernelHttp\tls\TlsHandshake12.cpp',
            'src\KernelHttp\tls\TlsHandshake13.cpp',
            'src\KernelHttp\tls\TlsRecord.cpp'
        )

    Compile-UserModeTest `
        -Name 'http2_client_tests' `
        -Source 'tests\http2_client_tests.cpp' `
        -ProjectSources @(
            'src\KernelHttp\http\HttpTypes.cpp',
            'src\KernelHttp\client\Http2Client.cpp',
            'src\KernelHttp\http2\Http2Connection.cpp',
            'src\KernelHttp\http2\Http2Frame.cpp',
            'src\KernelHttp\http2\Http2Stream.cpp',
            'src\KernelHttp\http2\Hpack.cpp',
            'src\KernelHttp\tls\TlsContext.cpp',
            'src\KernelHttp\tls\TlsHandshake12.cpp',
            'src\KernelHttp\tls\TlsHandshake13.cpp',
            'src\KernelHttp\tls\TlsRecord.cpp',
            'src\KernelHttp\tls\CertificateStore.cpp',
            'src\KernelHttp\tls\CertificateValidator.cpp',
            'src\KernelHttp\crypto\CngProvider.cpp',
            'src\KernelHttp\crypto\CngProviderCache.cpp'
        )

    Compile-UserModeTest `
        -Name 'khttp_tests' `
        -Source 'tests\khttp_tests.cpp' `
        -ProjectSources @(
            'src\KernelHttp\khttp\Khttp.cpp',
            'src\KernelHttp\khttp\AsyncOp.cpp',
            'src\KernelHttp\khttp\Http.cpp',
            'src\KernelHttp\khttp\HttpAsync.cpp',
            'src\KernelHttp\khttp\Request.cpp',
            'src\KernelHttp\khttp\Response.cpp',
            'src\KernelHttp\khttp\Session.cpp',
            'src\KernelHttp\khttp\WebSocket.cpp',
            'src\KernelHttp\engine\Engine.cpp',
            'src\KernelHttp\engine\HttpEngine.cpp',
            'src\KernelHttp\engine\UrlParser.cpp',
            'src\KernelHttp\engine\WsEngine.cpp',
            'src\KernelHttp\engine\Async.cpp',
            'src\KernelHttp\engine\ConnectionPool.cpp',
            'src\KernelHttp\engine\Workspace.cpp',
            'src\KernelHttp\http\HttpTypes.cpp',
            'src\KernelHttp\http\HttpRequest.cpp',
            'src\KernelHttp\http\HttpResponse.cpp',
            'src\KernelHttp\http\HttpContentEncoding.cpp',
            'src\KernelHttp\http\HttpParser.cpp',
            'src\KernelHttp\crypto\CngProvider.cpp',
            'src\KernelHttp\crypto\CngProviderCache.cpp',
            'src\KernelHttp\tls\CertificateStore.cpp',
            'src\KernelHttp\websocket\WebSocketFrame.cpp',
            'third_party\brotli\c\common\constants.c',
            'third_party\brotli\c\common\context.c',
            'third_party\brotli\c\common\dictionary.c',
            'third_party\brotli\c\common\platform.c',
            'third_party\brotli\c\common\shared_dictionary.c',
            'third_party\brotli\c\common\transform.c',
            'third_party\brotli\c\dec\bit_reader.c',
            'third_party\brotli\c\dec\decode.c',
            'third_party\brotli\c\dec\huffman.c',
            'third_party\brotli\c\dec\prefix.c',
            'third_party\brotli\c\dec\state.c',
            'third_party\brotli\c\dec\static_init.c'
        )

    Compile-UserModeTest `
        -Name 'high_level_api_tests' `
        -Source 'tests\high_level_api_tests.cpp' `
        -ProjectSources @(
            'src\KernelHttp\khttp\Khttp.cpp',
            'src\KernelHttp\khttp\AsyncOp.cpp',
            'src\KernelHttp\khttp\Http.cpp',
            'src\KernelHttp\khttp\HttpAsync.cpp',
            'src\KernelHttp\khttp\Request.cpp',
            'src\KernelHttp\khttp\Response.cpp',
            'src\KernelHttp\khttp\Session.cpp',
            'src\KernelHttp\khttp\WebSocket.cpp',
            'src\KernelHttp\engine\Engine.cpp',
            'src\KernelHttp\engine\HttpEngine.cpp',
            'src\KernelHttp\engine\UrlParser.cpp',
            'src\KernelHttp\engine\WsEngine.cpp',
            'src\KernelHttp\engine\Async.cpp',
            'src\KernelHttp\engine\ConnectionPool.cpp',
            'src\KernelHttp\engine\Workspace.cpp',
            'src\KernelHttp\samples\ExternalTrustStore.cpp',
            'src\KernelHttp\samples\HighLevelApiSamples.cpp',
            'src\KernelHttp\http\HttpTypes.cpp',
            'src\KernelHttp\http\HttpRequest.cpp',
            'src\KernelHttp\http\HttpResponse.cpp',
            'src\KernelHttp\http\HttpContentEncoding.cpp',
            'src\KernelHttp\http\HttpParser.cpp',
            'src\KernelHttp\crypto\CngProvider.cpp',
            'src\KernelHttp\crypto\CngProviderCache.cpp',
            'src\KernelHttp\tls\CertificateStore.cpp',
            'src\KernelHttp\websocket\WebSocketFrame.cpp',
            'third_party\brotli\c\common\constants.c',
            'third_party\brotli\c\common\context.c',
            'third_party\brotli\c\common\dictionary.c',
            'third_party\brotli\c\common\platform.c',
            'third_party\brotli\c\common\shared_dictionary.c',
            'third_party\brotli\c\common\transform.c',
            'third_party\brotli\c\dec\bit_reader.c',
            'third_party\brotli\c\dec\decode.c',
            'third_party\brotli\c\dec\huffman.c',
            'third_party\brotli\c\dec\prefix.c',
            'third_party\brotli\c\dec\state.c',
            'third_party\brotli\c\dec\static_init.c'
        )

    Compile-UserModeTest `
        -Name 'websocket_client_tests' `
        -Source 'tests\websocket_client_tests.cpp' `
        -ProjectSources @(
            'src\KernelHttp\client\WebSocketClient.cpp',
            'src\KernelHttp\http\HttpTypes.cpp',
            'src\KernelHttp\http\HttpRequest.cpp',
            'src\KernelHttp\http\HttpResponse.cpp',
            'src\KernelHttp\http\HttpParser.cpp',
            'src\KernelHttp\http\HttpContentEncoding.cpp',
            'src\KernelHttp\websocket\WebSocketFrame.cpp',
            'src\KernelHttp\crypto\CngProvider.cpp',
            'src\KernelHttp\crypto\CngProviderCache.cpp',
            'src\KernelHttp\tls\CertificateStore.cpp',
            'src\KernelHttp\tls\CertificateValidator.cpp',
            'src\KernelHttp\tls\TlsConnection.cpp',
            'src\KernelHttp\tls\TlsContext.cpp',
            'src\KernelHttp\tls\TlsHandshake12.cpp',
            'src\KernelHttp\tls\TlsHandshake13.cpp',
            'src\KernelHttp\tls\TlsRecord.cpp',
            'third_party\brotli\c\common\constants.c',
            'third_party\brotli\c\common\context.c',
            'third_party\brotli\c\common\dictionary.c',
            'third_party\brotli\c\common\platform.c',
            'third_party\brotli\c\common\shared_dictionary.c',
            'third_party\brotli\c\common\transform.c',
            'third_party\brotli\c\dec\bit_reader.c',
            'third_party\brotli\c\dec\decode.c',
            'third_party\brotli\c\dec\huffman.c',
            'third_party\brotli\c\dec\prefix.c',
            'third_party\brotli\c\dec\state.c',
            'third_party\brotli\c\dec\static_init.c'
        )

    if (-not $SkipDriverBuild) {
        $driverBuildArguments = @(
            (Join-Path $script:Root 'KernelHttp.sln'),
            '/m',
            '/restore',
            "/p:Configuration=$Configuration",
            "/p:Platform=$Platform"
        )

        $extraDefines = @()
        if ($VmSmoke) {
            $extraDefines += 'KERNEL_HTTP_REMOTE_HTTPS_ADDRESS_FAMILY_ONLY'
        }
        if ($TestDriverScenarios) {
            $extraDefines += 'KERNEL_HTTP_TEST_DRIVER_SCENARIOS'
        }
        if ($extraDefines.Count -ne 0) {
            $driverBuildArguments += "/p:KernelHttpExtraDefines=$($extraDefines -join ';')"
        }

        Invoke-Checked `
            -FilePath 'msbuild.exe' `
            -ArgumentList $driverBuildArguments
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-DriverLoadSmoke {
    if (-not (Test-IsAdministrator)) {
        throw '-VmSmoke requires an elevated pwsh session to create and load the driver service.'
    }

    $candidate = if ([string]::IsNullOrWhiteSpace($DriverPath)) {
        Join-Path $script:Root "$Platform\$Configuration\KernelHttp.sys"
    }
    else {
        $DriverPath
    }

    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Driver binary not found: $candidate"
    }

    $existing = & sc.exe query $ServiceName 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Step "removing existing service $ServiceName"
        & sc.exe stop $ServiceName | Out-Null
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Milliseconds 500
    }

    Invoke-Checked -FilePath 'sc.exe' -ArgumentList @('create', $ServiceName, 'type=', 'kernel', 'start=', 'demand', 'binPath=', $candidate)
    try {
        Invoke-Checked -FilePath 'sc.exe' -ArgumentList @('start', $ServiceName)
    }
    finally {
        if (-not $KeepService) {
            & sc.exe stop $ServiceName | Out-Null
            & sc.exe delete $ServiceName | Out-Null
        }
    }
}

Invoke-HostRegression

if ($VmSmoke) {
    Write-Step 'running remote nghttp2 HTTPS IPv4/IPv6 driver smoke'
    Invoke-DriverLoadSmoke
}

Write-Step 'regression completed'
