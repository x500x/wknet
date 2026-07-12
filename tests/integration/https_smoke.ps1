param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64', 'ARM64')]
    [string]$Platform = 'x64',

    [switch]$SkipDriverBuild,
    [switch]$VmSmoke,
    [switch]$TestDriverScenarios,
    [switch]$KeepService,

    [string]$ServiceName = 'wknettest',
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
    Write-Host "[wknet] $Message"
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
        '/source-charset:utf-8',
        '/execution-charset:.936',
        '/std:c++17',
        '/EHsc-',
        '/GR-',
        '/W4',
        '/WX',
        '/wd4100',
        '/wd4127',
        '/D', 'WKNET_USER_MODE_TEST=1',
        '/I', (Join-Path $script:Root 'include'),
        '/I', (Join-Path $script:Root 'src\wknettest'),
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
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\http1\HttpRequest.cpp',
            'src\wknetlib\http1\HttpResponse.cpp',
            'src\wknetlib\codec\ContentCoding.cpp',
            'src\wknetlib\http1\HttpContentEncoding.cpp',
            'src\wknetlib\http1\HttpTransferCoding.cpp',
            'src\wknetlib\http1\HttpParser.cpp',
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
        -Name 'tls_crypto_tests' `
        -Source 'tests\tls_crypto_tests.cpp' `
        -ProjectSources @(
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\crypto\Aead.cpp',
            'src\wknetlib\crypto\CngProvider.cpp',
            'src\wknetlib\crypto\CngProviderCache.cpp',
            'src\wknetlib\crypto\KeyExchange.cpp'
        )

    Compile-UserModeTest `
        -Name 'tls_handshake_tests' `
        -Source 'tests\tls_handshake_tests.cpp' `
        -ProjectSources @(
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\crypto\Aead.cpp',
            'src\wknetlib\crypto\CngProvider.cpp',
            'src\wknetlib\crypto\CngProviderCache.cpp',
            'src\wknetlib\crypto\KeyExchange.cpp',
            'src\wknetlib\tls\CertificateStore.cpp',
            'src\wknetlib\tls\CertificateValidator.cpp',
            'src\wknetlib\tls\TlsCapabilities.cpp',
            'src\wknetlib\tls\TlsConnection.cpp',
            'src\wknetlib\tls\TlsContext.cpp',
            'src\wknetlib\tls\TlsHandshake12.cpp',
            'src\wknetlib\tls\TlsHandshake13.cpp',
            'src\wknetlib\tls\TlsPolicy.cpp',
            'src\wknetlib\tls\TlsRecord.cpp'
        )

    Compile-UserModeTest `
        -Name 'tls_interop_matrix_tests' `
        -Source 'tests\tls_interop_matrix_tests.cpp' `
        -ProjectSources @(
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\tls\CertificateStore.cpp',
            'src\wknetlib\tls\TlsCapabilities.cpp',
            'src\wknetlib\tls\TlsPolicy.cpp'
        )

    Compile-UserModeTest `
        -Name 'tls_record_tests' `
        -Source 'tests\tls_record_tests.cpp' `
        -ProjectSources @(
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\crypto\Aead.cpp',
            'src\wknetlib\crypto\CngProvider.cpp',
            'src\wknetlib\crypto\CngProviderCache.cpp',
            'src\wknetlib\crypto\KeyExchange.cpp',
            'src\wknetlib\tls\CertificateStore.cpp',
            'src\wknetlib\tls\CertificateValidator.cpp',
            'src\wknetlib\tls\TlsCapabilities.cpp',
            'src\wknetlib\tls\TlsConnection.cpp',
            'src\wknetlib\tls\TlsContext.cpp',
            'src\wknetlib\tls\TlsHandshake12.cpp',
            'src\wknetlib\tls\TlsHandshake13.cpp',
            'src\wknetlib\tls\TlsPolicy.cpp',
            'src\wknetlib\tls\TlsRecord.cpp'
        )

    Compile-UserModeTest `
        -Name 'http2_client_tests' `
        -Source 'tests\http2_client_tests.cpp' `
        -ProjectSources @(
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\session\Http2RequestBuilder.cpp',
            'src\wknetlib\transport\TlsTransport.cpp',
            'src\wknetlib\session\Workspace.cpp',
            'src\wknetlib\http2\Http2Connection.cpp',
            'src\wknetlib\http2\Http2Frame.cpp',
            'src\wknetlib\http2\Http2Stream.cpp',
            'src\wknetlib\http2\Hpack.cpp',
            'src\wknetlib\tls\TlsContext.cpp',
            'src\wknetlib\tls\TlsHandshake12.cpp',
            'src\wknetlib\tls\TlsHandshake13.cpp',
            'src\wknetlib\tls\TlsRecord.cpp',
            'src\wknetlib\tls\CertificateStore.cpp',
            'src\wknetlib\tls\CertificateValidator.cpp',
            'src\wknetlib\tls\TlsCapabilities.cpp',
            'src\wknetlib\tls\TlsPolicy.cpp',
            'src\wknetlib\crypto\Aead.cpp',
            'src\wknetlib\crypto\CngProvider.cpp',
            'src\wknetlib\crypto\CngProviderCache.cpp',
            'src\wknetlib\crypto\KeyExchange.cpp'
        )

    Compile-UserModeTest `
        -Name 'khttp_tests' `
        -Source 'tests\khttp_tests.cpp' `
        -ProjectSources @(
            'src\wknetlib\http_api\Khttp.cpp',
            'src\wknetlib\http_api\AsyncOp.cpp',
            'src\wknetlib\http_api\Http.cpp',
            'src\wknetlib\http_api\HttpAsync.cpp',
            'src\wknetlib\http_api\Request.cpp',
            'src\wknetlib\http_api\Response.cpp',
            'src\wknetlib\http_api\Session.cpp',
            'src\wknetlib\http_api\WebSocket.cpp',
            'src\wknetlib\session\Engine.cpp',
            'src\wknetlib\session\HttpEngine.cpp',
            'src\wknetlib\session\UrlParser.cpp',
            'src\wknetlib\session\WsEngine.cpp',
            'src\wknetlib\session\Async.cpp',
            'src\wknetlib\session\ConnectionPool.cpp',
            'src\wknetlib\session\Workspace.cpp',
            'src\wknetlib\net\WskClient.cpp',
            'src\wknetlib\net\WskSocket.cpp',
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\http1\HttpRequest.cpp',
            'src\wknetlib\http1\HttpResponse.cpp',
            'src\wknetlib\codec\ContentCoding.cpp',
            'src\wknetlib\http1\HttpContentEncoding.cpp',
            'src\wknetlib\http1\HttpTransferCoding.cpp',
            'src\wknetlib\http1\HttpParser.cpp',
            'src\wknetlib\crypto\CngProvider.cpp',
            'src\wknetlib\crypto\CngProviderCache.cpp',
            'src\wknetlib\crypto\KeyExchange.cpp',
            'src\wknetlib\tls\CertificateStore.cpp',
            'src\wknetlib\tls\TlsCapabilities.cpp',
            'src\wknetlib\tls\TlsPolicy.cpp',
            'src\wknetlib\ws\WebSocketFrame.cpp',
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
            'src\wknetlib\http_api\Khttp.cpp',
            'src\wknetlib\http_api\AsyncOp.cpp',
            'src\wknetlib\http_api\Http.cpp',
            'src\wknetlib\http_api\HttpAsync.cpp',
            'src\wknetlib\http_api\Request.cpp',
            'src\wknetlib\http_api\Response.cpp',
            'src\wknetlib\http_api\Session.cpp',
            'src\wknetlib\http_api\WebSocket.cpp',
            'src\wknetlib\session\Engine.cpp',
            'src\wknetlib\session\HttpEngine.cpp',
            'src\wknetlib\session\UrlParser.cpp',
            'src\wknetlib\session\WsEngine.cpp',
            'src\wknetlib\session\Async.cpp',
            'src\wknetlib\session\ConnectionPool.cpp',
            'src\wknetlib\session\Workspace.cpp',
            'src\wknettest\samples\AdvancedScenarioSamples.cpp',
            'src\wknettest\samples\ExternalTrustStore.cpp',
            'src\wknettest\samples\HighLevelApiSamples.cpp',
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\http1\HttpRequest.cpp',
            'src\wknetlib\http1\HttpResponse.cpp',
            'src\wknetlib\codec\ContentCoding.cpp',
            'src\wknetlib\http1\HttpContentEncoding.cpp',
            'src\wknetlib\http1\HttpTransferCoding.cpp',
            'src\wknetlib\http1\HttpParser.cpp',
            'src\wknetlib\crypto\CngProvider.cpp',
            'src\wknetlib\crypto\CngProviderCache.cpp',
            'src\wknetlib\crypto\KeyExchange.cpp',
            'src\wknetlib\tls\CertificateStore.cpp',
            'src\wknetlib\tls\TlsCapabilities.cpp',
            'src\wknetlib\tls\TlsPolicy.cpp',
            'src\wknetlib\ws\WebSocketFrame.cpp',
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
            'src\wknetlib\session\WsConnection.cpp',
            'src\wknetlib\http1\HttpTypes.cpp',
            'src\wknetlib\http1\HttpRequest.cpp',
            'src\wknetlib\http1\HttpResponse.cpp',
            'src\wknetlib\codec\ContentCoding.cpp',
            'src\wknetlib\http1\HttpParser.cpp',
            'src\wknetlib\http1\HttpTransferCoding.cpp',
            'src\wknetlib\http1\HttpContentEncoding.cpp',
            'src\wknetlib\ws\WebSocketFrame.cpp',
            'src\wknetlib\crypto\Aead.cpp',
            'src\wknetlib\crypto\CngProvider.cpp',
            'src\wknetlib\crypto\CngProviderCache.cpp',
            'src\wknetlib\crypto\KeyExchange.cpp',
            'src\wknetlib\tls\CertificateStore.cpp',
            'src\wknetlib\tls\CertificateValidator.cpp',
            'src\wknetlib\tls\TlsCapabilities.cpp',
            'src\wknetlib\tls\TlsConnection.cpp',
            'src\wknetlib\tls\TlsContext.cpp',
            'src\wknetlib\tls\TlsHandshake12.cpp',
            'src\wknetlib\tls\TlsHandshake13.cpp',
            'src\wknetlib\tls\TlsPolicy.cpp',
            'src\wknetlib\tls\TlsRecord.cpp',
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
            (Join-Path $script:Root 'wknet.sln'),
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
        Join-Path $script:Root "$Platform\$Configuration\wknettest.sys"
    }
    else {
        $DriverPath
    }

    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Driver binary not found: $candidate"
    }

    $certificateSource = Join-Path $script:Root 'certs\cacert.pem'
    if (-not (Test-Path -LiteralPath $certificateSource)) {
        throw "Certificate bundle not found: $certificateSource"
    }

    $driverDirectory = Split-Path -Parent $candidate
    $certificateTarget = Join-Path $driverDirectory 'cacert.pem'
    Copy-Item -LiteralPath $certificateSource -Destination $certificateTarget -Force

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
