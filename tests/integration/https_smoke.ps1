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
        -Name 'high_level_api_tests' `
        -Source 'tests\high_level_api_tests.cpp' `
        -ProjectSources @(
            'src\KernelHttp\api\KernelHttpApi.cpp',
            'src\KernelHttp\api\KernelHttpAsync.cpp',
            'src\KernelHttp\api\KernelHttpConnectionPool.cpp',
            'src\KernelHttp\api\KernelHttpWorkspace.cpp',
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
            $extraDefines += 'KERNEL_HTTP_LOCAL_HTTPS_SMOKE_ONLY'
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

function Ensure-TestCertificate {
    New-Item -ItemType Directory -Force $script:HttpsDir | Out-Null
    $certPath = Join-Path $script:TestDataDir 'localhost.cert.pem'
    $keyPath = Join-Path $script:TestDataDir 'localhost.key.pem'

    if ((Test-Path -LiteralPath $certPath) -and (Test-Path -LiteralPath $keyPath)) {
        return @{
            CertPath = $certPath
            KeyPath = $keyPath
        }
    }

    $openssl = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if (-not $openssl) {
        throw 'openssl.exe is required for -VmSmoke HTTPS service certificate generation.'
    }

    $configPath = Join-Path $script:TestDataDir 'openssl-localhost.cnf'
    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "OpenSSL config not found: $configPath"
    }

    Invoke-Checked `
        -FilePath $openssl.Source `
        -ArgumentList @(
            'req',
            '-x509',
            '-newkey', 'rsa:2048',
            '-sha256',
            '-days', '7',
            '-nodes',
            '-keyout', $keyPath,
            '-out', $certPath,
            '-config', $configPath
        )

    return @{
        CertPath = $certPath
        KeyPath = $keyPath
    }
}

function Start-LocalHttpsService {
    $material = Ensure-TestCertificate
    $wwwRoot = Join-Path $script:HttpsDir 'www'
    New-Item -ItemType Directory -Force $wwwRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $script:TestDataDir 'sample_response_body.txt') -Destination (Join-Path $wwwRoot 'sample_response_body.txt') -Force

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $python) {
        throw 'python.exe is required for -VmSmoke HTTPS service.'
    }

    $serverScript = Join-Path $script:HttpsDir 'serve_https.py'
    $serverStdoutLog = Join-Path $script:HttpsDir 'server.stdout.log'
    $serverStderrLog = Join-Path $script:HttpsDir 'server.stderr.log'
    @"
import functools
import http.server
import ssl

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=r'$wwwRoot')
server = http.server.ThreadingHTTPServer(('127.0.0.1', $HttpsPort), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
if hasattr(ssl, 'TLSVersion'):
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile=r'$($material.CertPath)', keyfile=r'$($material.KeyPath)')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
"@ | Set-Content -LiteralPath $serverScript -Encoding ASCII

    Write-Step "starting local HTTPS service on https://127.0.0.1:$HttpsPort/"
    $process = Start-Process `
        -FilePath $python.Source `
        -ArgumentList @('-S', $serverScript) `
        -WorkingDirectory $wwwRoot `
        -RedirectStandardOutput $serverStdoutLog `
        -RedirectStandardError $serverStderrLog `
        -WindowStyle Hidden `
        -PassThru

    try {
        $deadline = (Get-Date).AddSeconds(10)
        $ready = $false
        do {
            if ($process.HasExited) {
                $serverOutput = ''
                if (Test-Path -LiteralPath $serverStdoutLog) {
                    $serverOutput += Get-Content -LiteralPath $serverStdoutLog -Raw
                }

                if (Test-Path -LiteralPath $serverStderrLog) {
                    $serverOutput += Get-Content -LiteralPath $serverStderrLog -Raw
                }

                throw "HTTPS smoke service exited early with code $($process.ExitCode). $serverOutput"
            }

            try {
                $response = Invoke-WebRequest `
                    -Uri "https://127.0.0.1:$HttpsPort/sample_response_body.txt" `
                    -SkipCertificateCheck `
                    -UseBasicParsing
                if ($response.StatusCode -eq 200 -and $response.Content -match 'kernel-http smoke') {
                    $ready = $true
                    break
                }
            }
            catch {
                if ((Get-Date) -ge $deadline) {
                    throw
                }

                Start-Sleep -Milliseconds 250
            }
        } while ((Get-Date) -lt $deadline)

        if (-not $ready) {
            throw 'HTTPS smoke service did not return expected test body.'
        }
    }
    catch {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw
    }

    return $process
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
    $server = Start-LocalHttpsService
    try {
        Invoke-DriverLoadSmoke
    }
    finally {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Step 'regression completed'
