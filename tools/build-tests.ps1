#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Test,
    [switch]$Run
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found; cannot locate Visual Studio."
    }
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ([string]::IsNullOrWhiteSpace($vsPath)) {
        throw "Visual Studio with VC tools was not found."
    }
    $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"
    & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$testCpp = Join-Path $repoRoot "tests\$Test.cpp"
if (-not (Test-Path $testCpp)) {
    throw "Test source not found: $testCpp"
}

$binDir = Join-Path $repoRoot 'tests\out\bin'
$objDir = Join-Path $repoRoot "tests\out\obj\$Test"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
New-Item -ItemType Directory -Force -Path $objDir | Out-Null
$exePath = Join-Path $binDir "$Test.exe"

# Kernel-facing entry points are opt-in per test. Some tests provide local stubs
# for WSK/TLS classes, so keep the default source set conservative.
$excludedLibSources = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    'Http2Client.cpp', 'HttpClient.cpp', 'HttpsClient.cpp',
    'KernelHttpConfig.cpp', 'WebSocketClient.cpp', 'WskSocket.cpp'
) | ForEach-Object { [void]$excludedLibSources.Add($_) }

switch ($Test) {
    'http2_client_tests' {
        [void]$excludedLibSources.Remove('Http2Client.cpp')
        [void]$excludedLibSources.Remove('HttpsClient.cpp')
        [void]$excludedLibSources.Add('TlsConnection.cpp')
    }
    'khttp_tests' {
        [void]$excludedLibSources.Remove('WskClient.cpp')
        [void]$excludedLibSources.Remove('WskSocket.cpp')
        [void]$excludedLibSources.Remove('Http2Client.cpp')
    }
    'high_level_api_tests' {
        [void]$excludedLibSources.Remove('WskClient.cpp')
    }
    'websocket_client_tests' {
        [void]$excludedLibSources.Add('WskClient.cpp')
        [void]$excludedLibSources.Remove('WebSocketClient.cpp')
    }
}

$libSources = Get-ChildItem -Path (Join-Path $repoRoot 'src\KernelHttpLib') -Recurse -Filter '*.cpp' |
    Where-Object { -not $excludedLibSources.Contains($_.Name) } |
    ForEach-Object { $_.FullName }

# Only the high-level integration test pulls in sample translation units, and only the
# three samples that compile under the user-mode harness. The HTTP/1.1-, HTTP/2-verb and
# khttp samples call kernel-only client classes (HttpsClient/Http2Client/WebSocketClient)
# that have no user-mode implementation, so they are excluded.
$sampleSources = @()
if ($Test -eq 'high_level_api_tests') {
    $sampleSources = @(
        'samples\AdvancedScenarioSamples.cpp',
        'samples\ExternalTrustStore.cpp',
        'samples\HighLevelApiSamples.cpp'
    ) | ForEach-Object { Join-Path $repoRoot "src\KernelHttpTest\$_" }
}

$brotliRoot = Join-Path $repoRoot 'third_party\brotli\c'
$brotliSources = @(
    'common\constants.c', 'common\context.c', 'common\dictionary.c',
    'common\platform.c', 'common\shared_dictionary.c', 'common\transform.c',
    'dec\bit_reader.c', 'dec\decode.c', 'dec\huffman.c',
    'dec\prefix.c', 'dec\state.c', 'dec\static_init.c'
) | ForEach-Object { Join-Path $brotliRoot $_ }
$zstdSources = @(
    Join-Path $repoRoot 'third_party\zstd\zstddeclib.c'
)

$includeArgs = @(
    "/I", (Join-Path $repoRoot 'include'),
    "/I", (Join-Path $repoRoot 'src\KernelHttpTest'),
    "/I", (Join-Path $brotliRoot 'include')
)

$clArgs = @(
    '/nologo', '/source-charset:utf-8', '/execution-charset:.936',
    '/std:c++17', '/EHsc-', '/GR-', '/W4', '/WX', '/wd4100', '/wd4127',
    '/D', 'KERNEL_HTTP_USER_MODE_TEST=1'
) + $includeArgs + @(
    "/Fe:$exePath",
    "/Fo:$objDir\"
) + @($testCpp) + $libSources + $sampleSources + $brotliSources + $zstdSources

& cl.exe @clArgs
if ($LASTEXITCODE -ne 0) {
    throw "cl.exe failed with exit code $LASTEXITCODE"
}

Write-Host "Built $exePath"

if ($Run) {
    & $exePath
    exit $LASTEXITCODE
}
