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
$thirdPartyObjDir = Join-Path $objDir 'third_party'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
New-Item -ItemType Directory -Force -Path $objDir | Out-Null
New-Item -ItemType Directory -Force -Path $thirdPartyObjDir | Out-Null
$exePath = Join-Path $binDir "$Test.exe"

# Kernel-facing entry points are opt-in per test. Some tests provide local stubs
# for WSK/TLS classes, so keep the default source set conservative.
$excludedLibSources = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    'WknetConfig.cpp', 'WsConnection.cpp', 'WskSocket.cpp', 'TransportWsk.cpp'
) | ForEach-Object { [void]$excludedLibSources.Add($_) }

switch ($Test) {
    'datagram_socket_tests' {
        [void]$excludedLibSources.Remove('WskClient.cpp')
    }
    'http_api_tests' {
        [void]$excludedLibSources.Remove('WskClient.cpp')
        [void]$excludedLibSources.Remove('WskSocket.cpp')
        [void]$excludedLibSources.Remove('TransportWsk.cpp')
    }
    'high_level_api_tests' {
        [void]$excludedLibSources.Remove('WskClient.cpp')
    }
    'websocket_client_tests' {
        [void]$excludedLibSources.Add('WskClient.cpp')
        [void]$excludedLibSources.Remove('WsConnection.cpp')
    }
}

$libSources = Get-ChildItem -Path (Join-Path $repoRoot 'src\wknetlib') -Recurse -Filter '*.cpp' |
    Where-Object { -not $excludedLibSources.Contains($_.Name) } |
    ForEach-Object { $_.FullName }

# Only the high-level integration test pulls in the public-API sample translation units.
$sampleSources = @()
if ($Test -eq 'high_level_api_tests') {
    $sampleSources = @(
        'samples\AdvancedScenarioSamples.cpp',
        'samples\ExternalTrustStore.cpp',
        'samples\HighLevelApiSamples.cpp'
    ) | ForEach-Object { Join-Path $repoRoot "src\wknettest\$_" }
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
$thirdPartySources = @($brotliSources) + @($zstdSources)
$thirdPartyObjects = @($thirdPartySources | ForEach-Object {
    Join-Path $thirdPartyObjDir (([System.IO.Path]::GetFileNameWithoutExtension($_)) + '.obj')
})

$thirdPartyArgs = @(
    '/nologo', '/c', '/TC', '/W3', '/WX-',
    '/source-charset:utf-8', '/execution-charset:.936',
    '/D', 'WKNET_USER_MODE_TEST=1',
    '/I', (Join-Path $brotliRoot 'include'),
    "/Fo:$thirdPartyObjDir\"
) + $thirdPartySources

& cl.exe @thirdPartyArgs
if ($LASTEXITCODE -ne 0) {
    throw "third-party cl.exe failed with exit code $LASTEXITCODE"
}

$includeArgs = @(
    "/I", (Join-Path $repoRoot 'include'),
    "/I", (Join-Path $repoRoot 'src\wknetlib'),
    "/I", (Join-Path $repoRoot 'src\wknettest'),
    "/I", (Join-Path $brotliRoot 'include')
)

$clArgs = @(
    '/nologo', '/source-charset:utf-8', '/execution-charset:.936',
    '/std:c++17', '/EHsc-', '/GR-', '/Wall', '/WX',
    '/wd4061', '/wd4100', '/wd4127', '/wd4255', '/wd4365', '/wd4464',
    '/wd4514', '/wd4603', '/wd4623', '/wd4625', '/wd4626', '/wd4627',
    '/wd4668', '/wd4710', '/wd4711', '/wd4820', '/wd4986', '/wd4987', '/wd5026',
    '/wd5027', '/wd5032', '/wd5045', '/wd5220', '/wd5246',
    '/D', 'WKNET_USER_MODE_TEST=1'
) + $includeArgs + @(
    "/Fe:$exePath",
    "/Fo:$objDir\"
) + @($testCpp) + $libSources + $sampleSources + $thirdPartyObjects

& cl.exe @clArgs
if ($LASTEXITCODE -ne 0) {
    throw "cl.exe failed with exit code $LASTEXITCODE"
}

Write-Host "Built $exePath"

if ($Run) {
    & $exePath
    exit $LASTEXITCODE
}
