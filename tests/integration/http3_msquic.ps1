#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [ValidateSet('x64')]
    [string]$Platform = 'x64',
    [ValidateRange(1, 1800)]
    [int]$TimeoutSeconds = 180,
    [ValidateSet(
        'handshake',
        'get-response-body',
        'head-no-body',
        'post-request-body',
        'trailers',
        'concurrent',
        'goaway',
        'cancel',
        'retry',
        'vn',
        'loss-reorder',
        'key-update'
    )]
    [string[]]$Scenario = @(
        'handshake',
        'get-response-body',
        'head-no-body',
        'post-request-body',
        'trailers',
        'concurrent',
        'goaway',
        'cancel',
        'retry',
        'vn',
        'loss-reorder',
        'key-update'
    )
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixtureRoot = Join-Path $repoRoot 'tests\fixtures\http3'
$peerRoot = Join-Path $repoRoot 'tests\out\http3-peers'
$sourceArchive = Join-Path $peerRoot 'msquic-v2.5.8.zip'
$sourceParent = Join-Path $peerRoot 'msquic-src'
$sourceRoot = Join-Path $sourceParent 'msquic-2.5.8'
$xdpArchive = Join-Path $peerRoot 'xdp-f23b1fb4.zip'
$xdpExtract = Join-Path $peerRoot 'xdp-extract'
$xdpTarget = Join-Path $sourceRoot 'submodules\xdp-for-windows'
$buildRoot = Join-Path $peerRoot 'msquic-build'
$peerOutput = Join-Path $peerRoot 'msquic-peer'
$peerExecutable = Join-Path $peerOutput 'msquic_peer.exe'
$manifest = Import-PowerShellDataFile (Join-Path $fixtureRoot 'peer-manifest.psd1')
$opensslCommand = Get-Command openssl.exe -ErrorAction SilentlyContinue
if ($null -ne $opensslCommand) {
    $openssl = $opensslCommand.Source
}
else {
    $openssl = @(
        'C:\Program Files\Git\mingw64\bin\openssl.exe',
        'C:\Program Files\Git\usr\bin\openssl.exe'
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($openssl)) {
    throw 'OpenSSL was not found for isolated test PKCS#12 generation.'
}

function Assert-FileHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Expected
    )
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for $Path. Expected $Expected, actual $actual."
    }
}

New-Item -ItemType Directory -Force -Path $peerRoot, $peerOutput | Out-Null
if (-not (Test-Path -LiteralPath $sourceArchive)) {
    Invoke-WebRequest -Uri $manifest.MsQuic.SourceUri -OutFile $sourceArchive
}
Assert-FileHash -Path $sourceArchive -Expected $manifest.MsQuic.Sha256
if (-not (Test-Path -LiteralPath $sourceRoot)) {
    Expand-Archive -LiteralPath $sourceArchive -DestinationPath $sourceParent
}

if (-not (Test-Path -LiteralPath $xdpArchive)) {
    Invoke-WebRequest -Uri $manifest.MsQuic.Xdp.SourceUri -OutFile $xdpArchive
}
Assert-FileHash -Path $xdpArchive -Expected $manifest.MsQuic.Xdp.Sha256
if (-not (Test-Path -LiteralPath (Join-Path $xdpTarget 'published\external'))) {
    Expand-Archive -LiteralPath $xdpArchive -DestinationPath $xdpExtract -Force
    $xdpSource = Get-ChildItem -LiteralPath $xdpExtract -Directory |
        Where-Object { $_.Name -like 'xdp-for-windows-*' } |
        Select-Object -First 1
    if ($null -eq $xdpSource) {
        throw 'The pinned XDP archive did not contain the expected source directory.'
    }
    New-Item -ItemType Directory -Force -Path $xdpTarget | Out-Null
    Copy-Item -Path (Join-Path $xdpSource.FullName '*') -Destination $xdpTarget -Recurse -Force
}

cmake -S $sourceRoot -B $buildRoot -G 'Visual Studio 17 2022' -A x64 `
    -DQUIC_TLS_LIB=schannel `
    -DQUIC_BUILD_TEST=OFF `
    -DQUIC_BUILD_TOOLS=OFF `
    -DQUIC_ENABLE_LOGGING=OFF `
    -DQUIC_BUILD_SHARED=ON `
    '-DCMAKE_C_FLAGS=/DQUIC_API_ENABLE_PREVIEW_FEATURES' `
    '-DCMAKE_CXX_FLAGS=/DQUIC_API_ENABLE_PREVIEW_FEATURES'
if ($LASTEXITCODE -ne 0) {
    throw "MsQuic CMake configuration failed with exit code $LASTEXITCODE."
}

# MsQuic 2.5.8 Debug asserts when a legal peer max_udp_payload_size=1200 maps to
# an IPv4 MTU below its IPv6-derived internal minimum. The pinned Release binary
# preserves the wire behavior without weakening wknet's frozen 1200-byte limit.
cmake --build $buildRoot --config Release --target msquic --parallel
if ($LASTEXITCODE -ne 0) {
    throw "MsQuic build failed with exit code $LASTEXITCODE."
}

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if ([string]::IsNullOrWhiteSpace($vsPath)) {
        throw 'Visual Studio with VC x64 tools was not found.'
    }
    & (Join-Path $vsPath.Trim() 'Common7\Tools\Launch-VsDevShell.ps1') `
        -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
}

$clArguments = @(
    '/nologo', '/std:c++17', '/EHsc', '/GR-', '/Wall', '/WX', '/DQUIC_API_ENABLE_PREVIEW_FEATURES',
    '/wd4061', '/wd4100', '/wd4127', '/wd4255', '/wd4365', '/wd4464',
    '/wd4514', '/wd4623', '/wd4625', '/wd4626', '/wd4668', '/wd4710',
    '/wd4711', '/wd4820', '/wd5026', '/wd5027', '/wd5039', '/wd5045',
    '/wd5246',
    '/I', $fixtureRoot,
    '/I', (Join-Path $sourceRoot 'src\inc'),
    "/Fe:$peerExecutable",
    (Join-Path $fixtureRoot 'msquic_peer_main.cpp'),
    (Join-Path $fixtureRoot 'msquic_peer_scenarios.cpp'),
    (Join-Path $fixtureRoot 'msquic_peer_impairment.cpp'),
    '/link',
    "/LIBPATH:$(Join-Path $buildRoot 'obj\Release')",
    'msquic.lib', 'ws2_32.lib', 'crypt32.lib'
)
if ($Configuration -eq 'Debug') {
    $clArguments = @('/Zi', '/DEBUG') + $clArguments
}
& cl.exe @clArguments
if ($LASTEXITCODE -ne 0) {
    throw "MsQuic peer compilation failed with exit code $LASTEXITCODE."
}
Copy-Item -LiteralPath (Join-Path $buildRoot 'bin\Release\msquic.dll') -Destination $peerOutput -Force

$pfx = Join-Path $peerOutput 'localhost.pfx'
& $openssl pkcs12 -export -out $pfx `
    -inkey (Join-Path $repoRoot 'tests\testdata\localhost.key.pem') `
    -in (Join-Path $repoRoot 'tests\testdata\localhost.cert.pem') `
    -passout 'pass:wknet-msquic-test'
if ($LASTEXITCODE -ne 0) {
    throw "test PKCS#12 generation failed with exit code $LASTEXITCODE."
}

pwsh -NoLogo -NoProfile -File (Join-Path $repoRoot 'tools\build-tests.ps1') -Test http3_interop_tests
if ($LASTEXITCODE -ne 0) {
    throw 'http3_interop_tests build failed.'
}
$testExecutable = Join-Path $repoRoot 'tests\out\bin\http3_interop_tests.exe'

foreach ($scenarioName in $Scenario) {
    $udp = [System.Net.Sockets.UdpClient]::new(0)
    try {
        $port = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
    }
    finally {
        $udp.Dispose()
    }
    $readyFile = Join-Path $peerOutput "msquic-$scenarioName-$port.ready"
    $logFile = Join-Path $peerOutput "msquic-$scenarioName-$port.log"
    Remove-Item -LiteralPath $readyFile -Force -ErrorAction SilentlyContinue
    $peerArguments = @(
        '-Scenario', $scenarioName,
        '-Port', "$port",
        '-Certificate', $pfx,
        '-Key', (Join-Path $repoRoot 'tests\testdata\localhost.key.pem'),
        '-ReadyFile', $readyFile,
        '-LogFile', $logFile
    )
    $peer = Start-Process -FilePath $peerExecutable -ArgumentList $peerArguments -PassThru -WindowStyle Hidden
    try {
        $readyDeadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $readyFile) -and -not $peer.HasExited -and
               [DateTime]::UtcNow -lt $readyDeadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $readyFile)) {
            throw "MsQuic peer failed to become ready for scenario $scenarioName; log: $logFile"
        }
        $env:WKNET_HTTP3_INTEROP_PORT = "$port"
        $env:WKNET_HTTP3_INTEROP_SCENARIO = $scenarioName
        $test = Start-Process -FilePath $testExecutable -PassThru -NoNewWindow
        if (-not $test.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-Process -Id $test.Id -Force
            $test.WaitForExit()
            throw "MsQuic scenario $scenarioName exceeded $TimeoutSeconds seconds; log: $logFile"
        }
        if ($test.ExitCode -ne 0) {
            throw "MsQuic scenario $scenarioName failed with exit code $($test.ExitCode); log: $logFile"
        }
        if ($scenarioName -eq 'loss-reorder') {
            $logText = Get-Content -LiteralPath $logFile -Raw
            if ($logText -notmatch 'loss-reorder dropped server datagram' -or
                $logText -notmatch 'loss-reorder reversed server datagrams') {
                throw "MsQuic loss-reorder scenario did not exercise both packet loss and reordering; log: $logFile"
            }
        }
        Write-Host "MsQuic scenario passed: $scenarioName"
    }
    finally {
        Remove-Item Env:WKNET_HTTP3_INTEROP_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:WKNET_HTTP3_INTEROP_SCENARIO -ErrorAction SilentlyContinue
        if (-not $peer.HasExited) {
            Stop-Process -Id $peer.Id -Force
        }
        $peer.WaitForExit()
        Remove-Item -LiteralPath $readyFile -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "MsQuic HTTP/3 interop passed for $($Scenario.Count) scenarios ($Configuration/$Platform)."
