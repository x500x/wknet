#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [ValidateSet('x64', 'ARM64')]
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
$venvRoot = Join-Path $peerRoot 'aioquic-venv'
$python = Join-Path $venvRoot 'Scripts\python.exe'
$requirements = Join-Path $fixtureRoot 'aioquic-requirements.txt'
$peerScript = Join-Path $fixtureRoot 'aioquic_peer.py'
$certificate = Join-Path $repoRoot 'tests\testdata\localhost.cert.pem'
$key = Join-Path $repoRoot 'tests\testdata\localhost.key.pem'
$testExecutable = Join-Path $repoRoot 'tests\out\bin\http3_interop_tests.exe'

if ($Platform -ne 'x64') {
    throw 'aioquic user-mode interop currently requires x64 Python and x64 test binaries.'
}

New-Item -ItemType Directory -Force -Path $peerRoot | Out-Null
if (-not (Test-Path -LiteralPath $python)) {
    python -m venv $venvRoot
    if ($LASTEXITCODE -ne 0) {
        throw "python venv creation failed with exit code $LASTEXITCODE"
    }
}

& $python -m pip install --disable-pip-version-check --only-binary=:all: --require-hashes -r $requirements
if ($LASTEXITCODE -ne 0) {
    throw "aioquic dependency installation failed with exit code $LASTEXITCODE"
}

pwsh -NoLogo -NoProfile -File (Join-Path $repoRoot 'tools\build-tests.ps1') -Test http3_interop_tests
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $testExecutable)) {
    throw 'http3_interop_tests build failed.'
}

foreach ($scenarioName in $Scenario) {
    $udp = [System.Net.Sockets.UdpClient]::new(0)
    try {
        $port = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
    }
    finally {
        $udp.Dispose()
    }

    $readyFile = Join-Path $peerRoot "aioquic-$scenarioName-$port.ready"
    $logFile = Join-Path $peerRoot "aioquic-$scenarioName-$port.log"
    Remove-Item -LiteralPath $readyFile -Force -ErrorAction SilentlyContinue
    $arguments = @(
        $peerScript,
        '-Scenario', $scenarioName,
        '-Port', "$port",
        '-Certificate', $certificate,
        '-Key', $key,
        '-ReadyFile', $readyFile,
        '-LogFile', $logFile
    )
    $peer = Start-Process -FilePath $python -ArgumentList $arguments -PassThru -WindowStyle Hidden
    try {
        $readyDeadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $readyFile) -and -not $peer.HasExited -and
               [DateTime]::UtcNow -lt $readyDeadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $readyFile)) {
            throw "aioquic peer failed to become ready for scenario $scenarioName; log: $logFile"
        }

        $env:WKNET_HTTP3_INTEROP_PORT = "$port"
        $env:WKNET_HTTP3_INTEROP_SCENARIO = $scenarioName
        $test = Start-Process -FilePath $testExecutable -PassThru -NoNewWindow
        if (-not $test.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-Process -Id $test.Id -Force
            $test.WaitForExit()
            throw "aioquic scenario $scenarioName exceeded $TimeoutSeconds seconds; log: $logFile"
        }
        if ($test.ExitCode -ne 0) {
            throw "aioquic scenario $scenarioName failed with exit code $($test.ExitCode); log: $logFile"
        }
        Write-Host "aioquic scenario passed: $scenarioName"
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

Write-Host "aioquic HTTP/3 interop passed for $($Scenario.Count) scenarios ($Configuration/$Platform)."
