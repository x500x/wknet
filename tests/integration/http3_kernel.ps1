#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [ValidateSet('x64', 'ARM64')]
    [string]$Platform = 'x64',
    [ValidateRange(1, 1800)]
    [int]$TimeoutSeconds = 180,
    [switch]$EnableVerifier,
    [switch]$SkipDriverBuild
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$driverServiceName = 'wknettest'
$driverRoot = Join-Path $repoRoot "$Platform\$Configuration"
$driverPath = Join-Path $driverRoot 'wknettest.sys'
$driverCertificate = Join-Path $driverRoot 'wknettest.cer'
$driverLog = Join-Path $driverRoot 'wknettest.log'
$certificateBundleSource = Join-Path $repoRoot 'certs\cacert.pem'
$certificateBundleTarget = Join-Path $driverRoot 'cacert.pem'
$peerRoot = Join-Path $repoRoot 'tests\out\http3-peers'
$fixtureRoot = Join-Path $repoRoot 'tests\fixtures\http3'
$requirements = Join-Path $fixtureRoot 'aioquic-requirements.txt'
$peerPython = Join-Path $peerRoot 'aioquic-venv\Scripts\python.exe'
$peerScript = Join-Path $fixtureRoot 'aioquic_peer.py'
$certificate = Join-Path $repoRoot 'tests\testdata\localhost.cert.pem'
$privateKey = Join-Path $repoRoot 'tests\testdata\localhost.key.pem'
$loopbackPort = 58443

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Ensure-TestSigning {
    $settings = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    if ($settings -notmatch '(?im)testsigning\s+Yes' -and
        $settings -notmatch '(?im)nointegritychecks\s+Yes') {
        throw '当前启动配置未启用测试签名或 nointegritychecks；拒绝伪造驱动集成通过。'
    }
}

function Ensure-AioquicPeerDependencies {
    New-Item -ItemType Directory -Force -Path $peerRoot | Out-Null
    if (-not (Test-Path -LiteralPath $peerPython)) {
        python -m venv (Join-Path $peerRoot 'aioquic-venv')
        if ($LASTEXITCODE -ne 0) {
            throw "python venv creation failed with exit code $LASTEXITCODE"
        }
    }

    & $peerPython -m pip install --disable-pip-version-check --only-binary=:all: --require-hashes -r $requirements
    if ($LASTEXITCODE -ne 0) {
        throw "aioquic dependency installation failed with exit code $LASTEXITCODE"
    }
}

function Start-AioquicPeer {
    $readyFile = Join-Path $peerRoot "kernel-load-handshake-$loopbackPort.ready"
    $logFile = Join-Path $peerRoot "kernel-load-handshake-$loopbackPort.log"
    $stderrFile = Join-Path $peerRoot "kernel-load-handshake-$loopbackPort.stderr.log"
    Remove-Item -LiteralPath $readyFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue

    $arguments = @(
        $peerScript,
        '-Scenario', 'handshake',
        '-Port', "$loopbackPort",
        '-Certificate', $certificate,
        '-Key', $privateKey,
        '-ReadyFile', $readyFile,
        '-LogFile', $logFile,
        '-Host', '127.0.0.1'
    )
    $process = Start-Process -FilePath $peerPython -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardError $stderrFile
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $readyFile) -and
           -not $process.HasExited -and
           [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $readyFile)) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
        $peerError = if (Test-Path -LiteralPath $stderrFile) { Get-Content -Raw -LiteralPath $stderrFile } else { '' }
        throw "aioquic peer 未就绪，端口=$loopbackPort，日志=$logFile，stderr=$peerError"
    }
    return [pscustomobject]@{
        Process = $process
        ReadyFile = $readyFile
        LogFile = $logFile
        StderrFile = $stderrFile
    }
}

function Stop-AioquicPeer {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Peer
    )

    if (-not $Peer.Process.HasExited) {
        Stop-Process -Id $Peer.Process.Id -Force
    }
    $Peer.Process.WaitForExit()
    Remove-Item -LiteralPath $Peer.ReadyFile -Force -ErrorAction SilentlyContinue
}

function Remove-DriverService {
    & sc.exe stop $driverServiceName | Out-Null
    & sc.exe delete $driverServiceName | Out-Null
    Start-Sleep -Milliseconds 500
}

function Install-DriverService {
    Remove-DriverService
    Invoke-Checked -FilePath 'sc.exe' -ArgumentList @(
        'create',
        $driverServiceName,
        'type=',
        'kernel',
        'start=',
        'demand',
        'binPath=',
        $driverPath
    )
}

function Assert-DriverLog {
    if (-not (Test-Path -LiteralPath $driverLog)) {
        throw "驱动日志不存在：$driverLog"
    }

    $log = Get-Content -Raw -LiteralPath $driverLog
    if ($log -notmatch '\[HTTP/3\].*HTTP/3 Required Loopback 通过') {
        $tail = ($log -split "`r?`n" | Select-Object -Last 80) -join "`n"
        throw "wknettest.sys 未在加载期跑通 HTTP/3 Required Loopback。日志尾部：`n$tail"
    }
    if ($log -notmatch 'wknettest 全量示例') {
        $tail = ($log -split "`r?`n" | Select-Object -Last 80) -join "`n"
        throw "wknettest.sys 未运行原有全量示例链路。日志尾部：`n$tail"
    }
}

if (-not (Test-IsAdministrator)) {
    throw 'http3_kernel.ps1 必须在管理员 pwsh 中运行。'
}
Ensure-TestSigning
Ensure-AioquicPeerDependencies

if (-not (Test-Path -LiteralPath $peerScript) -or
    -not (Test-Path -LiteralPath $certificate) -or
    -not (Test-Path -LiteralPath $privateKey) -or
    -not (Test-Path -LiteralPath $requirements)) {
    throw 'aioquic peer 或固定测试证书缺失。'
}

if (-not $SkipDriverBuild) {
    & msbuild.exe (Join-Path $repoRoot 'wknet.sln') /t:wknettest "/p:Configuration=$Configuration" "/p:Platform=$Platform" /m
    if ($LASTEXITCODE -ne 0) {
        throw "wknettest $Configuration/$Platform 构建失败。"
    }
}

if (-not (Test-Path -LiteralPath $driverPath) -or
    -not (Test-Path -LiteralPath $driverCertificate)) {
    throw "驱动或测试签名证书不存在：$driverPath / $driverCertificate"
}
if (-not (Test-Path -LiteralPath $certificateBundleSource)) {
    throw "证书信任包不存在：$certificateBundleSource"
}

Copy-Item -LiteralPath $certificateBundleSource -Destination $certificateBundleTarget -Force
Remove-Item -LiteralPath $driverLog -Force -ErrorAction SilentlyContinue

$certificateStorePath = 'Cert:\LocalMachine\Root'
$certificateObject = Get-PfxCertificate -FilePath $driverCertificate
$certificateThumbprint = $certificateObject.Thumbprint
$existingCertificate = Get-ChildItem -Path $certificateStorePath |
    Where-Object { $_.Thumbprint -eq $certificateThumbprint } |
    Select-Object -First 1
$certificateAdded = $false
$verifierChanged = $false
$originalVerifier = $null
$peer = $null

try {
    if ($null -eq $existingCertificate) {
        Invoke-Checked -FilePath 'certutil.exe' -ArgumentList @('-addstore', '-f', 'Root', $driverCertificate)
        $certificateAdded = $true
    }

    if ($EnableVerifier) {
        $originalVerifier = (& verifier.exe /querysettings 2>&1 | Out-String)
        $originalFlagsClear = $originalVerifier -match '(?im)Verifier Flags:\s*0x0+\s*$'
        $originalDriversClear = $originalVerifier -match '(?ims)Verified Drivers:\s*\r?\n\s*None\s*$'
        if (-not $originalFlagsClear -or -not $originalDriversClear) {
            throw '检测到已有 Driver Verifier 配置；为保证 finally 可精确恢复，拒绝覆盖现有设置。'
        }
        & verifier.exe /volatile /flags 0x33 /driver wknettest.sys
        if ($LASTEXITCODE -ne 0) {
            throw '当前系统不支持针对 wknettest.sys 的 volatile Driver Verifier 配置。'
        }
        $verifierChanged = $true
        $query = (& verifier.exe /querysettings 2>&1 | Out-String)
        if ($query -notmatch '(?i)wknettest' -or $query -notmatch '(?i)0x0*33') {
            throw "Driver Verifier 配置未按要求生效：$query"
        }
    }

    $peer = Start-AioquicPeer
    Install-DriverService
    Invoke-Checked -FilePath 'sc.exe' -ArgumentList @('start', $driverServiceName)
    Assert-DriverLog
    Write-Host "内核 HTTP/3 加载期集成测试通过 ($Configuration/$Platform)。"
}
finally {
    Remove-DriverService
    if ($null -ne $peer) {
        Stop-AioquicPeer -Peer $peer
    }
    if ($verifierChanged) {
        & verifier.exe /volatile /reset | Out-Null
    }
    if ($certificateAdded) {
        & certutil.exe -delstore Root $certificateThumbprint | Out-Null
    }
}
