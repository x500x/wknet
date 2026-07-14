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
$devicePath = '\\.\wknettest'
$driverRoot = Join-Path $repoRoot "$Platform\$Configuration"
$driverPath = Join-Path $driverRoot 'wknettest.sys'
$driverCertificate = Join-Path $driverRoot 'wknettest.cer'
$peerRoot = Join-Path $repoRoot 'tests\out\http3-peers'
$peerPython = Join-Path $peerRoot 'aioquic-venv\Scripts\python.exe'
$peerScript = Join-Path $repoRoot 'tests\fixtures\http3\aioquic_peer.py'
$certificate = Join-Path $repoRoot 'tests\testdata\localhost.cert.pem'
$privateKey = Join-Path $repoRoot 'tests\testdata\localhost.key.pem'

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

function Add-DeviceIoType {
    if ($null -ne ('WknetKernelIo' -as [type]) -and $null -ne ('WknetService' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

public static class WknetKernelIo
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Request
    {
        public UInt32 Version;
        public UInt32 Size;
        public UInt32 Test;
        public UInt32 AddressFamily;
        public UInt16 Port;
        public UInt16 Reserved;
        public UInt32 ConnectionCount;
        public UInt32 StreamCount;
        public UInt32 Iterations;
        public UInt32 TimeoutMilliseconds;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Result
    {
        public UInt32 Version;
        public UInt32 Size;
        public Int32 Status;
        public UInt32 RequestCount;
        public UInt32 CompletedCount;
        public UInt32 CancelledCount;
        public UInt32 OutstandingWorkers;
        public UInt32 OutstandingIrps;
        public UInt32 OutstandingTimers;
        public UInt32 OutstandingRundown;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string fileName,
        UInt32 desiredAccess,
        UInt32 shareMode,
        IntPtr securityAttributes,
        UInt32 creationDisposition,
        UInt32 flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr device,
        UInt32 ioControlCode,
        IntPtr inputBuffer,
        UInt32 inputBufferSize,
        IntPtr outputBuffer,
        UInt32 outputBufferSize,
        out UInt32 bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private const UInt32 GenericRead = 0x80000000;
    private const UInt32 GenericWrite = 0x40000000;
    private const UInt32 OpenExisting = 3;
    private const UInt32 IoctlRun = 0x80002004;
    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

    public static bool Run(
        string devicePath,
        UInt32 test,
        UInt32 addressFamily,
        UInt16 port,
        UInt32 connectionCount,
        UInt32 streamCount,
        UInt32 iterations,
        UInt32 timeoutMilliseconds,
        out Result result,
        out Int32 win32Error)
    {
        result = new Result();
        win32Error = 0;
        var request = new Request
        {
            Version = 1,
            Size = (UInt32)Marshal.SizeOf<Request>(),
            Test = test,
            AddressFamily = addressFamily,
            Port = port,
            ConnectionCount = connectionCount,
            StreamCount = streamCount,
            Iterations = iterations,
            TimeoutMilliseconds = timeoutMilliseconds
        };

        IntPtr device = CreateFile(
            devicePath,
            GenericRead | GenericWrite,
            0,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (device == InvalidHandleValue)
        {
            win32Error = Marshal.GetLastWin32Error();
            return false;
        }

        IntPtr buffer = Marshal.AllocHGlobal(Math.Max(Marshal.SizeOf<Request>(), Marshal.SizeOf<Result>()));
        try
        {
            Marshal.StructureToPtr(request, buffer, false);
            UInt32 bytesReturned;
            bool success = DeviceIoControl(
                device,
                IoctlRun,
                buffer,
                (UInt32)Marshal.SizeOf<Request>(),
                buffer,
                (UInt32)Marshal.SizeOf<Result>(),
                out bytesReturned,
                IntPtr.Zero);
            if (!success)
            {
                win32Error = Marshal.GetLastWin32Error();
                return false;
            }
            if (bytesReturned < Marshal.SizeOf<Result>())
            {
                win32Error = 122;
                return false;
            }
            result = Marshal.PtrToStructure<Result>(buffer);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            CloseHandle(device);
        }
    }
}

public static class WknetService
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public UInt32 ServiceType;
        public UInt32 CurrentState;
        public UInt32 ControlsAccepted;
        public UInt32 Win32ExitCode;
        public UInt32 ServiceSpecificExitCode;
        public UInt32 CheckPoint;
        public UInt32 WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(
        string machineName,
        string databaseName,
        UInt32 desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateService(
        IntPtr manager,
        string serviceName,
        string displayName,
        UInt32 desiredAccess,
        UInt32 serviceType,
        UInt32 startType,
        UInt32 errorControl,
        string binaryPathName,
        string loadOrderGroup,
        IntPtr tagId,
        string dependencies,
        string serviceStartName,
        string password);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(
        IntPtr manager,
        string serviceName,
        UInt32 desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartService(IntPtr service, UInt32 argumentCount, IntPtr arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr service, UInt32 control, ref ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr service);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private const UInt32 ScManagerAllAccess = 0xF003F;
    private const UInt32 ServiceAllAccess = 0xF01FF;
    private const UInt32 ServiceKernelDriver = 0x1;
    private const UInt32 ServiceDemandStart = 0x3;
    private const UInt32 ServiceErrorNormal = 0x1;
    private const UInt32 ServiceControlStop = 0x1;
    private const UInt32 ServiceStopped = 0x1;
    private const UInt32 ServiceStopPending = 0x3;
    private const UInt32 ErrorServiceDoesNotExist = 1060;
    private const UInt32 ErrorServiceNotActive = 1062;

    public static Int32 StopAndDelete(string serviceName)
    {
        IntPtr manager = OpenSCManager(null, null, ScManagerAllAccess);
        if (manager == IntPtr.Zero)
        {
            return Marshal.GetLastWin32Error();
        }
        try
        {
            IntPtr service = OpenService(manager, serviceName, ServiceAllAccess);
            if (service == IntPtr.Zero)
            {
                Int32 error = Marshal.GetLastWin32Error();
                return error == ErrorServiceDoesNotExist ? 0 : error;
            }
            try
            {
                ServiceStatus status;
                if (QueryServiceStatus(service, out status) && status.CurrentState != ServiceStopped)
                {
                    ControlService(service, ServiceControlStop, ref status);
                    for (Int32 index = 0; index < 100; ++index)
                    {
                        if (!QueryServiceStatus(service, out status) || status.CurrentState == ServiceStopped)
                        {
                            break;
                        }
                        Thread.Sleep(100);
                    }
                }
                if (!DeleteService(service))
                {
                    Int32 error = Marshal.GetLastWin32Error();
                    if (error != 1072)
                    {
                        return error;
                    }
                }
                return 0;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    public static Int32 InstallAndStart(string serviceName, string binaryPath)
    {
        Int32 cleanupError = StopAndDelete(serviceName);
        if (cleanupError != 0)
        {
            return cleanupError;
        }
        Thread.Sleep(500);
        IntPtr manager = OpenSCManager(null, null, ScManagerAllAccess);
        if (manager == IntPtr.Zero)
        {
            return Marshal.GetLastWin32Error();
        }
        try
        {
            IntPtr service = CreateService(
                manager,
                serviceName,
                serviceName,
                ServiceAllAccess,
                ServiceKernelDriver,
                ServiceDemandStart,
                ServiceErrorNormal,
                binaryPath,
                null,
                IntPtr.Zero,
                null,
                null,
                null);
            if (service == IntPtr.Zero)
            {
                return Marshal.GetLastWin32Error();
            }
            try
            {
                if (!StartService(service, 0, IntPtr.Zero))
                {
                    return Marshal.GetLastWin32Error();
                }
                return 0;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }
}
'@
}

function Get-FreeUdpPort {
    $udp = [System.Net.Sockets.UdpClient]::new(0)
    try {
        return ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
    }
    finally {
        $udp.Dispose()
    }
}

function Start-AioquicPeer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scenario,
        [Parameter(Mandatory = $true)]
        [string]$BindAddress,
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $safeAddress = $BindAddress.Replace(':', '_')
    $readyFile = Join-Path $peerRoot "kernel-$Scenario-$safeAddress-$Port.ready"
    $logFile = Join-Path $peerRoot "kernel-$Scenario-$safeAddress-$Port.log"
    $stderrFile = Join-Path $peerRoot "kernel-$Scenario-$safeAddress-$Port.stderr.log"
    Remove-Item -LiteralPath $readyFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    $arguments = @(
        $peerScript,
        '-Scenario', $Scenario,
        '-Port', "$Port",
        '-Certificate', $certificate,
        '-Key', $privateKey,
        '-ReadyFile', $readyFile,
        '-LogFile', $logFile,
        '-Host', $BindAddress
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
        throw "aioquic peer 未就绪，场景=$Scenario，地址=$BindAddress，日志=$logFile，stderr=$peerError"
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

function Invoke-KernelScenario {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [uint32]$Test,
        [Parameter(Mandatory = $true)]
        [uint32]$AddressFamily,
        [Parameter(Mandatory = $true)]
        [string]$PeerScenario,
        [Parameter(Mandatory = $true)]
        [string]$PeerHost,
        [uint32]$ConnectionCount = 1,
        [uint32]$StreamCount = 1,
        [uint32]$Iterations = 1,
        [switch]$UnloadDuringRequest
    )

    $port = Get-FreeUdpPort
    $peer = Start-AioquicPeer -Scenario $PeerScenario -BindAddress $PeerHost -Port $port
    try {
        $timeoutMilliseconds = [uint32]($TimeoutSeconds * 1000)
        if ($UnloadDuringRequest) {
            $job = Start-ThreadJob -ScriptBlock {
                param($path, $test, $family, $portValue, $connections, $streams, $iterationCount, $timeout)
                $result = [WknetKernelIo+Result]::new()
                $win32Error = 0
                $success = [WknetKernelIo]::Run(
                    $path,
                    $test,
                    $family,
                    [uint16]$portValue,
                    $connections,
                    $streams,
                    $iterationCount,
                    $timeout,
                    [ref]$result,
                    [ref]$win32Error)
                [pscustomobject]@{
                    Success = $success
                    Win32Error = $win32Error
                    Result = $result
                }
            } -ArgumentList $devicePath, $Test, $AddressFamily, $port, $ConnectionCount, $StreamCount, $Iterations, $timeoutMilliseconds
            Start-Sleep -Milliseconds 250
            $stopError = [WknetService]::StopAndDelete($driverServiceName)
            if ($stopError -ne 0) {
                throw "卸载并发请求期间停止驱动服务失败，Win32Error=$stopError"
            }
            $jobResult = Receive-Job -Job $job -Wait -AutoRemoveJob
            if ($null -eq $jobResult -or -not $jobResult.Success) {
                throw "卸载并发请求期间 IOCTL 失败，Win32Error=$($jobResult.Win32Error)"
            }
            $result = $jobResult.Result
        }
        else {
            $result = [WknetKernelIo+Result]::new()
            $win32Error = 0
            $success = [WknetKernelIo]::Run(
                $devicePath,
                $Test,
                $AddressFamily,
                [uint16]$port,
                $ConnectionCount,
                $StreamCount,
                $Iterations,
                $timeoutMilliseconds,
                [ref]$result,
                [ref]$win32Error)
            if (-not $success) {
                throw "场景 $Name 的 IOCTL 失败，Win32Error=$win32Error"
            }
        }

        if ($result.Status -lt 0) {
            $statusBits = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$result.Status), 0)
            throw "场景 $Name 返回 NTSTATUS 0x$('{0:X8}' -f $statusBits)，requests=$($result.RequestCount)，completed=$($result.CompletedCount)，cancelled=$($result.CancelledCount)"
        }
        if ($result.OutstandingWorkers -ne 0 -or
            $result.OutstandingIrps -ne 0 -or
            $result.OutstandingTimers -ne 0 -or
            $result.OutstandingRundown -ne 0) {
            throw "场景 $Name 完成后仍有未清理资源：worker=$($result.OutstandingWorkers), irp=$($result.OutstandingIrps), timer=$($result.OutstandingTimers), rundown=$($result.OutstandingRundown)"
        }
        Write-Host "内核 HTTP/3 场景通过：$Name (requests=$($result.RequestCount), completed=$($result.CompletedCount), cancelled=$($result.CancelledCount))"
    }
    catch {
        if (Test-Path -LiteralPath $peer.StderrFile) {
            $peerError = Get-Content -Raw -LiteralPath $peer.StderrFile
            if (-not [string]::IsNullOrWhiteSpace($peerError)) {
                Write-Error "aioquic peer stderr ($Name): $peerError"
            }
        }
        throw
    }
    finally {
        Stop-AioquicPeer -Peer $peer
    }
}

if (-not (Test-IsAdministrator)) {
    throw 'http3_kernel.ps1 必须在管理员 pwsh 中运行。'
}
Ensure-TestSigning
Add-DeviceIoType

if (-not (Test-Path -LiteralPath $peerPython)) {
    throw "aioquic venv 不存在：$peerPython。请先运行 tests/integration/http3_aioquic.ps1 完成固定依赖安装。"
}
if (-not (Test-Path -LiteralPath $peerScript) -or
    -not (Test-Path -LiteralPath $certificate) -or
    -not (Test-Path -LiteralPath $privateKey)) {
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

$certificateStorePath = "Cert:\LocalMachine\Root"
$certificateObject = Get-PfxCertificate -FilePath $driverCertificate
$certificateThumbprint = $certificateObject.Thumbprint
$existingCertificate = Get-ChildItem -Path $certificateStorePath |
    Where-Object { $_.Thumbprint -eq $certificateThumbprint } |
    Select-Object -First 1
$certificateAdded = $false
$verifierChanged = $false
$originalVerifier = $null

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

    $startError = [WknetService]::InstallAndStart($driverServiceName, $driverPath)
    if ($startError -ne 0) {
        throw "驱动服务启动失败，Win32Error=$startError"
    }

    Invoke-KernelScenario -Name 'ipv4' -Test 1 -AddressFamily 2 -PeerScenario 'handshake' -PeerHost '127.0.0.1'
    Invoke-KernelScenario -Name 'ipv6' -Test 2 -AddressFamily 23 -PeerScenario 'handshake' -PeerHost '::1'
    Invoke-KernelScenario -Name 'concurrent' -Test 3 -AddressFamily 2 -PeerScenario 'concurrent' -PeerHost '127.0.0.1' -ConnectionCount 1 -StreamCount 2
    Invoke-KernelScenario -Name 'cancel' -Test 4 -AddressFamily 2 -PeerScenario 'cancel' -PeerHost '127.0.0.1' -Iterations 100
    Invoke-KernelScenario -Name 'SessionClose' -Test 5 -AddressFamily 2 -PeerScenario 'handshake' -PeerHost '127.0.0.1' -Iterations 100
    Invoke-KernelScenario -Name 'unload-rundown' -Test 6 -AddressFamily 2 -PeerScenario 'handshake' -PeerHost '127.0.0.1' -UnloadDuringRequest

    Write-Host "内核 HTTP/3 集成测试通过 ($Configuration/$Platform)。"
}
finally {
    [void][WknetService]::StopAndDelete($driverServiceName)
    if ($verifierChanged) {
        & verifier.exe /volatile /reset | Out-Null
    }
    if ($certificateAdded) {
        & certutil.exe -delstore Root $certificateThumbprint | Out-Null
    }
}
