param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64', 'ARM64')]
    [string]$Platform = 'x64',

    [string]$OpenSslPath,
    [string]$BoringSslPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:OutDir = Join-Path $script:Root 'tests\out'
$script:BinDir = Join-Path $script:OutDir 'bin'
$script:MatrixDir = Join-Path $script:OutDir 'tls-matrix'
$script:LogDir = Join-Path $script:MatrixDir 'logs'
$script:SkipCount = 0
$script:PassCount = 0

function Write-Step {
    param([string]$Message)
    Write-Host "[tls-matrix] $Message"
}

function Add-Skip {
    param(
        [string]$Name,
        [string]$Reason
    )

    ++$script:SkipCount
    Write-Host "[tls-matrix] SKIP $Name - $Reason"
}

function Add-Pass {
    param([string]$Name)

    ++$script:PassCount
    Write-Host "[tls-matrix] PASS $Name"
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

function Invoke-NativeWithTimeout {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory = $script:Root,
        [string]$StandardInputText,
        [int]$TimeoutMilliseconds = 15000,
        [string]$LogPrefix = 'process'
    )

    New-Item -ItemType Directory -Force $script:LogDir | Out-Null
    $safePrefix = $LogPrefix -replace '[^A-Za-z0-9_.-]', '_'
    $stdoutPath = Join-Path $script:LogDir "$safePrefix.out.txt"
    $stderrPath = Join-Path $script:LogDir "$safePrefix.err.txt"
    $stdinPath = Join-Path $script:LogDir "$safePrefix.in.txt"

    $arguments = @{
        FilePath = $FilePath
        ArgumentList = $ArgumentList
        WorkingDirectory = $WorkingDirectory
        RedirectStandardOutput = $stdoutPath
        RedirectStandardError = $stderrPath
        PassThru = $true
        WindowStyle = 'Hidden'
    }

    if ($PSBoundParameters.ContainsKey('StandardInputText')) {
        Set-Content -LiteralPath $stdinPath -Value $StandardInputText -NoNewline -Encoding ASCII
        $arguments.RedirectStandardInput = $stdinPath
    }

    $process = Start-Process @arguments
    $completed = $process.WaitForExit($TimeoutMilliseconds)
    if (-not $completed) {
        try {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        catch {
        }
        return [pscustomobject]@{
            ExitCode = -1
            TimedOut = $true
            StdOut = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            StdErr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        }
    }

    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        TimedOut = $false
        StdOut = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
        StdErr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
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
        '/D', 'KERNEL_HTTP_USER_MODE_TEST=1',
        '/I', (Join-Path $script:Root 'include'),
        '/I', (Join-Path $script:Root 'src\KernelHttpTest'),
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

function Resolve-ExecutablePath {
    param(
        [string]$ConfiguredPath,
        [string[]]$EnvironmentNames,
        [string[]]$CommandNames
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        $resolved = Resolve-Path -LiteralPath $ConfiguredPath -ErrorAction SilentlyContinue
        if ($null -eq $resolved) {
            throw "Configured TLS tool was not found: $ConfiguredPath"
        }
        return $resolved.Path
    }

    foreach ($name in $EnvironmentNames) {
        $candidate = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $resolved = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
            if ($null -ne $resolved) {
                return $resolved.Path
            }
        }
    }

    foreach ($name in $CommandNames) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace($command.Source)) {
            return $command.Source
        }
    }

    return $null
}

function Resolve-TlsTool {
    $openssl = Resolve-ExecutablePath `
        -ConfiguredPath $OpenSslPath `
        -EnvironmentNames @('KERNEL_HTTP_OPENSSL', 'OPENSSL') `
        -CommandNames @('openssl.exe', 'openssl')
    if (-not [string]::IsNullOrWhiteSpace($openssl)) {
        return [pscustomobject]@{
            Kind = 'OpenSSL'
            Path = $openssl
        }
    }

    $boring = Resolve-ExecutablePath `
        -ConfiguredPath $BoringSslPath `
        -EnvironmentNames @('KERNEL_HTTP_BORINGSSL', 'BORINGSSL') `
        -CommandNames @('bssl.exe', 'bssl')
    if (-not [string]::IsNullOrWhiteSpace($boring)) {
        return [pscustomobject]@{
            Kind = 'BoringSSL'
            Path = $boring
        }
    }

    return $null
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return [int]$listener.LocalEndpoint.Port
    }
    finally {
        $listener.Stop()
    }
}

function Wait-TcpPort {
    param(
        [int]$Port,
        [int]$TimeoutMilliseconds = 5000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $async = $client.BeginConnect([System.Net.IPAddress]::Loopback, $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(200)) {
                $client.EndConnect($async)
                return $true
            }
        }
        catch {
        }
        finally {
            $client.Close()
        }

        Start-Sleep -Milliseconds 100
    }

    return $false
}

function New-EcdsaFixture {
    param([string]$OpenSsl)

    $keyPath = Join-Path $script:MatrixDir 'localhost-ecdsa.key.pem'
    $certPath = Join-Path $script:MatrixDir 'localhost-ecdsa.cert.pem'
    if ((Test-Path -LiteralPath $keyPath) -and (Test-Path -LiteralPath $certPath)) {
        return [pscustomobject]@{
            Key = $keyPath
            Cert = $certPath
        }
    }

    $keyResult = Invoke-NativeWithTimeout `
        -FilePath $OpenSsl `
        -ArgumentList @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $keyPath) `
        -TimeoutMilliseconds 10000 `
        -LogPrefix 'generate-ecdsa-key'
    if ($keyResult.ExitCode -ne 0 -or $keyResult.TimedOut) {
        Add-Skip 'tls12-ecdhe-ecdsa-aesgcm' 'OpenSSL could not generate a local ECDSA key fixture'
        return $null
    }

    $certResult = Invoke-NativeWithTimeout `
        -FilePath $OpenSsl `
        -ArgumentList @('req', '-new', '-x509', '-key', $keyPath, '-out', $certPath, '-days', '1', '-subj', '/CN=localhost') `
        -TimeoutMilliseconds 10000 `
        -LogPrefix 'generate-ecdsa-cert'
    if ($certResult.ExitCode -ne 0 -or $certResult.TimedOut) {
        Add-Skip 'tls12-ecdhe-ecdsa-aesgcm' 'OpenSSL could not generate a local ECDSA certificate fixture'
        return $null
    }

    return [pscustomobject]@{
        Key = $keyPath
        Cert = $certPath
    }
}

function Test-OpenSslScenarioUnsupported {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return $Text -match 'unknown option|no cipher match|no shared cipher|no suitable key share|group .* cannot be set|bad value|unsupported protocol|wrong curve|unable to set|no ciphers available'
}

function Test-OpenSslRenegotiationUnsupported {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return $Text -match 'no renegotiation|renegotiation disabled|unsafe legacy renegotiation disabled|disabled renegotiation|not accepting renegotiation'
}

function Resolve-OpenSslRuntimeDlls {
    param([string]$OpenSsl)

    $opensslDir = Split-Path -Parent $OpenSsl
    if ([string]::IsNullOrWhiteSpace($opensslDir) -or -not (Test-Path -LiteralPath $opensslDir)) {
        return $null
    }

    $crypto = Get-ChildItem -LiteralPath $opensslDir -Filter 'libcrypto*.dll' -File -ErrorAction SilentlyContinue |
        Sort-Object Name |
        Select-Object -First 1
    $ssl = Get-ChildItem -LiteralPath $opensslDir -Filter 'libssl*.dll' -File -ErrorAction SilentlyContinue |
        Sort-Object Name |
        Select-Object -First 1

    if ($null -eq $crypto -or $null -eq $ssl) {
        return $null
    }

    return [pscustomobject]@{
        Directory = $opensslDir
        Crypto = $crypto.FullName
        Ssl = $ssl.FullName
    }
}

function Invoke-OpenSslScenario {
    param(
        [string]$OpenSsl,
        [pscustomobject]$Scenario,
        [pscustomobject]$RsaFixture,
        [pscustomobject]$EcdsaFixture
    )

    $fixture = if ($Scenario.CertKind -eq 'ECDSA') { $EcdsaFixture } else { $RsaFixture }
    if ($null -eq $fixture) {
        Add-Skip $Scenario.Name "local $($Scenario.CertKind) certificate fixture is unavailable"
        return
    }

    $port = Get-FreeTcpPort
    $serverArgs = @(
        's_server',
        '-accept', "$port",
        '-cert', $fixture.Cert,
        '-key', $fixture.Key,
        '-www',
        '-quiet'
    )
    $serverArgs += $Scenario.ServerArgs

    if ($Scenario.ClientCertificate) {
        $serverArgs += @('-Verify', '1', '-CAfile', $RsaFixture.Cert)
    }

    $safeName = $Scenario.Name -replace '[^A-Za-z0-9_.-]', '_'
    $serverOut = Join-Path $script:LogDir "$safeName.server.out.txt"
    $serverErr = Join-Path $script:LogDir "$safeName.server.err.txt"
    $server = Start-Process `
        -FilePath $OpenSsl `
        -ArgumentList $serverArgs `
        -WorkingDirectory $script:Root `
        -RedirectStandardOutput $serverOut `
        -RedirectStandardError $serverErr `
        -WindowStyle Hidden `
        -PassThru

    try {
        if (-not (Wait-TcpPort -Port $port -TimeoutMilliseconds 5000)) {
            $errorText = if (Test-Path -LiteralPath $serverErr) { Get-Content -LiteralPath $serverErr -Raw } else { '' }
            if (Test-OpenSslScenarioUnsupported -Text $errorText) {
                Add-Skip $Scenario.Name 'local OpenSSL does not support this cipher/group/server option set'
                return
            }
            throw "OpenSSL server did not listen for $($Scenario.Name). See $serverErr"
        }

        $request = "GET / HTTP/1.0`r`nHost: localhost`r`n`r`n"
        $clientArgs = @(
            's_client',
            '-connect', "127.0.0.1:$port",
            '-servername', 'localhost'
        )
        $clientArgs += $Scenario.ClientArgs
        if ($Scenario.ClientCertificate) {
            $clientArgs += @('-cert', $RsaFixture.Cert, '-key', $RsaFixture.Key)
        }

        $clientResult = Invoke-NativeWithTimeout `
            -FilePath $OpenSsl `
            -ArgumentList $clientArgs `
            -StandardInputText $request `
            -TimeoutMilliseconds 15000 `
            -LogPrefix "$safeName.client"

        $combinedOutput = "$($clientResult.StdOut)`n$($clientResult.StdErr)"
        if ($clientResult.TimedOut) {
            throw "OpenSSL client timed out for $($Scenario.Name)"
        }
        if ($clientResult.ExitCode -ne 0) {
            if (Test-OpenSslScenarioUnsupported -Text $combinedOutput) {
                Add-Skip $Scenario.Name 'local OpenSSL does not support this cipher/group/client option set'
                return
            }
            throw "OpenSSL client failed for $($Scenario.Name) with exit code $($clientResult.ExitCode). See $script:LogDir"
        }

        if (-not [string]::IsNullOrWhiteSpace($Scenario.ExpectedText) -and $combinedOutput -notmatch $Scenario.ExpectedText) {
            throw "OpenSSL client output did not contain expected marker '$($Scenario.ExpectedText)' for $($Scenario.Name)"
        }

        Add-Pass $Scenario.Name
    }
    finally {
        if ($null -ne $server -and -not $server.HasExited) {
            Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-KernelHttpRenegotiationScenario {
    param(
        [string]$OpenSsl,
        [pscustomobject]$RsaFixture
    )

    $scenarioName = 'tls12-kernelhttp-renegotiation'
    if ($null -eq $RsaFixture -or
        -not (Test-Path -LiteralPath $RsaFixture.Cert) -or
        -not (Test-Path -LiteralPath $RsaFixture.Key)) {
        Add-Skip $scenarioName 'tests\testdata\localhost cert/key fixtures are missing'
        return
    }

    $client = Join-Path $script:BinDir 'tls_renegotiation_client.exe'
    if (-not (Test-Path -LiteralPath $client)) {
        Add-Skip $scenarioName 'KernelHttp renegotiation client test binary was not built'
        return
    }

    $serverBinary = Join-Path $script:BinDir 'tls_renegotiation_server.exe'
    if (-not (Test-Path -LiteralPath $serverBinary)) {
        Add-Skip $scenarioName 'OpenSSL renegotiation server test binary was not built'
        return
    }

    $runtime = Resolve-OpenSslRuntimeDlls -OpenSsl $OpenSsl
    if ($null -eq $runtime) {
        Add-Skip $scenarioName 'OpenSSL runtime DLLs were not found next to openssl.exe'
        return
    }

    $port = Get-FreeTcpPort
    $safeName = $scenarioName -replace '[^A-Za-z0-9_.-]', '_'
    $serverOut = Join-Path $script:LogDir "$safeName.server.out.txt"
    $serverErr = Join-Path $script:LogDir "$safeName.server.err.txt"
    $serverArgs = @(
        "$port",
        $runtime.Crypto,
        $runtime.Ssl,
        $RsaFixture.Cert,
        $RsaFixture.Key
    )

    $server = Start-Process `
        -FilePath $serverBinary `
        -ArgumentList $serverArgs `
        -WorkingDirectory $runtime.Directory `
        -RedirectStandardOutput $serverOut `
        -RedirectStandardError $serverErr `
        -WindowStyle Hidden `
        -PassThru

    try {
        if (-not (Wait-TcpPort -Port $port -TimeoutMilliseconds 5000)) {
            $errorText = ''
            if (Test-Path -LiteralPath $serverOut) {
                $errorText += Get-Content -LiteralPath $serverOut -Raw
            }
            if (Test-Path -LiteralPath $serverErr) {
                $errorText += "`n"
                $errorText += Get-Content -LiteralPath $serverErr -Raw
            }
            if ((Test-OpenSslScenarioUnsupported -Text $errorText) -or
                (Test-OpenSslRenegotiationUnsupported -Text $errorText) -or
                $errorText -match 'missing procedure|failed to load lib') {
                Add-Skip $scenarioName 'local OpenSSL does not support this TLS 1.2 renegotiation server mode'
                return
            }
            throw "OpenSSL server did not listen for $scenarioName. See $serverErr"
        }

        $clientResult = Invoke-NativeWithTimeout `
            -FilePath $client `
            -ArgumentList @("$port") `
            -TimeoutMilliseconds 30000 `
            -LogPrefix "$safeName.client"

        $serverText = ''
        if (Test-Path -LiteralPath $serverOut) {
            $serverText += Get-Content -LiteralPath $serverOut -Raw
        }
        if (Test-Path -LiteralPath $serverErr) {
            $serverText += "`n"
            $serverText += Get-Content -LiteralPath $serverErr -Raw
        }
        $combinedOutput = "$($clientResult.StdOut)`n$($clientResult.StdErr)`n$serverText"
        if ($clientResult.TimedOut) {
            throw "KernelHttp renegotiation client timed out for $scenarioName"
        }
        if ($clientResult.ExitCode -ne 0) {
            if (Test-OpenSslRenegotiationUnsupported -Text $combinedOutput) {
                Add-Skip $scenarioName 'local OpenSSL build disabled TLS 1.2 renegotiation'
                return
            }
            if ($combinedOutput -match 'missing procedure|failed to load lib') {
                Add-Skip $scenarioName 'local OpenSSL runtime does not expose the renegotiation APIs used by this harness'
                return
            }
            throw "KernelHttp renegotiation client failed for $scenarioName with exit code $($clientResult.ExitCode). See $script:LogDir"
        }

        Add-Pass $scenarioName
    }
    finally {
        if ($null -ne $server -and -not $server.HasExited) {
            Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-OpenSslWireMatrix {
    param([string]$OpenSsl)

    $rsaFixture = [pscustomobject]@{
        Cert = Join-Path $script:Root 'tests\testdata\localhost.cert.pem'
        Key = Join-Path $script:Root 'tests\testdata\localhost.key.pem'
    }

    if (-not (Test-Path -LiteralPath $rsaFixture.Cert) -or -not (Test-Path -LiteralPath $rsaFixture.Key)) {
        Add-Skip 'openssl-wire-matrix' 'tests\testdata\localhost cert/key fixtures are missing'
        return
    }

    $ecdsaFixture = New-EcdsaFixture -OpenSsl $OpenSsl

    $scenarios = @(
        [pscustomobject]@{
            Name = 'tls13-aes128-gcm-x25519-h2'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256', '-groups', 'X25519', '-alpn', 'h2,http/1.1')
            ClientArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256', '-groups', 'X25519', '-alpn', 'h2')
            ClientCertificate = $false
            ExpectedText = 'Protocol  : TLSv1.3|Ciphersuite: TLS_AES_128_GCM_SHA256|Cipher is TLS_AES_128_GCM_SHA256'
        },
        [pscustomobject]@{
            Name = 'tls13-aes256-gcm-x448-http11'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_256_GCM_SHA384', '-groups', 'X448', '-alpn', 'http/1.1')
            ClientArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_256_GCM_SHA384', '-groups', 'X448', '-alpn', 'http/1.1')
            ClientCertificate = $false
            ExpectedText = 'TLS_AES_256_GCM_SHA384'
        },
        [pscustomobject]@{
            Name = 'tls13-chacha20-p256'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_3', '-ciphersuites', 'TLS_CHACHA20_POLY1305_SHA256', '-groups', 'P-256')
            ClientArgs = @('-tls1_3', '-ciphersuites', 'TLS_CHACHA20_POLY1305_SHA256', '-groups', 'P-256')
            ClientCertificate = $false
            ExpectedText = 'TLS_CHACHA20_POLY1305_SHA256'
        },
        [pscustomobject]@{
            Name = 'tls13-aes128-ccm-p384'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_CCM_SHA256', '-groups', 'P-384')
            ClientArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_CCM_SHA256', '-groups', 'P-384')
            ClientCertificate = $false
            ExpectedText = 'TLS_AES_128_CCM_SHA256'
        },
        [pscustomobject]@{
            Name = 'tls13-aes128-ccm8-p521'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_CCM_8_SHA256', '-groups', 'P-521')
            ClientArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_CCM_8_SHA256', '-groups', 'P-521')
            ClientCertificate = $false
            ExpectedText = 'TLS_AES_128_CCM_8_SHA256'
        },
        [pscustomobject]@{
            Name = 'tls13-aes128-gcm-ffdhe2048'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256', '-groups', 'ffdhe2048')
            ClientArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256', '-groups', 'ffdhe2048')
            ClientCertificate = $false
            ExpectedText = 'TLS_AES_128_GCM_SHA256'
        },
        [pscustomobject]@{
            Name = 'tls12-ecdhe-rsa-aesgcm'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256', '-alpn', 'h2,http/1.1')
            ClientArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256', '-alpn', 'h2')
            ClientCertificate = $false
            ExpectedText = 'ECDHE-RSA-AES128-GCM-SHA256|Cipher is ECDHE-RSA-AES128-GCM-SHA256'
        },
        [pscustomobject]@{
            Name = 'tls12-ecdhe-ecdsa-aesgcm'
            CertKind = 'ECDSA'
            ServerArgs = @('-tls1_2', '-cipher', 'ECDHE-ECDSA-AES128-GCM-SHA256')
            ClientArgs = @('-tls1_2', '-cipher', 'ECDHE-ECDSA-AES128-GCM-SHA256')
            ClientCertificate = $false
            ExpectedText = 'ECDHE-ECDSA-AES128-GCM-SHA256|Cipher is ECDHE-ECDSA-AES128-GCM-SHA256'
        },
        [pscustomobject]@{
            Name = 'tls12-dhe-rsa-aesgcm-ffdhe2048'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_2', '-cipher', 'DHE-RSA-AES128-GCM-SHA256', '-groups', 'ffdhe2048')
            ClientArgs = @('-tls1_2', '-cipher', 'DHE-RSA-AES128-GCM-SHA256', '-groups', 'ffdhe2048')
            ClientCertificate = $false
            ExpectedText = 'DHE-RSA-AES128-GCM-SHA256|Cipher is DHE-RSA-AES128-GCM-SHA256'
        },
        [pscustomobject]@{
            Name = 'tls12-rsa-aesgcm-compat'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_2', '-cipher', 'AES128-GCM-SHA256:@SECLEVEL=0')
            ClientArgs = @('-tls1_2', '-cipher', 'AES128-GCM-SHA256:@SECLEVEL=0')
            ClientCertificate = $false
            ExpectedText = 'AES128-GCM-SHA256|Cipher is AES128-GCM-SHA256'
        },
        [pscustomobject]@{
            Name = 'tls12-ecdhe-rsa-cbc-etm-compat'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-AES128-SHA256:@SECLEVEL=0')
            ClientArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-AES128-SHA256:@SECLEVEL=0')
            ClientCertificate = $false
            ExpectedText = 'ECDHE-RSA-AES128-SHA256|Cipher is ECDHE-RSA-AES128-SHA256'
        },
        [pscustomobject]@{
            Name = 'tls12-ecdhe-rsa-chacha20'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-CHACHA20-POLY1305')
            ClientArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-CHACHA20-POLY1305')
            ClientCertificate = $false
            ExpectedText = 'ECDHE-RSA-CHACHA20-POLY1305|Cipher is ECDHE-RSA-CHACHA20-POLY1305'
        },
        [pscustomobject]@{
            Name = 'tls13-client-cert'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256', '-groups', 'X25519')
            ClientArgs = @('-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256', '-groups', 'X25519')
            ClientCertificate = $true
            ExpectedText = 'TLS_AES_128_GCM_SHA256'
        },
        [pscustomobject]@{
            Name = 'tls12-client-cert'
            CertKind = 'RSA'
            ServerArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256')
            ClientArgs = @('-tls1_2', '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256')
            ClientCertificate = $true
            ExpectedText = 'ECDHE-RSA-AES128-GCM-SHA256|Cipher is ECDHE-RSA-AES128-GCM-SHA256'
        }
    )

    foreach ($scenario in $scenarios) {
        Invoke-OpenSslScenario `
            -OpenSsl $OpenSsl `
            -Scenario $scenario `
            -RsaFixture $rsaFixture `
            -EcdsaFixture $ecdsaFixture
    }

    Invoke-KernelHttpRenegotiationScenario `
        -OpenSsl $OpenSsl `
        -RsaFixture $rsaFixture

    Add-Skip 'tls13-resumption-0rtt' 'project matrix binary covers PSK/0-RTT; this OpenSSL CLI harness does not use public endpoints or keep server state for early_data replay'
    Add-Skip 'tls13-keyupdate' 'project matrix binary covers KeyUpdate; OpenSSL s_client has no stable noninteractive KeyUpdate path in this harness'
}

New-Item -ItemType Directory -Force $script:MatrixDir | Out-Null
New-Item -ItemType Directory -Force $script:LogDir | Out-Null

$tool = Resolve-TlsTool

Import-VsDevShell

Compile-UserModeTest `
    -Name 'tls_interop_matrix_tests' `
    -Source 'tests\tls_interop_matrix_tests.cpp' `
    -ProjectSources @(
        'src\KernelHttpLib\http\HttpTypes.cpp',
        'src\KernelHttpLib\tls\CertificateStore.cpp',
        'src\KernelHttpLib\tls\TlsCapabilities.cpp',
        'src\KernelHttpLib\tls\TlsPolicy.cpp'
    )
Add-Pass 'tls_interop_matrix_tests'

if ($null -eq $tool) {
    Add-Skip 'local-openssl-boringssl-wire-matrix' 'no OpenSSL/BoringSSL executable found; set -OpenSslPath, -BoringSslPath, KERNEL_HTTP_OPENSSL, or KERNEL_HTTP_BORINGSSL'
}
elseif ($tool.Kind -ne 'OpenSSL') {
    Add-Skip 'local-boringssl-wire-matrix' "found $($tool.Kind) at $($tool.Path), but this harness requires OpenSSL-compatible s_server/s_client arguments"
}
else {
    Write-Step "using OpenSSL at $($tool.Path)"
    foreach ($testName in @('tls_renegotiation_client', 'tls_renegotiation_server')) {
        Invoke-Checked `
            -FilePath 'pwsh' `
            -ArgumentList @(
                '-NoLogo',
                '-NoProfile',
                '-File',
                (Join-Path $script:Root 'tools\build-tests.ps1'),
                '-Test',
                $testName
            )
    }
    Invoke-OpenSslWireMatrix -OpenSsl $tool.Path
}

Write-Step "matrix completed: pass=$script:PassCount skip=$script:SkipCount"
