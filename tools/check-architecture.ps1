#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure {
    param([Parameter(Mandatory = $true)][string]$Message)
    $failures.Add($Message)
}

function Invoke-Rg {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $output = @(& rg @Arguments 2>$null)
    if ($LASTEXITCODE -eq 0) {
        Add-Failure "$Description`n$($output -join "`n")"
    }
    elseif ($LASTEXITCODE -ne 1) {
        throw "rg failed while checking $Description with exit code $LASTEXITCODE"
    }
}

$publicRoot = Join-Path $root 'include\wknet'
$forbiddenPublicDirectories = @('session', 'net', 'tls', 'http1', 'http2', 'quic', 'http3', 'qpack', 'ws', 'transport', 'detail', 'client', 'engine')
foreach ($name in $forbiddenPublicDirectories) {
    $path = Join-Path $publicRoot $name
    if (Test-Path -LiteralPath $path) {
        Add-Failure "Forbidden public directory exists: $path"
    }
}

Invoke-Rg -Description 'Public headers reference private module paths or namespaces.' -Arguments @(
    '-n',
    '#\s*include\s*[<"](?:wknet/)?(?:session|net|tls|http1|http2|quic|http3|qpack|ws|transport|detail)/|\b(?:session|net|tls|http1|http2|quic|http3|qpack|ws|transport|detail)::',
    $publicRoot
)

Invoke-Rg -Description 'Legacy wknet::core namespace remains.' -Arguments @(
    '-n',
    'namespace\s+core\b|\bcore::',
    (Join-Path $root 'src\wknetlib'),
    $publicRoot
)

Invoke-Rg -Description 'Removed ITransport abstraction remains.' -Arguments @(
    '-n',
    '\bITransport\b|ITransport\.h',
    (Join-Path $root 'src\wknetlib'),
    (Join-Path $root 'tests')
)

Invoke-Rg -Description 'Opaque WSK public headers expose client or socket class layout.' -Arguments @(
    '-n',
    'class\s+Wsk(?:Client|Socket)\s*(?:final\s*)?\{',
    (Join-Path $root 'src\wknetlib\net\WskClient.h'),
    (Join-Path $root 'src\wknetlib\net\WskSocket.h')
)

Invoke-Rg -Description 'Session or transport includes HTTP/2 or TLS private connection state.' -Arguments @(
    '-n',
    '#\s*include\s*[<"](?:http2/Http2ConnectionPrivate\.hpp|tls/TlsConnectionPrivate\.hpp)[>"]',
    (Join-Path $root 'src\wknetlib\session'),
    (Join-Path $root 'src\wknetlib\transport')
)

$quicRoot = Join-Path $root 'src\wknetlib\quic'
if (Test-Path -LiteralPath $quicRoot) {
    Invoke-Rg -Description 'QUIC implementation depends upward on HTTP/3, QPACK, session, or transport.' -Arguments @(
        '-n',
        '#\s*include\s*[<"](?:http3|qpack|session|transport)/|\b(?:http3|qpack|session|transport)::',
        $quicRoot
    )
}

$http3Root = Join-Path $root 'src\wknetlib\http3'
if (Test-Path -LiteralPath $http3Root) {
    Invoke-Rg -Description 'HTTP/3 bypasses QuicStream services or directly depends on network/packet internals.' -Arguments @(
        '-n',
        '#\s*include\s*[<"](?:net/|quic/(?:QuicPacket|QuicFrame|QuicCrypto|QuicTls|QuicRecovery|QuicCongestion|QuicConnectionPrivate))|\bWsk(?:Client|Socket|DatagramSocket)\b',
        $http3Root
    )
}

$qpackRoot = Join-Path $root 'src\wknetlib\qpack'
if (Test-Path -LiteralPath $qpackRoot) {
    Invoke-Rg -Description 'QPACK owns connection, session, transport, or network policy.' -Arguments @(
        '-n',
        '#\s*include\s*[<"](?:session|transport|net|quic)/|\b(?:session|transport|net|quic)::',
        $qpackRoot
    )
}

Invoke-Rg -Description 'Opaque module objects are freed outside their owning close service.' -Arguments @(
    '-n',
    'FreeNonPagedObject(?:<[^>]*(?:Transport|TlsConnection|Http2Connection|WskClient|WskSocket)[^>]*>)?\s*\([^\r\n]*(?:Transport|Tls|Http2|WskClient|WskSocket)',
    (Join-Path $root 'src\wknetlib\session'),
    (Join-Path $root 'src\wknetlib\http_api')
)

Invoke-Rg -Description 'PooledConnection fields are accessed outside ConnectionPool.cpp.' -Arguments @(
    '-n',
    '--glob', '!ConnectionPool.cpp',
    '--glob', '!ConnectionPool.h',
    '\b(?:pooledConnection|connection)(?:->|\.)(?:InUse|Connected|Id|LastUsedTime|Http2StreamLeases|Http2MaxStreamLeases|Http1PipelineLeases|Http1MaxPipelineLeases|Http1PipelineNextSequence|Http1PipelineNextReceiveSequence|Http1PipelineFailureStatus|Http1PipelineBufferedBytes|Http1PipelineBufferedLength|Http1PipelineBufferedCapacity|CloseWhenIdle|ProxyTunnelEstablished|Http2KeepAliveInProgress|Http2LastKeepAliveTime|Http2KeepAliveSequence|Http2KeepAliveOpaqueData|Key|Socket|RawTransport|Tls|Transport|Http2)\b',
    (Join-Path $root 'src\wknetlib\session')
)

$privateHeaders = @(Get-ChildItem -LiteralPath (Join-Path $root 'src\wknetlib') -Recurse -File -Filter '*Private.hpp')
$whiteBoxPrivateHeaderConsumers = @{
    'http2/Http2ConnectionPrivate.hpp' = @('http2_client_tests.cpp')
    'tls/TlsConnectionPrivate.hpp' = @(
        'tls_interop_matrix_tests.cpp',
        'tls_record_tests.cpp',
        'tls_renegotiation_client.cpp'
    )
}
foreach ($header in $privateHeaders) {
    $relativeHeader = [System.IO.Path]::GetRelativePath((Join-Path $root 'src\wknetlib'), $header.FullName).Replace('\', '/')
    $moduleName = $relativeHeader.Split('/')[0]
    $matches = @(& rg -l --glob '*.h' --glob '*.hpp' --glob '*.cpp' ([regex]::Escape($header.Name)) (Join-Path $root 'src\wknetlib') 2>$null)
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
        throw "rg failed while checking private header $relativeHeader"
    }
    foreach ($match in $matches) {
        $relativeMatch = [System.IO.Path]::GetRelativePath((Join-Path $root 'src\wknetlib'), $match).Replace('\', '/')
        if (-not $relativeMatch.StartsWith("$moduleName/", [System.StringComparison]::OrdinalIgnoreCase)) {
            Add-Failure "Private header $relativeHeader is included outside its module by $relativeMatch"
        }
    }

    $testMatches = @(& rg -l --glob '*.h' --glob '*.hpp' --glob '*.cpp' ([regex]::Escape($header.Name)) (Join-Path $root 'tests') 2>$null)
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
        throw "rg failed while checking test consumers of private header $relativeHeader"
    }
    $allowedTestConsumers = @($whiteBoxPrivateHeaderConsumers[$relativeHeader])
    foreach ($match in $testMatches) {
        $testName = Split-Path -Leaf $match
        if ($allowedTestConsumers -notcontains $testName) {
            Add-Failure "Private header $relativeHeader is included by non-white-box test $testName"
        }
    }
}

$projectPath = Join-Path $root 'src\wknetlib\wknetlib.vcxproj'
[xml]$project = Get-Content -LiteralPath $projectPath -Raw
$projectDirectory = Split-Path -Parent $projectPath
$projectItems = @(
    $project.SelectNodes("/*[local-name()='Project']/*[local-name()='ItemGroup']/*[local-name()='ClCompile' or local-name()='ClInclude']")
)
foreach ($item in $projectItems) {
    if ($null -eq $item.Include) {
        continue
    }
    $itemPath = Join-Path $projectDirectory ([string]$item.Include)
    if (-not (Test-Path -LiteralPath $itemPath)) {
        Add-Failure "Project references missing item: $($item.Include)"
    }
}

Invoke-Rg -Description 'Legacy product names or macros remain in first-party implementation files.' -Arguments @(
    '-n',
    '--glob', '!.git/**',
    '--glob', '!certs/**',
    '--glob', '!third_party/**',
    '--glob', '!docs/plans/**',
    '--glob', '!tools/check-architecture.ps1',
    'KernelHttp|KERNEL_HTTP_|Source Files\\khttp|Header Files\\(?:khttp|kws)',
    $root
)

$legacyPaths = @(rg --files $root | Where-Object {
    $relative = [System.IO.Path]::GetRelativePath($root, $_).Replace('\', '/')
    $relative -match '(^|/)(?:Khttp|khttp|kws)[^/]*' -and
    $relative -notmatch '^tests/fixtures/'
})
foreach ($legacyPath in $legacyPaths) {
    Add-Failure "Legacy path remains: $legacyPath"
}

if ($failures.Count -ne 0) {
    foreach ($failure in $failures) {
        Write-Error $failure -ErrorAction Continue
    }
    Write-Host "Architecture check failed with $($failures.Count) issue group(s)."
    exit 1
}

Write-Host 'Architecture checks passed.'
