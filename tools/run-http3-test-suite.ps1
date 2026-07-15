#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('QuicCore', 'H3Session', 'Protocol', 'Regression', 'AllFirstParty', 'KernelVm')]
    [string]$Group,
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
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildTests = Join-Path $PSScriptRoot 'build-tests.ps1'
$kernelVmTests = Join-Path $repoRoot 'tests\integration\http3_kernel.ps1'

$groups = @{
    QuicCore = @(
        'quic_packet_tests',
        'quic_frame_tests',
        'quic_transport_parameter_tests',
        'quic_recovery_tests',
        'quic_connection_lifecycle_tests',
        'quic_stream_tests'
    )
    H3Session = @(
        'qpack_tests',
        'http3_client_tests',
        'http_api_tests'
    )
    Protocol = @(
        'datagram_socket_tests',
        'quic_packet_tests',
        'quic_frame_tests',
        'quic_transport_parameter_tests',
        'quic_recovery_tests',
        'quic_connection_lifecycle_tests',
        'quic_stream_tests',
        'qpack_tests',
        'http3_client_tests',
        'http_api_tests',
        'protocol_failure_injection_tests',
        'protocol_log_safety_tests',
        'http3_interop_tests',
        'quic_stress_tests'
    )
    Regression = @(
        'tls13_services_tests',
        'tls_crypto_tests',
        'tls_handshake_tests',
        'tls_record_tests',
        'tls_interop_matrix_tests',
        'http_parser_tests',
        'http2_frame_tests',
        'http2_client_tests',
        'http_api_tests',
        'http_stress_tests',
        'high_level_api_tests',
        'websocket_frame_tests',
        'websocket_client_tests',
        'trace_tests'
    )
}

if ($Group -eq 'AllFirstParty')
{
    $groups[$Group] = @(
        & rg --files (Join-Path $repoRoot 'tests') -g '*_tests.cpp' |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) } |
            Sort-Object -Unique
    )
    if ($LASTEXITCODE -ne 0)
    {
        throw "Failed to discover first-party test targets."
    }
}

if ($Group -eq 'KernelVm')
{
    Write-Host "[http3-suite] group=KernelVm configuration=$Configuration platform=$Platform"
    $kernelArgs = @(
        '-NoLogo',
        '-NoProfile',
        '-File',
        $kernelVmTests,
        '-Configuration',
        $Configuration,
        '-Platform',
        $Platform,
        '-TimeoutSeconds',
        "$TimeoutSeconds"
    )
    if ($EnableVerifier)
    {
        $kernelArgs += '-EnableVerifier'
    }
    if ($SkipDriverBuild)
    {
        $kernelArgs += '-SkipDriverBuild'
    }
    & pwsh @kernelArgs
    if ($LASTEXITCODE -ne 0)
    {
        exit $LASTEXITCODE
    }
    Write-Host "[http3-suite] group=KernelVm passed"
    exit 0
}

Write-Host "[http3-suite] group=$Group count=$($groups[$Group].Count)"
foreach ($test in $groups[$Group])
{
    Write-Host "[http3-suite] target=$test"
}

foreach ($test in $groups[$Group])
{
    $source = Join-Path $repoRoot "tests\$test.cpp"
    if (-not (Test-Path -LiteralPath $source))
    {
        throw "HTTP/3 test suite target is missing: $source"
    }

    Write-Host "[http3-suite] group=$Group test=$test"
    if ($test -eq 'http3_interop_tests')
    {
        & pwsh -NoLogo -NoProfile -File $buildTests -Test $test
    }
    else
    {
        & pwsh -NoLogo -NoProfile -File $buildTests -Test $test -Run
    }
    if ($LASTEXITCODE -ne 0)
    {
        exit $LASTEXITCODE
    }
}

Write-Host "[http3-suite] group=$Group passed"
