param(
    [ValidateSet('Debug', 'Release', 'All')]
    [string]$Configuration = 'All',

    [ValidateSet('x64', 'ARM64', 'All')]
    [string]$Platform = 'All',

    [switch]$NoRestore
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:Solution = Join-Path $script:Root 'KernelHttp.sln'
$script:LibTarget = 'KernelHttpLib'
$script:KernelPlatforms = @('x64', 'ARM64')
$script:Configurations = @('Debug', 'Release')

function Write-Step {
    param([string]$Message)
    Write-Host "[kernel-http-lib] $Message"
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

function Get-MsBuildPath {
    param([string]$VsPath)

    $msbuild = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path -LiteralPath $msbuild)) {
        throw "MSBuild.exe not found at $msbuild"
    }

    return $msbuild
}

function Assert-KernelPlatformToolset {
    param(
        [string]$VsPath,
        [string]$PlatformName
    )

    $vcTargetsPath = Join-Path $VsPath 'MSBuild\Microsoft\VC\v170'
    $kernelToolset = Join-Path $vcTargetsPath "Platforms\$PlatformName\PlatformToolsets\WindowsKernelModeDriver10.0\Toolset.props"
    if (-not (Test-Path -LiteralPath $kernelToolset)) {
        throw "WindowsKernelModeDriver10.0 toolset is not installed for $PlatformName."
    }

    $vcToolset = Join-Path $vcTargetsPath "Platforms\$PlatformName\PlatformToolsets\v143\Toolset.props"
    if (-not (Test-Path -LiteralPath $vcToolset)) {
        throw "VC v143 $PlatformName build tools are not installed. Install the $PlatformName MSVC build tools and matching WDK components, then rerun this script."
    }
}

$platformsToBuild = if ($Platform -eq 'All') { $script:KernelPlatforms } else { @($Platform) }
$configurationsToBuild = if ($Configuration -eq 'All') { $script:Configurations } else { @($Configuration) }
$vsPath = Get-VsInstallationPath
$msbuild = Get-MsBuildPath -VsPath $vsPath

foreach ($platformToBuild in $platformsToBuild) {
    Assert-KernelPlatformToolset -VsPath $vsPath -PlatformName $platformToBuild
}

foreach ($configurationToBuild in $configurationsToBuild) {
    foreach ($platformToBuild in $platformsToBuild) {
        $arguments = @(
            $script:Solution,
            '/m',
            '/nr:false',
            "/t:$script:LibTarget",
            "/p:Configuration=$configurationToBuild",
            "/p:Platform=$platformToBuild"
        )

        if (-not $NoRestore) {
            $arguments += '/restore'
        }

        Invoke-Checked -FilePath $msbuild -ArgumentList $arguments

        $libPath = Join-Path $script:Root "$platformToBuild\$configurationToBuild\KernelHttpLib.lib"
        if (-not (Test-Path -LiteralPath $libPath)) {
            throw "Library output was not found: $libPath"
        }

        Write-Step "built $libPath"
    }
}
