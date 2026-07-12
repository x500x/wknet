[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$JavaHome,

    [Parameter(Mandatory)]
    [string]$ExificientCoreJar,

    [Parameter(Mandatory)]
    [string]$ExificientGrammarsJar,

    [Parameter(Mandatory)]
    [string]$Slf4jApiJar,

    [Parameter(Mandatory)]
    [string]$XercesJar,

    [Parameter(Mandatory)]
    [string]$XmlApisJar,

    [string]$OutputRoot = (Join-Path $PSScriptRoot 'corpus')
)

$ErrorActionPreference = 'Stop'

function Assert-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file does not exist: $Path"
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE"
    }
}

$source = Join-Path $PSScriptRoot 'GenerateExiFixtures.java'
$javac = Join-Path $JavaHome 'bin\javac.exe'
$java = Join-Path $JavaHome 'bin\java.exe'
foreach ($path in @(
        $source,
        $javac,
        $java,
        $ExificientCoreJar,
        $ExificientGrammarsJar,
        $Slf4jApiJar,
        $XercesJar,
        $XmlApisJar)) {
    Assert-File $path
}

$classes = Join-Path ([System.IO.Path]::GetTempPath()) 'wknet-exi-generator-classes'
New-Item -ItemType Directory -Force -Path $classes | Out-Null
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$classpath = "$ExificientCoreJar;$ExificientGrammarsJar;$Slf4jApiJar;$XercesJar;$XmlApisJar"
Invoke-Native $javac @('-cp', $classpath, '-d', $classes, $source)
Invoke-Native $java @(
    '-cp', "$classes;$classpath",
    'GenerateExiFixtures', '--corpus', $OutputRoot)

$files = Get-ChildItem -LiteralPath $OutputRoot -File |
    Where-Object { $_.Name -notin @('SHA256SUMS', 'provenance.json') } |
    Sort-Object Name
$sumLines = foreach ($file in $files) {
    "$(Get-Sha256 $file.FullName)  $($file.Name)"
}
[System.IO.File]::WriteAllLines(
    (Join-Path $OutputRoot 'SHA256SUMS'),
    $sumLines,
    [System.Text.UTF8Encoding]::new($false))

$provenance = [ordered]@{
    ReferenceEncoder = 'Siemens EXIficient Core 1.0.7'
    ReferenceEncoderUrl = 'https://repo1.maven.org/maven2/com/siemens/ct/exi/exificient-core/1.0.7/exificient-core-1.0.7.jar'
    ReferenceEncoderSha256 = Get-Sha256 $ExificientCoreJar
    GrammarsSha256 = Get-Sha256 $ExificientGrammarsJar
    Slf4jApiSha256 = Get-Sha256 $Slf4jApiJar
    XercesSha256 = Get-Sha256 $XercesJar
    XmlApisSha256 = Get-Sha256 $XmlApisJar
    Generator = 'tests/fixtures/exi/GenerateExiCorpus.ps1'
    Alignments = @('bit-packed', 'byte-aligned', 'pre-compression', 'compression')
    Infosets = @('basic', 'xsi-nil-true', 'xsi-nil-false', 'xsi-nil-invalid-content')
    Files = $sumLines
}
[System.IO.File]::WriteAllText(
    (Join-Path $OutputRoot 'provenance.json'),
    ($provenance | ConvertTo-Json -Depth 5) + "`n",
    [System.Text.UTF8Encoding]::new($false))
