[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Jdk6Home,

    [Parameter(Mandatory)]
    [string]$Jdk7Home,

    [Parameter(Mandatory)]
    [string]$Jdk8Home,

    [Parameter(Mandatory)]
    [string]$AsmJar,

    [Parameter(Mandatory)]
    [string]$CommonsCompressJar,

    [string]$OutputRoot = (Join-Path $PSScriptRoot 'corpus'),

    [string]$Jdk6Archive,
    [string]$Jdk7Archive,
    [string]$Jdk8Archive
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

function Assert-PackVersion([string]$Path, [int]$Minor, [int]$Major) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 6 -or
        $bytes[0] -ne 0xca -or $bytes[1] -ne 0xfe -or
        $bytes[2] -ne 0xd0 -or $bytes[3] -ne 0x0d -or
        $bytes[4] -ne $Minor -or $bytes[5] -ne $Major) {
        throw "Unexpected Pack200 header in $Path; expected $Major.$Minor"
    }
}

$generatorSource = Join-Path $PSScriptRoot 'GeneratePack200Fixtures.java'
$javac = Join-Path $Jdk8Home 'bin\javac.exe'
$java = Join-Path $Jdk8Home 'bin\java.exe'
foreach ($path in @($generatorSource, $javac, $java, $AsmJar, $CommonsCompressJar)) {
    Assert-File $path
}

$classes = Join-Path ([System.IO.Path]::GetTempPath()) 'win-khttp-pack200-generator-classes'
New-Item -ItemType Directory -Force -Path $classes | Out-Null
$classpath = "$AsmJar;$CommonsCompressJar"
Invoke-Native $javac @('-cp', $classpath, '-d', $classes, $generatorSource)
$generatorClasspath = "$classes;$classpath"

$matrix = @(
    [ordered]@{ Name = 'jdk5'; ClassMajor = 49; ClassName = 'Jdk5Fixture'; PackMajor = 150; PackMinor = 7; ToolHome = $Jdk6Home },
    [ordered]@{ Name = 'jdk6'; ClassMajor = 50; ClassName = 'Jdk6Fixture'; PackMajor = 160; PackMinor = 1; ToolHome = $Jdk6Home },
    [ordered]@{ Name = 'jdk7'; ClassMajor = 51; ClassName = 'Jdk7Fixture'; PackMajor = 170; PackMinor = 1; ToolHome = $Jdk8Home },
    [ordered]@{ Name = 'jdk8'; ClassMajor = 52; ClassName = 'Jdk8Fixture'; PackMajor = 171; PackMinor = 0; ToolHome = $Jdk8Home }
)

foreach ($item in $matrix) {
    $directory = Join-Path $OutputRoot $item.Name
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $inputJar = Join-Path $directory 'input.jar'
    $rawPack = Join-Path $directory 'archive.pack'
    $gzipPack = Join-Path $directory 'archive.pack.gz'
    $referenceJar = Join-Path $directory 'reference.jar'
    Invoke-Native $java @(
        '-cp', $generatorClasspath,
        'GeneratePack200Fixtures',
        '--versioned-jar', [string]$item.ClassMajor, $item.ClassName, $inputJar)
    $pack200 = Join-Path $item.ToolHome 'bin\pack200.exe'
    $unpack200 = Join-Path $item.ToolHome 'bin\unpack200.exe'
    Assert-File $pack200
    Assert-File $unpack200
    Invoke-Native $pack200 @('--no-gzip', $rawPack, $inputJar)
    Invoke-Native $pack200 @($gzipPack, $inputJar)
    Invoke-Native $unpack200 @($rawPack, $referenceJar)
    Assert-PackVersion $rawPack $item.PackMinor $item.PackMajor
}

$customDirectory = Join-Path $OutputRoot 'jdk8'
$customInput = Join-Path $customDirectory 'custom-attributes.input.jar'
$customPack = Join-Path $customDirectory 'custom-attributes.pack'
Invoke-Native $java @(
    '-cp', $generatorClasspath,
    'GeneratePack200Fixtures', '--custom-jar', $customInput)
$customArguments = @('--no-gzip', '--unknown-attribute=error')
foreach ($index in 0..59) {
    $customArguments += ('-COverflow{0:D2}=B' -f $index)
}
$customArguments += '-CPackCustom=[NH[(1)]][TB(0-1)[B(-1)]()[H]]'
$customArguments += '-CReferenceCustom=KIHKJHKFHKDHKSHKLHRCHRSHRDHRFHRMHRIHRUHRUNHRQHRNH'
$customArguments += '-FFieldCustom=HRUH'
$customArguments += '-MMethodCustom=RUH'
$customArguments += '-DCodeCustom=PHPOHPHOHPHOSH'
$customArguments += $customPack
$customArguments += $customInput
Invoke-Native (Join-Path $Jdk8Home 'bin\pack200.exe') $customArguments
Assert-PackVersion $customPack 7 150

$files = Get-ChildItem -LiteralPath $OutputRoot -Recurse -File |
    Where-Object { $_.Name -notin @('SHA256SUMS', 'provenance.json') } |
    Sort-Object { $_.FullName.Substring($OutputRoot.Length + 1) }
$sumLines = foreach ($file in $files) {
    $relative = $file.FullName.Substring($OutputRoot.Length + 1).Replace('\', '/')
    "$(Get-Sha256 $file.FullName)  $relative"
}
[System.IO.File]::WriteAllLines(
    (Join-Path $OutputRoot 'SHA256SUMS'),
    $sumLines,
    [System.Text.UTF8Encoding]::new($false))

$archives = @(
    [ordered]@{ Name = 'Azul Zulu 6'; Version = '6.22.0.3-jdk6.0.119'; Url = 'https://cdn.azul.com/zulu/bin/zulu6.22.0.3-ca-jdk6.0.119-win_x64.zip'; Path = $Jdk6Archive; Home = $Jdk6Home },
    [ordered]@{ Name = 'Azul Zulu 7'; Version = '7.56.0.11-ca-jdk7.0.352'; Url = 'https://cdn.azul.com/zulu/bin/zulu7.56.0.11-ca-jdk7.0.352-win_x64.zip'; Path = $Jdk7Archive; Home = $Jdk7Home },
    [ordered]@{ Name = 'Eclipse Temurin 8'; Version = 'jdk8u492-b09'; Url = 'https://api.adoptium.net/v3/binary/latest/8/ga/windows/x64/jdk/hotspot/normal/eclipse'; Path = $Jdk8Archive; Home = $Jdk8Home }
)
foreach ($archive in $archives) {
    $archive['ArchiveSha256'] = if ($archive.Path) { Get-Sha256 $archive.Path } else { $null }
    $archive['Pack200Sha256'] = Get-Sha256 (Join-Path $archive.Home 'bin\pack200.exe')
    $archive.Remove('Path')
    $archive.Remove('Home')
}
$provenance = [ordered]@{
    GeneratedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    Generator = 'tests/fixtures/pack200/GenerateJdkPack200Corpus.ps1'
    Toolchains = $archives
    Formats = @(
        [ordered]@{ Directory = 'jdk5'; Pack200 = '150.7'; ClassMajor = 49; Packer = 'Azul Zulu 6 (Java 5 format producer)' },
        [ordered]@{ Directory = 'jdk6'; Pack200 = '160.1'; ClassMajor = 50; Packer = 'Azul Zulu 6' },
        [ordered]@{ Directory = 'jdk7'; Pack200 = '170.1'; ClassMajor = 51; Packer = 'Eclipse Temurin 8 (Java 7 format producer; the archived Zulu 7 packer emits only 160.1)' },
        [ordered]@{ Directory = 'jdk8'; Pack200 = '171.0'; ClassMajor = 52; Packer = 'Eclipse Temurin 8' }
    )
    CustomAttributeFixture = [ordered]@{
        Packer = 'Eclipse Temurin 8 native pack200'
        Pack200 = '150.7 (Java 5 classfile input)'
        Contexts = @('class', 'field', 'method', 'code')
        Layouts = @(
            '[NH[(1)]][TB(0-1)[B(-1)]()[H]]',
            'KIHKJHKFHKDHKSHKLHRCHRSHRDHRFHRMHRIHRUHRUNHRQHRNH',
            'HRUH',
            'RUH',
            'PHPOHPHOHPHOSH')
        Note = 'Native JDK 8 pack200 fails while emitting a user-defined KQ band (null index for field-specific constant); KQ is covered by layout/compiler tests and the decoder implements descriptor-directed field-specific relocation.'
    }
    Files = $sumLines
}
$json = $provenance | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText(
    (Join-Path $OutputRoot 'provenance.json'),
    $json + "`n",
    [System.Text.UTF8Encoding]::new($false))
