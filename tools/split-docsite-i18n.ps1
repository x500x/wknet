<#
.SYNOPSIS
    Split the mixed Chinese/English .md files in docsite/ into pure Chinese
    (X.md) and pure English (X.en.md) for mkdocs-static-i18n (suffix mode).

.DESCRIPTION
    Idempotent: cleans previously generated *.en.md first.
    Splits on the literal Chinese and English section headings (the Chinese
    heading is built from code points below). We match the exact literal
    because high-level-api.md / low-level-api.md use ## as section titles
    inside the body.
    Cross-file links [x](y.md) are left untouched; the i18n plugin rewrites
    them per language automatically.
    The script is pure-ASCII so it parses under Windows PowerShell 5.1
    without a BOM.
#>
param(
    [string]$SourceDir = "docsite"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SourceDir)) {
    throw "SourceDir not found: $SourceDir"
}
$sourceRoot = (Resolve-Path -LiteralPath $SourceDir).Path
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Build the Chinese heading from code points so this script stays ASCII-only.
$zhHeading = "## " + [char]0x7B80 + [char]0x4F53 + [char]0x4E2D + [char]0x6587

function Test-ContainsCjk {
    # True if the string has any CJK Unified Ideograph (U+4E00..U+9FFF).
    param([string]$Value)
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($code -ge 0x4E00 -and $code -le 0x9FFF) { return $true }
    }
    return $false
}

# Idempotent: remove previously generated English files.
Get-ChildItem -LiteralPath $sourceRoot -Filter "*.en.md" -File |
    Remove-Item -Force

function Split-H1Title {
    # Input "# Chinese / English"; returns @(<chinese>, <english>). If no
    # " / " is present both halves are the same. Splitting on " / " (with
    # spaces) keeps "HTTP/1.1" (no spaces) intact.
    param([string]$Line)
    $inner = ($Line -replace "^#\s*", "").Trim()
    $at = $inner.IndexOf(" / ")
    if ($at -ge 0) {
        return @($inner.Substring(0, $at).Trim(), $inner.Substring($at + 3).Trim())
    }
    return @($inner, $inner)
}

function Clean-Body {
    # Trim leading blanks; trim trailing blanks and a single trailing "---"
    # (the separator between the Chinese body and the English heading). Only
    # one "---" is removed so legitimate thematic breaks are preserved.
    param([string[]]$Body)
    $list = [System.Collections.Generic.List[string]]::new([string[]]$Body)
    while ($list.Count -gt 0 -and $list[$list.Count - 1].Trim() -eq "") {
        $list.RemoveAt($list.Count - 1)
    }
    if ($list.Count -gt 0 -and $list[$list.Count - 1].Trim() -eq "---") {
        $list.RemoveAt($list.Count - 1)
    }
    while ($list.Count -gt 0 -and $list[$list.Count - 1].Trim() -eq "") {
        $list.RemoveAt($list.Count - 1)
    }
    while ($list.Count -gt 0 -and $list[0].Trim() -eq "") {
        $list.RemoveAt(0)
    }
    return ,$list.ToArray()
}

function Build-Output {
    param(
        [string]$H1,
        [string[]]$Taglines,
        [string[]]$Body,
        [string]$Eol
    )
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("# " + $H1)
    foreach ($tg in $Taglines) { $parts.Add(""); $parts.Add($tg) }
    $parts.Add("")
    foreach ($b in $Body) { $parts.Add($b) }
    return (($parts -join $Eol) + $Eol)
}

$sourceFiles = Get-ChildItem -LiteralPath $sourceRoot -Filter "*.md" -File |
    Where-Object { $_.Name -notlike "*.en.md" } |
    Sort-Object Name

$split = 0
foreach ($file in $sourceFiles) {
    $text = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
    # Preserve the original line ending style to avoid noisy git diffs.
    $eol = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = $text -split '\r?\n'

    $zhIdx = -1; $enIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $t = $lines[$i].TrimEnd()
        if ($zhIdx -lt 0 -and $t -eq $zhHeading) { $zhIdx = $i }
        elseif ($t -eq "## English") { $enIdx = $i; break }
    }
    if ($zhIdx -lt 0 -or $enIdx -lt 0 -or $enIdx -le $zhIdx) {
        throw "$($file.Name): anchors not found (zhIdx=$zhIdx enIdx=$enIdx)"
    }

    $titles = Split-H1Title -Line $lines[0]

    # Tagline lines in the preamble (only index.md has them): lines
    # containing CJK go to the Chinese file, others to the English file.
    $zhTags = [System.Collections.Generic.List[string]]::new()
    $enTags = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -lt $zhIdx; $i++) {
        $s = $lines[$i].Trim()
        if ($s.StartsWith("**") -and $s.EndsWith("**") -and $s.Length -gt 4) {
            if (Test-ContainsCjk -Value $lines[$i]) { $zhTags.Add($lines[$i]) }
            else { $enTags.Add($lines[$i]) }
        }
    }

    $zhBody = @()
    if ($enIdx - 1 -ge $zhIdx + 1) {
        $zhBody = Clean-Body -Body $lines[($zhIdx + 1)..($enIdx - 1)]
    }
    $enBody = @()
    if ($lines.Count - 1 -ge $enIdx + 1) {
        $enBody = Clean-Body -Body $lines[($enIdx + 1)..($lines.Count - 1)]
    }

    $zhContent = Build-Output -H1 $titles[0] -Taglines $zhTags.ToArray() -Body $zhBody -Eol $eol
    $enContent = Build-Output -H1 $titles[1] -Taglines $enTags.ToArray() -Body $enBody -Eol $eol

    $enPath = Join-Path $sourceRoot ($file.BaseName + ".en.md")
    [System.IO.File]::WriteAllText($file.FullName, $zhContent, $utf8NoBom)
    [System.IO.File]::WriteAllText($enPath, $enContent, $utf8NoBom)

    Write-Host ("{0,-28} zh:{1,5} en:{2,5} tags:{3}" -f $file.Name, $zhBody.Count, $enBody.Count, ($zhTags.Count + $enTags.Count))
    $split++
}

Write-Host ""
Write-Host "Split $split files in $sourceRoot"
