[CmdletBinding()]
param(
    [string[]]$SourceRoots = @(
        (Join-Path $PSScriptRoot '..\include\wknet'),
        (Join-Path $PSScriptRoot '..\src\wknetlib')
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TraceInvocations {
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $macroPattern = [regex]'\bWKNET_TRACE(?:_CORRELATED)?\s*\('
    foreach ($match in $macroPattern.Matches($Text)) {
        $lineStart = $Text.LastIndexOf("`n", $match.Index)
        $linePrefix = $Text.Substring($lineStart + 1, $match.Index - $lineStart - 1)
        if ($linePrefix -match '^\s*#\s*define\b') {
            continue
        }

        $openIndex = $Text.IndexOf('(', $match.Index)
        $depth = 0
        $inString = $false
        $inCharacter = $false
        $inLineComment = $false
        $inBlockComment = $false
        $escaped = $false
        $endIndex = -1

        for ($index = $openIndex; $index -lt $Text.Length; ++$index) {
            $current = $Text[$index]
            $next = if ($index + 1 -lt $Text.Length) { $Text[$index + 1] } else { [char]0 }

            if ($inLineComment) {
                if ($current -eq "`n") {
                    $inLineComment = $false
                }
                continue
            }
            if ($inBlockComment) {
                if ($current -eq '*' -and $next -eq '/') {
                    $inBlockComment = $false
                    ++$index
                }
                continue
            }
            if ($inString -or $inCharacter) {
                if ($escaped) {
                    $escaped = $false
                    continue
                }
                if ($current -eq '\') {
                    $escaped = $true
                    continue
                }
                if (($inString -and $current -eq '"') -or ($inCharacter -and $current -eq "'")) {
                    $inString = $false
                    $inCharacter = $false
                }
                continue
            }

            if ($current -eq '/' -and $next -eq '/') {
                $inLineComment = $true
                ++$index
                continue
            }
            if ($current -eq '/' -and $next -eq '*') {
                $inBlockComment = $true
                ++$index
                continue
            }
            if ($current -eq '"') {
                $inString = $true
                continue
            }
            if ($current -eq "'") {
                $inCharacter = $true
                continue
            }
            if ($current -eq '(') {
                ++$depth
                continue
            }
            if ($current -eq ')') {
                --$depth
                if ($depth -eq 0) {
                    $endIndex = $index
                    break
                }
            }
        }

        if ($endIndex -lt 0) {
            throw "Unterminated trace macro in ${Path}."
        }

        $line = 1 + ([regex]::Matches($Text.Substring(0, $match.Index), "`n")).Count
        [pscustomobject]@{
            Path = $Path
            Line = $line
            Text = $Text.Substring($match.Index, $endIndex - $match.Index + 1)
        }
    }
}

function Get-FirstStringLiteral {
    param(
        [Parameter(Mandatory)]
        [string]$Invocation
    )

    $literal = [regex]::Match($Invocation, '"(?<value>(?:\\.|[^"\\])*)"')
    if (-not $literal.Success) {
        return $null
    }
    return $literal.Groups['value'].Value
}

$extensions = @('.c', '.cc', '.cpp', '.h', '.hh', '.hpp')
$failures = [System.Collections.Generic.List[string]]::new()
$checkedCount = 0

foreach ($root in $SourceRoots) {
    $resolvedRoot = (Resolve-Path -LiteralPath $root).Path
    $files = Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File |
        Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() }

    foreach ($file in $files) {
        $text = Get-Content -Raw -LiteralPath $file.FullName
        foreach ($invocation in Get-TraceInvocations -Text $text -Path $file.FullName) {
            ++$checkedCount
            $format = Get-FirstStringLiteral -Invocation $invocation.Text
            $location = '{0}:{1}' -f $invocation.Path, $invocation.Line

            if ($null -eq $format) {
                $failures.Add("${location}: trace macro has no literal format string")
                continue
            }
            if ($format -notmatch '^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+(?=$| )') {
                $failures.Add("${location}: unstable event name: $format")
            }
            if ($invocation.Text -match '\\r\\n') {
                $failures.Add("${location}: trace macro must not append CRLF")
            }
            if ($format -match '(?i)%[-+ #0-9.]*p') {
                $failures.Add("${location}: pointer formatting is forbidden")
            }
            if ($format -match '(?i)(authorization|proxy_authorization|cookie|credential|password|secret|private_key|random_bytes|certificate_der|certificate_raw|url_query|query_string|header_value)\s*=\s*%') {
                $failures.Add("${location}: sensitive value formatting is forbidden")
            }
        }
    }
}

if ($failures.Count -ne 0) {
    $failures | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}

Write-Host "Trace event check passed: $checkedCount invocation(s)."
