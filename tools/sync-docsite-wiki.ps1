param(
    [string]$SourceDir = "docsite",
    [string]$WikiDir = "wiki",
    [string]$MkDocsFile = "mkdocs.yml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-WikiPageName {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $normalized = ($RelativePath -replace '\\', '/').TrimStart('/')
    $dir = [System.IO.Path]::GetDirectoryName($normalized)
    if ($null -eq $dir) { $dir = "" }
    $dir = ($dir -replace '\\', '/').Trim('/')
    $fileName = [System.IO.Path]::GetFileName($normalized)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($fileName)

    if ($stem -eq "index" -and [string]::IsNullOrEmpty($dir)) {
        return "Home"
    }

    $knownWords = @{
        "api" = "API"
        "faq" = "FAQ"
        "http1" = "HTTP1"
        "http2" = "HTTP2"
        "ntstatus" = "NTSTATUS"
        "tls" = "TLS"
        "websocket" = "WebSocket"
        "sse" = "SSE"
    }

    $rawParts = @()
    if (-not [string]::IsNullOrEmpty($dir)) {
        $rawParts += ($dir -split '/')
    }
    $rawParts += ($stem -split "-")

    $parts = foreach ($part in $rawParts) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $word = $part.ToLowerInvariant()
        if ($knownWords.ContainsKey($word)) {
            $knownWords[$word]
        } elseif ($word -eq "and") {
            "and"
        } elseif ($word.Length -gt 1) {
            $word.Substring(0, 1).ToUpperInvariant() + $word.Substring(1)
        } else {
            $word.ToUpperInvariant()
        }
    }

    return ($parts -join "-")
}

function Get-ResolvedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Create
    )

    if ($Create -and -not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }

    $resolved = Resolve-Path -LiteralPath $Path
    $item = Get-Item -LiteralPath $resolved.Path
    if (-not $item.PSIsContainer) {
        throw "Path is not a directory: $Path"
    }

    return $resolved.Path
}

function ConvertTo-PosixRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$FullPath
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $pathFull = [System.IO.Path]::GetFullPath($FullPath)
    if (-not $pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside source root: $FullPath"
    }

    $relative = $pathFull.Substring($rootFull.Length).TrimStart('\', '/')
    return ($relative -replace '\\', '/')
}

function Resolve-DocsiteLinkPath {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CurrentDir,
        [Parameter(Mandatory = $true)][string]$LinkPath
    )

    $normalizedLink = ($LinkPath -replace '\\', '/').Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedLink)) {
        return $null
    }

    # Drop a leading "./"
    while ($normalizedLink.StartsWith("./")) {
        $normalizedLink = $normalizedLink.Substring(2)
    }

    $combined = if ([string]::IsNullOrEmpty($CurrentDir) -or $normalizedLink.StartsWith("/")) {
        $normalizedLink.TrimStart('/')
    } else {
        ($CurrentDir.Trim('/') + "/" + $normalizedLink).Trim('/')
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($part in ($combined -split '/')) {
        if ([string]::IsNullOrEmpty($part) -or $part -eq ".") { continue }
        if ($part -eq "..") {
            if ($parts.Count -eq 0) {
                return $null
            }
            $parts.RemoveAt($parts.Count - 1)
            continue
        }
        $parts.Add($part)
    }

    return ($parts -join '/')
}

function ConvertTo-ChineseSourceKey {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $key = ($RelativePath -replace '\\', '/').ToLowerInvariant()
    if ($key.EndsWith(".en.md")) {
        return $key.Substring(0, $key.Length - ".en.md".Length) + ".md"
    }
    return $key
}

function New-PageMap {
    param([Parameter(Mandatory = $true)][string]$Root)

    $map = @{}
    $pages = Get-ChildItem -LiteralPath $Root -Filter "*.md" -File -Recurse |
        Where-Object {
            $_.Name -notlike "*.en.md" -and
            $_.FullName -notmatch '[\\/](stylesheets|javascripts|assets|images|img|static)([\\/]|$)'
        } |
        Sort-Object FullName

    foreach ($page in $pages) {
        $relative = ConvertTo-PosixRelativePath -Root $Root -FullPath $page.FullName
        $key = $relative.ToLowerInvariant()
        $wikiName = ConvertTo-WikiPageName -RelativePath $relative
        if ($map.ContainsKey($key)) {
            throw "Duplicate docsite page path: $relative"
        }
        if ($map.Values -contains $wikiName) {
            throw "Duplicate generated wiki page name: $wikiName (from $relative)"
        }
        $map[$key] = $wikiName
    }

    return $map
}

function ConvertTo-WikiLinkTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][hashtable]$PageMap,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CurrentDir
    )

    if ($Target.StartsWith("#")) {
        return $Target
    }
    if ($Target -match "^[a-zA-Z][a-zA-Z0-9+.-]*:") {
        return $Target
    }

    $fragment = ""
    $path = $Target
    $hashIndex = $Target.IndexOf("#")
    if ($hashIndex -ge 0) {
        $path = $Target.Substring(0, $hashIndex)
        $fragment = $Target.Substring($hashIndex)
    }

    if ([string]::IsNullOrWhiteSpace($path)) {
        return $Target
    }

    $resolved = Resolve-DocsiteLinkPath -CurrentDir $CurrentDir -LinkPath $path
    if ($null -eq $resolved) {
        throw "Markdown link escapes the docsite root: $Target"
    }

    if (-not $resolved.EndsWith(".md", [System.StringComparison]::OrdinalIgnoreCase)) {
        # Non-markdown assets keep their original target.
        return $Target
    }

    # Wiki pages are bilingual and keyed by the Chinese source path (X.md).
    # English sources may cross-link with either X.md or X.en.md.
    $key = ConvertTo-ChineseSourceKey -RelativePath $resolved
    if (-not $PageMap.ContainsKey($key)) {
        throw "Markdown link points to an unknown docsite page: $Target"
    }

    return "$($PageMap[$key])$fragment"
}

function Convert-MarkdownLinks {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][hashtable]$PageMap,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CurrentDir
    )

    $pattern = "(?<!!)\[(?<text>[^\]]+)\]\((?<target>[^)]+)\)"
    return [System.Text.RegularExpressions.Regex]::Replace(
        $Content,
        $pattern,
        {
            param([System.Text.RegularExpressions.Match]$match)

            $text = $match.Groups["text"].Value
            $target = $match.Groups["target"].Value.Trim()
            $converted = ConvertTo-WikiLinkTarget -Target $target -PageMap $PageMap -CurrentDir $CurrentDir
            return "[$text]($converted)"
        })
}

function Get-MkDocsNavLines {
    param([Parameter(Mandatory = $true)][string]$Path)

    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    $inNav = $false
    $navLines = [System.Collections.Generic.List[string]]::new()

    foreach ($line in $lines) {
        if (-not $inNav) {
            if ($line -match "^nav:\s*$") {
                $inNav = $true
            }
            continue
        }

        if ($line -match "^\S" -and $line -notmatch "^nav:\s*$") {
            break
        }
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line.TrimStart().StartsWith("#")) {
            continue
        }

        $navLines.Add($line)
    }

    if ($navLines.Count -eq 0) {
        throw "No nav entries found in $Path"
    }

    return $navLines
}

function Get-NavTranslations {
    # Parse the `nav_translations` block under the English locale in
    # mkdocs.yml into a hashtable mapping the default-language (Chinese)
    # label to the English label.
    param([Parameter(Mandatory = $true)][string]$Path)

    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    $map = @{}
    $inTrans = $false
    $headIndent = -1
    foreach ($line in $lines) {
        if (-not $inTrans) {
            if ($line -match "^\s*nav_translations:\s*$") {
                $inTrans = $true
                $headIndent = $line.Length - $line.TrimStart().Length
            }
            continue
        }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $curIndent = $line.Length - $line.TrimStart().Length
        if ($curIndent -le $headIndent) { break }
        $m = [System.Text.RegularExpressions.Regex]::Match($line, "^\s*(?<key>[^:]+):\s*(?<val>.+?)\s*$")
        if ($m.Success) {
            $map[$m.Groups["key"].Value.Trim()] = $m.Groups["val"].Value.Trim()
        }
    }
    return $map
}

function New-SidebarContent {
    param(
        [Parameter(Mandatory = $true)][string]$MkDocsPath,
        [Parameter(Mandatory = $true)][hashtable]$PageMap
    )

    $translations = Get-NavTranslations -Path $MkDocsPath
    $sidebar = [System.Collections.Generic.List[string]]::new()
    $sidebar.Add("### wknet Wiki")
    $sidebar.Add("")

    foreach ($line in (Get-MkDocsNavLines -Path $MkDocsPath)) {
        $match = [System.Text.RegularExpressions.Regex]::Match($line, "^(?<indent>\s*)-\s+(?<label>[^:]+):(?:\s*(?<target>.*))?$")
        if (-not $match.Success) {
            throw "Unsupported mkdocs nav line: $line"
        }

        $indent = $match.Groups["indent"].Value.Length
        $level = [Math]::Max(0, [int][Math]::Floor(($indent - 2) / 4))
        $prefix = "  " * $level
        $zhLabel = $match.Groups["label"].Value.Trim()
        $target = $match.Groups["target"].Value.Trim()

        # Bilingual label for the single-page bilingual wiki.
        if ($translations.ContainsKey($zhLabel)) {
            $label = "$zhLabel / $($translations[$zhLabel])"
        } else {
            $label = $zhLabel
        }

        if ([string]::IsNullOrWhiteSpace($target)) {
            if ($level -eq 0 -and $sidebar[$sidebar.Count - 1] -ne "") {
                $sidebar.Add("")
            }
            $sidebar.Add("$prefix- **$label**")
            continue
        }

        $key = ConvertTo-ChineseSourceKey -RelativePath (($target -replace '\\', '/').TrimStart('/'))
        if (-not $PageMap.ContainsKey($key)) {
            throw "mkdocs nav points to an unknown docsite page: $target"
        }

        $sidebar.Add("$prefix- [$label]($($PageMap[$key]))")
    }

    $sidebar.Add("")
    return ($sidebar -join "`n")
}

$sourceRoot = Get-ResolvedDirectory -Path $SourceDir
$wikiRoot = Get-ResolvedDirectory -Path $WikiDir -Create
$mkdocsPath = (Resolve-Path -LiteralPath $MkDocsFile).Path
$pageMap = New-PageMap -Root $sourceRoot

Get-ChildItem -LiteralPath $wikiRoot -Filter "*.md" -File | Remove-Item -Force

# Each wiki page is bilingual: Chinese body, separator, English body. Only
# the Chinese sources (X.md) drive the loop; the matching X.en.md is
# appended when present. Nested docs (e.g. api/*.md) are included.
$sourcePages = Get-ChildItem -LiteralPath $sourceRoot -Filter "*.md" -File -Recurse |
    Where-Object {
        $_.Name -notlike "*.en.md" -and
        $_.FullName -notmatch '[\\/](stylesheets|javascripts|assets|images|img|static)([\\/]|$)'
    } |
    Sort-Object FullName

foreach ($sourcePage in $sourcePages) {
    $relative = ConvertTo-PosixRelativePath -Root $sourceRoot -FullPath $sourcePage.FullName
    $key = $relative.ToLowerInvariant()
    $wikiPage = $pageMap[$key]
    $targetPath = Join-Path -Path $wikiRoot -ChildPath "$wikiPage.md"
    $currentDir = [System.IO.Path]::GetDirectoryName($relative)
    if ($null -eq $currentDir) { $currentDir = "" }
    $currentDir = ($currentDir -replace '\\', '/').Trim('/')

    $zhRaw = Get-Content -LiteralPath $sourcePage.FullName -Raw -Encoding UTF8
    $zhConverted = Convert-MarkdownLinks -Content $zhRaw -PageMap $pageMap -CurrentDir $currentDir

    $enRelative = if ($relative -match '\.md$') {
        $relative.Substring(0, $relative.Length - 3) + ".en.md"
    } else {
        $relative + ".en.md"
    }
    $enSource = Join-Path $sourceRoot ($enRelative -replace '/', [System.IO.Path]::DirectorySeparatorChar)
    if (Test-Path -LiteralPath $enSource) {
        $enRaw = Get-Content -LiteralPath $enSource -Raw -Encoding UTF8
        $enConverted = Convert-MarkdownLinks -Content $enRaw -PageMap $pageMap -CurrentDir $currentDir
        $combined = $zhConverted.TrimEnd() + "`n`n---`n`n## English`n`n" + $enConverted.TrimEnd() + "`n"
    } else {
        $combined = $zhConverted
    }

    Set-Content -LiteralPath $targetPath -Value $combined -Encoding utf8NoBOM
}

$sidebarContent = New-SidebarContent -MkDocsPath $mkdocsPath -PageMap $pageMap
Set-Content -LiteralPath (Join-Path -Path $wikiRoot -ChildPath "_Sidebar.md") -Value $sidebarContent -Encoding utf8NoBOM

$footerContent = @(
    "---",
    "wknet · 纯内核态 HTTP/HTTPS 客户端库 · Pure kernel-mode HTTP/HTTPS client · MIT License ·",
    "[仓库 / Repo](https://github.com/x500x/wknet) · [Issues](https://github.com/x500x/wknet/issues)",
    "",
    "This Wiki is generated from `docsite`; edit repository docs and let the docs workflow sync it."
) -join "`n"
Set-Content -LiteralPath (Join-Path -Path $wikiRoot -ChildPath "_Footer.md") -Value $footerContent -Encoding utf8NoBOM

Write-Host "Synced $($pageMap.Count) docsite pages to $wikiRoot"
