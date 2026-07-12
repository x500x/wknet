param(
    [string]$SourceDir = "docsite",
    [string]$WikiDir = "wiki",
    [string]$MkDocsFile = "mkdocs.yml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-WikiPageName {
    param([Parameter(Mandatory = $true)][string]$SourceFileName)

    $stem = [System.IO.Path]::GetFileNameWithoutExtension($SourceFileName)
    if ($stem -eq "index") {
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
    }

    $parts = foreach ($part in ($stem -split "-")) {
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

function New-PageMap {
    param([Parameter(Mandatory = $true)][string]$Root)

    $map = @{}
    $pages = Get-ChildItem -LiteralPath $Root -Filter "*.md" -File |
        Where-Object { $_.Name -notlike "*.en.md" } |
        Sort-Object Name
    foreach ($page in $pages) {
        $key = $page.Name.ToLowerInvariant()
        $wikiName = ConvertTo-WikiPageName -SourceFileName $page.Name
        if ($map.ContainsKey($key)) {
            throw "Duplicate docsite page name: $($page.Name)"
        }
        if ($map.Values -contains $wikiName) {
            throw "Duplicate generated wiki page name: $wikiName"
        }
        $map[$key] = $wikiName
    }

    return $map
}

function ConvertTo-WikiLinkTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][hashtable]$PageMap
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

    $fileName = [System.IO.Path]::GetFileName($path)
    if ([string]::IsNullOrWhiteSpace($fileName) -or -not $fileName.EndsWith(".md", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Target
    }

    $key = $fileName.ToLowerInvariant()
    if (-not $PageMap.ContainsKey($key)) {
        throw "Markdown link points to an unknown docsite page: $Target"
    }

    return "$($PageMap[$key])$fragment"
}

function Convert-MarkdownLinks {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][hashtable]$PageMap
    )

    $pattern = "(?<!!)\[(?<text>[^\]]+)\]\((?<target>[^)]+)\)"
    return [System.Text.RegularExpressions.Regex]::Replace(
        $Content,
        $pattern,
        {
            param([System.Text.RegularExpressions.Match]$match)

            $text = $match.Groups["text"].Value
            $target = $match.Groups["target"].Value.Trim()
            $converted = ConvertTo-WikiLinkTarget -Target $target -PageMap $PageMap
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

        $fileName = [System.IO.Path]::GetFileName($target).ToLowerInvariant()
        if (-not $PageMap.ContainsKey($fileName)) {
            throw "mkdocs nav points to an unknown docsite page: $target"
        }

        $sidebar.Add("$prefix- [$label]($($PageMap[$fileName]))")
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
# appended when present.
foreach ($sourcePage in (Get-ChildItem -LiteralPath $sourceRoot -Filter "*.md" -File | Where-Object { $_.Name -notlike "*.en.md" } | Sort-Object Name)) {
    $wikiPage = $pageMap[$sourcePage.Name.ToLowerInvariant()]
    $targetPath = Join-Path -Path $wikiRoot -ChildPath "$wikiPage.md"

    $zhRaw = Get-Content -LiteralPath $sourcePage.FullName -Raw -Encoding UTF8
    $zhConverted = Convert-MarkdownLinks -Content $zhRaw -PageMap $pageMap

    $enSource = Join-Path $sourceRoot ($sourcePage.BaseName + ".en.md")
    if (Test-Path -LiteralPath $enSource) {
        $enRaw = Get-Content -LiteralPath $enSource -Raw -Encoding UTF8
        $enConverted = Convert-MarkdownLinks -Content $enRaw -PageMap $pageMap
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
