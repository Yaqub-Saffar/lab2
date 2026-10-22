<#
.SYNOPSIS
    Convert a Markdown file to PDF on the host: pandoc -> HTML -> Edge(headless).

.DESCRIPTION
    Two chains were tried on this machine:
      1) pandoc -> .docx -> Word COM (SaveAs2 wdFormatPDF)
         - worked in Experiment 1, but here Word hung on a first-run dialog and
           had to be killed, so it is NOT used any more.
      2) pandoc -> standalone HTML + scripts/pdf.css -> Edge in headless mode
         with --print-to-pdf. Fast, no COM, and the CJK fonts are correct.

    Usage:  .\scripts\md2pdf.ps1 -Md "..\实践过程.md"
    Output: <name>.html and <name>.pdf next to the Markdown file.

    NOTE: this file is intentionally ASCII-only. Windows PowerShell 5.1 reads
    BOM-less .ps1 files as ANSI (GBK), which corrupts non-ASCII text.
    Chinese file names are passed in as parameters instead.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Md,
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'

$Md = (Resolve-Path -LiteralPath $Md).Path
if (-not $OutDir) { $OutDir = Split-Path -Parent $Md }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$base = [System.IO.Path]::GetFileNameWithoutExtension($Md)
$html = Join-Path $OutDir "$base.html"
$pdf  = Join-Path $OutDir "$base.pdf"
$css  = Join-Path $PSScriptRoot 'pdf.css'

$pandoc = (Get-Command pandoc -ErrorAction SilentlyContinue).Source
if (-not $pandoc) { throw "pandoc not found in PATH" }

$edge = $null
foreach ($c in @(
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "C:\Program Files\Microsoft\Edge\Application\msedge.exe")) {
    if (Test-Path $c) { $edge = $c; break }
}
if (-not $edge) { throw "Microsoft Edge not found" }

Write-Host "[1/3] pandoc: $Md -> $html"
& $pandoc --from markdown --to html5 --toc --toc-depth=2 --standalone `
          --metadata title="$base" --css $css `
          --resource-path (Split-Path -Parent $Md) `
          -o $html $Md
if ($LASTEXITCODE -ne 0) { throw "pandoc failed" }

Write-Host "[2/3] Edge headless: $html -> $pdf"
$profile = Join-Path $env:TEMP "edge_pdf_profile"
$url = 'file:///' + ($html -replace '\\', '/')
# Edge always writes harmless ERROR lines to stderr (importers, sandbox, ...);
# with Stop those would abort the script before the PDF is written.
$ErrorActionPreference = 'Continue'
& $edge --headless=new --disable-gpu --no-pdf-header-footer `
        --user-data-dir="$profile" --print-to-pdf="$pdf" $url 2>&1 | Out-Null
$ErrorActionPreference = 'Stop'

Start-Sleep -Seconds 2
if (-not (Test-Path $pdf)) { throw "Edge did not produce the PDF" }

Write-Host "[3/3] done: $pdf ($((Get-Item $pdf).Length) bytes)"
