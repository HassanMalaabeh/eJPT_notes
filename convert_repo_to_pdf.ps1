param(
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'

$RootDir = (Get-Item -LiteralPath $PSScriptRoot).FullName
if (-not $OutputRoot -or [string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $RootDir 'build/pdf'
}

$Pandoc = Get-Command pandoc -ErrorAction SilentlyContinue
if (-not $Pandoc) {
    Write-Error 'pandoc is required to convert Markdown to PDF. Install pandoc from https://pandoc.org/installing.html and try again.'
    exit 1
}

$OutputRootItem = New-Item -ItemType Directory -Path $OutputRoot -Force
$OutputRoot = $OutputRootItem.FullName

$gitPath = Join-Path $RootDir '.git'

Get-ChildItem -Path $RootDir -Filter '*.md' -File -Recurse | ForEach-Object {
    $file = $_
    if ($file.FullName.StartsWith($OutputRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    if ($file.FullName.StartsWith($gitPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    $relativePath = $file.FullName.Substring($RootDir.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)
    $outputFile = Join-Path $OutputRoot ($relativePath -replace '\.md$', '.pdf')
    $outputDir = Split-Path -Parent $outputFile
    if (-not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $displayOutput = if ($outputFile.StartsWith($RootDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        $outputFile.Substring($RootDir.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)
    } else {
        $outputFile
    }

    Write-Host "Converting $relativePath -> $displayOutput"
    & $Pandoc.Source $file.FullName --from markdown --to pdf --output $outputFile
}

Write-Host "All Markdown files converted. PDFs are located in: $OutputRoot"
