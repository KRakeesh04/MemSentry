param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$bundle = Join-Path $root 'dist\MemSentry'
$buildDirectory = Join-Path $root 'build\msi'
$assetsDirectory = Join-Path $root 'release-assets'
$icon = Join-Path $root 'build\icons\memsentry.ico'
$productWxs = Join-Path $root 'packaging\windows\Product.wxs'

if (-not (Test-Path (Join-Path $bundle 'MemSentry.exe'))) {
    throw "PyInstaller bundle not found at $bundle"
}
if (-not (Test-Path $icon)) {
    throw "Generated application icon not found at $icon"
}

$wixDirectory = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} 'WiX Toolset v3*') `
    -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    Select-Object -First 1
if (-not $wixDirectory) {
    throw 'WiX Toolset v3 is required to build the MSI.'
}
$wixBin = Join-Path $wixDirectory.FullName 'bin'
foreach ($tool in @('heat.exe', 'candle.exe', 'light.exe')) {
    if (-not (Test-Path (Join-Path $wixBin $tool))) {
        throw "WiX Toolset command was not found: $tool"
    }
}

New-Item -ItemType Directory -Force -Path $buildDirectory, $assetsDirectory | Out-Null
$harvest = Join-Path $buildDirectory 'MemSentryFiles.wxs'
$productObject = Join-Path $buildDirectory 'Product.wixobj'
$filesObject = Join-Path $buildDirectory 'MemSentryFiles.wixobj'
$msi = Join-Path $assetsDirectory "MemSentry-$Version-windows-x86_64.msi"

& (Join-Path $wixBin 'heat.exe') dir $bundle `
    -cg MemSentryFiles -dr INSTALLFOLDER -gg -sfrag -srd `
    -var var.SourceDir -out $harvest
if ($LASTEXITCODE -ne 0) { throw 'WiX heat failed while harvesting the app bundle.' }

& (Join-Path $wixBin 'candle.exe') -nologo -arch x64 `
    "-dProductVersion=$Version" "-dIconPath=$icon" `
    -out $productObject $productWxs
if ($LASTEXITCODE -ne 0) { throw 'WiX candle failed for Product.wxs.' }

& (Join-Path $wixBin 'candle.exe') -nologo -arch x64 `
    "-dSourceDir=$bundle" -out $filesObject $harvest
if ($LASTEXITCODE -ne 0) { throw 'WiX candle failed for the harvested app bundle.' }

& (Join-Path $wixBin 'light.exe') -nologo -ext WixUIExtension `
    -out $msi $productObject $filesObject
if ($LASTEXITCODE -ne 0) { throw 'WiX light failed while linking the MSI.' }

Write-Host "Created $msi"
