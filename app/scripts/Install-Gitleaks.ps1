$ErrorActionPreference = 'Stop'
$version = '8.30.1'
$archiveName = "gitleaks_${version}_windows_x64.zip"
$toolDir = Join-Path $PSScriptRoot '..\tools'
$null = New-Item -ItemType Directory -Path $toolDir -Force
$releaseRoot = "https://github.com/gitleaks/gitleaks/releases/download/v$version"
$archivePath = Join-Path $toolDir $archiveName
Invoke-WebRequest -Uri "$releaseRoot/$archiveName" -OutFile $archivePath
$checksums = (Invoke-WebRequest -Uri "$releaseRoot/gitleaks_${version}_checksums.txt").Content
if ($checksums -is [byte[]]) { $checksums = [System.Text.Encoding]::UTF8.GetString($checksums) }
$checksumLine = ($checksums -split "`n" | Where-Object { $_.Trim().EndsWith($archiveName) })
if (@($checksumLine).Count -ne 1) { throw 'Missing or ambiguous release checksum' }
$expected = ($checksumLine.Trim() -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'Gitleaks archive checksum mismatch' }
Expand-Archive -LiteralPath $archivePath -DestinationPath $toolDir -Force
@{ version = $version; archive_sha256 = $actual; source = $releaseRoot } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $toolDir 'gitleaks-provenance.json')
& (Join-Path $toolDir 'gitleaks.exe') version
if ($LASTEXITCODE -ne 0) { throw 'Gitleaks verification failed' }
