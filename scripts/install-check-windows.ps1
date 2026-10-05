# Install check on Windows: the release's windows-amd64 binary matches SHA256SUMS and runs
# `rollcall --help` and `rollcall --version`.
#
# Usage: scripts/install-check-windows.ps1 -Tag v0.1.0 [-BaseUrl URL]
#
# Downloads rollcall-<Tag>-windows-amd64.zip and SHA256SUMS from the GitHub release (or BaseUrl),
# checks the zip's SHA-256 against its SHA256SUMS entry (a mismatch fails before anything is
# unpacked), unpacks it, then runs rollcall.exe --help (exit 0, lists `generate`) and
# rollcall.exe --version (first line `rollcall <version>`).
#
# Exit codes: 0 pass; 1 a check failed; 64 usage error.
param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [string]$BaseUrl = ""
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Fail([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("::error::install-check-windows: $Message")
    exit $Code
}

if ($Tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$') {
    Fail 64 "Tag must be a release tag such as v0.1.0, not '$Tag'"
}
$version = $Tag.Substring(1)
if ($BaseUrl -eq "") { $BaseUrl = "https://github.com/smhasan94/rollcall/releases/download/$Tag" }
$asset = "rollcall-$Tag-windows-amd64.zip"
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("rollcall-check-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null

foreach ($name in @("SHA256SUMS", $asset)) {
    try {
        Invoke-WebRequest -Uri "$BaseUrl/$name" -OutFile (Join-Path $work $name) -UseBasicParsing
    } catch {
        Fail 1 "cannot download $BaseUrl/$name : $_"
    }
}

$published = $null
foreach ($line in Get-Content (Join-Path $work "SHA256SUMS")) {
    $fields = $line -split '\s+', 2
    if ($fields.Count -eq 2 -and ($fields[1] -eq $asset -or $fields[1] -eq "*$asset")) {
        $published = $fields[0].ToLowerInvariant()
        break
    }
}
if ($null -eq $published) { Fail 1 "SHA256SUMS of $Tag does not list $asset" }
$actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $work $asset)).Hash.ToLowerInvariant()
if ($actual -ne $published) { Fail 1 "$asset has sha256 $actual, but SHA256SUMS of $Tag lists $published" }

Expand-Archive -Path (Join-Path $work $asset) -DestinationPath $work
$exe = Join-Path $work "rollcall-$Tag-windows-amd64\rollcall.exe"
if (-not (Test-Path $exe)) { Fail 1 "$asset holds no rollcall-$Tag-windows-amd64\rollcall.exe" }

$help = & $exe --help
if ($LASTEXITCODE -ne 0) { Fail 1 "rollcall.exe --help exited $LASTEXITCODE" }
if (-not (($help -join "`n") -match 'generate')) { Fail 1 "rollcall.exe --help does not list generate" }
$out = & $exe --version
if ($LASTEXITCODE -ne 0) { Fail 1 "rollcall.exe --version exited $LASTEXITCODE" }
$first = @($out)[0]
if ($first -ne "rollcall $version") { Fail 1 "rollcall.exe --version printed '$first', not 'rollcall $version'" }

$help | Write-Output
$out | Write-Output
Write-Output "install-check-windows: PASS $asset (sha256 $actual) runs --help and --version"
