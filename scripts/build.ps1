<#
.SYNOPSIS
  Restore, build, test and publish OW2 EU Region Guard as self-contained x64 single-file EXEs.

.DESCRIPTION
  Output: artifacts\OW2-EU-Region-Guard-win-x64\
            OW2RG.exe            desktop app (no .NET install needed)
            ow2rg-cli.exe        command-line tool / emergency repair
            scripts\remove-own-rules.ps1, verify-environment.ps1
            data\servers.json, datacenter-map.json, servers.schema.json, sources.md
            README.md, docs\...
          artifacts\OW2-EU-Region-Guard-win-x64.zip  (+ .sha256)

.PARAMETER SkipTests     Do not run the test suites.
.PARAMETER LiveFirewallTests  Also run the opt-in tests that write (and remove) a documentation-address firewall rule. Requires an elevated shell.
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$LiveFirewallTests,
    [string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet -and (Test-Path "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe")) {
    $dotnet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"
    $env:DOTNET_ROOT = Split-Path $dotnet
}
if (-not $dotnet) { throw '.NET SDK 10 not found. Install it from https://dotnet.microsoft.com/download/dotnet/10.0' }
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
Write-Host "Using $dotnet ($(& $dotnet --version))"

& $dotnet restore OW2RG.sln
if ($LASTEXITCODE) { throw 'restore failed' }
& $dotnet build OW2RG.sln -c $Configuration --no-restore
if ($LASTEXITCODE) { throw 'build failed' }

if (-not $SkipTests) {
    if ($LiveFirewallTests) { $env:OW2RG_LIVE_FIREWALL_TESTS = '1' } else { Remove-Item Env:\OW2RG_LIVE_FIREWALL_TESTS -ErrorAction SilentlyContinue }
    $results = Join-Path $root 'artifacts\test-results'
    & $dotnet test OW2RG.sln -c $Configuration --no-build --logger "trx" --results-directory $results
    if ($LASTEXITCODE) { throw 'tests failed' }
}

$out = Join-Path $root 'artifacts\OW2-EU-Region-Guard-win-x64'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
$common = @('-c', $Configuration, '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true',
            '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:EnableCompressionInSingleFile=true', '-p:DebugType=none', '-o', $out)
& $dotnet publish src\OW2RG.App\OW2RG.App.csproj @common
if ($LASTEXITCODE) { throw 'publish (app) failed' }
& $dotnet publish src\OW2RG.Cli\OW2RG.Cli.csproj @common
if ($LASTEXITCODE) { throw 'publish (cli) failed' }

New-Item -ItemType Directory -Force (Join-Path $out 'scripts'), (Join-Path $out 'data'), (Join-Path $out 'docs') | Out-Null
Copy-Item scripts\remove-own-rules.ps1, scripts\verify-environment.ps1 (Join-Path $out 'scripts')
Copy-Item data\servers.json, data\datacenter-map.json, data\servers.schema.json, data\sources.md (Join-Path $out 'data')
Copy-Item README.md, LICENSE, NOTICE.md $out
Copy-Item docs\*.md (Join-Path $out 'docs')

$zip = "$out.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $(Split-Path $zip -Leaf)" | Set-Content "$zip.sha256" -Encoding ascii

Get-ChildItem $out -File | Select-Object Name, @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } } | Format-Table -AutoSize
Write-Host "Published to $out"
Write-Host "Zip: $zip  sha256 $hash"
