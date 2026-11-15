<#
.SYNOPSIS
  Read-only environment check for OW2 EU Region Guard. Changes nothing.
  Reports: Windows version, admin rights, firewall profile state, group-policy hints,
  existing OW2RG-* rules, .NET SDK presence (for building) and Overwatch install hints.
#>
$ErrorActionPreference = 'Continue'
Write-Host 'OW2 EU Region Guard - environment check (read-only)' -ForegroundColor Cyan

$os = Get-CimInstance Win32_OperatingSystem
Write-Host ("Windows:        {0} build {1} ({2})" -f $os.Caption, $os.BuildNumber, $os.OSArchitecture)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("Administrator:  {0}" -f $isAdmin)

try {
    Get-NetFirewallProfile | ForEach-Object {
        Write-Host ("Firewall {0,-8} enabled={1}  defaultOutbound={2}" -f $_.Name, $_.Enabled, $_.DefaultOutboundAction)
    }
    $active = Get-NetConnectionProfile -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NetworkCategory -Unique
    Write-Host ("Active network: {0}" -f ($active -join ', '))
} catch { Write-Host "Firewall query failed: $($_.Exception.Message)" -ForegroundColor Yellow }

$gp = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.AllowLocalFirewallRules -eq 'False' }
if ($gp) { Write-Host 'WARNING: policy disallows local firewall rules on at least one profile - rules from this app would be ignored.' -ForegroundColor Yellow }

$own = @(Get-NetFirewallRule -All -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'OW2RG-*' })
Write-Host ("OW2RG rules:    {0}" -f $own.Count)
$own | ForEach-Object { Write-Host ("   {0} ({1}, {2}, enabled={3})" -f $_.DisplayName, $_.Direction, $_.Action, $_.Enabled) }

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet -and (Test-Path "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe")) { $dotnet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" }
if ($dotnet) { Write-Host ("SDKs:           {0}" -f ((& $dotnet --list-sdks) -join '; ')) } else { Write-Host 'SDKs:           none (only needed to build from source)' }

$running = Get-Process Overwatch -ErrorAction SilentlyContinue
Write-Host ("Overwatch running: {0}" -f [bool]$running)
$keys = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Overwatch' } | ForEach-Object {
    Write-Host ("Install hint:   {0} -> {1}" -f $_.DisplayName, $_.InstallLocation)
}
