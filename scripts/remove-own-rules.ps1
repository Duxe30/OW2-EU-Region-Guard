<#
.SYNOPSIS
  Emergency recovery for OW2 EU Region Guard. Removes ONLY firewall rules whose display name starts with "OW2RG-".

.DESCRIPTION
  Works without the app, without the catalog and without the game installed.
  It never resets the firewall, never changes profiles or default policies, never touches any other rule.
  Run from an elevated PowerShell (Run as Administrator).

.PARAMETER WhatIf
  List what would be removed without removing anything.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\remove-own-rules.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\remove-own-rules.ps1 -WhatIf
#>
[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Stop'
$Prefix = 'OW2RG-'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIf) {
    Write-Host 'This script must run as Administrator (right-click PowerShell > Run as administrator).' -ForegroundColor Yellow
    exit 5
}

# Exact prefix match on the display name. Never a broader wildcard, never another property.
$rules = @(Get-NetFirewallRule -All -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) })

if ($rules.Count -eq 0) {
    Write-Host 'No OW2RG-* rules found. Nothing to do.' -ForegroundColor Green
    exit 0
}

Write-Host "Found $($rules.Count) OW2RG rule(s):"
$rules | ForEach-Object { Write-Host ("  {0}  [{1}, {2}, {3}]" -f $_.DisplayName, $_.Direction, $_.Action, $(if ($_.Enabled -eq 'True') { 'enabled' } else { 'disabled' })) }

if ($WhatIf) {
    Write-Host 'WhatIf: nothing removed.' -ForegroundColor Cyan
    exit 0
}

$failed = 0
foreach ($r in $rules) {
    try {
        # Remove by the rule's unique internal Name (GUID-like ID), so duplicates with the same display name are all handled.
        Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop
    } catch {
        $failed++
        Write-Host "  Failed to remove $($r.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

$left = @(Get-NetFirewallRule -All -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) })
if ($left.Count -eq 0 -and $failed -eq 0) {
    Write-Host "Removed $($rules.Count) OW2RG rule(s). No other firewall rules were touched." -ForegroundColor Green
    exit 0
}
Write-Host "$($left.Count) OW2RG rule(s) remain. Open 'Windows Defender Firewall with Advanced Security' > Outbound Rules and delete rules starting with OW2RG- manually." -ForegroundColor Red
exit 1
