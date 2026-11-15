using System.Management;

namespace OW2RG.Infrastructure.Windows.Firewall;

/// <summary>
/// Asks Windows Security Center which firewall products are registered. A third-party product that is "on"
/// (productState bit 0x1000) replaces Windows Defender Firewall as the enforcing firewall; Defender's rules are then
/// stored but ignored. Read-only WMI query; any failure is reported as "unknown" (empty list).
/// Observed values: Kaspersky firewall on = 266240 (0x41000), off = 262144 (0x40000).
/// </summary>
public static class SecurityCenter
{
    private static readonly string[] MicrosoftNames = ["Windows Firewall", "Windows Defender Firewall", "Microsoft Defender Firewall"];

    public static IReadOnlyList<string> ActiveThirdPartyFirewalls()
    {
        var result = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM FirewallProduct");
            foreach (var o in searcher.Get())
            {
                string name = o["displayName"]?.ToString()?.Trim() ?? "";
                uint state = Convert.ToUInt32(o["productState"] ?? 0);
                if (name.Length == 0 || MicrosoftNames.Any(m => name.StartsWith(m, StringComparison.OrdinalIgnoreCase))) continue;
                if ((state & 0x1000) != 0) result.Add(name);
            }
        }
        catch
        {
            // Security Center unavailable (server SKU, service stopped): report nothing rather than guessing.
        }
        return result;
    }
}
