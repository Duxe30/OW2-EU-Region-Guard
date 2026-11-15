using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using OW2RG.Core.Firewall;
using OW2RG.Core.Net;
using OW2RG.Infrastructure.Windows.Firewall;

namespace OW2RG.Infrastructure.Windows;

public sealed record SelfTestStep(string Name, bool Passed, string Detail);

public sealed record SelfTestReport(bool Passed, bool? EnforcementObserved, IReadOnlyList<SelfTestStep> Steps)
{
    public IEnumerable<string> Lines() => Steps.Select(s => $"[{(s.Passed ? "PASS" : "FAIL")}] {s.Name}: {s.Detail}");
}

/// <summary>
/// Proves the firewall engine works on THIS PC without touching Overwatch:
///  1. A DNS question ("example.com", type A) is sent over UDP from this very program to the PC's own DNS server
///     and must be answered.
///  2. A temporary rule blocks UDP from this program to that one DNS server (plus a documentation address).
///     The same question must now go unanswered (or be refused locally).
///  3. The rules are removed in a finally block and the question must be answered again.
/// Every other program keeps using DNS normally the whole time, because the rule is scoped to this EXE.
/// </summary>
public static class SelfTest
{
    private static readonly IPAddress DocProbe = IPAddress.Parse("192.0.2.1");

    public static SelfTestReport RunOffline(ComFirewallStore store)
    {
        var steps = new List<SelfTestStep>();
        var env = store.ReadEnvironment();
        steps.Add(new("Windows Firewall API", env.ApiAvailable, env.ApiAvailable ? "INetFwPolicy2 reachable" : env.ApiError ?? "unavailable"));
        if (!env.ApiAvailable) return new SelfTestReport(false, null, steps);
        steps.Add(new("Active profile protected", env.CurrentProfilesEnabled,
            $"active: {FirewallEnvironment.ProfileNames(env.CurrentProfileTypes)}; enabled: {string.Join(", ", env.EnabledByProfile.Where(k => k.Value).Select(k => k.Key))}"));
        steps.Add(new("Windows Firewall is the enforcing firewall", env.ThirdPartyFirewalls.Count == 0,
            env.ThirdPartyFirewalls.Count == 0 ? "no third-party firewall product is registered as active"
                : $"{string.Join(", ", env.ThirdPartyFirewalls)} is the active firewall; Windows Firewall rules are stored but NOT enforced on this PC"));
        steps.Add(new("Local rules honoured", env.LocalPolicyModifyState != 1, env.LocalPolicyModifyState switch
        {
            0 => "local rules take effect",
            1 => "Group Policy overrides local rules",
            2 => "inbound rules restricted by policy (outbound rules still apply)",
            _ => $"state {env.LocalPolicyModifyState}",
        }));
        try
        {
            var owned = store.ReadOwnedRules();
            steps.Add(new("Read OW2RG rules", true, $"{owned.Count} OW2RG rule(s) present"));
        }
        catch (Exception ex)
        {
            steps.Add(new("Read OW2RG rules", false, ex.Message));
        }

        string exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "ow2rg-cli.exe");
        var spec = FirewallRuleSpec.CreateSelfTest(OwnedRules.SelfTestPrefix + "DRY", exe, [CidrBlock.Parse("192.0.2.0/24"), CidrBlock.Parse("2001:db8::/32")]);
        var dry = store.DryValidate(spec);
        steps.Add(new("Rule object accepted by Windows (not saved)", dry.Accepted, dry.Accepted ? $"read-back: {dry.WindowsReadBack}" : dry.Error ?? "rejected"));
        return new SelfTestReport(steps.All(s => s.Passed || s.Name is "Active profile protected" or "Local rules honoured" or "Windows Firewall is the enforcing firewall"), null, steps);
    }

    public static SelfTestReport RunLive(ComFirewallStore store)
    {
        var steps = new List<SelfTestStep>();
        if (!Elevation.IsElevated())
        {
            steps.Add(new("Administrator rights", false, "The live self-test must run elevated."));
            return new SelfTestReport(false, null, steps);
        }
        var env = store.ReadEnvironment();
        steps.Add(new("Firewall active for current profile", env.CurrentProfilesEnabled && env.LocalPolicyModifyState != 1, env.CurrentProfilesEnabled ? "yes" : string.Join(" ", env.Problems)));
        steps.Add(new("Windows Firewall is the enforcing firewall", env.ThirdPartyFirewalls.Count == 0,
            env.ThirdPartyFirewalls.Count == 0 ? "no third-party firewall product is registered as active"
                : $"{string.Join(", ", env.ThirdPartyFirewalls)} is the active firewall — expect the enforcement step below to FAIL until its Firewall component is turned off"));

        string exe = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine own executable path.");
        string tag = Guid.NewGuid().ToString("N")[..10].ToUpperInvariant();
        var dns = FindDnsServer();

        // ---- Baseline without any rule.
        var baseDns = dns is null ? null : DnsRoundTrip(dns);
        var baseDoc = SendOnce(DocProbe);
        steps.Add(new("Baseline (no rule)", baseDns?.Answered ?? true,
            (dns is null ? "no usable IPv4 DNS server found; " : $"DNS question to {dns} → {baseDns!.Detail}; ") + $"UDP send to 192.0.2.1 → {baseDoc}"));

        var rules = new List<FirewallRuleSpec> { FirewallRuleSpec.CreateSelfTest(OwnedRules.SelfTestPrefix + tag + "-DOC", exe, [CidrBlock.Parse("192.0.2.1/32")], GuardEngine.AppVersion) };
        if (dns is not null && baseDns!.Answered)
        {
            IpCodec.TryParseStrict(dns.ToString(), out var fam, out var val);
            rules.Add(FirewallRuleSpec.CreateSelfTestHostProbe(OwnedRules.SelfTestPrefix + tag + "-DNS", exe, new CidrBlock(fam, val, IpFamilyInfo.Bits(fam)), GuardEngine.AppVersion));
        }

        bool? enforcement = null;
        var added = new List<string>();
        try
        {
            foreach (var r in rules)
            {
                store.AddRule(r);
                added.Add(r.Name);
            }
            var back = store.ReadOwnedRules();
            var readProblems = rules.Select(r =>
            {
                var got = back.Where(b => b.Name == r.Name).ToList();
                return got.Count != 1 ? $"{r.Name}: found {got.Count}" : RuleComparer.Matches(r, got[0]) ? null : $"{r.Name}: {string.Join(", ", RuleComparer.Differences(r, got[0]))}";
            }).Where(p => p is not null).ToList();
            steps.Add(new("Create + read back rule(s)", readProblems.Count == 0,
                readProblems.Count == 0 ? $"{rules.Count} rule(s): OUT, BLOCK, UDP, program={exe}" : string.Join("; ", readProblems)));

            Thread.Sleep(500);
            var blockedDns = dns is not null && baseDns!.Answered ? DnsRoundTrip(dns) : null;
            var blockedDoc = SendOnce(DocProbe);
            if (blockedDns is not null)
            {
                enforcement = !blockedDns.Answered;
                steps.Add(new("Rule enforced by Windows", enforcement == true,
                    enforcement == true
                        ? $"same DNS question from this program is now blocked ({blockedDns.Detail}); UDP send to 192.0.2.1 → {blockedDoc}"
                        : $"DNS still answered ({blockedDns.Detail}) — the block did NOT take effect"));
            }
            else
            {
                steps.Add(new("Rule enforced by Windows", false,
                    $"Cannot observe: no answering DNS server for a round-trip check. UDP send to 192.0.2.1 → {blockedDoc}."));
            }
        }
        catch (Exception ex)
        {
            steps.Add(new("Create + read back rule(s)", false, ex.Message));
        }
        finally
        {
            var leftover = store.ReadOwnedRules().Where(r => r.Name.StartsWith(OwnedRules.SelfTestPrefix + tag, StringComparison.OrdinalIgnoreCase)).Select(r => r.Name).Distinct().ToList();
            try
            {
                foreach (var name in leftover) store.RemoveRules(name);
                bool gone = store.ReadOwnedRules().All(r => !r.Name.StartsWith(OwnedRules.SelfTestPrefix + tag, StringComparison.OrdinalIgnoreCase));
                steps.Add(new("Remove rule(s) (cleanup)", gone, gone ? $"removed {leftover.Count}; no self-test rule left behind" : "STILL PRESENT — run Restore Default"));
            }
            catch (Exception ex)
            {
                steps.Add(new("Remove rule(s) (cleanup)", false, ex.Message + " — run Restore Default or scripts\\remove-own-rules.ps1"));
            }
        }

        if (dns is not null && baseDns!.Answered)
        {
            Thread.Sleep(300);
            var after = DnsRoundTrip(dns);
            steps.Add(new("Traffic restored after removal", after.Answered, $"DNS question to {dns} → {after.Detail}"));
        }
        return new SelfTestReport(steps.All(s => s.Passed), enforcement, steps);
    }

    private sealed record DnsResult(bool Answered, string Detail);

    /// <summary>One standard DNS question (example.com, A) over UDP from this process; true if a matching reply arrives.</summary>
    private static DnsResult DnsRoundTrip(IPAddress server)
    {
        ushort id = (ushort)Random.Shared.Next(1, 65535);
        byte[] query =
        [
            (byte)(id >> 8), (byte)id, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0,
            0x00, 0x01, 0x00, 0x01,
        ];
        try
        {
            using var s = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 2500 };
            var sw = System.Diagnostics.Stopwatch.StartNew();
            s.SendTo(query, new IPEndPoint(server, 53));
            var buf = new byte[1500];
            EndPoint from = new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            while (true)
            {
                int n = s.ReceiveFrom(buf, ref from);
                if (n >= 2 && buf[0] == (byte)(id >> 8) && buf[1] == (byte)id) return new DnsResult(true, $"answered in {sw.ElapsedMilliseconds} ms");
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            return new DnsResult(false, "no answer within 2.5 s");
        }
        catch (SocketException ex)
        {
            return new DnsResult(false, $"refused locally: {ex.SocketErrorCode} ({ex.ErrorCode})");
        }
    }

    private static string SendOnce(IPAddress target)
    {
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.SendTo([0], new IPEndPoint(target, 9));
            return "send call succeeded";
        }
        catch (SocketException ex)
        {
            return $"refused: {ex.SocketErrorCode} ({ex.ErrorCode})";
        }
    }

    /// <summary>The first IPv4 DNS server of an active, non-loopback adapter with a default gateway.</summary>
    private static IPAddress? FindDnsServer()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = nic.GetIPProperties();
                if (props.GatewayAddresses.Count == 0) continue;
                var dns = props.DnsAddresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a));
                if (dns is not null) return dns;
            }
        }
        catch { }
        return null;
    }
}
