using System.Text.RegularExpressions;
using OW2RG.Core.Game;
using OW2RG.Core.Net;

namespace OW2RG.Core.Firewall;

public enum FwProtocol { Tcp = 6, Udp = 17 }
public enum FwDirection { In = 1, Out = 2 }
public enum FwAction { Block = 0, Allow = 1 }

/// <summary>Ownership rules. The app may only ever create, change or delete rules whose name starts with <see cref="Prefix"/>.</summary>
public static partial class OwnedRules
{
    public const string Prefix = "OW2RG-";
    public const string SelfTestPrefix = "OW2RG-SELFTEST-";
    public const string Grouping = "OW2 EU Region Guard";
    /// <summary>NET_FW_PROFILE2_ALL – the rule applies on Domain, Private and Public networks.</summary>
    public const int AllProfiles = 0x7FFFFFFF;
    public const int MaxNameLength = 120;

    [GeneratedRegex("^OW2RG-[A-Za-z0-9-]{1,110}$")] private static partial Regex NameRegex();

    /// <summary>Windows Firewall rule names compare case-insensitively, as does the recovery script.</summary>
    public static bool IsOwnedName(string? name) =>
        name is not null && name.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    public static bool IsWellFormedName(string? name) => name is not null && NameRegex().IsMatch(name);

    public static void RequireOwned(string? name)
    {
        if (!IsOwnedName(name))
            throw new InvalidOperationException($"Refusing to touch firewall rule '{name}': it is not owned by OW2 EU Region Guard (prefix {Prefix}).");
    }
}

/// <summary>
/// A firewall rule this app is allowed to write. Instances can only be produced by the factory methods,
/// which enforce the policy boundary: outbound, block, a single validated program, UDP/TCP, explicit
/// remote networks, never "*" and never a /0.
/// </summary>
public sealed class FirewallRuleSpec
{
    private FirewallRuleSpec(string name, string description, string applicationPath, FwProtocol protocol,
        IReadOnlyList<CidrBlock> remote, bool enabled)
    {
        Name = name;
        Description = description;
        ApplicationPath = applicationPath;
        Protocol = protocol;
        RemoteAddresses = remote;
        Enabled = enabled;
        RemoteSet = IpSet.From(remote);
    }

    public string Name { get; }
    public string Description { get; }
    public string Grouping => OwnedRules.Grouping;
    public string ApplicationPath { get; }
    public FwProtocol Protocol { get; }
    public FwDirection Direction => FwDirection.Out;
    public FwAction Action => FwAction.Block;
    public int Profiles => OwnedRules.AllProfiles;
    public bool Enabled { get; }
    public IReadOnlyList<CidrBlock> RemoteAddresses { get; }
    public IpSet RemoteSet { get; }
    public string RemoteAddressesText => string.Join(",", RemoteAddresses);

    public FirewallRuleSpec WithEnabled(bool enabled) =>
        new(Name, Description, ApplicationPath, Protocol, RemoteAddresses, enabled);

    public static FirewallRuleSpec CreateGameBlock(string name, string description, ValidatedGamePath game,
        FwProtocol protocol, IReadOnlyList<CidrBlock> remote, bool enabled)
    {
        CheckCommon(name, description, protocol, remote);
        return new FirewallRuleSpec(name, description, game.FullPath, protocol, remote.ToArray(), enabled);
    }

    /// <summary>
    /// Self-test rule: may only target documentation address space (RFC 5737 / RFC 3849), so it can never
    /// affect real traffic, and must use the SELFTEST prefix so every cleanup path removes it.
    /// </summary>
    public static FirewallRuleSpec CreateSelfTest(string name, string applicationPath, IReadOnlyList<CidrBlock> remote, string appVersion = "0.0.0")
    {
        if (!name.StartsWith(OwnedRules.SelfTestPrefix, StringComparison.Ordinal))
            throw new ArgumentException($"Self-test rule names must start with {OwnedRules.SelfTestPrefix}.");
        var doc = IpSet.From(SpecialRanges.All.Where(r => r.IsDocumentation).Select(r => r.Block));
        if (!IpSet.From(remote).IsSubsetOf(doc))
            throw new ArgumentException("Self-test rules may only target documentation address ranges.");
        if (string.IsNullOrWhiteSpace(applicationPath) || applicationPath.Length < 4 || applicationPath[1] != ':' || applicationPath[2] != '\\'
            || !applicationPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || applicationPath.Contains('%') || applicationPath.Contains('"'))
            throw new ArgumentException("Self-test application path must be an absolute local .exe path.");
        // Same description format as real profile rules, so the live self-test proves Windows accepts it.
        string description = Describe(appVersion, "selftest", "000000000000", 1, 1, "selftest-documentation-addresses", "selftest");
        CheckCommon(name, description, FwProtocol.Udp, remote);
        return new FirewallRuleSpec(name, description, applicationPath, FwProtocol.Udp, remote.ToArray(), enabled: true);
    }

    /// <summary>
    /// Self-test probe rule: blocks UDP from the self-test program itself to exactly ONE host (e.g. the PC's own
    /// DNS server), so enforcement can be observed as a missing reply. It cannot affect any other program.
    /// </summary>
    public static FirewallRuleSpec CreateSelfTestHostProbe(string name, string applicationPath, CidrBlock singleHost, string appVersion = "0.0.0")
    {
        if (!name.StartsWith(OwnedRules.SelfTestPrefix, StringComparison.Ordinal))
            throw new ArgumentException($"Self-test rule names must start with {OwnedRules.SelfTestPrefix}.");
        if (singleHost.PrefixLength != IpFamilyInfo.Bits(singleHost.Family))
            throw new ArgumentException("A self-test host probe must target exactly one address.");
        if (string.IsNullOrWhiteSpace(applicationPath) || applicationPath.Length < 4 || applicationPath[1] != ':' || applicationPath[2] != '\\'
            || !applicationPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || applicationPath.Contains('%') || applicationPath.Contains('"'))
            throw new ArgumentException("Self-test application path must be an absolute local .exe path.");
        string description = Describe(appVersion, "selftest", "000000000000", 1, 1, "selftest-dns-probe", "selftest");
        CheckCommon(name, description, FwProtocol.Udp, [singleHost]);
        return new FirewallRuleSpec(name, description, applicationPath, FwProtocol.Udp, [singleHost], enabled: true);
    }

    /// <summary>
    /// Rebuild a spec from a rule previously read from the firewall (used to roll back to a snapshot).
    /// Only rules that still satisfy every invariant are recreated; anything else is refused.
    /// </summary>
    public static bool TryRecreate(FirewallRuleRecord record, out FirewallRuleSpec? spec, out string? reason)
    {
        spec = null;
        reason = null;
        if (!OwnedRules.IsWellFormedName(record.Name)) { reason = "name is not a well-formed OW2RG name"; return false; }
        if (record.Direction != (int)FwDirection.Out) { reason = "not an outbound rule"; return false; }
        if (record.Action != (int)FwAction.Block) { reason = "not a block rule"; return false; }
        if (record.Protocol is not ((int)FwProtocol.Udp or (int)FwProtocol.Tcp)) { reason = "protocol is not UDP/TCP"; return false; }
        if (!FirewallRuleRecord.IsAny(record.RemotePorts) || !FirewallRuleRecord.IsAny(record.LocalPorts) || !FirewallRuleRecord.IsAny(record.LocalAddresses))
        { reason = "rule has port/local-address filters this app never writes"; return false; }
        var parsed = AddressListParser.Parse(record.RemoteAddresses);
        if (!parsed.Success || parsed.Set.IsEmpty) { reason = "remote addresses are not an explicit network list"; return false; }
        var cidrs = parsed.Set.ToCidrs();
        try
        {
            if (record.Name.StartsWith(OwnedRules.SelfTestPrefix, StringComparison.OrdinalIgnoreCase))
            {
                spec = CreateSelfTest(record.Name, record.ApplicationName ?? "", cidrs);
                return true;
            }
            var check = GamePathValidator.Validate(record.ApplicationName, AssumeExistsProbe.Instance);
            if (!check.IsValid) { reason = "program path is not a valid Overwatch.exe path: " + string.Join("; ", check.Errors); return false; }
            spec = CreateGameBlock(record.Name, record.Description ?? "", check.Path!, (FwProtocol)record.Protocol, cidrs, record.Enabled);
            return true;
        }
        catch (ArgumentException ex)
        {
            reason = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// The text every OW2RG rule carries in its Description. One format for profile rules AND self-test rules, so
    /// the live self-test exercises exactly what Apply writes. Never contains '|' (see <see cref="CheckCommon"/>).
    /// </summary>
    public static string Describe(string appVersion, string profileCode, string planHash12, int part, int total, string catalogVersion, string tiers) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"Managed by OW2 EU Region Guard {appVersion}; profile={profileCode}; plan={planHash12}; part={part}/{total}; catalog={catalogVersion}; tiers={tiers}; remove via Restore Default or scripts\\remove-own-rules.ps1")
        .Replace('|', '/');

    private static void CheckCommon(string name, string description, FwProtocol protocol, IReadOnlyList<CidrBlock> remote)
    {
        if (!OwnedRules.IsWellFormedName(name)) throw new ArgumentException($"Rule name '{name}' is not a well-formed {OwnedRules.Prefix} name.");
        if (description.Length > 1000) throw new ArgumentException("Description too long.");
        // Windows stores rules as one '|'-delimited registry string; a '|' in Name/Description/Grouping is accepted on
        // property assignment but makes INetFwRules.Add fail with E_INVALIDARG. Dry validation cannot catch that.
        if (description.Contains('|') || OwnedRules.Grouping.Contains('|'))
            throw new ArgumentException("Rule description/grouping must not contain '|'.");
        if (description.Any(ch => char.IsControl(ch))) throw new ArgumentException("Rule description must not contain control characters.");
        if (protocol is not (FwProtocol.Udp or FwProtocol.Tcp)) throw new ArgumentException("Only UDP or TCP rules are supported.");
        if (remote.Count == 0) throw new ArgumentException("A block rule must name at least one remote network (never '*').");
        foreach (var b in remote)
        {
            int min = b.Family == IpFamily.V4 ? 8 : 16;
            if (b.PrefixLength < min) throw new ArgumentException($"Remote network {b} is too broad for a block rule.");
        }
    }

    private sealed class AssumeExistsProbe : IFileProbe
    {
        public static readonly AssumeExistsProbe Instance = new();
        public bool FileExists(string path) => true;
        public long? FileLength(string path) => null;
    }
}

/// <summary>A rule as read back from Windows Firewall.</summary>
public sealed record FirewallRuleRecord
{
    public required string Name { get; init; }
    public string? Description { get; init; }
    public string? Grouping { get; init; }
    public string? ApplicationName { get; init; }
    public string? ServiceName { get; init; }
    public int Protocol { get; init; }
    public int Direction { get; init; }
    public int Action { get; init; }
    public bool Enabled { get; init; }
    public string? RemoteAddresses { get; init; }
    public string? LocalAddresses { get; init; }
    public string? RemotePorts { get; init; }
    public string? LocalPorts { get; init; }
    public int Profiles { get; init; }
    public string? InterfaceTypes { get; init; }

    public static bool IsAny(string? value) => string.IsNullOrWhiteSpace(value) || value.Trim() == "*";

    public static FirewallRuleRecord FromSpec(FirewallRuleSpec s) => new()
    {
        Name = s.Name,
        Description = s.Description,
        Grouping = s.Grouping,
        ApplicationName = s.ApplicationPath,
        Protocol = (int)s.Protocol,
        Direction = (int)s.Direction,
        Action = (int)s.Action,
        Enabled = s.Enabled,
        RemoteAddresses = s.RemoteAddressesText,
        LocalAddresses = "*",
        RemotePorts = "*",
        LocalPorts = "*",
        Profiles = s.Profiles,
        InterfaceTypes = "All",
    };
}

public static class RuleComparer
{
    /// <summary>Lists every difference between what we intended to write and what Windows reports.</summary>
    public static IReadOnlyList<string> Differences(FirewallRuleSpec spec, FirewallRuleRecord actual)
    {
        var d = new List<string>();
        if (!string.Equals(spec.Name, actual.Name, StringComparison.OrdinalIgnoreCase)) d.Add("name");
        if (!string.Equals(spec.ApplicationPath, actual.ApplicationName, StringComparison.OrdinalIgnoreCase)) d.Add($"program ('{actual.ApplicationName}')");
        if (!string.IsNullOrEmpty(actual.ServiceName) && actual.ServiceName != "*") d.Add("service filter");
        if ((int)spec.Protocol != actual.Protocol) d.Add($"protocol ({actual.Protocol})");
        if ((int)spec.Direction != actual.Direction) d.Add($"direction ({actual.Direction})");
        if ((int)spec.Action != actual.Action) d.Add($"action ({actual.Action})");
        if (spec.Enabled != actual.Enabled) d.Add($"enabled ({actual.Enabled})");
        if (!FirewallRuleRecord.IsAny(actual.RemotePorts)) d.Add("remote ports");
        if (!FirewallRuleRecord.IsAny(actual.LocalPorts)) d.Add("local ports");
        if (!FirewallRuleRecord.IsAny(actual.LocalAddresses)) d.Add("local addresses");
        if ((actual.Profiles & OwnedRules.AllProfiles) != OwnedRules.AllProfiles) d.Add($"profiles ({actual.Profiles})");
        var parsed = AddressListParser.Parse(actual.RemoteAddresses);
        if (!parsed.Success) d.Add("remote addresses unparseable");
        else if (!parsed.Set.Equals(spec.RemoteSet)) d.Add("remote addresses differ");
        return d;
    }

    public static bool Matches(FirewallRuleSpec spec, FirewallRuleRecord actual) => Differences(spec, actual).Count == 0;
}

/// <summary>Firewall state relevant to whether rules can be written and whether they would take effect.</summary>
public sealed record FirewallEnvironment
{
    public required bool ApiAvailable { get; init; }
    public string? ApiError { get; init; }
    /// <summary>Bitmask of active profiles: 1 = Domain, 2 = Private, 4 = Public.</summary>
    public int CurrentProfileTypes { get; init; }
    public IReadOnlyDictionary<string, bool> EnabledByProfile { get; init; } = new Dictionary<string, bool>();
    public bool CurrentProfilesEnabled { get; init; }
    /// <summary>NET_FW_MODIFY_STATE: 0 = OK, 1 = group policy overrides local rules, 2 = inbound blocked.</summary>
    public int LocalPolicyModifyState { get; init; }
    public bool IsElevated { get; init; }

    public bool RulesWouldTakeEffect => ApiAvailable && CurrentProfilesEnabled && LocalPolicyModifyState != 1;

    public IReadOnlyList<string> Problems
    {
        get
        {
            var p = new List<string>();
            if (!ApiAvailable) p.Add("Windows Firewall API is unavailable: " + (ApiError ?? "unknown error"));
            else
            {
                if (!CurrentProfilesEnabled)
                    p.Add("Windows Defender Firewall is OFF for the active network profile (or managed by another firewall product). Rules would have no effect. This app will not change that setting.");
                if (LocalPolicyModifyState == 1)
                    p.Add("Group Policy overrides local firewall rules on this PC, so rules written by this app would be ignored.");
            }
            return p;
        }
    }

    public static string ProfileNames(int mask)
    {
        var names = new List<string>();
        if ((mask & 1) != 0) names.Add("Domain");
        if ((mask & 2) != 0) names.Add("Private");
        if ((mask & 4) != 0) names.Add("Public");
        return names.Count == 0 ? "none" : string.Join(", ", names);
    }
}

public sealed class FirewallOperationException(string message, int? hresult = null, Exception? inner = null)
    : Exception(message, inner)
{
    public int? NativeErrorCode { get; } = hresult;
    public bool IsAccessDenied => NativeErrorCode == unchecked((int)0x80070005);
}

/// <summary>
/// Minimal, owned-rules-only firewall surface. There is deliberately no way to enumerate or modify
/// foreign rules, change default policies, profiles, or the firewall's enabled state.
/// </summary>
public interface IFirewallRuleStore
{
    FirewallEnvironment ReadEnvironment();
    IReadOnlyList<FirewallRuleRecord> ReadOwnedRules();
    void AddRule(FirewallRuleSpec spec);
    void SetEnabled(string ownedName, bool enabled);
    /// <summary>Removes every rule with exactly this owned name; returns how many were removed.</summary>
    int RemoveRules(string ownedName);
}

/// <summary>Defense in depth: wraps any store and refuses any operation on a non-owned name.</summary>
public sealed class OwnedOnlyFirewallStore(IFirewallRuleStore inner) : IFirewallRuleStore
{
    public FirewallEnvironment ReadEnvironment() => inner.ReadEnvironment();

    public IReadOnlyList<FirewallRuleRecord> ReadOwnedRules() =>
        inner.ReadOwnedRules().Where(r => OwnedRules.IsOwnedName(r.Name)).ToList();

    public void AddRule(FirewallRuleSpec spec)
    {
        OwnedRules.RequireOwned(spec.Name);
        inner.AddRule(spec);
    }

    public void SetEnabled(string ownedName, bool enabled)
    {
        OwnedRules.RequireOwned(ownedName);
        inner.SetEnabled(ownedName, enabled);
    }

    public int RemoveRules(string ownedName)
    {
        OwnedRules.RequireOwned(ownedName);
        return inner.RemoveRules(ownedName);
    }
}
