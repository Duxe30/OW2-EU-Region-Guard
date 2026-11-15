using System.Globalization;
using System.Text.RegularExpressions;
using OW2RG.Core.Net;
using OW2RG.Core.Planning;

namespace OW2RG.Core.Firewall;

public enum GuardState
{
    NoOwnRules,
    Active,
    Partial,
    Error,
}

/// <summary>What the firewall actually contains right now. The firewall is the source of truth, never a settings cache.</summary>
public sealed record OwnedState
{
    public required GuardState State { get; init; }
    public ProfileId? Profile { get; init; }
    public string? PlanHash12 { get; init; }
    public int RuleCount { get; init; }
    public int BlockedNetworkCount { get; init; }
    public IReadOnlyList<string> TargetPrograms { get; init; } = [];
    public IReadOnlyList<string> Problems { get; init; } = [];
    public IReadOnlyList<FirewallRuleRecord> Rules { get; init; } = [];
    /// <summary>Null when no current plan was supplied for comparison.</summary>
    public bool? MatchesCurrentPlan { get; init; }
    public bool? TargetsCurrentGamePath { get; init; }
    public int SelfTestRuleCount { get; init; }

    public string Label => State switch
    {
        GuardState.NoOwnRules => "No own rules",
        GuardState.Active when Profile == ProfileId.BlockMiddleEast => "Active: Block ME",
        GuardState.Active when Profile == ProfileId.PreferEurope => "Active: Prefer EU",
        GuardState.Active => "Active",
        GuardState.Partial => "Partial/Unknown",
        _ => "Error",
    };
}

public static partial class OwnedStateInspector
{
    [GeneratedRegex(@"profile=(?<p>[a-z-]+)")] private static partial Regex ProfileRx();
    [GeneratedRegex(@"plan=(?<h>[0-9a-f]{12})")] private static partial Regex PlanRx();
    [GeneratedRegex(@"part=(?<i>\d{1,3})/(?<n>\d{1,3})")] private static partial Regex PartRx();

    public static OwnedState Inspect(IReadOnlyList<FirewallRuleRecord> ownedRules, BlockPlan? currentPlan = null, string? currentGamePath = null)
    {
        var rules = ownedRules.Where(r => OwnedRules.IsOwnedName(r.Name)).ToList();
        int selfTest = rules.Count(r => r.Name.StartsWith(OwnedRules.SelfTestPrefix, StringComparison.OrdinalIgnoreCase));
        var profileRules = rules.Where(r => !r.Name.StartsWith(OwnedRules.SelfTestPrefix, StringComparison.OrdinalIgnoreCase)).ToList();
        var problems = new List<string>();
        if (selfTest > 0) problems.Add($"{selfTest} leftover self-test rule(s) (documentation addresses only; harmless). Restore Default removes them.");

        if (profileRules.Count == 0)
        {
            return new OwnedState
            {
                State = selfTest > 0 ? GuardState.Partial : GuardState.NoOwnRules,
                Problems = problems,
                Rules = rules,
                SelfTestRuleCount = selfTest,
            };
        }

        var profiles = new HashSet<string>();
        var hashes = new HashSet<string>();
        var parts = new Dictionary<int, int>();
        int expectedParts = -1;
        bool structureOk = true;
        var programs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var blocked = new List<IpSet>();

        foreach (var r in profileRules)
        {
            string desc = r.Description ?? "";
            var pm = ProfileRx().Match(desc);
            var hm = PlanRx().Match(desc);
            var partm = PartRx().Match(desc);
            if (!pm.Success || !hm.Success || !partm.Success)
            {
                problems.Add($"{r.Name}: description was edited or is not from this app.");
                structureOk = false;
            }
            else
            {
                profiles.Add(pm.Groups["p"].Value);
                hashes.Add(hm.Groups["h"].Value);
                int i = int.Parse(partm.Groups["i"].Value, CultureInfo.InvariantCulture);
                int n = int.Parse(partm.Groups["n"].Value, CultureInfo.InvariantCulture);
                parts[i] = parts.GetValueOrDefault(i) + 1;
                if (expectedParts == -1) expectedParts = n;
                else if (expectedParts != n) structureOk = false;
                if (!r.Name.EndsWith(hm.Groups["h"].Value, StringComparison.OrdinalIgnoreCase))
                {
                    problems.Add($"{r.Name}: name and description disagree.");
                    structureOk = false;
                }
            }

            if (!FirewallRuleSpec.TryRecreate(r, out _, out var reason))
            {
                problems.Add($"{r.Name}: does not look like a rule this app writes ({reason}).");
                structureOk = false;
            }
            if (!r.Enabled)
            {
                problems.Add($"{r.Name}: is disabled (left over from an interrupted apply?).");
                structureOk = false;
            }
            if (!string.IsNullOrEmpty(r.ApplicationName)) programs.Add(r.ApplicationName);
            var parsed = AddressListParser.Parse(r.RemoteAddresses);
            if (parsed.Success) blocked.Add(parsed.Set);
        }

        if (profiles.Count > 1 || hashes.Count > 1)
        {
            problems.Add("Rules from more than one profile/plan are installed at the same time.");
            structureOk = false;
        }
        if (expectedParts > 0 && (parts.Count != expectedParts || parts.Values.Any(c => c != 1) || parts.Keys.Any(k => k < 1 || k > expectedParts)))
        {
            problems.Add($"Expected {expectedParts} rule part(s), found {profileRules.Count}.");
            structureOk = false;
        }

        ProfileId? profile = null;
        if (profiles.Count == 1 && Profiles.TryParse(profiles.First(), out var p) && p != ProfileId.Default) profile = p;
        else structureOk = false;

        bool? targetsCurrent = null;
        if (!string.IsNullOrEmpty(currentGamePath))
        {
            targetsCurrent = programs.Count == 1 && programs.Contains(currentGamePath);
            if (targetsCurrent == false)
                problems.Add("Installed rules target a different program path than the currently selected game (moved or reinstalled?). Re-apply to replace them.");
        }

        bool? matchesPlan = null;
        if (currentPlan is not null && currentPlan.Profile == profile && currentPlan.IsEnforceable)
        {
            matchesPlan = currentPlan.Rules.Count == profileRules.Count &&
                          currentPlan.Rules.All(spec => profileRules.Count(r => string.Equals(r.Name, spec.Name, StringComparison.OrdinalIgnoreCase)) == 1 &&
                                                         RuleComparer.Matches(spec, profileRules.First(r => string.Equals(r.Name, spec.Name, StringComparison.OrdinalIgnoreCase))));
            if (matchesPlan == false)
                problems.Add("Installed rules differ from what the current catalog would produce (catalog updated?). Re-apply to update.");
        }

        var set = IpSet.UnionAll(blocked);
        return new OwnedState
        {
            State = structureOk ? GuardState.Active : GuardState.Partial,
            Profile = profile,
            PlanHash12 = hashes.Count == 1 ? hashes.First() : null,
            RuleCount = profileRules.Count,
            BlockedNetworkCount = set.ToCidrs().Count,
            TargetPrograms = programs.ToList(),
            Problems = problems,
            Rules = rules,
            MatchesCurrentPlan = matchesPlan,
            TargetsCurrentGamePath = targetsCurrent,
            SelfTestRuleCount = selfTest,
        };
    }
}
