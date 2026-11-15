using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using OW2RG.Core.Catalog;
using OW2RG.Core.Firewall;
using OW2RG.Core.Game;
using OW2RG.Core.Net;

namespace OW2RG.Core.Planning;

public sealed record PlanOptions
{
    /// <summary>Explicit per-catalog opt-in to enforce single-source community data (high risk).</summary>
    public bool AllowCommunityData { get; init; }
    public FwProtocol Protocol { get; init; } = FwProtocol.Udp;
    /// <summary>Maximum serialized length of one rule's RemoteAddresses string.</summary>
    public int MaxRemoteAddressCharsPerRule { get; init; } = 1000;
    public int MaxRules { get; init; } = 64;
    public int MaxBlockedCidrs { get; init; } = 4000;
    public string AppVersion { get; init; } = "1.0.0";
}

public enum EntryRole { Protected, Target, Excluded, Other }

/// <summary>Why each catalog entry is or is not part of the plan — shown verbatim in the preview.</summary>
public sealed record EntryDecision(ValidatedEntry Entry, EntryRole Role, bool Eligible, string Reason);

/// <summary>Every blocked CIDR keeps the ids of the catalog entries it came from.</summary>
public sealed record BlockedFragment(CidrBlock Block, IReadOnlyList<string> SourceEntryIds);

public sealed class PlanInvariantException(string message) : Exception(message);

public sealed class BlockPlan
{
    public required ProfileId Profile { get; init; }
    public required string CatalogVersion { get; init; }
    public required string CatalogSha256 { get; init; }
    public ValidatedGamePath? Game { get; init; }
    public required IReadOnlyList<FirewallRuleSpec> Rules { get; init; }
    public required IpSet BlockSet { get; init; }
    public required IpSet CandidateSet { get; init; }
    public required IpSet ProtectedSet { get; init; }
    public required IpSet RemovedByEuProtection { get; init; }
    public required IpSet RemovedAsContested { get; init; }
    public required IReadOnlyList<EntryDecision> Decisions { get; init; }
    public required IReadOnlyList<BlockedFragment> Fragments { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public required IReadOnlyList<Confidence> ConfidenceTiersUsed { get; init; }
    public required string PlanHash { get; init; }
    public string? NotEnforceableReason { get; init; }

    /// <summary>True when applying the plan does something meaningful (Default always is: it removes our rules).</summary>
    public bool IsEnforceable => NotEnforceableReason is null;
    public int BlockedCidrCount => Fragments.Count;
    public int TargetDatacenterCount => Decisions.Count(d => d.Role == EntryRole.Target && d.Eligible);
    public BigInteger BlockedIpv4Addresses => BlockSet.AddressCountV4;
    public string ShortHash => PlanHash[..12];
}

/// <summary>
/// Turns (profile, catalog, game path) into an exact, overlap-safe firewall plan.
///   candidates := union of eligible target-region entries
///   protected  := union of EVERY European entry, whatever its confidence (protecting more is always safe)
///   contested  := addresses also claimed by any non-target region (incl. UNKNOWN) or by an excluded network
///   block      := candidates − protected − contested − special-purpose space
/// The result is emitted as a minimal exact CIDR cover and re-checked against hard invariants.
/// </summary>
public static class BlockPlanBuilder
{
    public static BlockPlan Build(ProfileId profile, ValidatedCatalog catalog, ValidatedGamePath? game, PlanOptions options)
    {
        var warnings = new List<string>();
        var decisions = new List<EntryDecision>();

        if (profile == ProfileId.Default)
        {
            foreach (var e in catalog.Entries)
                decisions.Add(new EntryDecision(e, e.Region == Region.EU ? EntryRole.Protected : EntryRole.Other, false, "Default profile blocks nothing."));
            return new BlockPlan
            {
                Profile = profile,
                CatalogVersion = catalog.Document.CatalogVersion,
                CatalogSha256 = catalog.Sha256,
                Game = game,
                Rules = [],
                BlockSet = IpSet.Empty,
                CandidateSet = IpSet.Empty,
                ProtectedSet = IpSet.Empty,
                RemovedByEuProtection = IpSet.Empty,
                RemovedAsContested = IpSet.Empty,
                Decisions = decisions,
                Fragments = [],
                Warnings = warnings,
                ConfidenceTiersUsed = [],
                PlanHash = Hash(profile, null, options.Protocol, []),
            };
        }

        string? notEnforceable = null;
        if (!catalog.IsUsable)
            notEnforceable = "The server catalog has validation errors, so nothing can be enforced: " +
                             string.Join(" | ", catalog.Errors.Take(3).Select(i => i.Message));
        if (game is null)
            notEnforceable ??= "No validated Overwatch.exe is selected.";

        var targetSets = new List<IpSet>();
        var protectedSets = new List<IpSet>();
        var contestedSets = new List<IpSet>();
        var tiers = new SortedSet<Confidence>();

        foreach (var e in catalog.Entries)
        {
            var d = e.Document;
            if (e.Region == Region.EU)
            {
                protectedSets.Add(e.Addresses);
                decisions.Add(new EntryDecision(e, EntryRole.Protected, false,
                    e.HasAddresses ? "European: these addresses are protected and can never be blocked." : "European entry without addresses."));
                continue;
            }

            if (!Profiles.Targets(profile, e.Region))
            {
                contestedSets.Add(e.Addresses);
                decisions.Add(new EntryDecision(e, EntryRole.Other, false,
                    e.Region == Region.UNKNOWN ? "Unknown region: never blocked." : $"Region {e.Region} is not blocked by this profile."));
                continue;
            }

            if (d.ExcludeFromBlocking || d.ProtectOnly)
            {
                contestedSets.Add(e.Addresses);
                decisions.Add(new EntryDecision(e, EntryRole.Excluded, false,
                    "Excluded from blocking: " + (d.ExclusionReason ?? "marked protect-only in the catalog.")));
                continue;
            }

            string? why = null;
            if (!d.Enabled) why = "Disabled in the catalog.";
            else if (!e.HasAddresses) why = "No addresses available — cannot enforce.";
            else if (e.Confidence == Confidence.Unverified) why = "Unverified data is never enforced.";
            else if (e.Confidence == Confidence.Community && !options.AllowCommunityData)
                why = "Community-only data: enforced only after you explicitly allow community data.";

            if (why is not null)
            {
                decisions.Add(new EntryDecision(e, EntryRole.Target, false, why));
                continue;
            }

            targetSets.Add(e.Addresses);
            tiers.Add(e.Confidence);
            if (e.IsStale) warnings.Add($"{e.DisplayName}: data is stale or has no verification date.");
            decisions.Add(new EntryDecision(e, EntryRole.Target, true,
                $"Blocked ({ConfidenceLabel(e.Confidence)}; {e.Cidrs.Count} source range(s))."));
        }

        // Cross-region conflicts found by the validator: explain what happens to each one under this profile.
        foreach (var c in catalog.Conflicts)
        {
            bool aBlocked = decisions.Any(d => d.Eligible && d.Entry.Id == c.EntryA);
            bool bBlocked = decisions.Any(d => d.Eligible && d.Entry.Id == c.EntryB);
            if (!aBlocked && !bBlocked) continue;
            int blocks = c.Overlap.ToCidrs().Count;
            warnings.Add(aBlocked && bBlocked
                ? $"Catalog conflict: {c.EntryA} ({c.RegionA}) and {c.EntryB} ({c.RegionB}) claim the same {blocks} block(s); both are blocked by this profile."
                : $"Catalog conflict: {c.EntryA} ({c.RegionA}) and {c.EntryB} ({c.RegionB}) claim the same {blocks} block(s); the contested part is left open.");
        }

        var candidates = IpSet.UnionAll(targetSets);
        var protectedEu = IpSet.UnionAll(protectedSets);
        var contested = IpSet.UnionAll(contestedSets);
        var forbidden = SpecialRanges.Forbidden(catalog.AllowsDocumentationRanges);

        var afterEu = candidates.Subtract(protectedEu);
        var removedByEu = candidates.Intersect(protectedEu);
        var afterContested = afterEu.Subtract(contested);
        var removedContested = afterEu.Intersect(contested);
        var block = afterContested.Subtract(forbidden);
        if (!afterContested.Intersect(forbidden).IsEmpty)
            warnings.Add("Some candidate addresses fell in special-purpose space and were dropped.");

        if (!removedByEu.IsEmpty)
            warnings.Add($"{removedByEu.ToCidrs().Count} block(s) overlapping European datacenters were carved out and stay reachable.");
        if (!removedContested.IsEmpty)
            warnings.Add($"{removedContested.ToCidrs().Count} block(s) claimed by another region or an excluded network were left unblocked.");

        // ---- Hard invariants. A violation is a bug, never a user error. ----
        if (block.Overlaps(protectedEu)) throw new PlanInvariantException("Block set intersects protected European addresses.");
        if (!block.IsSubsetOf(candidates)) throw new PlanInvariantException("Block set is not a subset of the selected candidates.");
        if (block.Overlaps(forbidden)) throw new PlanInvariantException("Block set contains special-purpose addresses.");
        if (block.Overlaps(contested)) throw new PlanInvariantException("Block set contains contested addresses.");

        var cidrs = block.ToCidrs();
        if (!IpSet.From(cidrs).Equals(block)) throw new PlanInvariantException("CIDR cover is not exact.");

        if (notEnforceable is null && cidrs.Count == 0)
        {
            notEnforceable = BuildEmptyReason(profile, decisions);
        }
        if (cidrs.Count > options.MaxBlockedCidrs)
            notEnforceable ??= $"Plan needs {cidrs.Count} CIDR blocks, above the safety limit of {options.MaxBlockedCidrs}.";

        var fragments = cidrs.Select(c =>
        {
            var one = IpSet.From([c]);
            var ids = catalog.Entries
                .Where(e => decisions.Any(d => d.Entry == e && d.Eligible) && e.Addresses.Overlaps(one))
                .Select(e => e.Id).ToList();
            return new BlockedFragment(c, ids);
        }).ToList();

        string hash = Hash(profile, game, options.Protocol, cidrs);
        var rules = new List<FirewallRuleSpec>();
        if (notEnforceable is null && game is not null)
        {
            var chunks = Chunk(cidrs, options.MaxRemoteAddressCharsPerRule);
            if (chunks.Count > options.MaxRules)
            {
                notEnforceable = $"Plan needs {chunks.Count} firewall rules, above the safety limit of {options.MaxRules}.";
            }
            else
            {
                string tierText = string.Join("+", tiers.Reverse().Select(t => t.ToString().ToLowerInvariant()));
                for (int i = 0; i < chunks.Count; i++)
                {
                    string name = RuleName(profile, i + 1, hash);
                    string description = FirewallRuleSpec.Describe(options.AppVersion, Profiles.Code(profile), hash[..12], i + 1, chunks.Count,
                        catalog.Document.CatalogVersion, tierText);
                    rules.Add(FirewallRuleSpec.CreateGameBlock(name, description, game, options.Protocol, chunks[i], enabled: true));
                }
                var union = IpSet.UnionAll(rules.Select(r => r.RemoteSet));
                if (!union.Equals(block)) throw new PlanInvariantException("Rules do not cover exactly the block set.");
            }
        }

        return new BlockPlan
        {
            Profile = profile,
            CatalogVersion = catalog.Document.CatalogVersion,
            CatalogSha256 = catalog.Sha256,
            Game = game,
            Rules = notEnforceable is null ? rules : [],
            BlockSet = block,
            CandidateSet = candidates,
            ProtectedSet = protectedEu,
            RemovedByEuProtection = removedByEu,
            RemovedAsContested = removedContested,
            Decisions = decisions,
            Fragments = fragments,
            Warnings = warnings,
            ConfidenceTiersUsed = tiers.Reverse().ToList(),
            PlanHash = hash,
            NotEnforceableReason = notEnforceable,
        };
    }

    public static string RuleName(ProfileId profile, int part, string planHash) =>
        string.Create(CultureInfo.InvariantCulture, $"{OwnedRules.Prefix}{Profiles.Tag(profile)}-{part:00}-{planHash[..12]}");

    public static string ConfidenceLabel(Confidence c) => c switch
    {
        Confidence.Observed => "observed in game",
        Confidence.Corroborated => "corroborated",
        Confidence.Community => "community-only",
        _ => "unverified",
    };

    private static string BuildEmptyReason(ProfileId profile, List<EntryDecision> decisions)
    {
        var targets = decisions.Where(d => d.Role == EntryRole.Target).ToList();
        if (targets.Count == 0)
            return $"No verified addresses available for '{Profiles.DisplayName(profile)}' — the catalog has no datacenters in the targeted regions. Cannot enforce yet.";
        if (targets.All(d => !d.Eligible) && targets.Any(d => d.Entry.Confidence == Confidence.Community))
            return "No verified addresses available — the targeted datacenters only have community data. Allow community data (higher risk) or import verified data. Cannot enforce yet.";
        if (targets.Any(d => d.Eligible))
            return "Every eligible address overlaps protected European or contested space, so nothing would be blocked.";
        return "No verified addresses available for the targeted datacenters. Cannot enforce yet.";
    }

    /// <summary>Packs CIDRs into rules, IPv4 first, never splitting a CIDR and never mixing families in one rule.</summary>
    internal static List<List<CidrBlock>> Chunk(IReadOnlyList<CidrBlock> cidrs, int maxChars)
    {
        var chunks = new List<List<CidrBlock>>();
        foreach (var family in new[] { IpFamily.V4, IpFamily.V6 })
        {
            List<CidrBlock>? current = null;
            int length = 0;
            foreach (var c in cidrs.Where(c => c.Family == family))
            {
                string text = c.ToString();
                int add = (current is { Count: > 0 } ? 1 : 0) + text.Length;
                if (current is null || (current.Count > 0 && length + add > maxChars))
                {
                    current = [];
                    chunks.Add(current);
                    length = 0;
                    add = text.Length;
                }
                current.Add(c);
                length += add;
            }
        }
        return chunks;
    }

    private static string Hash(ProfileId profile, ValidatedGamePath? game, FwProtocol protocol, IReadOnlyList<CidrBlock> cidrs)
    {
        var sb = new StringBuilder("ow2rg-plan-v1\n");
        sb.Append(Profiles.Code(profile)).Append('\n');
        sb.Append(game?.FullPath.ToUpperInvariant() ?? "-").Append('\n');
        sb.Append((int)protocol).Append('\n');
        foreach (var c in cidrs) sb.Append(c).Append('\n');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }
}
