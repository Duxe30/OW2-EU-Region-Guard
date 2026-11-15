using OW2RG.Core.Catalog;
using OW2RG.Core.Firewall;
using OW2RG.Core.Game;
using OW2RG.Core.Net;
using OW2RG.Core.Planning;
using static OW2RG.Tests.TestData;

namespace OW2RG.Tests;

public class PlanBuilderTests
{
    private static readonly PlanOptions Opts = new();

    private static ValidatedCatalog Standard() => Validate(Catalog(
        Entry("me-mes1", Region.ME, Confidence.Corroborated, "192.0.2.0/24"),
        Entry("eu-ams1", Region.EU, Confidence.Community, "192.0.2.64/26"),
        Entry("na-ord1", Region.NA, Confidence.Corroborated, "198.51.100.0/25"),
        Entry("unk-x", Region.UNKNOWN, Confidence.Corroborated, "203.0.113.0/24")));

    [Fact]
    public void Block_me_carves_out_europe_exactly()
    {
        var plan = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Standard(), Game(), Opts);
        Assert.True(plan.IsEnforceable, plan.NotEnforceableReason);
        Assert.Equal(["192.0.2.0/26", "192.0.2.128/25"], plan.Fragments.Select(f => f.Block.ToString()));
        Assert.All(plan.Fragments, f => Assert.Equal(["me-mes1"], f.SourceEntryIds));
        Assert.Equal(["192.0.2.64/26"], plan.RemovedByEuProtection.ToCidrs().Select(c => c.ToString()));
        var rule = Assert.Single(plan.Rules);
        Assert.Equal(GamePath, rule.ApplicationPath);
        Assert.Equal(FwProtocol.Udp, rule.Protocol);
        Assert.Equal(FwDirection.Out, rule.Direction);
        Assert.Equal(FwAction.Block, rule.Action);
        Assert.StartsWith("OW2RG-ME-01-", rule.Name);
        Assert.Contains("profile=block-me", rule.Description);
    }

    [Fact]
    public void Prefer_eu_blocks_all_known_non_eu_but_never_unknown()
    {
        var plan = BlockPlanBuilder.Build(ProfileId.PreferEurope, Standard(), Game(), Opts);
        var blocked = plan.BlockSet;
        Assert.True(blocked.Contains(IpFamily.V4, Ip("198.51.100.1")));
        Assert.False(blocked.Contains(IpFamily.V4, Ip("203.0.113.1")));   // UNKNOWN stays reachable
        Assert.False(blocked.Contains(IpFamily.V4, Ip("192.0.2.70")));    // EU stays reachable
        Assert.StartsWith("OW2RG-EU-", plan.Rules[0].Name);
    }

    [Fact]
    public void Contested_addresses_are_never_blocked()
    {
        var cat = Validate(Catalog(
            Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24"),
            Entry("as-b", Region.AS, Confidence.Unverified, "192.0.2.0/25"))); // claimed by another region, even unverified
        var plan = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, cat, Game(), Opts);
        Assert.Equal(["192.0.2.128/25"], plan.Fragments.Select(f => f.Block.ToString()));
        Assert.False(plan.RemovedAsContested.IsEmpty);
    }

    [Fact]
    public void Catalog_conflicts_are_explained_in_plan_warnings()
    {
        var cat = Validate(Catalog(
            Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24"),
            Entry("as-b", Region.AS, Confidence.Corroborated, "192.0.2.0/25")));
        Assert.Single(cat.Conflicts);

        var blockMe = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, cat, Game(), Opts);
        Assert.Contains(blockMe.Warnings, w => w.StartsWith("Catalog conflict: me-a (ME) and as-b (AS)") && w.EndsWith("left open."));
        Assert.False(blockMe.BlockSet.Contains(IpFamily.V4, Ip("192.0.2.1")));

        var preferEu = BlockPlanBuilder.Build(ProfileId.PreferEurope, cat, Game(), Opts);
        Assert.Contains(preferEu.Warnings, w => w.StartsWith("Catalog conflict: me-a (ME) and as-b (AS)") && w.EndsWith("both are blocked by this profile."));
        Assert.True(preferEu.BlockSet.Contains(IpFamily.V4, Ip("192.0.2.1")));

        var unrelated = BlockPlanBuilder.Build(ProfileId.Default, cat, null, Opts);
        Assert.DoesNotContain(unrelated.Warnings, w => w.StartsWith("Catalog conflict"));
    }

    [Fact]
    public void Excluded_networks_are_never_blocked_and_shield_overlaps()
    {
        var excluded = Entry("me-bliz", Region.ME, Confidence.Corroborated, "192.0.2.0/26");
        var doc = Catalog(
            Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24"),
            new CatalogEntryDocument
            {
                Id = excluded.Id, Name = excluded.Name, Region = excluded.Region, Cidrs = excluded.Cidrs, Confidence = excluded.Confidence,
                Sources = excluded.Sources, LastVerifiedAtUtc = excluded.LastVerifiedAtUtc, ExcludeFromBlocking = true, ExclusionReason = "Blizzard-owned",
            });
        var plan = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Validate(doc), Game(), Opts);
        Assert.False(plan.BlockSet.Contains(IpFamily.V4, Ip("192.0.2.1")));
        Assert.True(plan.BlockSet.Contains(IpFamily.V4, Ip("192.0.2.200")));
        Assert.Contains(plan.Decisions, d => d.Entry.Id == "me-bliz" && d.Role == EntryRole.Excluded && !d.Eligible);
    }

    [Fact]
    public void Community_data_requires_explicit_opt_in_and_unverified_is_never_used()
    {
        var cat = Validate(Catalog(
            Entry("me-c", Region.ME, Confidence.Community, "192.0.2.0/24"),
            Entry("me-u", Region.ME, Confidence.Unverified, "198.51.100.0/24")));
        var off = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, cat, Game(), Opts);
        Assert.False(off.IsEnforceable);
        Assert.Contains("community", off.NotEnforceableReason, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(off.Rules);

        var on = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, cat, Game(), Opts with { AllowCommunityData = true });
        Assert.True(on.IsEnforceable);
        Assert.Equal(["192.0.2.0/24"], on.Fragments.Select(f => f.Block.ToString()));
        Assert.Equal([Confidence.Community], on.ConfidenceTiersUsed);
        Assert.Contains("tiers=community", on.Rules[0].Description);
    }

    [Fact]
    public void Empty_catalog_is_honestly_not_active()
    {
        var cat = Validate(Catalog(
            Entry("me-mes1", Region.ME, Confidence.Unverified),
            Entry("eu-ams1", Region.EU, Confidence.Unverified)));
        var plan = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, cat, Game(), Opts);
        Assert.False(plan.IsEnforceable);
        Assert.Contains("No verified addresses available", plan.NotEnforceableReason);
        Assert.Empty(plan.Rules);
    }

    [Fact]
    public void Invalid_catalog_or_missing_game_is_not_enforceable()
    {
        var bad = Validate(Catalog(Entry("me-a", Region.ME, Confidence.Corroborated, "10.0.0.0/8")));
        Assert.False(BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, bad, Game(), Opts).IsEnforceable);
        var noGame = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Standard(), null, Opts);
        Assert.False(noGame.IsEnforceable);
        Assert.Empty(noGame.Rules);
    }

    [Fact]
    public void Default_profile_has_no_rules()
    {
        var plan = BlockPlanBuilder.Build(ProfileId.Default, Standard(), null, Opts);
        Assert.True(plan.IsEnforceable);
        Assert.Empty(plan.Rules);
    }

    [Fact]
    public void Plan_hash_and_names_are_deterministic()
    {
        var a = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Standard(), Game(), Opts);
        var b = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Standard(), Game(), Opts);
        Assert.Equal(a.PlanHash, b.PlanHash);
        Assert.Equal(a.Rules.Select(r => r.Name), b.Rules.Select(r => r.Name));
        var other = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Standard(), Game(@"E:\OW\_retail_\Overwatch.exe"), Opts);
        Assert.NotEqual(a.PlanHash, other.PlanHash);
    }

    [Fact]
    public void Large_plans_are_chunked_exactly_within_the_character_limit()
    {
        // 200 disjoint /32s inside TEST-NET-2 and TEST-NET-3 plus IPv6.
        var cidrs = Enumerable.Range(0, 100).Select(i => $"198.51.100.{i * 2}/32")
            .Concat(Enumerable.Range(0, 100).Select(i => $"203.0.113.{i * 2}/32"))
            .Concat(Enumerable.Range(0, 30).Select(i => $"2001:db8:{i:x}::/48")).ToArray();
        var cat = Validate(Catalog(Entry("me-a", Region.ME, Confidence.Corroborated, cidrs)));
        var plan = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, cat, Game(), Opts with { MaxRemoteAddressCharsPerRule = 300 });
        Assert.True(plan.Rules.Count > 5);
        Assert.All(plan.Rules, r => Assert.True(r.RemoteAddressesText.Length <= 300));
        Assert.All(plan.Rules, r => Assert.Single(r.RemoteAddresses.Select(c => c.Family).Distinct()));
        Assert.Equal(plan.BlockSet, IpSet.UnionAll(plan.Rules.Select(r => r.RemoteSet)));
        Assert.Equal(plan.Rules.Count, plan.Rules.Select(r => r.Name).Distinct().Count());
    }

    [Fact]
    public void Random_catalogs_never_violate_invariants()
    {
        var rng = new Random(1107);
        var regions = new[] { Region.EU, Region.ME, Region.NA, Region.AS, Region.UNKNOWN };
        for (int round = 0; round < 200; round++)
        {
            var entries = new List<CatalogEntryDocument>();
            int n = rng.Next(1, 7);
            for (int i = 0; i < n; i++)
            {
                var cidrs = Enumerable.Range(0, rng.Next(1, 4)).Select(_ =>
                {
                    int prefix = rng.Next(24, 33);
                    int size = 1 << (32 - prefix);
                    int start = rng.Next(0, 256 / size) * size;
                    return $"198.51.100.{start}/{prefix}";
                }).Distinct().ToArray();
                entries.Add(Entry($"e{i}-x", regions[rng.Next(regions.Length)], (Confidence)rng.Next(0, 4), cidrs));
            }
            var cat = Validate(Catalog([.. entries]));
            foreach (var profile in new[] { ProfileId.BlockMiddleEast, ProfileId.PreferEurope })
            {
                var plan = BlockPlanBuilder.Build(profile, cat, Game(), Opts with { AllowCommunityData = rng.Next(2) == 0 });
                var eu = IpSet.UnionAll(cat.Entries.Where(e => e.Region == Region.EU).Select(e => e.Addresses));
                var nonTarget = IpSet.UnionAll(cat.Entries.Where(e => !Profiles.Targets(profile, e.Region)).Select(e => e.Addresses));
                Assert.False(plan.BlockSet.Overlaps(eu));
                Assert.False(plan.BlockSet.Overlaps(nonTarget));
                Assert.True(plan.BlockSet.IsSubsetOf(plan.CandidateSet));
                Assert.Equal(plan.BlockSet, IpSet.UnionAll(plan.Rules.Select(r => r.RemoteSet)).Union(plan.IsEnforceable ? IpSet.Empty : plan.BlockSet));
            }
        }
    }

    private static UInt128 Ip(string s)
    {
        Assert.True(IpCodec.TryParseStrict(s, out _, out var v));
        return v;
    }
}

public class GamePathValidatorTests
{
    [Theory]
    [InlineData(@"Overwatch\_retail_\Overwatch.exe")]                 // relative
    [InlineData(@"D:\Games\Overwatch\Overwatch Launcher.exe")]        // launcher
    [InlineData(@"C:\Program Files (x86)\Battle.net\Battle.net.exe")] // Battle.net
    [InlineData(@"C:\Windows\System32\svchost.exe")]
    [InlineData(@"C:\Windows\Overwatch.exe")]
    [InlineData(@"D:\Games\..\Overwatch\_retail_\Overwatch.exe")]
    [InlineData(@"%ProgramFiles%\Overwatch\_retail_\Overwatch.exe")]
    [InlineData(@"\\server\share\Overwatch\_retail_\Overwatch.exe")]
    [InlineData(@"\\?\D:\Overwatch\_retail_\Overwatch.exe")]
    [InlineData(@"D:\Games\Overwatch\_retail_\Overwatch.exe:stream")]
    [InlineData(@"D:/Games/Overwatch/_retail_/Overwatch.exe")]
    [InlineData(@"D:\Games\Overwatch\_retail_\notepad.exe")]
    [InlineData(@"D:\Games\Overwatch \_retail_\Overwatch.exe")]
    [InlineData("")]
    public void Unsafe_or_wrong_paths_are_rejected(string path)
    {
        var check = GamePathValidator.Validate(path, new FakeFiles(path));
        Assert.False(check.IsValid);
        Assert.NotEmpty(check.Errors);
    }

    [Fact]
    public void Missing_file_is_rejected()
    {
        Assert.False(GamePathValidator.Validate(GamePath, new FakeFiles()).IsValid);
    }

    [Fact]
    public void Valid_steam_and_battlenet_paths_are_accepted()
    {
        foreach (var p in new[] { @"D:\SteamLibrary\steamapps\common\Overwatch\_retail_\Overwatch.exe", @"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe" })
        {
            var check = GamePathValidator.Validate(p, new FakeFiles(p));
            Assert.True(check.IsValid, string.Join(";", check.Errors));
            Assert.Empty(check.Warnings);
        }
    }

    [Fact]
    public void Unusual_location_and_small_file_warn()
    {
        string p = @"D:\Elsewhere\Overwatch.exe";
        var check = GamePathValidator.Validate(p, new FakeFiles(p) { Size = 4 * 1024 * 1024 });
        Assert.True(check.IsValid);
        Assert.Equal(2, check.Warnings.Count);
    }
}
