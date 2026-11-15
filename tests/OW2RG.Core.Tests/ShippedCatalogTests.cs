using OW2RG.Core.Catalog;
using OW2RG.Core.Net;
using OW2RG.Core.Planning;
using static OW2RG.Tests.TestData;

namespace OW2RG.Tests;

/// <summary>Checks the real data/servers.json that ships with the app, not just synthetic fixtures.</summary>
public class ShippedCatalogTests
{
    private static ValidatedCatalog Load()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "data", "servers.json");
        Assert.True(File.Exists(path), "data/servers.json was not copied to the test output.");
        var (doc, sha) = CatalogJson.LoadFile(path);
        return CatalogValidator.Validate(doc, sha, new CatalogValidationOptions { Now = doc.GeneratedAtUtc.AddDays(1) });
    }

    [Fact]
    public void Shipped_catalog_is_valid_in_production_mode()
    {
        var c = Load();
        Assert.True(c.IsUsable, string.Join("\n", c.Errors));
        Assert.False(c.AllowsDocumentationRanges);
        Assert.Empty(c.Conflicts); // no region claims overlap another region's addresses
    }

    [Fact]
    public void Block_me_targets_exactly_the_three_middle_east_datacenters()
    {
        var c = Load();
        var plan = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, c, Game(), new PlanOptions());
        Assert.True(plan.IsEnforceable, plan.NotEnforceableReason);
        var blocked = plan.Decisions.Where(d => d.Eligible).Select(d => d.Entry.Document.DatacenterCode ?? "").Order().ToArray();
        Assert.Equal(["GMEC1", "GMEC2", "MES1"], blocked);
        Assert.All(plan.Decisions.Where(d => d.Eligible), d => Assert.Equal(Region.ME, d.Entry.Region));
        Assert.All(plan.Decisions.Where(d => d.Eligible), d => Assert.Equal(Confidence.Corroborated, d.Entry.Confidence));
    }

    [Fact]
    public void No_plan_can_touch_any_european_or_blizzard_owned_address()
    {
        var c = Load();
        var eu = IpSet.UnionAll(c.Entries.Where(e => e.Region == Region.EU).Select(e => e.Addresses));
        var blizzard = IpSet.UnionAll(c.Entries.Where(e => e.Document.Hosting?.Provider == "blizzard").Select(e => e.Addresses));
        Assert.False(eu.IsEmpty);
        foreach (var p in new[] { ProfileId.BlockMiddleEast, ProfileId.PreferEurope })
        {
            foreach (bool community in new[] { false, true })
            {
                var plan = BlockPlanBuilder.Build(p, c, Game(), new PlanOptions { AllowCommunityData = community });
                Assert.True(plan.IsEnforceable);
                Assert.False(plan.BlockSet.Overlaps(eu), $"{p}: blocks European space");
                Assert.False(plan.BlockSet.Overlaps(blizzard), $"{p}: blocks Blizzard-owned space");
                Assert.All(plan.Rules, r => Assert.True(r.RemoteAddressesText.Length <= 1000));
            }
        }
    }

    [Theory]
    [InlineData("64.224.26.10", false)]   // AMS1 (Blizzard, Amsterdam)
    [InlineData("34.88.1.1", false)]      // GEN1 (Google europe-north1, Finland)
    [InlineData("35.204.10.10", false)]   // Google europe-west4 (Netherlands)
    [InlineData("15.185.1.1", true)]      // MES1 (AWS me-south-1, Bahrain)
    [InlineData("157.175.20.20", true)]   // MES1
    [InlineData("34.18.0.5", true)]       // GMEC1 (Google me-central1, Doha)
    [InlineData("34.166.0.84", true)]     // GMEC2 (Google me-central2, Dammam)
    [InlineData("34.165.1.1", false)]     // Tel Aviv: community-only, not blocked without opt-in
    [InlineData("8.8.8.8", false)]        // unknown: never blocked
    public void Block_me_spot_checks(string ip, bool blocked)
    {
        var plan = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Load(), Game(), new PlanOptions());
        Assert.True(IpCodec.TryParseStrict(ip, out var fam, out var v));
        Assert.Equal(blocked, plan.BlockSet.Contains(fam, v));
    }

    [Fact]
    public void Every_entry_has_provenance()
    {
        foreach (var e in Load().Entries.Where(e => !e.Document.ProtectOnly))
        {
            Assert.NotEmpty(e.Document.Sources);
            Assert.Contains(e.Document.Sources, s => s.Kind is "community-list" or "official-provider-feed");
        }
    }
}
