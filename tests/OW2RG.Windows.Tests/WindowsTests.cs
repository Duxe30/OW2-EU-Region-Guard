using System.Runtime.InteropServices;
using OW2RG.Core.Firewall;
using OW2RG.Core.Game;
using OW2RG.Core.Planning;
using OW2RG.Infrastructure.Windows;
using OW2RG.Infrastructure.Windows.Firewall;

namespace OW2RG.Windows.Tests;

/// <summary>Runs only when OW2RG_LIVE_FIREWALL_TESTS=1 AND the test process is elevated. Use a disposable VM.</summary>
public sealed class LiveFirewallFactAttribute : FactAttribute
{
    public LiveFirewallFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("OW2RG_LIVE_FIREWALL_TESTS") != "1")
            Skip = "Opt-in: set OW2RG_LIVE_FIREWALL_TESTS=1 and run elevated to write a temporary documentation-address rule.";
        else if (!Elevation.IsElevated())
            Skip = "Live firewall tests need an elevated (Administrator) test process.";
    }
}

public class HelperProtocolTests
{
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void Apply_request_round_trips()
    {
        var req = new HelperRequest
        {
            Operation = "apply", ResultId = Guid.NewGuid(), Profile = ProfileId.BlockMiddleEast,
            GamePath = @"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe", CatalogToken = "embedded", AllowCommunity = true, ExpectedPlanHash = Hash,
        };
        Assert.True(HelperRequest.TryParse(req.ToArgs(), out var back, out var err), err);
        Assert.Equal(req, back);
    }

    [Theory]
    [InlineData("--helper", "format-disk", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff")]
    [InlineData("--helper", "restore", "--result-id", "not-a-guid")]
    [InlineData("--helper", "restore", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff", "--profile", "block-me")]
    [InlineData("--helper", "apply", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff", "--profile", "default", "--game", @"C:\x\_retail_\Overwatch.exe", "--catalog", "embedded", "--expect-plan", Hash)]
    [InlineData("--helper", "apply", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff", "--profile", "block-me", "--game", @"C:\x\_retail_\Overwatch.exe", "--catalog", @"relative\servers.json", "--expect-plan", Hash)]
    [InlineData("--helper", "apply", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff", "--profile", "block-me", "--game", @"C:\x\_retail_\Overwatch.exe", "--catalog", "embedded", "--expect-plan", "abc")]
    [InlineData("--helper", "apply", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff", "--profile", "block-me", "--game", @"C:\x\_retail_\Overwatch.exe", "--catalog", "embedded", "--expect-plan", Hash, "--exec", "calc")]
    [InlineData("--helper", "apply", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff", "--result-id", "6f9619ff-8b86-d011-b42d-00cf4fc964ff")]
    public void Malformed_helper_requests_are_rejected(params string[] args)
    {
        Assert.False(HelperRequest.TryParse(args, out _, out var err));
        Assert.NotNull(err);
    }

    [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CommandLineToArgvW(string cmdLine, out int argc);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);

    [Theory]
    [InlineData(@"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe")]
    [InlineData(@"D:\Games\Over ""watch""\x\")]
    [InlineData(@"trailing\\")]
    [InlineData("")]
    [InlineData("a b\tc")]
    public void Arguments_are_quoted_exactly_as_windows_splits_them(string arg)
    {
        string line = "prog.exe " + Elevation.JoinArguments(["--game", arg, "--x"]);
        IntPtr p = CommandLineToArgvW(line, out int argc);
        try
        {
            var parsed = new string[argc];
            for (int i = 0; i < argc; i++) parsed[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, i * IntPtr.Size))!;
            Assert.Equal(["prog.exe", "--game", arg, "--x"], parsed);
        }
        finally
        {
            LocalFree(p);
        }
    }
}

public class EmbeddedDataTests
{
    [Fact]
    public void Embedded_catalog_and_map_load_and_validate()
    {
        var c = CatalogProvider.LoadEmbedded([]);
        Assert.True(c.Catalog.IsUsable, string.Join("\n", c.Catalog.Errors));
        Assert.NotEmpty(CatalogProvider.LoadEmbeddedMap().Datacenters);
    }

    [Fact]
    public void Game_locator_runs_without_throwing_and_only_returns_validated_or_explained_candidates()
    {
        foreach (var c in GameLocator.FindCandidates())
        {
            Assert.EndsWith("Overwatch.exe", c.Path, StringComparison.OrdinalIgnoreCase);
            Assert.True(c.Check.IsValid || c.Check.Errors.Count > 0);
        }
    }
}

/// <summary>Talks to the real Windows Firewall COM API but never saves a rule.</summary>
public class ComReadOnlyTests
{
    [Fact]
    public void Environment_and_owned_rules_are_readable_without_admin()
    {
        var store = new ComFirewallStore();
        var env = store.ReadEnvironment();
        Assert.True(env.ApiAvailable, env.ApiError);
        Assert.All(store.ReadOwnedRules(), r => Assert.StartsWith(OwnedRules.Prefix, r.Name, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Windows_accepts_every_rule_of_both_real_plans_in_a_dry_check()
    {
        var store = new ComFirewallStore();
        int ownedBefore = store.ReadOwnedRules().Count;
        var catalog = CatalogProvider.LoadEmbedded([]);
        var game = GamePathValidator.Validate(@"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe", new AssumeExists()).Path!;
        foreach (var profile in new[] { ProfileId.BlockMiddleEast, ProfileId.PreferEurope })
        {
            var plan = BlockPlanBuilder.Build(profile, catalog.Catalog, game, new PlanOptions());
            Assert.True(plan.IsEnforceable, plan.NotEnforceableReason);
            foreach (var spec in plan.Rules)
            {
                var dry = store.DryValidate(spec);
                Assert.True(dry.Accepted, $"{spec.Name}: {dry.Error}");
                Assert.NotNull(dry.WindowsReadBack);
            }
        }
        Assert.Equal(ownedBefore, store.ReadOwnedRules().Count); // dry checks never persist anything
    }

    [Fact]
    public void Missing_owned_rule_is_reported_without_touching_anything()
    {
        var store = new ComFirewallStore();
        const string name = "OW2RG-SELFTEST-DOES-NOT-EXIST";
        Assert.DoesNotContain(store.ReadOwnedRules(), r => r.Name == name);
        Assert.Equal(0, store.RemoveRules(name));                       // Item(name) not found → nothing to remove, no elevation needed
        var ex = Assert.Throws<FirewallOperationException>(() => store.SetEnabled(name, true));
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public void Store_refuses_to_touch_foreign_rules()
    {
        var store = new ComFirewallStore();
        Assert.Throws<InvalidOperationException>(() => store.RemoveRules("Core Networking - DNS (UDP-Out)"));
        Assert.Throws<InvalidOperationException>(() => store.SetEnabled("Core Networking - DNS (UDP-Out)", false));
    }

    private sealed class AssumeExists : IFileProbe
    {
        public bool FileExists(string path) => true;
        public long? FileLength(string path) => null;
    }
}

/// <summary>Opt-in only: writes ONE rule for this test process to 192.0.2.1 (TEST-NET-1) and always removes it.</summary>
public class LiveFirewallTests
{
    [LiveFirewallFact]
    public void Create_enforce_and_remove_a_documentation_address_rule()
    {
        var store = new ComFirewallStore();
        var report = SelfTest.RunLive(store);
        Assert.True(report.Passed, string.Join("\n", report.Lines()));
        Assert.DoesNotContain(store.ReadOwnedRules(), r => r.Name.StartsWith(OwnedRules.SelfTestPrefix, StringComparison.OrdinalIgnoreCase));
    }
}
