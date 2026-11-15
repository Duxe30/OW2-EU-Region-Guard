using OW2RG.Core.Catalog;
using OW2RG.Core.Firewall;
using OW2RG.Core.Net;
using OW2RG.Core.Planning;
using static OW2RG.Tests.TestData;

namespace OW2RG.Tests;

/// <summary>
/// In-memory firewall that behaves like Windows where it matters: it holds foreign rules too, allows
/// duplicate names, rewrites IPv4 CIDRs into "address/mask" form on read-back, and can inject failures.
/// </summary>
internal sealed class FakeFirewall : IFirewallRuleStore
{
    public List<FirewallRuleRecord> All { get; } = [];
    public FirewallEnvironment Environment { get; set; } = new() { ApiAvailable = true, CurrentProfileTypes = 2, CurrentProfilesEnabled = true, IsElevated = true };
    public int Adds, Enables, Removes;
    public int? FailOnAdd, FailOnEnable, FailOnRemove;
    public bool FailAllMutationsAfterFirstFailure;
    private bool _failed;

    public FirewallEnvironment ReadEnvironment() => Environment;

    public IReadOnlyList<FirewallRuleRecord> ReadOwnedRules() => All.Where(r => OwnedRules.IsOwnedName(r.Name)).ToList();

    public void AddRule(FirewallRuleSpec spec)
    {
        Adds++;
        Maybe(FailOnAdd, Adds, "add");
        var rec = FirewallRuleRecord.FromSpec(spec) with { RemoteAddresses = WindowsStyle(spec.RemoteAddresses) };
        All.Add(rec);
    }

    public void SetEnabled(string ownedName, bool enabled)
    {
        Enables++;
        Maybe(FailOnEnable, Enables, "enable");
        for (int i = 0; i < All.Count; i++)
            if (string.Equals(All[i].Name, ownedName, StringComparison.OrdinalIgnoreCase)) All[i] = All[i] with { Enabled = enabled };
    }

    public int RemoveRules(string ownedName)
    {
        Removes++;
        Maybe(FailOnRemove, Removes, "remove");
        return All.RemoveAll(r => string.Equals(r.Name, ownedName, StringComparison.OrdinalIgnoreCase));
    }

    private void Maybe(int? failAt, int count, string op)
    {
        if (_failed && FailAllMutationsAfterFirstFailure) throw new FirewallOperationException($"injected {op} failure (sticky)", unchecked((int)0x80004005));
        if (failAt == count)
        {
            _failed = true;
            throw new FirewallOperationException($"injected {op} failure #{count}", unchecked((int)0x80004005));
        }
    }

    private static string WindowsStyle(IEnumerable<CidrBlock> blocks) => string.Join(",", blocks.Select(b =>
    {
        if (b.Family == IpFamily.V6) return b.ToString();
        if (b.PrefixLength == 32) return IpCodec.Format(b.Family, b.Network);
        uint mask = b.PrefixLength == 0 ? 0 : uint.MaxValue << (32 - b.PrefixLength);
        return $"{IpCodec.Format(b.Family, b.Network)}/{IpCodec.Format(IpFamily.V4, mask)}";
    }));
}

internal sealed class MemorySnapshots : ISnapshotStore
{
    public List<FirewallSnapshot> Saved { get; } = [];
    public bool Fail { get; set; }
    public string Save(FirewallSnapshot snapshot)
    {
        if (Fail) throw new IOException("disk full");
        Saved.Add(snapshot);
        return $"mem://{Saved.Count}";
    }
}

internal sealed class MemoryAudit : IAuditLog
{
    public List<AuditEvent> Events { get; } = [];
    public void Write(AuditEvent e) => Events.Add(e);
}

public class FirewallApplyTests
{
    private static readonly FirewallRuleRecord Foreign1 = new()
    {
        Name = "Steam Web Helper", Description = "foreign", ApplicationName = @"C:\Program Files (x86)\Steam\bin\cef\steamwebhelper.exe",
        Protocol = 6, Direction = 2, Action = 1, Enabled = true, RemoteAddresses = "*", Profiles = 7,
    };
    private static readonly FirewallRuleRecord Foreign2 = new()
    {
        Name = "Some VPN block", Description = "foreign", ApplicationName = null, Protocol = 17, Direction = 2, Action = 0, Enabled = true,
        RemoteAddresses = "203.0.113.0/255.255.255.0", Profiles = 0x7FFFFFFF,
    };

    private static ValidatedCatalog Cat() => Validate(Catalog(
        Entry("me-mes1", Region.ME, Confidence.Corroborated, "192.0.2.0/24", "2001:db8:1::/48"),
        Entry("eu-ams1", Region.EU, Confidence.Corroborated, "192.0.2.64/26"),
        Entry("na-ord1", Region.NA, Confidence.Corroborated, "198.51.100.0/24")));

    private static BlockPlan Plan(ProfileId p, string game = GamePath, int maxChars = 1000) =>
        BlockPlanBuilder.Build(p, Cat(), Game(game), new PlanOptions { MaxRemoteAddressCharsPerRule = maxChars });

    private static (FakeFirewall Fw, FirewallApplyService Svc, MemorySnapshots Snaps, MemoryAudit Audit) Setup()
    {
        var fw = new FakeFirewall();
        fw.All.Add(Foreign1);
        fw.All.Add(Foreign2);
        var snaps = new MemorySnapshots();
        var audit = new MemoryAudit();
        return (fw, new FirewallApplyService(fw, snaps, audit, () => Now), snaps, audit);
    }

    private static void AssertForeignUntouched(FakeFirewall fw)
    {
        var foreign = fw.All.Where(r => !OwnedRules.IsOwnedName(r.Name)).ToList();
        Assert.Equal([Foreign1, Foreign2], foreign); // record equality: byte-for-byte identical fields
    }

    [Fact]
    public void Apply_block_me_creates_only_exact_game_scoped_udp_outbound_blocks()
    {
        var (fw, svc, snaps, audit) = Setup();
        var plan = Plan(ProfileId.BlockMiddleEast);
        var r = svc.Apply(plan);
        Assert.Equal(ApplyStatus.Succeeded, r.Status);
        var owned = fw.ReadOwnedRules();
        Assert.Equal(plan.Rules.Count, owned.Count);
        Assert.Equal(2, owned.Count); // one IPv4 rule, one IPv6 rule
        foreach (var rule in owned)
        {
            Assert.Equal(GamePath, rule.ApplicationName);
            Assert.Equal(17, rule.Protocol);
            Assert.Equal(2, rule.Direction);
            Assert.Equal(0, rule.Action);
            Assert.True(rule.Enabled);
            Assert.DoesNotContain("*", rule.RemoteAddresses);
            Assert.Equal(OwnedRules.AllProfiles, rule.Profiles);
        }
        var blocked = IpSet.UnionAll(owned.Select(o => AddressListParser.Parse(o.RemoteAddresses).Set));
        Assert.Equal(plan.BlockSet, blocked);
        Assert.False(blocked.Overlaps(IpSet.From([CidrBlock.Parse("192.0.2.64/26")])));
        AssertForeignUntouched(fw);
        Assert.Single(snaps.Saved);
        Assert.Contains(audit.Events, e => e.Operation == "apply" && e.Result == "Succeeded");
    }

    [Fact]
    public void Apply_twice_is_idempotent()
    {
        var (fw, svc, _, _) = Setup();
        var plan = Plan(ProfileId.BlockMiddleEast);
        svc.Apply(plan);
        int adds = fw.Adds;
        var again = svc.Apply(plan);
        Assert.Equal(ApplyStatus.NoChangesNeeded, again.Status);
        Assert.Equal(adds, fw.Adds);
        Assert.Equal(plan.Rules.Count, fw.ReadOwnedRules().Count);
        Assert.Equal(fw.ReadOwnedRules().Count, fw.ReadOwnedRules().Select(r => r.Name).Distinct().Count());
    }

    [Fact]
    public void Switching_profiles_replaces_only_obsolete_own_rules()
    {
        var (fw, svc, _, _) = Setup();
        svc.Apply(Plan(ProfileId.BlockMiddleEast));
        var eu = Plan(ProfileId.PreferEurope);
        var r = svc.Apply(eu);
        Assert.Equal(ApplyStatus.Succeeded, r.Status);
        Assert.Equal(eu.Rules.Select(x => x.Name).Order(), fw.ReadOwnedRules().Select(x => x.Name).Order());
        Assert.All(fw.ReadOwnedRules(), x => Assert.StartsWith("OW2RG-EU-", x.Name));
        AssertForeignUntouched(fw);
        var state = OwnedStateInspector.Inspect(fw.ReadOwnedRules(), eu, GamePath);
        Assert.Equal(GuardState.Active, state.State);
        Assert.Equal(ProfileId.PreferEurope, state.Profile);
        Assert.True(state.MatchesCurrentPlan);
    }

    [Fact]
    public void Moving_the_game_replaces_stale_rules_for_the_old_path()
    {
        var (fw, svc, _, _) = Setup();
        svc.Apply(Plan(ProfileId.BlockMiddleEast));
        const string moved = @"E:\Games\Overwatch\_retail_\Overwatch.exe";
        Assert.False(OwnedStateInspector.Inspect(fw.ReadOwnedRules(), null, moved).TargetsCurrentGamePath);
        svc.Apply(Plan(ProfileId.BlockMiddleEast, moved));
        Assert.All(fw.ReadOwnedRules(), x => Assert.Equal(moved, x.ApplicationName));
    }

    [Fact]
    public void Restore_removes_only_own_rules_and_works_without_catalog_or_game()
    {
        var (fw, svc, _, _) = Setup();
        svc.Apply(Plan(ProfileId.BlockMiddleEast));
        fw.All.Add(FirewallRuleRecord.FromSpec(FirewallRuleSpec.CreateSelfTest("OW2RG-SELFTEST-1", @"C:\Tools\ow2rg-cli.exe", [CidrBlock.Parse("192.0.2.1/32")])));
        var r = svc.Restore();
        Assert.Equal(ApplyStatus.Succeeded, r.Status);
        Assert.Empty(fw.ReadOwnedRules());
        AssertForeignUntouched(fw);
        Assert.Equal(ApplyStatus.NoChangesNeeded, svc.Restore().Status);
    }

    [Theory]
    [InlineData("add", 1)]
    [InlineData("add", 2)]
    [InlineData("enable", 1)]
    [InlineData("enable", 2)]
    [InlineData("remove", 1)]
    [InlineData("remove", 2)]
    public void Failure_at_any_step_rolls_back_to_the_previous_state(string op, int n)
    {
        var (fw, svc, _, _) = Setup();
        svc.Apply(Plan(ProfileId.BlockMiddleEast));
        var before = fw.ReadOwnedRules().ToList();
        fw.Adds = fw.Enables = fw.Removes = 0;
        if (op == "add") fw.FailOnAdd = n;
        if (op == "enable") fw.FailOnEnable = n;
        if (op == "remove") fw.FailOnRemove = n;

        var r = svc.Apply(Plan(ProfileId.PreferEurope, maxChars: 20)); // several rules → several steps to fail at
        Assert.Equal(ApplyStatus.FailedRolledBack, r.Status);
        Assert.Null(r.RecoveryHint);
        Assert.Equal(before.OrderBy(x => x.Name), fw.ReadOwnedRules().OrderBy(x => x.Name));
        AssertForeignUntouched(fw);
    }

    [Fact]
    public void Failed_rollback_is_reported_loudly_with_a_recovery_command()
    {
        var (fw, svc, _, _) = Setup();
        svc.Apply(Plan(ProfileId.BlockMiddleEast));
        fw.Adds = fw.Enables = fw.Removes = 0;
        fw.FailOnEnable = 1;
        fw.FailAllMutationsAfterFirstFailure = true;
        var r = svc.Apply(Plan(ProfileId.PreferEurope, maxChars: 20));
        Assert.Equal(ApplyStatus.FailedRollbackIncomplete, r.Status);
        Assert.Contains("remove-own-rules.ps1", r.RecoveryHint);
        Assert.False(r.IsSuccess);
        AssertForeignUntouched(fw);
    }

    [Fact]
    public void Apply_is_refused_when_rules_would_not_take_effect()
    {
        var (fw, svc, _, _) = Setup();
        fw.Environment = fw.Environment with { CurrentProfilesEnabled = false };
        var r = svc.Apply(Plan(ProfileId.BlockMiddleEast));
        Assert.Equal(ApplyStatus.Refused, r.Status);
        Assert.Contains("OFF", r.Summary);
        Assert.Empty(fw.ReadOwnedRules());

        fw.Environment = fw.Environment with { CurrentProfilesEnabled = true, LocalPolicyModifyState = 1 };
        Assert.Equal(ApplyStatus.Refused, svc.Apply(Plan(ProfileId.BlockMiddleEast)).Status);
        // Restore is always allowed, even when the firewall is off.
        fw.Environment = fw.Environment with { CurrentProfilesEnabled = false };
        Assert.True(svc.Restore().IsSuccess);
    }

    [Fact]
    public void Apply_is_refused_without_a_durable_snapshot()
    {
        var (fw, svc, snaps, _) = Setup();
        snaps.Fail = true;
        Assert.Equal(ApplyStatus.Refused, svc.Apply(Plan(ProfileId.BlockMiddleEast)).Status);
        Assert.Empty(fw.ReadOwnedRules());
    }

    [Fact]
    public void Non_enforceable_plan_is_refused_and_changes_nothing()
    {
        var (fw, svc, _, _) = Setup();
        svc.Apply(Plan(ProfileId.BlockMiddleEast));
        var before = fw.All.ToList();
        var empty = BlockPlanBuilder.Build(ProfileId.BlockMiddleEast, Validate(Catalog(Entry("me-x", Region.ME, Confidence.Unverified))), Game(), new PlanOptions());
        var r = svc.Apply(empty);
        Assert.Equal(ApplyStatus.Refused, r.Status);
        Assert.Equal(before, fw.All);
    }

    [Fact]
    public void Tampered_same_name_rule_is_replaced_not_duplicated()
    {
        var (fw, svc, _, _) = Setup();
        var plan = Plan(ProfileId.BlockMiddleEast);
        svc.Apply(plan);
        int i = fw.All.FindIndex(r => r.Name == plan.Rules[0].Name);
        fw.All[i] = fw.All[i] with { RemoteAddresses = "192.0.2.0/255.255.255.0,192.0.2.64/255.255.255.192" }; // someone widened it into EU space
        var r = svc.Apply(plan);
        Assert.Equal(ApplyStatus.Succeeded, r.Status);
        var rule = Assert.Single(fw.ReadOwnedRules(), x => x.Name == plan.Rules[0].Name);
        Assert.True(RuleComparer.Matches(plan.Rules[0], rule));
    }

    [Fact]
    public void Store_guard_refuses_foreign_names()
    {
        var guarded = new OwnedOnlyFirewallStore(new FakeFirewall());
        Assert.Throws<InvalidOperationException>(() => guarded.RemoveRules("Steam Web Helper"));
        Assert.Throws<InvalidOperationException>(() => guarded.SetEnabled("Core Networking - DNS (UDP-Out)", false));
    }

    [Fact]
    public void Rule_text_never_contains_the_pipe_character_windows_rejects_on_add()
    {
        // Windows Firewall stores each rule as one '|'-delimited registry string. A '|' in Name/Description/Grouping
        // passes property assignment (so dry validation) but makes INetFwRules.Add fail with E_INVALIDARG.
        // This happened in the field with the first release.
        var plan = Plan(ProfileId.PreferEurope, maxChars: 200);
        Assert.NotEmpty(plan.Rules);
        foreach (var r in plan.Rules)
        {
            Assert.DoesNotContain('|', r.Name);
            Assert.DoesNotContain('|', r.Description);
            Assert.DoesNotContain('|', r.Grouping);
            Assert.Contains("profile=prefer-eu", r.Description);
            Assert.Matches(@"plan=[0-9a-f]{12}", r.Description);
            Assert.Matches(@"part=\d+/\d+", r.Description);
        }
        var selfTest = FirewallRuleSpec.CreateSelfTest("OW2RG-SELFTEST-X", @"C:\Tools\ow2rg-cli.exe", [CidrBlock.Parse("192.0.2.1/32")], "1.2.3");
        Assert.DoesNotContain('|', selfTest.Description);
        Assert.StartsWith("Managed by OW2 EU Region Guard 1.2.3; profile=selftest;", selfTest.Description);

        Assert.Throws<ArgumentException>(() => FirewallRuleSpec.CreateGameBlock("OW2RG-ME-01-x", "a | b", Game(), FwProtocol.Udp, [CidrBlock.Parse("192.0.2.0/24")], true));
        Assert.Throws<ArgumentException>(() => FirewallRuleSpec.CreateGameBlock("OW2RG-ME-01-x", "line\nbreak", Game(), FwProtocol.Udp, [CidrBlock.Parse("192.0.2.0/24")], true));
        Assert.Contains("|", "cat|log"); // sanity: a catalog version containing '|' is neutralised, not propagated
        Assert.DoesNotContain('|', FirewallRuleSpec.Describe("1.0.0", "block-me", "abcdefabcdef", 1, 1, "cat|log", "corroborated"));
    }

    [Fact]
    public void Rule_specs_cannot_be_built_unsafely()
    {
        var game = Game();
        Assert.Throws<ArgumentException>(() => FirewallRuleSpec.CreateGameBlock("OW2RG-ME-01-x", "d", game, FwProtocol.Udp, [], true));
        Assert.Throws<ArgumentException>(() => FirewallRuleSpec.CreateGameBlock("OW2RG-ME-01-x", "d", game, FwProtocol.Udp, [CidrBlock.Parse("0.0.0.0/0")], true));
        Assert.Throws<ArgumentException>(() => FirewallRuleSpec.CreateGameBlock("Block stuff", "d", game, FwProtocol.Udp, [CidrBlock.Parse("192.0.2.0/24")], true));
        Assert.Throws<ArgumentException>(() => FirewallRuleSpec.CreateSelfTest("OW2RG-SELFTEST-1", @"C:\x\a.exe", [CidrBlock.Parse("8.8.8.8/32")]));
        Assert.Throws<ArgumentException>(() => FirewallRuleSpec.CreateSelfTest("OW2RG-ME-1", @"C:\x\a.exe", [CidrBlock.Parse("192.0.2.1/32")]));
    }

    [Fact]
    public void Inspector_reconstructs_state_from_the_firewall_after_a_crash()
    {
        var (fw, svc, _, _) = Setup();
        var plan = Plan(ProfileId.BlockMiddleEast);
        Assert.Equal(GuardState.NoOwnRules, OwnedStateInspector.Inspect(fw.ReadOwnedRules()).State);

        // Simulate a crash after staging: rules exist but are disabled.
        foreach (var spec in plan.Rules) fw.AddRule(spec.WithEnabled(false));
        var crashed = OwnedStateInspector.Inspect(fw.ReadOwnedRules(), plan, GamePath);
        Assert.Equal(GuardState.Partial, crashed.State);
        Assert.Contains(crashed.Problems, p => p.Contains("disabled"));

        // Re-applying repairs it.
        Assert.True(svc.Apply(plan).IsSuccess);
        var healed = OwnedStateInspector.Inspect(fw.ReadOwnedRules(), plan, GamePath);
        Assert.Equal(GuardState.Active, healed.State);
        Assert.Equal("Active: Block ME", healed.Label);

        // A missing part is detected.
        fw.RemoveRules(plan.Rules[0].Name);
        Assert.Equal(GuardState.Partial, OwnedStateInspector.Inspect(fw.ReadOwnedRules(), plan, GamePath).State);
    }

    [Fact]
    public void Rollback_recreation_refuses_rules_that_break_invariants()
    {
        var bad = new FirewallRuleRecord { Name = "OW2RG-ME-01-abc", ApplicationName = null, Protocol = 17, Direction = 2, Action = 0, Enabled = true, RemoteAddresses = "*" };
        Assert.False(FirewallRuleSpec.TryRecreate(bad, out _, out var reason));
        Assert.NotNull(reason);
        var inbound = bad with { Direction = 1, ApplicationName = GamePath, RemoteAddresses = "192.0.2.0/24" };
        Assert.False(FirewallRuleSpec.TryRecreate(inbound, out _, out _));
    }
}
