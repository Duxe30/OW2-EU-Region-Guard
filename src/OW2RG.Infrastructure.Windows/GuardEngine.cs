using System.Reflection;
using System.Text;
using System.Text.Json;
using OW2RG.Core.Catalog;
using OW2RG.Core.Firewall;
using OW2RG.Core.Game;
using OW2RG.Core.Planning;
using OW2RG.Core.Verification;
using OW2RG.Infrastructure.Windows.Firewall;

namespace OW2RG.Infrastructure.Windows;

/// <summary>Composition root shared by the GUI, the CLI and the elevated helper.</summary>
public sealed class GuardEngine
{
    public static string AppVersion { get; } =
        typeof(GuardEngine).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "1.0.0";

    private GuardEngine(ComFirewallStore store)
    {
        Store = store;
        Service = new FirewallApplyService(store, new JsonSnapshotStore(AppPaths.Snapshots), new JsonlAuditLog(AppPaths.AuditLog), () => DateTimeOffset.UtcNow);
    }

    public ComFirewallStore Store { get; }
    public FirewallApplyService Service { get; }

    public static GuardEngine Create() => new(new ComFirewallStore());
    internal static GuardEngine CreateForHelper() => new(new ComFirewallStore());

    public static GamePathCheck CheckGame(string? path) => GamePathValidator.Validate(path, RealFileProbe.Instance);

    public BlockPlan BuildPlan(ProfileId profile, string? gamePath, bool allowCommunity, LoadedCatalog catalog)
    {
        ValidatedGamePath? game = null;
        if (profile != ProfileId.Default)
        {
            var check = CheckGame(gamePath);
            game = check.Path;
        }
        return BlockPlanBuilder.Build(profile, catalog.Catalog, game, new PlanOptions { AllowCommunityData = allowCommunity, AppVersion = AppVersion });
    }

    public OwnedState ReadState(BlockPlan? currentPlan, string? gamePath)
    {
        var rules = Store.ReadOwnedRules();
        return OwnedStateInspector.Inspect(rules, currentPlan, gamePath);
    }

    public IReadOnlyList<DryValidation> DryValidate(BlockPlan plan) => plan.Rules.Select(Store.DryValidate).ToList();

    /// <summary>
    /// Apply. If this process is already elevated the change happens in-process; otherwise an elevated copy of
    /// <paramref name="exe"/> is started through the normal UAC prompt.
    /// </summary>
    public HelperResult Apply(string exe, BlockPlan plan, LoadedCatalog catalog, string gamePath, bool allowCommunity)
    {
        if (Elevation.IsElevated())
        {
            var o = Service.Apply(plan);
            return new HelperResult { Status = o.Status.ToString(), Summary = o.Summary, Outcome = o, ExitCode = o.IsSuccess ? 0 : 2 };
        }
        var req = new HelperRequest
        {
            Operation = "apply", ResultId = Guid.NewGuid(), Profile = plan.Profile, GamePath = gamePath,
            CatalogToken = catalog.HelperToken, AllowCommunity = allowCommunity, ExpectedPlanHash = plan.PlanHash,
        };
        return HelperClient.Run(exe, req, TimeSpan.FromMinutes(3));
    }

    public HelperResult Restore(string exe)
    {
        if (Elevation.IsElevated())
        {
            var o = Service.Restore();
            return new HelperResult { Status = o.Status.ToString(), Summary = o.Summary, Outcome = o, ExitCode = o.IsSuccess ? 0 : 4 };
        }
        return HelperClient.Run(exe, new HelperRequest { Operation = "restore", ResultId = Guid.NewGuid() }, TimeSpan.FromMinutes(3));
    }

    public HelperResult LiveSelfTest(string exe)
    {
        if (Elevation.IsElevated())
        {
            var r = SelfTest.RunLive(Store);
            return new HelperResult { Status = r.Passed ? "Passed" : "Failed", Summary = r.Passed ? "Live self-test passed." : "Live self-test failed.", SelfTest = r, ExitCode = r.Passed ? 0 : 2 };
        }
        return HelperClient.Run(exe, new HelperRequest { Operation = "selftest", ResultId = Guid.NewGuid() }, TimeSpan.FromMinutes(2));
    }

    /// <summary>Downloads official feeds and builds a candidate catalog. Nothing is saved or applied here.</summary>
    public static async Task<(CatalogBuildResult Build, ValidatedCatalog Validated)> BuildCatalogFromFeedsAsync(CancellationToken ct)
    {
        var feeds = await FeedDownloader.DownloadBothAsync(ct).ConfigureAwait(false);
        var map = CatalogProvider.LoadEmbeddedMap();
        var build = CatalogBuilder.Build(map, feeds, DateTimeOffset.UtcNow, $"OW2 EU Region Guard {AppVersion} (in-app refresh)");
        var bytes = Encoding.UTF8.GetBytes(CatalogJson.Serialize(build.Catalog));
        var (doc, sha) = CatalogJson.Parse(bytes);
        return (build, CatalogValidator.Validate(doc, sha, CatalogProvider.Options()));
    }

    /// <summary>Human-readable comparison of two catalogs, per entry.</summary>
    public static IReadOnlyList<string> DiffCatalogs(ValidatedCatalog current, ValidatedCatalog proposed)
    {
        var lines = new List<string>();
        var cur = current.Entries.ToDictionary(e => e.Id);
        foreach (var p in proposed.Entries)
        {
            if (!cur.TryGetValue(p.Id, out var c)) { lines.Add($"+ {p.DisplayName}: new entry, {p.Cidrs.Count} range(s)"); continue; }
            var added = p.Addresses.Subtract(c.Addresses).ToCidrs().Count;
            var removed = c.Addresses.Subtract(p.Addresses).ToCidrs().Count;
            if (added > 0 || removed > 0 || c.Confidence != p.Confidence)
                lines.Add($"~ {p.DisplayName}: +{added} / -{removed} block(s), confidence {c.Confidence} → {p.Confidence}");
        }
        foreach (var c in current.Entries.Where(c => proposed.Entries.All(p => p.Id != c.Id)))
            lines.Add($"- {c.DisplayName}: removed");
        if (lines.Count == 0) lines.Add("No address changes.");
        return lines;
    }

    /// <summary>Writes a diagnostics bundle. Paths and IPs are redacted unless the user opts in.</summary>
    public string ExportDiagnostics(LoadedCatalog catalog, string? gamePath, bool includePersonal)
    {
        string Redact(string? s)
        {
            if (string.IsNullOrEmpty(s) || includePersonal) return s ?? "";
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return s.Replace(profile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase).Replace(Environment.UserName, "<user>", StringComparison.OrdinalIgnoreCase);
        }
        var env = Store.ReadEnvironment();
        var state = ReadState(null, gamePath);
        var obs = ObservationStore.Load();
        var bundle = new
        {
            app = "OW2 EU Region Guard",
            version = AppVersion,
            createdAtUtc = DateTimeOffset.UtcNow,
            os = Environment.OSVersion.VersionString,
            redacted = !includePersonal,
            firewall = new
            {
                env.ApiAvailable, env.ApiError, activeProfiles = FirewallEnvironment.ProfileNames(env.CurrentProfileTypes),
                env.EnabledByProfile, env.LocalPolicyModifyState, env.IsElevated, problems = env.Problems,
            },
            ownedState = new
            {
                state = state.State.ToString(), label = state.Label, profile = state.Profile?.ToString(), state.PlanHash12, state.RuleCount, state.BlockedNetworkCount,
                programs = state.TargetPrograms.Select(Redact), state.Problems,
                rules = state.Rules.Select(r => new { r.Name, r.Enabled, r.Protocol, r.Direction, r.Action, program = Redact(r.ApplicationName), remoteChars = r.RemoteAddresses?.Length ?? 0 }),
            },
            catalog = new
            {
                catalog.Catalog.Document.CatalogVersion, catalog.Catalog.Sha256, origin = catalog.Origin.ToString(), location = Redact(catalog.Location),
                issues = catalog.Catalog.Issues.Select(i => i.ToString()),
            },
            game = Redact(gamePath),
            observations = obs.Select(o => new { o.AtUtc, o.DatacenterCode, ip = includePersonal ? o.RemoteIp : ObservationAnalyzer.MaskIp(o.RemoteIp), o.PingMs, o.Mode, o.InParty, region = o.InferredRegion?.ToString(), o.ActiveProfile }),
            auditTail = JsonlAuditLog.Tail(AppPaths.AuditLog, 50).Select(Redact),
        };
        AppPaths.Ensure(AppPaths.Exports);
        string path = Path.Combine(AppPaths.Exports, $"ow2rg-diagnostics-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(bundle, LocalJson.Options));
        return path;
    }
}
