using System.Text;
using OW2RG.Core.Catalog;
using OW2RG.Core.Firewall;
using OW2RG.Core.Planning;
using OW2RG.Core.Verification;
using OW2RG.Infrastructure.Windows;

namespace OW2RG.Cli;

internal static class Program
{
    private const string Banner = "OW2 EU Region Guard — unofficial, not affiliated with or endorsed by Blizzard.";

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length > 0 && args[0] == "--helper") return HelperHost.Execute(args);

        var a = new Args(args);
        try
        {
            return a.Command switch
            {
                "" or "help" or "--help" or "-h" => Help(),
                "status" or "--status" => Status(a),
                "preview" or "--preview" => Preview(a),
                "apply" => Apply(a),
                "restore" or "--restore" => Restore(),
                "doctor" or "--doctor" => Doctor(a),
                "locate" => Locate(),
                "selftest" => SelfTestCmd(a),
                "catalog" => Catalog(a),
                "observe" => Observe(a),
                "export-diagnostics" or "--export-diagnostics" => Export(a),
                _ => Fail($"Unknown command '{a.Command}'. Run 'ow2rg-cli help'."),
            };
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    private static int Help()
    {
        Console.WriteLine(Banner);
        Console.WriteLine("""

            Usage: ow2rg-cli <command> [options]

              status                         Real firewall state, game path, catalog
              preview --profile <p>          Dry run: exactly which rules would be written
              apply   --profile <p> [--yes]  Write rules (asks for administrator via UAC)
              restore                        Remove ALL and ONLY OW2RG-* rules (asks for administrator)
              doctor                         Full environment check incl. Windows dry-validation of the rules
              locate                         List Overwatch.exe candidates (Steam, Battle.net, registry, running)
              selftest [--live]              Offline COM check; --live creates+tests+removes a harmless rule
              catalog show|validate [--catalog <file>]
              catalog build --out <file> [--map <file>] [--aws <file>] [--gcp <file>]
                                             Build a catalog from the official AWS/Google feeds (downloads if no files given)
              observe add --code <DC> [--ip <x>] [--ping <ms>] [--mode custom|quickplay|...] [--party]
              observe list                   Your manual NetGraph observations
              export-diagnostics [--include-personal]

            Profiles: block-me (recommended), prefer-eu (stronger, higher risk), default (= restore)
            Options:  --game <path to _retail_\Overwatch.exe>   --allow-community (high risk)

            Blocking servers can disconnect you and may cause leaver penalties. It can only INFLUENCE
            matchmaking, never guarantee Europe. Test in a Custom Game first, never in Competitive.
            """);
        return 0;
    }

    // ---------------------------------------------------------------- status / preview

    private static int Status(Args a)
    {
        var engine = GuardEngine.Create();
        var catalog = CatalogProvider.LoadActive();
        string? game = ResolveGame(a, quiet: true);
        var env = engine.Store.ReadEnvironment();
        var state = engine.ReadState(null, game);

        Console.WriteLine(Banner);
        Console.WriteLine();
        Console.WriteLine($"State:      {state.Label}");
        if (state.State == GuardState.Active)
            Console.WriteLine($"            {state.RuleCount} rule(s), {state.BlockedNetworkCount} blocked network(s), plan {state.PlanHash12}");
        foreach (var p in state.Problems) Console.WriteLine($"  ! {p}");
        Console.WriteLine($"Firewall:   {(env.ApiAvailable ? (env.CurrentProfilesEnabled ? "Enabled" : "OFF for active profile") : "API unavailable")} (active profile: {FirewallEnvironment.ProfileNames(env.CurrentProfileTypes)})");
        foreach (var p in env.Problems) Console.WriteLine($"  ! {p}");
        Console.WriteLine($"Admin:      {(env.IsElevated ? "yes (this terminal is elevated)" : "no — changes will ask via UAC")}");
        Console.WriteLine($"Game:       {game ?? "(not found — use --game or 'locate')"}");
        if (GameLocator.IsGameRunning()) Console.WriteLine("            Overwatch is running. Apply changes from the main menu or after closing the game.");
        PrintCatalogLine(catalog);
        var obs = ObservationAnalyzer.Summarize(ObservationStore.Load());
        Console.WriteLine($"In-game:    {obs.Describe()}");
        return 0;
    }

    private static int Preview(Args a)
    {
        var profile = RequireProfile(a);
        var engine = GuardEngine.Create();
        var catalog = CatalogProvider.LoadActive();
        string? game = ResolveGame(a, quiet: false);
        bool community = a.Has("--allow-community");
        var plan = engine.BuildPlan(profile, game, community, catalog);
        PrintPlan(plan, catalog);

        if (plan.IsEnforceable && plan.Rules.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Windows dry-validation (rule objects built and read back, NOT saved):");
            foreach (var d in engine.DryValidate(plan))
                Console.WriteLine($"  [{(d.Accepted ? "OK" : "REJECTED")}] {d.RuleName} ({d.Characters} chars){(d.Accepted ? "" : " — " + d.Error)}");
            var state = engine.ReadState(plan, game);
            Console.WriteLine();
            Console.WriteLine($"Current firewall state: {state.Label}{(state.MatchesCurrentPlan == true ? " (already matches this plan)" : "")}");
        }
        return plan.IsEnforceable ? 0 : 3;
    }

    private static void PrintPlan(BlockPlan plan, LoadedCatalog catalog)
    {
        Console.WriteLine($"Profile:    {Profiles.DisplayName(plan.Profile)}");
        PrintCatalogLine(catalog);
        Console.WriteLine($"Game:       {plan.Game?.FullPath ?? "(none)"}");
        Console.WriteLine();
        Console.WriteLine("Datacenters:");
        foreach (var d in plan.Decisions.OrderBy(d => d.Role).ThenBy(d => d.Entry.Region))
        {
            string mark = d.Eligible ? "BLOCK " : d.Role == EntryRole.Protected ? "KEEP  " : "skip  ";
            Console.WriteLine($"  {mark} {d.Entry.Region,-3} {d.Entry.DisplayName,-58} {d.Reason}");
        }
        Console.WriteLine();
        if (!plan.IsEnforceable)
        {
            Console.WriteLine($"NOT ENFORCEABLE: {plan.NotEnforceableReason}");
            return;
        }
        if (plan.Profile == ProfileId.Default)
        {
            Console.WriteLine("Default profile: applying it removes every OW2RG rule and nothing else.");
            return;
        }
        Console.WriteLine($"Summary:    {plan.TargetDatacenterCount} datacenter(s), {plan.BlockedCidrCount} network block(s), {plan.Rules.Count} firewall rule(s), {plan.BlockedIpv4Addresses:N0} IPv4 addresses");
        Console.WriteLine($"            {plan.RemovedByEuProtection.ToCidrs().Count} block(s) carved out to protect Europe, {plan.RemovedAsContested.ToCidrs().Count} contested block(s) left open");
        Console.WriteLine($"Tiers used: {string.Join(", ", plan.ConfidenceTiersUsed)}   Plan: {plan.ShortHash}");
        foreach (var w in plan.Warnings) Console.WriteLine($"  ! {w}");
        Console.WriteLine();
        Console.WriteLine("Rules (outbound, block, UDP, program-scoped):");
        foreach (var r in plan.Rules)
            Console.WriteLine($"  {r.Name}  {r.RemoteAddresses.Count} network(s): {Shorten(r.RemoteAddressesText, 110)}");
    }

    // ---------------------------------------------------------------- apply / restore

    private static int Apply(Args a)
    {
        var profile = RequireProfile(a);
        if (profile == ProfileId.Default) return Restore();
        var engine = GuardEngine.Create();
        var catalog = CatalogProvider.LoadActive();
        string? game = ResolveGame(a, quiet: false);
        if (game is null) return Fail("No valid Overwatch.exe found. Use --game \"<path>\\_retail_\\Overwatch.exe\".");
        bool community = a.Has("--allow-community");
        var plan = engine.BuildPlan(profile, game, community, catalog);
        PrintPlan(plan, catalog);
        if (!plan.IsEnforceable) return 3;

        Console.WriteLine();
        Console.WriteLine("WARNING: this may disconnect you and can result in leaver penalties. Do not test in Competitive.");
        Console.WriteLine("It can only influence matchmaking; it never guarantees European servers. Not endorsed by Blizzard.");
        if (GameLocator.IsGameRunning()) Console.WriteLine("Overwatch is running: do not apply during a match. Restart the game afterwards.");
        if (!a.Has("--yes"))
        {
            Console.Write("Type APPLY to continue: ");
            if (!string.Equals(Console.ReadLine()?.Trim(), "APPLY", StringComparison.Ordinal)) return Fail("Cancelled. Nothing was changed.");
        }
        var result = engine.Apply(SelfExe(), plan, catalog, game, community);
        PrintResult(result);
        return result.ExitCode;
    }

    private static int Restore()
    {
        var engine = GuardEngine.Create();
        Console.WriteLine("Removing all OW2RG-* firewall rules (and nothing else)...");
        var result = engine.Restore(SelfExe());
        PrintResult(result);
        return result.ExitCode;
    }

    private static void PrintResult(HelperResult r)
    {
        Console.WriteLine();
        Console.WriteLine($"Result: {r.Status} — {r.Summary}");
        if (r.Outcome is { } o)
        {
            foreach (var s in o.Steps) Console.WriteLine($"  · {s}");
            foreach (var e in o.Errors) Console.WriteLine($"  ! {e}");
            if (o.RecoveryHint is not null) Console.WriteLine($"RECOVERY: {o.RecoveryHint}");
        }
        if (r.SelfTest is { } st) foreach (var l in st.Lines()) Console.WriteLine("  " + l);
    }

    // ---------------------------------------------------------------- doctor / selftest / locate

    private static int Doctor(Args a)
    {
        Console.WriteLine(Banner);
        Console.WriteLine($"Version {GuardEngine.AppVersion}, {Environment.OSVersion.VersionString}, .NET {Environment.Version}, elevated={Elevation.IsElevated()}");
        Console.WriteLine();
        var engine = GuardEngine.Create();
        var offline = SelfTest.RunOffline(engine.Store);
        Console.WriteLine("Firewall:");
        foreach (var l in offline.Lines()) Console.WriteLine("  " + l);

        Console.WriteLine();
        Console.WriteLine("Catalog:");
        var catalog = CatalogProvider.LoadActive();
        PrintCatalogLine(catalog);
        foreach (var n in catalog.Notes) Console.WriteLine($"  ! {n}");
        foreach (var i in catalog.Catalog.Issues.Where(i => i.Severity != IssueSeverity.Info).Take(30)) Console.WriteLine($"  {i}");

        Console.WriteLine();
        Console.WriteLine("Game executable candidates:");
        foreach (var c in GameLocator.FindCandidates())
            Console.WriteLine($"  [{(c.Check.IsValid ? "OK" : "--")}] {c.Source}: {c.Path}{(c.Note is null ? "" : "  — " + c.Note)}{(c.Check.IsValid ? "" : "  (" + string.Join("; ", c.Check.Errors) + ")")}");
        string? game = ResolveGame(a, quiet: true);

        Console.WriteLine();
        Console.WriteLine("Plans (dry-validated by Windows, nothing saved):");
        string planGame = game ?? @"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe";
        foreach (var p in new[] { ProfileId.BlockMiddleEast, ProfileId.PreferEurope })
        {
            var plan = BlockPlanBuilder.Build(p, catalog.Catalog, GamePathValidator_Syntactic(planGame), new PlanOptions { AppVersion = GuardEngine.AppVersion });
            if (!plan.IsEnforceable) { Console.WriteLine($"  {Profiles.Code(p)}: not enforceable — {plan.NotEnforceableReason}"); continue; }
            var dry = engine.DryValidate(plan);
            Console.WriteLine($"  {Profiles.Code(p)}: {plan.BlockedCidrCount} blocks in {plan.Rules.Count} rule(s); Windows accepted {dry.Count(d => d.Accepted)}/{dry.Count}{(game is null ? " (placeholder game path)" : "")}");
            foreach (var d in dry.Where(d => !d.Accepted)) Console.WriteLine($"     REJECTED {d.RuleName}: {d.Error}");
        }

        if (a.Has("--probe-limits"))
        {
            Console.WriteLine();
            var (count, chars, err) = engine.Store.ProbeRemoteAddressLimit();
            Console.WriteLine($"RemoteAddresses limit on an unsaved rule object: {count} CIDRs / {chars} chars accepted{(err is null ? "" : $"; first rejection: {err}")}");
        }
        Console.WriteLine();
        Console.WriteLine("Live game verification: NOT performed by this tool. Use NetGraph (Ctrl+Shift+N) in a Custom Game.");
        return offline.Passed ? 0 : 1;
    }

    private static Core.Game.ValidatedGamePath? GamePathValidator_Syntactic(string path) =>
        Core.Game.GamePathValidator.Validate(path, new AssumeExists()).Path;

    private sealed class AssumeExists : Core.Game.IFileProbe
    {
        public bool FileExists(string path) => true;
        public long? FileLength(string path) => null;
    }

    private static int SelfTestCmd(Args a)
    {
        var engine = GuardEngine.Create();
        if (!a.Has("--live"))
        {
            var r = SelfTest.RunOffline(engine.Store);
            foreach (var l in r.Lines()) Console.WriteLine(l);
            Console.WriteLine(r.Passed ? "Offline self-test passed (no system changes were made)." : "Offline self-test FAILED.");
            return r.Passed ? 0 : 1;
        }
        Console.WriteLine("Live self-test: asks your DNS server one normal question over UDP from THIS program, adds a temporary rule");
        Console.WriteLine("blocking UDP from this program only, checks the answer is now blocked, removes the rule and checks it");
        Console.WriteLine("works again. Overwatch and every other program are never affected.");
        var result = engine.LiveSelfTest(SelfExe());
        PrintResult(result);
        return result.ExitCode;
    }

    private static int Locate()
    {
        var list = GameLocator.FindCandidates();
        if (list.Count == 0) Console.WriteLine("No Overwatch installation found. Pass --game with the full path to _retail_\\Overwatch.exe.");
        foreach (var c in list)
        {
            Console.WriteLine($"[{(c.Check.IsValid ? "VALID" : "-----")}] {c.Path}");
            Console.WriteLine($"         source: {c.Source}{(c.Note is null ? "" : "; " + c.Note)}");
            foreach (var e in c.Check.Errors) Console.WriteLine($"         ✗ {e}");
            foreach (var w in c.Check.Warnings) Console.WriteLine($"         ! {w}");
        }
        return 0;
    }

    // ---------------------------------------------------------------- catalog

    private static int Catalog(Args a)
    {
        string sub = a.Positional(1) ?? "show";
        switch (sub)
        {
            case "show":
            case "validate":
            {
                var cat = a.Value("--catalog") is { } file ? CatalogProvider.LoadByToken(Path.GetFullPath(file)) : CatalogProvider.LoadActive();
                PrintCatalogLine(cat);
                foreach (var n in cat.Notes) Console.WriteLine($"  ! {n}");
                if (sub == "show")
                {
                    foreach (var e in cat.Catalog.Entries)
                        Console.WriteLine($"  {e.Region,-3} {e.DisplayName,-60} {e.Confidence,-12} {e.Cidrs.Count,4} range(s)  {(e.Document.ProtectOnly ? "protect-only" : e.Document.ExcludeFromBlocking ? "never-blocked" : "")}");
                }
                foreach (var i in cat.Catalog.Issues) Console.WriteLine($"  {i}");
                foreach (var c in cat.Catalog.Conflicts)
                    Console.WriteLine($"  conflict: {c.EntryA} ({c.RegionA}) <-> {c.EntryB} ({c.RegionB}): {c.Overlap.ToCidrs().Count} shared block(s), never blocked unless both regions are targeted");
                Console.WriteLine(cat.Catalog.IsUsable ? "Catalog is valid." : "Catalog is INVALID and will not be used for enforcement.");
                return cat.Catalog.IsUsable ? 0 : 1;
            }
            case "build":
            {
                string outPath = Path.GetFullPath(a.Value("--out") ?? throw new ArgumentException("--out <file> is required."));
                var map = a.Value("--map") is { } mp ? CatalogBuilder.ParseMap(File.ReadAllBytes(mp)) : CatalogProvider.LoadEmbeddedMap();
                IReadOnlyList<ProviderFeed> feeds;
                if (a.Value("--aws") is { } awsFile && a.Value("--gcp") is { } gcpFile)
                {
                    feeds = [CloudFeeds.ParseAws(File.ReadAllBytes(awsFile), out int s1), CloudFeeds.ParseGoogleCloud(File.ReadAllBytes(gcpFile), out int s2)];
                    Console.WriteLine($"Read local feeds ({s1 + s2} malformed prefixes skipped).");
                }
                else
                {
                    Console.WriteLine("Downloading official feeds over HTTPS:");
                    Console.WriteLine($"  {CloudFeeds.AwsUrl}");
                    Console.WriteLine($"  {CloudFeeds.GoogleCloudUrl}");
                    feeds = FeedDownloader.DownloadBothAsync(CancellationToken.None).GetAwaiter().GetResult();
                }
                foreach (var f in feeds) Console.WriteLine($"  {f.Id}: {f.Prefixes.Count} prefixes, published {f.PublisherTimestamp}, sha256 {f.Sha256}");
                var build = CatalogBuilder.Build(map, feeds, DateTimeOffset.UtcNow, $"ow2rg-cli {GuardEngine.AppVersion} catalog build");
                foreach (var l in build.Report) Console.WriteLine("  " + l);
                string json = CatalogJson.Serialize(build.Catalog);
                var (doc, sha) = CatalogJson.Parse(Encoding.UTF8.GetBytes(json));
                var v = CatalogValidator.Validate(doc, sha, CatalogProvider.Options());
                foreach (var i in v.Issues.Where(i => i.Severity == IssueSeverity.Error)) Console.WriteLine($"  {i}");
                if (!v.IsUsable) return Fail("Built catalog failed validation; not written.");
                Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
                File.WriteAllText(outPath, json);
                Console.WriteLine($"Wrote {outPath} ({json.Length:N0} bytes, sha256 {sha}). Review it before shipping; installed rules are not changed.");
                return 0;
            }
            default:
                return Fail("Usage: catalog show|validate|build");
        }
    }

    // ---------------------------------------------------------------- observations / export

    private static int Observe(Args a)
    {
        string sub = a.Positional(1) ?? "list";
        var list = ObservationStore.Load();
        if (sub == "list")
        {
            foreach (var o in list.TakeLast(50))
                Console.WriteLine($"{o.AtUtc:yyyy-MM-dd HH:mm}  {o.DatacenterCode,-6} {o.InferredRegion?.ToString() ?? "?",-7} {o.Mode,-11} {(o.InParty ? "party" : "solo "),-5} ping {o.PingMs?.ToString() ?? "-"}  profile {o.ActiveProfile ?? "-"}");
            Console.WriteLine(ObservationAnalyzer.Summarize(list).Describe());
            return 0;
        }
        if (sub != "add") return Fail("Usage: observe add|list");
        if (!ObservationAnalyzer.TryNormalizeCode(a.Value("--code"), out var code)) return Fail("--code must look like AMS1, GEN1, MES1, GMEC2 …");
        string? ip = a.Value("--ip");
        if (ip is not null && !Core.Net.IpCodec.TryParseStrict(ip, out _, out _)) return Fail("--ip is not a valid IP address.");
        int? ping = a.Value("--ping") is { } ps && int.TryParse(ps, out var pv) && pv is >= 0 and < 2000 ? pv : null;
        string mode = a.Value("--mode") ?? "custom";
        if (!ObservationAnalyzer.Modes.Contains(mode)) return Fail("--mode must be one of " + string.Join(", ", ObservationAnalyzer.Modes));
        var catalog = CatalogProvider.LoadActive();
        var engine = GuardEngine.Create();
        var state = engine.ReadState(null, null);
        var (region, entry) = ObservationAnalyzer.Infer(code, ip, catalog.Catalog);
        list.Add(new MatchObservation
        {
            AtUtc = DateTimeOffset.UtcNow, DatacenterCode = code, RemoteIp = ip, PingMs = ping, Mode = mode, InParty = a.Has("--party"),
            Notes = a.Value("--notes"), ActiveProfile = state.Profile is { } p ? Profiles.Code(p) : "none", ActivePlanHash12 = state.PlanHash12,
            InferredRegion = region, MatchedEntryId = entry,
        });
        ObservationStore.Save(list);
        Console.WriteLine($"Recorded {code} ({region?.ToString() ?? "region unknown"}) as a manual NetGraph observation.");
        Console.WriteLine(ObservationAnalyzer.Summarize(list).Describe());
        return 0;
    }

    private static int Export(Args a)
    {
        var engine = GuardEngine.Create();
        string path = engine.ExportDiagnostics(CatalogProvider.LoadActive(), ResolveGame(a, quiet: true), a.Has("--include-personal"));
        Console.WriteLine($"Diagnostics written to {path}{(a.Has("--include-personal") ? "" : " (paths and IPs redacted)")}.");
        return 0;
    }

    // ---------------------------------------------------------------- helpers

    private static void PrintCatalogLine(LoadedCatalog c)
    {
        var d = c.Catalog.Document;
        int age = (int)(DateTimeOffset.UtcNow - d.GeneratedAtUtc).TotalDays;
        var tiers = c.Catalog.Entries.Where(e => e.HasAddresses).GroupBy(e => e.Confidence).OrderByDescending(g => g.Key).Select(g => $"{g.Count()} {g.Key.ToString().ToLowerInvariant()}");
        Console.WriteLine($"Catalog:    {d.CatalogVersion} ({d.GeneratedAtUtc:yyyy-MM-dd}, {age} day(s) old) from {c.Origin}; {string.Join(", ", tiers)}; {(c.Catalog.IsUsable ? "valid" : "INVALID")}");
    }

    private static string? ResolveGame(Args a, bool quiet)
    {
        if (a.Value("--game") is { } explicitPath)
        {
            var check = GuardEngine.CheckGame(explicitPath);
            if (!check.IsValid)
            {
                Console.WriteLine($"--game rejected: {string.Join("; ", check.Errors)}");
                return null;
            }
            foreach (var w in check.Warnings) Console.WriteLine($"  ! {w}");
            return check.Path!.FullPath;
        }
        var settings = UserSettings.Load();
        if (settings.GamePath is { } saved && GuardEngine.CheckGame(saved).IsValid) return GuardEngine.CheckGame(saved).Path!.FullPath;
        var best = GameLocator.FindCandidates().FirstOrDefault(c => c.Check.IsValid);
        if (best is null && !quiet) Console.WriteLine("No valid Overwatch.exe found automatically. Run 'ow2rg-cli locate' or pass --game.");
        return best?.Check.Path!.FullPath;
    }

    private static ProfileId RequireProfile(Args a)
    {
        if (!Profiles.TryParse(a.Value("--profile"), out var p)) throw new ArgumentException("--profile must be block-me, prefer-eu or default.");
        return p;
    }

    private static string SelfExe() => Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate own executable.");

    private static string Shorten(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    private static int Fail(string message)
    {
        Console.Error.WriteLine("Error: " + message);
        return 1;
    }

    private sealed class Args(string[] raw)
    {
        public string Command => raw.Length > 0 ? raw[0] : "";
        public string? Positional(int index) => raw.Length > index && !raw[index].StartsWith("--", StringComparison.Ordinal) ? raw[index] : null;
        public bool Has(string flag) => raw.Contains(flag, StringComparer.Ordinal);
        public string? Value(string flag)
        {
            int i = Array.IndexOf(raw, flag);
            return i >= 0 && i + 1 < raw.Length ? raw[i + 1] : null;
        }
    }
}
