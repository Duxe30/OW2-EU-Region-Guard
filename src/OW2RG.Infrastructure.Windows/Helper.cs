using System.Text.Json;
using System.Text.RegularExpressions;
using OW2RG.Core.Firewall;
using OW2RG.Core.Planning;

namespace OW2RG.Infrastructure.Windows;

/// <summary>
/// The narrowly scoped elevated operation. The non-elevated UI never sends rules to the elevated side:
/// it sends (profile, game path, catalog, opt-in, expected plan hash). The elevated side re-validates
/// everything, rebuilds the plan itself and refuses unless the hash matches what the user previewed.
/// </summary>
public sealed partial record HelperRequest
{
    public required string Operation { get; init; } // apply | restore | selftest
    public required Guid ResultId { get; init; }
    public ProfileId Profile { get; init; } = ProfileId.Default;
    public string? GamePath { get; init; }
    public string? CatalogToken { get; init; }
    public bool AllowCommunity { get; init; }
    public string? ExpectedPlanHash { get; init; }

    [GeneratedRegex("^[0-9a-f]{64}$")] private static partial Regex HashRx();

    public IReadOnlyList<string> ToArgs()
    {
        var a = new List<string> { "--helper", Operation, "--result-id", ResultId.ToString("D") };
        if (Operation == "apply")
        {
            a.AddRange(["--profile", Profiles.Code(Profile), "--game", GamePath!, "--catalog", CatalogToken!, "--expect-plan", ExpectedPlanHash!]);
            if (AllowCommunity) a.Add("--allow-community");
        }
        return a;
    }

    public static bool TryParse(IReadOnlyList<string> args, out HelperRequest? request, out string? error)
    {
        request = null;
        error = null;
        if (args.Count < 4 || args[0] != "--helper") { error = "not a helper invocation"; return false; }
        string op = args[1];
        if (op is not ("apply" or "restore" or "selftest")) { error = "unknown operation"; return false; }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        bool community = false;
        for (int i = 2; i < args.Count; i++)
        {
            string key = args[i];
            if (key == "--allow-community") { community = true; continue; }
            if (key is not ("--result-id" or "--profile" or "--game" or "--catalog" or "--expect-plan")) { error = $"unexpected argument {key}"; return false; }
            if (i + 1 >= args.Count) { error = $"missing value for {key}"; return false; }
            if (!values.TryAdd(key, args[++i])) { error = $"duplicate {key}"; return false; }
        }
        if (!values.TryGetValue("--result-id", out var rid) || !Guid.TryParseExact(rid, "D", out var guid)) { error = "invalid result id"; return false; }
        if (op != "apply")
        {
            if (values.Count != 1 || community) { error = "unexpected arguments for " + op; return false; }
            request = new HelperRequest { Operation = op, ResultId = guid };
            return true;
        }
        if (!values.TryGetValue("--profile", out var p) || !Profiles.TryParse(p, out var profile) || profile == ProfileId.Default) { error = "invalid profile"; return false; }
        if (!values.TryGetValue("--game", out var game) || game.Length > 1024) { error = "invalid game path"; return false; }
        if (!values.TryGetValue("--catalog", out var cat) || !(cat == "embedded" || (Path.IsPathFullyQualified(cat) && cat.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))) { error = "invalid catalog"; return false; }
        if (!values.TryGetValue("--expect-plan", out var hash) || !HashRx().IsMatch(hash)) { error = "invalid plan hash"; return false; }
        request = new HelperRequest { Operation = op, ResultId = guid, Profile = profile, GamePath = game, CatalogToken = cat, AllowCommunity = community, ExpectedPlanHash = hash };
        return true;
    }
}

public sealed record HelperResult
{
    public required string Status { get; init; }
    public required string Summary { get; init; }
    public int ExitCode { get; init; }
    public ApplyOutcome? Outcome { get; init; }
    public SelfTestReport? SelfTest { get; init; }

    public static string PathFor(Guid id) => Path.Combine(AppPaths.Results, id.ToString("D") + ".json");
}

public static class HelperHost
{
    public const int ExitOk = 0, ExitRefused = 2, ExitRolledBack = 3, ExitRollbackIncomplete = 4, ExitNotElevated = 5, ExitBadRequest = 6, ExitCrashed = 7;

    /// <summary>Entry point inside the elevated process. Returns the process exit code.</summary>
    public static int Execute(IReadOnlyList<string> args)
    {
        if (!HelperRequest.TryParse(args, out var req, out var error)) return ExitBadRequest;
        HelperResult result;
        try
        {
            result = Run(req!);
        }
        catch (Exception ex)
        {
            result = new HelperResult { Status = "Crashed", Summary = "Unexpected error in elevated helper: " + ex.Message, ExitCode = ExitCrashed };
        }
        try
        {
            AppPaths.Ensure(AppPaths.Results);
            LocalJson.WriteAtomic(HelperResult.PathFor(req!.ResultId), JsonSerializer.Serialize(result, LocalJson.Options));
        }
        catch { /* the caller falls back to reading the firewall state itself */ }
        return result.ExitCode;
    }

    private static HelperResult Run(HelperRequest req)
    {
        if (!Elevation.IsElevated()) return new HelperResult { Status = "NotElevated", Summary = "Helper is not running as administrator.", ExitCode = ExitNotElevated };
        var engine = GuardEngine.CreateForHelper();
        if (req.Operation == "selftest")
        {
            var report = SelfTest.RunLive(engine.Store);
            return new HelperResult { Status = report.Passed ? "Passed" : "Failed", Summary = report.Passed ? "Live self-test passed." : "Live self-test failed.", SelfTest = report, ExitCode = report.Passed ? ExitOk : ExitRefused };
        }

        ApplyOutcome outcome;
        if (req.Operation == "restore")
        {
            outcome = engine.Service.Restore();
        }
        else
        {
            var catalog = CatalogProvider.LoadByToken(req.CatalogToken!);
            var plan = engine.BuildPlan(req.Profile, req.GamePath, req.AllowCommunity, catalog);
            if (!string.Equals(plan.PlanHash, req.ExpectedPlanHash, StringComparison.Ordinal))
            {
                return new HelperResult
                {
                    Status = "Refused",
                    Summary = "Not applied: the catalog or game path changed between preview and apply. Preview again.",
                    ExitCode = ExitRefused,
                };
            }
            outcome = engine.Service.Apply(plan);
        }
        int code = outcome.Status switch
        {
            ApplyStatus.Succeeded or ApplyStatus.NoChangesNeeded => ExitOk,
            ApplyStatus.Refused => ExitRefused,
            ApplyStatus.FailedRolledBack => ExitRolledBack,
            _ => ExitRollbackIncomplete,
        };
        return new HelperResult { Status = outcome.Status.ToString(), Summary = outcome.Summary, Outcome = outcome, ExitCode = code };
    }
}

public static class HelperClient
{
    /// <summary>Runs the request in an elevated copy of <paramref name="exe"/> (UAC prompt) and reads its result.</summary>
    public static HelperResult Run(string exe, HelperRequest req, TimeSpan timeout)
    {
        var (launch, exit, err) = Elevation.RunElevatedAndWait(exe, req.ToArgs(), timeout);
        if (launch == Elevation.LaunchResult.UserCancelled)
            return new HelperResult { Status = "Cancelled", Summary = err ?? "Cancelled.", ExitCode = -1 };
        if (launch != Elevation.LaunchResult.Completed)
            return new HelperResult { Status = "Failed", Summary = err ?? "Elevated helper failed to start.", ExitCode = -1 };

        string path = HelperResult.PathFor(req.ResultId);
        try
        {
            if (File.Exists(path))
            {
                var r = JsonSerializer.Deserialize<HelperResult>(File.ReadAllText(path), LocalJson.Options);
                File.Delete(path);
                if (r is not null) return r;
            }
        }
        catch { }
        return new HelperResult
        {
            Status = exit == 0 ? "Completed" : "Unknown",
            Summary = $"Elevated helper exited with code {exit}. Detailed result unavailable (administrator account differs?); the dashboard now shows the real firewall state.",
            ExitCode = exit,
        };
    }
}
