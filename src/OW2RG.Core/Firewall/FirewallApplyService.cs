using OW2RG.Core.Planning;

namespace OW2RG.Core.Firewall;

public enum ApplyStatus
{
    Succeeded,
    NoChangesNeeded,
    Refused,
    FailedRolledBack,
    FailedRollbackIncomplete,
}

public sealed record FirewallSnapshot
{
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required string Reason { get; init; }
    public string? PlanHash { get; init; }
    public required IReadOnlyList<FirewallRuleRecord> Rules { get; init; }
}

public interface ISnapshotStore
{
    /// <summary>Durably persists the snapshot and returns where it was written.</summary>
    string Save(FirewallSnapshot snapshot);
}

public sealed record AuditEvent
{
    public required DateTimeOffset AtUtc { get; init; }
    public required string Operation { get; init; }
    public string? Profile { get; init; }
    public string? PlanHash { get; init; }
    public int RuleCount { get; init; }
    public required string Result { get; init; }
    public IReadOnlyList<string> Details { get; init; } = [];
    public IReadOnlyList<string> ErrorCodes { get; init; } = [];
}

public interface IAuditLog
{
    void Write(AuditEvent e);
}

public sealed record ApplyOutcome
{
    public required ApplyStatus Status { get; init; }
    public required string Summary { get; init; }
    public ProfileId Profile { get; init; }
    public string? PlanHash { get; init; }
    public IReadOnlyList<string> Added { get; init; } = [];
    public IReadOnlyList<string> Removed { get; init; } = [];
    public IReadOnlyList<string> Kept { get; init; } = [];
    public IReadOnlyList<string> Errors { get; init; } = [];
    public IReadOnlyList<string> Steps { get; init; } = [];
    public string? SnapshotPath { get; init; }
    public string? RecoveryHint { get; init; }

    public bool IsSuccess => Status is ApplyStatus.Succeeded or ApplyStatus.NoChangesNeeded;
}

/// <summary>
/// Transaction-like apply with compensating rollback. Windows Firewall has no ACID transaction for a set of
/// rules, so this service: snapshots our own rules durably, stages new rules disabled, verifies them by
/// read-back, enables them, removes obsolete ones, verifies the final state, and on any failure restores the
/// snapshot. If rollback itself fails it says so loudly and points to the standalone recovery script.
/// </summary>
public sealed class FirewallApplyService(IFirewallRuleStore store, ISnapshotStore snapshots, IAuditLog audit, Func<DateTimeOffset> clock)
{
    public const string RecoveryHintText =
        "Run as Administrator:  powershell -ExecutionPolicy Bypass -File scripts\\remove-own-rules.ps1   (removes only OW2RG-* rules)  — or use 'Restore default' / 'ow2rg-cli restore'.";

    private readonly IFirewallRuleStore _store = new OwnedOnlyFirewallStore(store);

    public ApplyOutcome Apply(BlockPlan plan)
    {
        if (plan.Profile == ProfileId.Default) return Restore("apply default profile");

        var steps = new List<string>();
        var errors = new List<string>();

        if (!plan.IsEnforceable)
            return Done(Refused(plan, "Not applied: " + plan.NotEnforceableReason, steps));
        if (plan.Rules.Count == 0)
            return Done(Refused(plan, "Not applied: the plan contains no rules.", steps));

        FirewallEnvironment env;
        try { env = _store.ReadEnvironment(); }
        catch (Exception ex) { return Done(Refused(plan, "Cannot read Windows Firewall state: " + ex.Message, steps)); }
        if (!env.RulesWouldTakeEffect)
            return Done(Refused(plan, "Not applied: " + string.Join(" ", env.Problems), steps));

        // 1-3. Read current owned rules and persist a reversible snapshot.
        IReadOnlyList<FirewallRuleRecord> before;
        try { before = _store.ReadOwnedRules(); }
        catch (Exception ex) { return Done(Refused(plan, "Cannot read existing OW2RG rules: " + ex.Message, steps)); }
        steps.Add($"Read {before.Count} existing OW2RG rule(s).");

        string snapshotPath;
        try
        {
            snapshotPath = snapshots.Save(new FirewallSnapshot { CreatedAtUtc = clock(), Reason = "before apply " + Profiles.Code(plan.Profile), PlanHash = plan.PlanHash, Rules = before });
        }
        catch (Exception ex)
        {
            return Done(Refused(plan, "Not applied: could not persist a rollback snapshot (" + ex.Message + ").", steps));
        }
        steps.Add("Snapshot saved: " + snapshotPath);

        // 4. Diff.
        var desired = plan.Rules.ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);
        var byName = before.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        var keep = desired.Values.Where(spec => byName.TryGetValue(spec.Name, out var list) && list.Count == 1 && RuleComparer.Matches(spec, list[0]))
            .Select(s => s.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var toAdd = desired.Values.Where(s => !keep.Contains(s.Name)).ToList();
        var conflictingSameName = toAdd.Where(s => byName.ContainsKey(s.Name)).Select(s => s.Name).ToList();
        var obsolete = byName.Keys.Where(n => !desired.ContainsKey(n)).ToList();
        steps.Add($"Plan: add {toAdd.Count}, remove {obsolete.Count + conflictingSameName.Count}, keep {keep.Count}.");

        if (toAdd.Count == 0 && obsolete.Count == 0)
        {
            var o = new ApplyOutcome
            {
                Status = ApplyStatus.NoChangesNeeded,
                Summary = $"Already active: {plan.Rules.Count} rule(s) match the plan exactly. Nothing changed.",
                Profile = plan.Profile, PlanHash = plan.PlanHash, Kept = keep.ToList(), Steps = steps, SnapshotPath = snapshotPath,
            };
            return Done(o);
        }

        var added = new List<string>();
        var removed = new List<string>();
        try
        {
            // Same-named rules with different content (tampered/corrupted) must go first: Windows allows
            // duplicate names, and removing by name later would also remove the new rule.
            foreach (var name in conflictingSameName)
            {
                _store.RemoveRules(name);
                removed.Add(name);
                steps.Add("Removed mismatched rule " + name);
            }

            // 5. Stage new rules disabled.
            foreach (var spec in toAdd)
            {
                _store.AddRule(spec.WithEnabled(false));
                added.Add(spec.Name);
            }
            steps.Add($"Staged {added.Count} new rule(s) disabled.");

            // 6. Verify staged rules by read-back.
            var staged = _store.ReadOwnedRules().GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
            foreach (var spec in toAdd)
            {
                if (!staged.TryGetValue(spec.Name, out var got) || got.Count != 1)
                    throw new FirewallOperationException($"Read-back: staged rule {spec.Name} is missing or duplicated.");
                var diff = RuleComparer.Differences(spec.WithEnabled(false), got[0]);
                if (diff.Count > 0) throw new FirewallOperationException($"Read-back: staged rule {spec.Name} differs from plan ({string.Join(", ", diff)}).");
            }
            steps.Add("Read-back verified every staged rule.");

            // 7. Commit: enable new rules, then remove obsolete ones.
            foreach (var spec in toAdd) _store.SetEnabled(spec.Name, true);
            steps.Add($"Enabled {toAdd.Count} rule(s).");
            foreach (var name in obsolete)
            {
                _store.RemoveRules(name);
                removed.Add(name);
            }
            if (obsolete.Count > 0) steps.Add($"Removed {obsolete.Count} obsolete OW2RG rule(s).");

            // 8. Final verification against the real firewall state.
            var final = _store.ReadOwnedRules();
            var problems = VerifyExactly(plan, final);
            if (problems.Count > 0) throw new FirewallOperationException("Final verification failed: " + string.Join("; ", problems));
            steps.Add($"Final read-back: exactly {plan.Rules.Count} OW2RG rule(s), all match the plan.");

            var ok = new ApplyOutcome
            {
                Status = ApplyStatus.Succeeded,
                Summary = $"Rules installed: {Profiles.DisplayName(plan.Profile)} — {plan.Rules.Count} rule(s), {plan.BlockedCidrCount} blocked network(s). " +
                          "This is not proof your matches are in Europe; verify with NetGraph (Ctrl+Shift+N) in a Custom Game.",
                Profile = plan.Profile, PlanHash = plan.PlanHash,
                Added = added, Removed = removed, Kept = keep.ToList(), Steps = steps, SnapshotPath = snapshotPath,
            };
            return Done(ok);
        }
        catch (Exception ex)
        {
            errors.Add(Describe(ex));
            steps.Add("FAILED: " + Describe(ex) + " — rolling back to the snapshot.");
            var (rolledBack, rollbackErrors) = RollBack(before, steps);
            errors.AddRange(rollbackErrors);
            var o = new ApplyOutcome
            {
                Status = rolledBack ? ApplyStatus.FailedRolledBack : ApplyStatus.FailedRollbackIncomplete,
                Summary = rolledBack
                    ? "Apply failed and was rolled back; your previous OW2RG rules are restored exactly. Nothing else was touched."
                    : "Apply failed AND rollback is incomplete. Use Restore Default or the recovery script now.",
                Profile = plan.Profile, PlanHash = plan.PlanHash,
                Added = added, Removed = removed, Errors = errors, Steps = steps, SnapshotPath = snapshotPath,
                RecoveryHint = rolledBack ? null : RecoveryHintText,
            };
            return Done(o);
        }
    }

    /// <summary>Removes all and only OW2RG rules. Needs no catalog and no game path.</summary>
    public ApplyOutcome Restore(string reason = "restore default")
    {
        var steps = new List<string>();
        IReadOnlyList<FirewallRuleRecord> before;
        try { before = _store.ReadOwnedRules(); }
        catch (Exception ex)
        {
            return Done(new ApplyOutcome { Status = ApplyStatus.Refused, Summary = "Cannot read firewall rules: " + Describe(ex), Profile = ProfileId.Default, Steps = steps, RecoveryHint = RecoveryHintText });
        }
        if (before.Count == 0)
            return Done(new ApplyOutcome { Status = ApplyStatus.NoChangesNeeded, Summary = "No OW2RG rules present. Windows Firewall has no restrictions from this app.", Profile = ProfileId.Default, Steps = ["No OW2RG rules found."] });

        string? snapshotPath = null;
        try { snapshotPath = snapshots.Save(new FirewallSnapshot { CreatedAtUtc = clock(), Reason = reason, Rules = before }); steps.Add("Snapshot saved: " + snapshotPath); }
        catch (Exception ex) { steps.Add("Warning: snapshot could not be saved (" + ex.Message + "); continuing because removal only makes things safer."); }

        var removed = new List<string>();
        var errors = new List<string>();
        foreach (var name in before.Select(r => r.Name).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    _store.RemoveRules(name);
                    removed.Add(name);
                    break;
                }
                catch (Exception ex) when (attempt == 0)
                {
                    steps.Add($"Retrying removal of {name}: {Describe(ex)}");
                }
                catch (Exception ex)
                {
                    errors.Add($"{name}: {Describe(ex)}");
                }
            }
        }

        IReadOnlyList<FirewallRuleRecord> after;
        try { after = _store.ReadOwnedRules(); }
        catch (Exception ex) { errors.Add("Read-back failed: " + Describe(ex)); after = before; }

        bool ok = after.Count == 0;
        steps.Add(ok ? $"Removed {removed.Count} rule name(s); read-back shows zero OW2RG rules." : $"{after.Count} OW2RG rule(s) still present after removal.");
        return Done(new ApplyOutcome
        {
            Status = ok ? ApplyStatus.Succeeded : ApplyStatus.FailedRollbackIncomplete,
            Summary = ok ? $"Restored default: removed {before.Count} OW2RG rule(s). No other firewall rules were touched."
                         : $"Restore incomplete: {after.Count} OW2RG rule(s) remain.",
            Profile = ProfileId.Default, Removed = removed, Errors = errors, Steps = steps, SnapshotPath = snapshotPath,
            RecoveryHint = ok ? null : RecoveryHintText,
        });
    }

    private (bool Ok, List<string> Errors) RollBack(IReadOnlyList<FirewallRuleRecord> snapshot, List<string> steps)
    {
        var errors = new List<string>();
        try
        {
            var current = _store.ReadOwnedRules();
            var wanted = snapshot.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
            var have = current.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

            // Remove everything that was not in the snapshot, or whose copy differs from it.
            foreach (var (name, rules) in have)
            {
                bool identical = wanted.TryGetValue(name, out var w) && w.Count == rules.Count && rules.All(r => w.Contains(r));
                if (!identical)
                {
                    try { _store.RemoveRules(name); steps.Add("Rollback: removed " + name); }
                    catch (Exception ex) { errors.Add($"Rollback remove {name}: {Describe(ex)}"); }
                }
            }

            // Recreate snapshot rules that are now missing.
            current = _store.ReadOwnedRules();
            var present = current.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var record in snapshot.Where(r => !present.Contains(r.Name)))
            {
                if (FirewallRuleSpec.TryRecreate(record, out var spec, out var reason))
                {
                    try { _store.AddRule(spec!); steps.Add("Rollback: recreated " + record.Name); }
                    catch (Exception ex) { errors.Add($"Rollback recreate {record.Name}: {Describe(ex)}"); }
                }
                else
                {
                    steps.Add($"Rollback: did not recreate {record.Name} ({reason}); leaving it removed is the safer state.");
                }
            }

            // Verify: nothing outside the snapshot remains, and every recreatable snapshot rule is back.
            var finalRules = _store.ReadOwnedRules();
            bool same = true;
            foreach (var f in finalRules)
            {
                if (!snapshot.Any(s => string.Equals(s.Name, f.Name, StringComparison.OrdinalIgnoreCase) && (s == f || SameContent(s, f))))
                {
                    same = false;
                    errors.Add($"Rollback verification: unexpected rule {f.Name} is present.");
                }
            }
            foreach (var s in snapshot)
            {
                bool presentNow = finalRules.Any(f => string.Equals(s.Name, f.Name, StringComparison.OrdinalIgnoreCase) && (s == f || SameContent(s, f)));
                if (!presentNow && FirewallRuleSpec.TryRecreate(s, out _, out _))
                {
                    same = false;
                    errors.Add($"Rollback verification: {s.Name} was not restored.");
                }
            }
            return (same && errors.Count == 0, errors);
        }
        catch (Exception ex)
        {
            errors.Add("Rollback aborted: " + Describe(ex));
            return (false, errors);
        }
    }

    private static bool SameContent(FirewallRuleRecord expected, FirewallRuleRecord actual)
    {
        if (!FirewallRuleSpec.TryRecreate(expected, out var spec, out _)) return false;
        return RuleComparer.Matches(spec!, actual);
    }

    private static List<string> VerifyExactly(BlockPlan plan, IReadOnlyList<FirewallRuleRecord> actual)
    {
        var problems = new List<string>();
        var groups = actual.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        foreach (var spec in plan.Rules)
        {
            if (!groups.TryGetValue(spec.Name, out var list)) { problems.Add($"{spec.Name} missing"); continue; }
            if (list.Count != 1) { problems.Add($"{spec.Name} duplicated x{list.Count}"); continue; }
            var diff = RuleComparer.Differences(spec, list[0]);
            if (diff.Count > 0) problems.Add($"{spec.Name}: {string.Join(", ", diff)}");
        }
        foreach (var name in groups.Keys.Where(n => plan.Rules.All(r => !string.Equals(r.Name, n, StringComparison.OrdinalIgnoreCase))))
            problems.Add($"unexpected extra rule {name}");
        return problems;
    }

    private ApplyOutcome Refused(BlockPlan plan, string message, List<string> steps) => new()
    {
        Status = ApplyStatus.Refused,
        Summary = message,
        Profile = plan.Profile,
        PlanHash = plan.PlanHash,
        Steps = steps,
    };

    private ApplyOutcome Done(ApplyOutcome outcome)
    {
        try
        {
            audit.Write(new AuditEvent
            {
                AtUtc = clock(),
                Operation = outcome.Profile == ProfileId.Default ? "restore" : "apply",
                Profile = Profiles.Code(outcome.Profile),
                PlanHash = outcome.PlanHash,
                RuleCount = outcome.Added.Count + outcome.Kept.Count,
                Result = outcome.Status.ToString(),
                Details = [outcome.Summary, .. outcome.Steps],
                ErrorCodes = outcome.Errors,
            });
        }
        catch
        {
            // Audit failure must never mask the real outcome.
        }
        return outcome;
    }

    private static string Describe(Exception ex) => ex switch
    {
        FirewallOperationException { IsAccessDenied: true } => "Access denied (administrator rights are required to change firewall rules).",
        FirewallOperationException f when f.NativeErrorCode is { } code => $"{f.Message} (0x{code:X8})",
        _ => ex.Message,
    };
}
