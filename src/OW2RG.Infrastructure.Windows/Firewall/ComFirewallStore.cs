using OW2RG.Core.Firewall;
using OW2RG.Core.Net;

namespace OW2RG.Infrastructure.Windows.Firewall;

/// <summary>
/// Windows Defender Firewall adapter (INetFwPolicy2 / INetFwRule via COM). It can only read the firewall's
/// state, read rules named OW2RG-*, and add / enable / remove OW2RG-* rules. It never touches profile
/// enablement, default inbound/outbound actions or any other rule.
/// </summary>
public sealed class ComFirewallStore : IFirewallRuleStore
{
    private const string PolicyProgId = "HNetCfg.FwPolicy2";
    private const string RuleProgId = "HNetCfg.FWRule";

    public FirewallEnvironment ReadEnvironment()
    {
        object? policy = null;
        try
        {
            policy = Com.Create(PolicyProgId);
            int current = Com.GetInt(policy, "CurrentProfileTypes");
            var enabled = new Dictionary<string, bool>();
            foreach (var (name, bit) in new[] { ("Domain", 1), ("Private", 2), ("Public", 4) })
            {
                enabled[name] = Convert.ToBoolean(Com.Get(policy, "FirewallEnabled", bit) ?? false);
            }
            bool currentOn = current != 0 &&
                             (((current & 1) == 0) || enabled["Domain"]) &&
                             (((current & 2) == 0) || enabled["Private"]) &&
                             (((current & 4) == 0) || enabled["Public"]);
            int modifyState = 0;
            try { modifyState = Com.GetInt(policy, "LocalPolicyModifyState"); } catch (FirewallOperationException) { /* not fatal */ }
            return new FirewallEnvironment
            {
                ApiAvailable = true,
                CurrentProfileTypes = current,
                EnabledByProfile = enabled,
                CurrentProfilesEnabled = currentOn,
                LocalPolicyModifyState = modifyState,
                IsElevated = Elevation.IsElevated(),
                ThirdPartyFirewalls = SecurityCenter.ActiveThirdPartyFirewalls(),
            };
        }
        catch (Exception ex)
        {
            return new FirewallEnvironment { ApiAvailable = false, ApiError = ex.Message, IsElevated = Elevation.IsElevated() };
        }
        finally
        {
            Com.Release(policy);
        }
    }

    public IReadOnlyList<FirewallRuleRecord> ReadOwnedRules()
    {
        var result = new List<FirewallRuleRecord>();
        WithRules(rules =>
        {
            foreach (var rule in Com.Enumerate(rules))
            {
                try
                {
                    string? name = Com.GetString(rule, "Name");
                    if (OwnedRules.IsOwnedName(name)) result.Add(ReadRecord(rule, name!));
                }
                finally
                {
                    Com.Release(rule);
                }
            }
        });
        return result;
    }

    public void AddRule(FirewallRuleSpec spec)
    {
        OwnedRules.RequireOwned(spec.Name);
        object rule = BuildRuleObject(spec);
        try
        {
            WithRules(rules => Com.Call(rules, "Add", rule));
        }
        finally
        {
            Com.Release(rule);
        }
    }

    public void SetEnabled(string ownedName, bool enabled)
    {
        OwnedRules.RequireOwned(ownedName);
        WithRules(rules =>
        {
            object rule = TryGetItem(rules, ownedName) ?? throw new FirewallOperationException($"Rule {ownedName} not found.");
            try { Com.Set(rule, "Enabled", enabled); }
            finally { Com.Release(rule); }
        });
    }

    public int RemoveRules(string ownedName)
    {
        OwnedRules.RequireOwned(ownedName);
        int removed = 0;
        WithRules(rules =>
        {
            // INetFwRules.Remove deletes ONE rule per call. Windows allows several rules with the same name,
            // so keep removing while Item(name) still finds one (bounded, in case the API misbehaves).
            for (int guard = 0; guard < 64; guard++)
            {
                object? existing = TryGetItem(rules, ownedName);
                if (existing is null) return;
                Com.Release(existing);
                Com.Call(rules, "Remove", ownedName);
                removed++;
            }
            throw new FirewallOperationException($"Rules named {ownedName} keep reappearing; stopped after 64 removals.");
        });
        return removed;
    }

    /// <summary>INetFwRules.Item(name), or null when no rule has that name. Other failures propagate.</summary>
    private static object? TryGetItem(object rules, string name)
    {
        try
        {
            return Com.Call(rules, "Item", name);
        }
        catch (FirewallOperationException ex) when (ex.NativeErrorCode is unchecked((int)0x80070002) or unchecked((int)0x80070057) or unchecked((int)0x80004005))
        {
            // ERROR_FILE_NOT_FOUND / E_INVALIDARG / E_FAIL are what the firewall returns for an unknown name.
            return null;
        }
    }

    /// <summary>
    /// Builds an unsaved HNetCfg.FWRule with every property assigned, then reads it back — WITHOUT adding it to
    /// the policy. Windows validates property values on assignment, so this proves the exact rule text is
    /// accepted, with no elevation and no system change.
    /// </summary>
    public DryValidation DryValidate(FirewallRuleSpec spec)
    {
        object? rule = null;
        try
        {
            rule = BuildRuleObject(spec);
            string? remote = Com.GetString(rule, "RemoteAddresses");
            string? app = Com.GetString(rule, "ApplicationName");
            var parsed = AddressListParser.Parse(remote);
            bool sameSet = parsed.Success && parsed.Set.Equals(spec.RemoteSet);
            bool sameApp = string.Equals(app, spec.ApplicationPath, StringComparison.OrdinalIgnoreCase);
            return new DryValidation(spec.Name, sameSet && sameApp, remote, sameSet ? null : "read-back address set differs", spec.RemoteAddressesText.Length);
        }
        catch (Exception ex)
        {
            return new DryValidation(spec.Name, false, null, ex.Message, spec.RemoteAddressesText.Length);
        }
        finally
        {
            Com.Release(rule);
        }
    }

    /// <summary>Largest RemoteAddresses length (in CIDR count) that an unsaved rule object accepts. No system change.</summary>
    public (int AcceptedCount, int AcceptedChars, string? FirstError) ProbeRemoteAddressLimit(int maxCount = 20000)
    {
        int lo = 0, hi = maxCount;
        string? firstError = null;
        int acceptedChars = 0;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            string text = string.Join(",", Enumerable.Range(0, mid).Select(i => $"10.{(i >> 8) & 255}.{i & 255}.0/24"));
            object? rule = null;
            try
            {
                rule = Com.Create(RuleProgId);
                Com.Set(rule, "Protocol", 17);
                Com.Set(rule, "RemoteAddresses", text);
                lo = mid;
                acceptedChars = text.Length;
            }
            catch (Exception ex)
            {
                firstError ??= ex.Message;
                hi = mid - 1;
            }
            finally
            {
                Com.Release(rule);
            }
        }
        return (lo, acceptedChars, firstError);
    }

    private static object BuildRuleObject(FirewallRuleSpec spec)
    {
        object rule = Com.Create(RuleProgId);
        try
        {
            Com.Set(rule, "Name", spec.Name);
            Com.Set(rule, "Description", spec.Description);
            Com.Set(rule, "Grouping", spec.Grouping);
            Com.Set(rule, "ApplicationName", spec.ApplicationPath);
            Com.Set(rule, "Protocol", (int)spec.Protocol);          // must precede any port property
            Com.Set(rule, "Direction", (int)spec.Direction);        // NET_FW_RULE_DIR_OUT = 2
            Com.Set(rule, "Action", (int)spec.Action);              // NET_FW_ACTION_BLOCK = 0
            Com.Set(rule, "RemoteAddresses", spec.RemoteAddressesText);
            Com.Set(rule, "Profiles", spec.Profiles);               // NET_FW_PROFILE2_ALL
            Com.Set(rule, "InterfaceTypes", "All");
            Com.Set(rule, "Enabled", spec.Enabled);
            return rule;
        }
        catch
        {
            Com.Release(rule);
            throw;
        }
    }

    private static FirewallRuleRecord ReadRecord(object rule, string name)
    {
        string? Try(string p) { try { return Com.GetString(rule, p); } catch (FirewallOperationException) { return null; } }
        int TryInt(string p) { try { return Com.GetInt(rule, p); } catch (FirewallOperationException) { return -1; } }
        return new FirewallRuleRecord
        {
            Name = name,
            Description = Try("Description"),
            Grouping = Try("Grouping"),
            ApplicationName = Try("ApplicationName"),
            ServiceName = Try("ServiceName"),
            Protocol = TryInt("Protocol"),
            Direction = TryInt("Direction"),
            Action = TryInt("Action"),
            Enabled = Com.GetBool(rule, "Enabled"),
            RemoteAddresses = Try("RemoteAddresses"),
            LocalAddresses = Try("LocalAddresses"),
            RemotePorts = Try("RemotePorts"),
            LocalPorts = Try("LocalPorts"),
            Profiles = TryInt("Profiles"),
            InterfaceTypes = Try("InterfaceTypes"),
        };
    }

    private static void WithRules(Action<object> action)
    {
        object? policy = null;
        object? rules = null;
        try
        {
            policy = Com.Create(PolicyProgId);
            rules = Com.Get(policy, "Rules") ?? throw new FirewallOperationException("INetFwPolicy2.Rules returned null.");
            action(rules);
        }
        finally
        {
            Com.Release(rules);
            Com.Release(policy);
        }
    }
}

public sealed record DryValidation(string RuleName, bool Accepted, string? WindowsReadBack, string? Error, int Characters);
