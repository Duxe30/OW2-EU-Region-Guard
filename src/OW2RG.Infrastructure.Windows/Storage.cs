using System.Text.Json;
using System.Text.Json.Serialization;
using OW2RG.Core.Firewall;
using OW2RG.Core.Verification;

namespace OW2RG.Infrastructure.Windows;

/// <summary>All local data lives under %LOCALAPPDATA%\OW2RG. Nothing is ever sent anywhere.</summary>
public static class AppPaths
{
    public static string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OW2RG");
    public static string Snapshots => Path.Combine(Root, "snapshots");
    public static string Results => Path.Combine(Root, "results");
    public static string UserCatalogDir => Path.Combine(Root, "catalog");
    public static string UserCatalog => Path.Combine(UserCatalogDir, "servers.json");
    public static string AuditLog => Path.Combine(Root, "audit.log.jsonl");
    public static string Settings => Path.Combine(Root, "user-settings.json");
    public static string Observations => Path.Combine(Root, "observations.json");
    public static string Exports => Path.Combine(Root, "exports");

    public static void Ensure(string dir) => Directory.CreateDirectory(dir);
}

internal static class LocalJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Atomic-ish write: temp file + replace, so a crash never leaves a half-written file.</summary>
    public static void WriteAtomic(string path, string content)
    {
        AppPaths.Ensure(Path.GetDirectoryName(path)!);
        string tmp = path + ".tmp-" + Guid.NewGuid().ToString("N")[..8];
        File.WriteAllText(tmp, content);
        File.Move(tmp, path, overwrite: true);
    }
}

public sealed class JsonSnapshotStore(string directory) : ISnapshotStore
{
    public string Save(FirewallSnapshot snapshot)
    {
        AppPaths.Ensure(directory);
        string path = Path.Combine(directory, $"snapshot-{snapshot.CreatedAtUtc:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6]}.json");
        LocalJson.WriteAtomic(path, JsonSerializer.Serialize(snapshot, LocalJson.Options));
        Prune(directory, keep: 50);
        return path;
    }

    private static void Prune(string dir, int keep)
    {
        try
        {
            foreach (var f in new DirectoryInfo(dir).GetFiles("snapshot-*.json").OrderByDescending(f => f.Name).Skip(keep)) f.Delete();
        }
        catch { /* pruning is best effort */ }
    }
}

/// <summary>Append-only JSON-lines audit log, rotated at 2 MB. No credentials, payloads or packet data — ever.</summary>
public sealed class JsonlAuditLog(string path) : IAuditLog
{
    private static readonly object Gate = new();

    public void Write(AuditEvent e)
    {
        lock (Gate)
        {
            AppPaths.Ensure(Path.GetDirectoryName(path)!);
            var fi = new FileInfo(path);
            if (fi.Exists && fi.Length > 2 * 1024 * 1024) File.Move(path, path + ".1", overwrite: true);
            var line = JsonSerializer.Serialize(e, new JsonSerializerOptions(LocalJson.Options) { WriteIndented = false });
            File.AppendAllText(path, line + Environment.NewLine);
        }
    }

    public static IReadOnlyList<string> Tail(string path, int lines)
    {
        try
        {
            if (!File.Exists(path)) return [];
            return File.ReadLines(path).TakeLast(lines).ToList();
        }
        catch
        {
            return [];
        }
    }
}

public sealed class UserSettings
{
    public string? GamePath { get; set; }
    /// <summary>Community opt-in is remembered per catalog fingerprint; a new catalog asks again.</summary>
    public string? CommunityOptInCatalogSha { get; set; }
    public string? LastProfile { get; set; }

    public static UserSettings Load()
    {
        try
        {
            if (File.Exists(AppPaths.Settings))
            {
                var info = new FileInfo(AppPaths.Settings);
                if (info.Length < 64 * 1024)
                    return JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(AppPaths.Settings), LocalJson.Options) ?? new UserSettings();
            }
        }
        catch { /* corrupt settings are ignored; the firewall is the source of truth anyway */ }
        return new UserSettings();
    }

    public void Save() => LocalJson.WriteAtomic(AppPaths.Settings, JsonSerializer.Serialize(this, LocalJson.Options));
}

public static class ObservationStore
{
    public static List<MatchObservation> Load()
    {
        try
        {
            if (File.Exists(AppPaths.Observations) && new FileInfo(AppPaths.Observations).Length < 4 * 1024 * 1024)
                return JsonSerializer.Deserialize<List<MatchObservation>>(File.ReadAllText(AppPaths.Observations), LocalJson.Options) ?? [];
        }
        catch { }
        return [];
    }

    public static void Save(List<MatchObservation> list) =>
        LocalJson.WriteAtomic(AppPaths.Observations, JsonSerializer.Serialize(list.TakeLast(2000).ToList(), LocalJson.Options));
}
