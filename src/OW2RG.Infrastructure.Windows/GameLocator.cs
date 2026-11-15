using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using OW2RG.Core.Game;

namespace OW2RG.Infrastructure.Windows;

public sealed class RealFileProbe : IFileProbe
{
    public static readonly RealFileProbe Instance = new();
    public bool FileExists(string path) { try { return File.Exists(path); } catch { return false; } }
    public long? FileLength(string path) { try { return new FileInfo(path).Length; } catch { return null; } }
}

public sealed record GameCandidate(string Path, string Source, bool Exists, string? Note, GamePathCheck Check);

/// <summary>
/// Finds the Overwatch game client (never the launcher or Battle.net). Every source is only a hint:
/// each candidate is re-validated against the file system. Read-only: nothing is started, modified or injected.
/// </summary>
public static partial class GameLocator
{
    public const string SteamAppId = "2357570";

    public static IReadOnlyList<GameCandidate> FindCandidates()
    {
        var found = new List<(string Path, string Source, string? Note)>();
        void Add(string? p, string source, string? note = null)
        {
            if (string.IsNullOrWhiteSpace(p)) return;
            try { p = System.IO.Path.GetFullPath(p.Trim().Trim('"')); } catch { return; }
            if (found.Any(f => string.Equals(f.Path, p, StringComparison.OrdinalIgnoreCase))) return;
            found.Add((p, source, note));
        }

        foreach (var p in RunningClients()) Add(p, "Running game process");
        foreach (var (p, note) in SteamCandidates()) Add(p, "Steam library", note);
        foreach (var p in BattleNetProductDbCandidates()) Add(p, "Battle.net install database");
        foreach (var p in UninstallRegistryCandidates()) Add(p, "Windows uninstall registry");
        foreach (var p in CommonFolderCandidates()) Add(p, "Common install folder");

        return found.Select(f =>
        {
            var check = GamePathValidator.Validate(f.Path, RealFileProbe.Instance);
            bool exists = RealFileProbe.Instance.FileExists(f.Path);
            return new GameCandidate(f.Path, f.Source, exists, f.Note, check);
        })
        .OrderByDescending(c => c.Check.IsValid)
        .ThenBy(c => c.Source == "Running game process" ? 0 : 1)
        .ToList();
    }

    public static bool IsGameRunning() => Process.GetProcessesByName("Overwatch").Length > 0;

    private static IEnumerable<string> RunningClients()
    {
        Process[] procs;
        try { procs = Process.GetProcessesByName("Overwatch"); } catch { yield break; }
        foreach (var p in procs)
        {
            string? path = QueryImagePath(p.Id);
            p.Dispose();
            if (path is not null) yield return path;
        }
    }

    private static IEnumerable<(string Path, string? Note)> SteamCandidates()
    {
        var libraries = new List<string>();
        string? steamPath = null;
        try { steamPath = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string; } catch { }
        try { steamPath ??= Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath", null) as string; } catch { }
        if (!string.IsNullOrEmpty(steamPath))
        {
            steamPath = steamPath.Replace('/', '\\');
            libraries.Add(steamPath);
            string vdf = System.IO.Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
            try
            {
                if (File.Exists(vdf) && new FileInfo(vdf).Length < 1024 * 1024)
                {
                    foreach (Match m in VdfPathRx().Matches(File.ReadAllText(vdf)))
                        libraries.Add(m.Groups[1].Value.Replace(@"\\", @"\"));
                }
            }
            catch { }
        }
        foreach (var lib in libraries.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string manifest = System.IO.Path.Combine(lib, "steamapps", $"appmanifest_{SteamAppId}.acf");
            string root = System.IO.Path.Combine(lib, "steamapps", "common", "Overwatch");
            string exe = System.IO.Path.Combine(root, "_retail_", GamePathValidator.ExpectedFileName);
            bool hasManifest = File.Exists(manifest);
            if (!hasManifest && !Directory.Exists(root)) continue;
            string? note = null;
            if (!File.Exists(exe))
            {
                note = "Steam lists Overwatch here, but the game files are not present yet (download not finished?).";
                try
                {
                    if (hasManifest && File.ReadAllText(manifest).Contains("\"BytesDownloaded\"\t\t\"0\"")) note = "Steam lists Overwatch here, but nothing has been downloaded yet.";
                }
                catch { }
            }
            yield return (exe, note);
        }
    }

    private static IEnumerable<string> BattleNetProductDbCandidates()
    {
        // product.db is protobuf, but install roots are stored as plain strings. We only read and pattern-match it.
        string db = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Battle.net", "Agent", "product.db");
        byte[] bytes;
        try
        {
            if (!File.Exists(db) || new FileInfo(db).Length > 8 * 1024 * 1024) yield break;
            bytes = File.ReadAllBytes(db);
        }
        catch { yield break; }
        string text = Encoding.UTF8.GetString(bytes);
        foreach (Match m in DrivePathRx().Matches(text))
        {
            string root = m.Value.TrimEnd('\\', '/').Replace('/', '\\');
            if (!root.Contains("Overwatch", StringComparison.OrdinalIgnoreCase)) continue;
            yield return System.IO.Path.Combine(root, "_retail_", GamePathValidator.ExpectedFileName);
        }
    }

    private static IEnumerable<string> UninstallRegistryCandidates()
    {
        var results = new List<string>();
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var uninstall = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (uninstall is null) continue;
                    foreach (var name in uninstall.GetSubKeyNames())
                    {
                        using var k = uninstall.OpenSubKey(name);
                        if (k?.GetValue("DisplayName") is not string display || !display.Contains("Overwatch", StringComparison.OrdinalIgnoreCase)) continue;
                        if (k.GetValue("DisplayIcon") is string icon)
                        {
                            string iconPath = icon.Split(',')[0].Trim('"');
                            if (iconPath.EndsWith(GamePathValidator.ExpectedFileName, StringComparison.OrdinalIgnoreCase)) results.Add(iconPath);
                        }
                        if (k.GetValue("InstallLocation") is string loc && loc.Length > 3)
                            results.Add(System.IO.Path.Combine(loc.Trim('"'), "_retail_", GamePathValidator.ExpectedFileName));
                    }
                }
                catch { }
            }
        }
        return results;
    }

    private static IEnumerable<string> CommonFolderCandidates()
    {
        var roots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                roots.Add(d.RootDirectory.FullName);
                roots.Add(System.IO.Path.Combine(d.RootDirectory.FullName, "Games"));
                roots.Add(System.IO.Path.Combine(d.RootDirectory.FullName, "Program Files (x86)"));
                roots.Add(System.IO.Path.Combine(d.RootDirectory.FullName, "Battle.net"));
            }
            catch { }
        }
        foreach (var r in roots.Where(r => !string.IsNullOrEmpty(r)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string exe = System.IO.Path.Combine(r, "Overwatch", "_retail_", GamePathValidator.ExpectedFileName);
            if (File.Exists(exe)) yield return exe;
        }
    }

    [GeneratedRegex("\"path\"\\s+\"([^\"]{3,260})\"", RegexOptions.IgnoreCase)]
    private static partial Regex VdfPathRx();

    [GeneratedRegex(@"[A-Za-z]:[\\/][^\x00-\x1f""<>|*?]{1,240}")]
    private static partial Regex DrivePathRx();

    // QueryFullProcessImageName with PROCESS_QUERY_LIMITED_INFORMATION: reads the image path only.
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageName(IntPtr process, uint flags, [Out] char[] buffer, ref uint size);

    private static string? QueryImagePath(int pid)
    {
        IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var buffer = new char[1024];
            uint size = (uint)buffer.Length;
            return QueryFullProcessImageName(h, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
        }
        finally
        {
            CloseHandle(h);
        }
    }
}
