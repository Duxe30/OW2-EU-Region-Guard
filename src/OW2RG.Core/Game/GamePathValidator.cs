namespace OW2RG.Core.Game;

public interface IFileProbe
{
    bool FileExists(string path);
    long? FileLength(string path);
}

/// <summary>
/// A game executable path that passed <see cref="GamePathValidator"/>. It can only be created by the
/// validator, so every firewall rule built from it is provably scoped to a validated Overwatch.exe.
/// </summary>
public sealed class ValidatedGamePath : IEquatable<ValidatedGamePath>
{
    internal ValidatedGamePath(string fullPath) => FullPath = fullPath;

    public string FullPath { get; }

    public bool Equals(ValidatedGamePath? other) =>
        other is not null && string.Equals(FullPath, other.FullPath, StringComparison.OrdinalIgnoreCase);

    public override bool Equals(object? obj) => Equals(obj as ValidatedGamePath);
    public override int GetHashCode() => StringComparer.OrdinalIgnoreCase.GetHashCode(FullPath);
    public override string ToString() => FullPath;
}

public sealed record GamePathCheck(ValidatedGamePath? Path, IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings)
{
    public bool IsValid => Path is not null;
}

public static class GamePathValidator
{
    public const string ExpectedFileName = "Overwatch.exe";
    public const long SuspiciouslySmallBytes = 20L * 1024 * 1024;

    private static readonly Dictionary<string, string> KnownWrongFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Overwatch Launcher.exe"] = "This is the launcher stub, not the game client. Pick _retail_\\Overwatch.exe.",
        ["Battle.net.exe"] = "Battle.net must never be firewalled by this app.",
        ["Battle.net Launcher.exe"] = "Battle.net must never be firewalled by this app.",
        ["Agent.exe"] = "Blizzard Agent must never be firewalled by this app.",
        ["steam.exe"] = "Steam must never be firewalled by this app.",
        ["svchost.exe"] = "System processes are never firewalled by this app.",
        ["explorer.exe"] = "System processes are never firewalled by this app.",
    };

    private static readonly string[] ExpectedParents = ["_retail_", "_ptr_", "_beta_"];

    public static GamePathCheck Validate(string? input, IFileProbe probe)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        GamePathCheck Fail(string e) { errors.Add(e); return new GamePathCheck(null, errors, warnings); }

        if (string.IsNullOrWhiteSpace(input)) return Fail("No game executable selected.");
        string path = input;
        if (path.Length > 1024) return Fail("Path is too long.");
        if (path != path.Trim()) return Fail("Path has leading or trailing whitespace.");
        foreach (char ch in path)
        {
            if (char.IsControl(ch)) return Fail("Path contains control characters.");
            if (ch is '"' or '*' or '?' or '<' or '>' or '|' or '%' or '/')
                return Fail($"Path contains a forbidden character '{ch}'. ('%' is refused because Windows Firewall expands environment variables.)");
            if (ch is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069' or '\u200B' or '\u200E' or '\u200F' or '\uFEFF')
                return Fail("Path contains invisible or bidirectional-override characters.");
        }
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return Fail("Network (UNC) and device paths are not supported; select a file on a local drive.");
        if (path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
            return Fail("Path must be an absolute local path such as D:\\Games\\Overwatch\\_retail_\\Overwatch.exe.");

        var segments = path[3..].Split('\\');
        foreach (var seg in segments)
        {
            if (seg.Length == 0) return Fail("Path contains an empty segment (\\\\).");
            if (seg is "." or "..") return Fail("Relative path segments ('.' or '..') are not allowed.");
            if (seg.EndsWith(' ') || seg.EndsWith('.')) return Fail("A path segment ends with a space or dot, which Windows silently strips.");
            if (seg.Contains(':')) return Fail("Alternate data streams / extra drive separators are not allowed.");
        }

        string fileName = segments[^1];
        if (KnownWrongFiles.TryGetValue(fileName, out var why)) return Fail(why);
        if (!fileName.Equals(ExpectedFileName, StringComparison.OrdinalIgnoreCase))
            return Fail($"Selected file is '{fileName}'. Select the game client '{ExpectedFileName}'.");

        if (segments.Length >= 2 && segments[0].Equals("Windows", StringComparison.OrdinalIgnoreCase))
            return Fail("Files inside the Windows directory are never targeted.");

        if (!probe.FileExists(path)) return Fail("The file does not exist (is the game fully installed?).");

        if (probe.FileLength(path) is { } len && len < SuspiciouslySmallBytes)
            warnings.Add($"The file is only {len / 1024 / 1024} MB, smaller than the game client is expected to be. Double-check it is not a stub.");
        string parent = segments.Length >= 2 ? segments[^2] : "";
        if (!ExpectedParents.Contains(parent, StringComparer.OrdinalIgnoreCase))
            warnings.Add($"Unusual location: the client normally lives in a '_retail_' folder (found '{parent}').");

        string normalized = char.ToUpperInvariant(path[0]) + path[1..];
        return new GamePathCheck(new ValidatedGamePath(normalized), errors, warnings);
    }
}
