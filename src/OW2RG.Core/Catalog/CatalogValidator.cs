using System.Text.RegularExpressions;
using OW2RG.Core.Net;

namespace OW2RG.Core.Catalog;

public enum IssueSeverity { Info, Warning, Error }

public sealed record CatalogIssue(IssueSeverity Severity, string Code, string Message, string? EntryId = null)
{
    public override string ToString() => EntryId is null ? $"[{Severity}] {Code}: {Message}" : $"[{Severity}] {Code} ({EntryId}): {Message}";
}

/// <summary>Addresses claimed by entries of two different regions.</summary>
public sealed record RegionConflict(string EntryA, Region RegionA, string EntryB, Region RegionB, IpSet Overlap);

public sealed record CatalogValidationOptions
{
    public required DateTimeOffset Now { get; init; }
    /// <summary>Entries not verified for longer than this are flagged stale (a warning, not proof of invalidity).</summary>
    public TimeSpan StaleAfter { get; init; } = TimeSpan.FromDays(30);
    /// <summary>Tests only: permit RFC 5737 / RFC 3849 documentation ranges.</summary>
    public bool AllowDocumentationRanges { get; init; }
    public int MaxEntries { get; init; } = 1000;
    public int MaxCidrsPerEntry { get; init; } = 20_000;
    public int MaxCidrsTotal { get; init; } = 60_000;
    public int MinIpv4Prefix { get; init; } = 8;
    public int MinIpv6Prefix { get; init; } = 16;
}

public sealed class ValidatedEntry
{
    internal ValidatedEntry(CatalogEntryDocument doc, IReadOnlyList<CidrBlock> cidrs, bool isStale, TimeSpan? age)
    {
        Document = doc;
        Cidrs = cidrs;
        Addresses = IpSet.From(cidrs);
        IsStale = isStale;
        VerificationAge = age;
    }

    public CatalogEntryDocument Document { get; }
    public string Id => Document.Id;
    public Region Region => Document.Region;
    public Confidence Confidence => Document.Confidence;
    public IReadOnlyList<CidrBlock> Cidrs { get; }
    public IpSet Addresses { get; }
    public bool IsStale { get; }
    public TimeSpan? VerificationAge { get; }
    public bool HasAddresses => !Addresses.IsEmpty;
    public string DisplayName => Document.DatacenterCode is { Length: > 0 } code ? $"{code} – {Document.Name}" : Document.Name;
}

public sealed class ValidatedCatalog
{
    internal ValidatedCatalog(ServerCatalogDocument doc, string sha256, IReadOnlyList<ValidatedEntry> entries,
        IReadOnlyList<CatalogIssue> issues, IReadOnlyList<RegionConflict> conflicts, bool allowDocumentationRanges)
    {
        Document = doc;
        Sha256 = sha256;
        Entries = entries;
        Issues = issues;
        Conflicts = conflicts;
        AllowsDocumentationRanges = allowDocumentationRanges;
    }

    public ServerCatalogDocument Document { get; }
    public string Sha256 { get; }
    public IReadOnlyList<ValidatedEntry> Entries { get; }
    public IReadOnlyList<CatalogIssue> Issues { get; }
    public IReadOnlyList<RegionConflict> Conflicts { get; }
    public bool AllowsDocumentationRanges { get; }
    public bool IsUsable => Issues.All(i => i.Severity != IssueSeverity.Error);
    public IEnumerable<CatalogIssue> Errors => Issues.Where(i => i.Severity == IssueSeverity.Error);
    public IEnumerable<CatalogIssue> Warnings => Issues.Where(i => i.Severity == IssueSeverity.Warning);
}

/// <summary>
/// Validates schema, address syntax and bounds, special/reserved ranges, duplicates, provenance,
/// freshness, hostile text and cross-region conflicts. Any Error makes the whole catalog unusable:
/// a partially broken catalog is never partially enforced.
/// </summary>
public static partial class CatalogValidator
{
    public const int SupportedSchemaVersion = 1;

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,63}$")] private static partial Regex IdRegex();
    [GeneratedRegex("^[A-Z0-9]{2,8}$")] private static partial Regex CodeRegex();
    [GeneratedRegex("^[A-Z]{2}$")] private static partial Regex CountryRegex();
    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,40}$")] private static partial Regex TokenRegex();

    private static readonly HashSet<string> SourceKinds = new(StringComparer.Ordinal)
    {
        "official-provider-feed", "community-list", "netgraph-observation", "registry-whois", "other",
    };

    private static readonly HashSet<string> Providers = new(StringComparer.Ordinal)
    {
        "aws", "google-cloud", "blizzard", "other", "unknown",
    };

    public static ValidatedCatalog Validate(ServerCatalogDocument doc, string sha256, CatalogValidationOptions options)
    {
        var issues = new List<CatalogIssue>();
        void Error(string code, string msg, string? id = null) => issues.Add(new(IssueSeverity.Error, code, msg, id));
        void Warn(string code, string msg, string? id = null) => issues.Add(new(IssueSeverity.Warning, code, msg, id));

        if (doc.SchemaVersion != SupportedSchemaVersion)
            Error("schema-version", $"Unsupported schemaVersion {doc.SchemaVersion}; this app reads version {SupportedSchemaVersion}.");
        CheckText(doc.CatalogVersion, "catalogVersion", 64, required: true, issues, null);
        CheckText(doc.Generator, "generator", 200, required: false, issues, null);
        CheckText(doc.Description, "description", 4000, required: false, issues, null, multiline: true);
        if (doc.GeneratedAtUtc > options.Now.AddDays(1))
            Warn("future-timestamp", "generatedAtUtc is in the future.");
        if (options.Now - doc.GeneratedAtUtc > options.StaleAfter)
            Warn("catalog-stale", $"Catalog was generated {(int)(options.Now - doc.GeneratedAtUtc).TotalDays} days ago; consider refreshing it from the official feeds.");

        foreach (var feed in doc.Feeds ?? [])
        {
            CheckText(feed.Id, "feeds.id", 64, true, issues, null);
            if (!IsHttpsUrl(feed.Url, out var why)) Error("feed-url", $"Feed '{feed.Id}' url is not acceptable: {why}");
            if (feed.Sha256 is { } s && (s.Length != 64 || !s.All(char.IsAsciiHexDigitLower)))
                Error("feed-sha256", $"Feed '{feed.Id}' sha256 must be 64 lowercase hex characters.");
        }

        var entries = doc.Entries ?? [];
        if (entries.Count > options.MaxEntries)
        {
            Error("too-many-entries", $"{entries.Count} entries exceeds limit {options.MaxEntries}.");
            return new ValidatedCatalog(doc, sha256, [], issues, [], options.AllowDocumentationRanges);
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var codes = new Dictionary<string, string>(StringComparer.Ordinal);
        var validated = new List<ValidatedEntry>();
        int totalCidrs = 0;

        foreach (var e in entries)
        {
            string id = e.Id ?? "";
            if (!IdRegex().IsMatch(id)) { Error("entry-id", $"Entry id '{Sanitize(id)}' must match ^[a-z0-9][a-z0-9-]{{1,63}}$."); continue; }
            if (!ids.Add(id)) { Error("duplicate-id", $"Duplicate entry id '{id}'.", id); continue; }

            CheckText(e.Name, "name", 120, true, issues, id);
            CheckText(e.Notes, "notes", 2000, false, issues, id, multiline: true);
            CheckText(e.ExclusionReason, "exclusionReason", 500, false, issues, id);
            CheckText(e.AcquisitionMethod, "acquisitionMethod", 120, false, issues, id);

            if (e.DatacenterCode is { } code)
            {
                if (!CodeRegex().IsMatch(code)) Error("datacenter-code", $"Datacenter code '{Sanitize(code)}' must be 2-8 uppercase letters/digits.", id);
                else if (codes.TryGetValue(code, out var other)) Warn("duplicate-code", $"Datacenter code {code} also used by '{other}'.", id);
                else codes[code] = id;
            }
            if (e.Country is { } c && !CountryRegex().IsMatch(c)) Error("country", $"Country '{Sanitize(c)}' must be an ISO 3166-1 alpha-2 code.", id);
            if (!Enum.IsDefined(e.Region)) Error("region", "Unknown region.", id);
            if (!Enum.IsDefined(e.Confidence)) Error("confidence", "Unknown confidence.", id);

            if (e.Hosting is { } h)
            {
                if (!Providers.Contains(h.Provider)) Error("hosting-provider", $"Unknown hosting provider '{Sanitize(h.Provider)}'.", id);
                foreach (var pr in h.ProviderRegions ?? [])
                {
                    if (!TokenRegex().IsMatch(pr)) Error("provider-region", $"Provider region '{Sanitize(pr)}' is not a plain token.", id);
                }
            }

            // Provenance.
            int goodSources = 0;
            foreach (var s in e.Sources ?? [])
            {
                if (!SourceKinds.Contains(s.Kind)) Error("source-kind", $"Unknown source kind '{Sanitize(s.Kind)}'.", id);
                CheckText(s.Note, "sources.note", 500, false, issues, id);
                if (IsHttpsUrl(s.Url, out var why)) goodSources++;
                else Warn("source-url", $"Source url rejected: {why}", id);
            }
            if (e.Confidence > Confidence.Unverified && goodSources == 0)
                Error("missing-provenance", $"Confidence '{e.Confidence}' requires at least one valid https source.", id);
            if (e.Confidence == Confidence.Observed && e.ObservedAtUtc is null)
                Error("observed-without-timestamp", "Confidence 'observed' requires observedAtUtc.", id);

            // Addresses.
            var cidrList = e.Cidrs ?? [];
            if (cidrList.Count > options.MaxCidrsPerEntry)
            {
                Error("too-many-cidrs", $"{cidrList.Count} CIDRs exceeds per-entry limit {options.MaxCidrsPerEntry}.", id);
                continue;
            }
            totalCidrs += cidrList.Count;
            var blocks = new List<CidrBlock>(cidrList.Count);
            var seen = new HashSet<CidrBlock>();
            bool entryHasErrors = false;
            foreach (var raw in cidrList)
            {
                if (!CidrBlock.TryParse(raw, out var block, out var err))
                {
                    Error("invalid-cidr", $"'{Sanitize(raw)}': {err}", id);
                    entryHasErrors = true;
                    continue;
                }
                // Report every problem with this CIDR, not just the first one.
                bool bad = false;
                if (SpecialRanges.FindConflict(block, options.AllowDocumentationRanges) is { } reason)
                {
                    Error("special-range", $"{block} overlaps special-purpose space {reason}.", id);
                    bad = true;
                }
                int min = block.Family == IpFamily.V4 ? options.MinIpv4Prefix : options.MinIpv6Prefix;
                if (block.PrefixLength < min)
                {
                    Error("cidr-too-broad", $"{block} is broader than /{min} and is refused.", id);
                    bad = true;
                }
                if (bad)
                {
                    entryHasErrors = true;
                    continue;
                }
                if (!seen.Add(block)) { Warn("duplicate-cidr", $"{block} listed more than once (deduplicated).", id); continue; }
                blocks.Add(block);
            }
            if (entryHasErrors) continue;
            blocks.Sort();
            if (blocks.Count == 0 && e.Enabled)
                Warn("no-addresses", "Entry has no addresses and cannot be enforced.", id);

            // Freshness.
            DateTimeOffset? lastCheck = Max(e.LastVerifiedAtUtc, e.ObservedAtUtc);
            TimeSpan? age = lastCheck is { } t ? options.Now - t : null;
            if (lastCheck is { } lc && lc > options.Now.AddDays(1)) Warn("future-timestamp", "Verification timestamp is in the future.", id);
            bool stale = age is null || age > options.StaleAfter;
            if (blocks.Count > 0 && age is null) Warn("never-verified", "Entry has no verification timestamp.", id);
            else if (blocks.Count > 0 && stale) Warn("entry-stale", $"Last verified {(int)age!.Value.TotalDays} days ago.", id);

            validated.Add(new ValidatedEntry(e, blocks, stale, age));
        }

        if (totalCidrs > options.MaxCidrsTotal)
            Error("too-many-cidrs-total", $"{totalCidrs} CIDRs exceeds total limit {options.MaxCidrsTotal}.");

        // Cross-region conflicts: same addresses claimed by two different regions.
        var conflicts = new List<RegionConflict>();
        for (int i = 0; i < validated.Count; i++)
        {
            for (int j = i + 1; j < validated.Count; j++)
            {
                var a = validated[i];
                var b = validated[j];
                if (a.Region == b.Region) continue;
                var overlap = a.Addresses.Intersect(b.Addresses);
                if (overlap.IsEmpty) continue;
                conflicts.Add(new RegionConflict(a.Id, a.Region, b.Id, b.Region, overlap));
                var sample = overlap.ToCidrs();
                Warn("region-conflict",
                    $"{a.Id} ({a.Region}) and {b.Id} ({b.Region}) both claim {sample.Count} block(s), e.g. {sample[0]}. " +
                    "Contested addresses are never blocked.", a.Id);
            }
        }

        return new ValidatedCatalog(doc, sha256, validated, issues, conflicts, options.AllowDocumentationRanges);
    }

    private static DateTimeOffset? Max(DateTimeOffset? a, DateTimeOffset? b) =>
        a is null ? b : b is null ? a : (a > b ? a : b);

    internal static bool IsHttpsUrl(string? url, out string why)
    {
        why = "";
        if (string.IsNullOrWhiteSpace(url)) { why = "empty"; return false; }
        if (url.Length > 500) { why = "too long"; return false; }
        if (ContainsHostileChars(url)) { why = "contains control or invisible characters"; return false; }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) { why = "not an absolute URL"; return false; }
        if (uri.Scheme != Uri.UriSchemeHttps) { why = "must use https"; return false; }
        string host = uri.IdnHost.ToLowerInvariant();
        if (host is "localhost" || host.EndsWith(".invalid", StringComparison.Ordinal) || host.EndsWith(".test", StringComparison.Ordinal)
            || host.EndsWith(".example", StringComparison.Ordinal) || host is "example.com" or "example.org" or "example.net")
        {
            why = $"placeholder host '{host}'";
            return false;
        }
        if (!string.IsNullOrEmpty(uri.UserInfo)) { why = "credentials in URL"; return false; }
        return true;
    }

    private static void CheckText(string? value, string field, int maxLength, bool required, List<CatalogIssue> issues, string? id, bool multiline = false)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            if (required) issues.Add(new(IssueSeverity.Error, "missing-field", $"'{field}' is required.", id));
            return;
        }
        if (value.Length > maxLength) issues.Add(new(IssueSeverity.Error, "field-too-long", $"'{field}' exceeds {maxLength} characters.", id));
        if (ContainsHostileChars(value, allowNewlines: multiline))
            issues.Add(new(IssueSeverity.Error, "hostile-text", $"'{field}' contains control, bidi-override or invisible characters{(multiline ? "" : " (or line breaks)")}.", id));
    }

    // Written as numeric constants on purpose: literal bidi / zero-width characters in source are invisible.
    private const char BidiEmbeddingFirst = (char)0x202A, BidiEmbeddingLast = (char)0x202E;   // LRE..RLO
    private const char BidiIsolateFirst = (char)0x2066, BidiIsolateLast = (char)0x2069;       // LRI..PDI
    private const char ZeroWidthSpace = (char)0x200B, ZeroWidthNonJoiner = (char)0x200C, ZeroWidthJoiner = (char)0x200D,
        LeftToRightMark = (char)0x200E, RightToLeftMark = (char)0x200F, WordJoiner = (char)0x2060, ByteOrderMark = (char)0xFEFF,
        ArabicLetterMark = (char)0x061C;

    /// <summary>
    /// Control characters, bidirectional overrides/isolates and zero-width characters. Line breaks and tabs are only
    /// acceptable in multi-line fields (description, notes); single-line fields such as names end up in firewall rule
    /// descriptions and must stay on one line.
    /// </summary>
    public static bool ContainsHostileChars(string value, bool allowNewlines = false)
    {
        foreach (char ch in value)
        {
            if (char.IsControl(ch) && !(allowNewlines && ch is (char)10 or (char)13 or (char)9)) return true;
            if (IsInvisibleFormatting(ch)) return true;
        }
        return false;
    }

    private static bool IsInvisibleFormatting(char ch) =>
        ch is >= BidiEmbeddingFirst and <= BidiEmbeddingLast
        || ch is >= BidiIsolateFirst and <= BidiIsolateLast
        || ch is ZeroWidthSpace or ZeroWidthNonJoiner or ZeroWidthJoiner or LeftToRightMark or RightToLeftMark or WordJoiner or ByteOrderMark or ArabicLetterMark;

    private static string Sanitize(string? s)
    {
        if (s is null) return "(null)";
        return new string(s.Where(ch => !char.IsControl(ch) && !IsInvisibleFormatting(ch)).Take(60).ToArray());
    }
}
