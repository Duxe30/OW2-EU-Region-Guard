using System.Text.RegularExpressions;
using OW2RG.Core.Catalog;
using OW2RG.Core.Net;

namespace OW2RG.Core.Verification;

/// <summary>
/// A match datacenter the USER read from the in-game NetGraph (Ctrl+Shift+N). This is manual observation,
/// labeled as such everywhere; the app never claims to detect the match region by itself.
/// </summary>
public sealed record MatchObservation
{
    public required DateTimeOffset AtUtc { get; init; }
    public required string DatacenterCode { get; init; }
    public string? RemoteIp { get; init; }
    public int? PingMs { get; init; }
    /// <summary>custom | quickplay | arcade | competitive | other</summary>
    public string Mode { get; init; } = "custom";
    public bool InParty { get; init; }
    public string? Notes { get; init; }
    public string? ActiveProfile { get; init; }
    public string? ActivePlanHash12 { get; init; }
    public Region? InferredRegion { get; init; }
    public string? MatchedEntryId { get; init; }
    public string Method { get; init; } = "manual-netgraph";
}

public sealed record ObservationSummary(int Total, int Europe, int MiddleEast, int Other, int Unknown)
{
    public string Describe() => Total == 0
        ? "Live match region: not verified (manual NetGraph check required)."
        : $"User-reported matches: {Total} — Europe {Europe}, Middle East {MiddleEast}, other {Other}, unknown {Unknown}." +
          (Total < 5 ? " Too few matches to draw conclusions." : "");
}

public static partial class ObservationAnalyzer
{
    [GeneratedRegex("^[A-Z]{2,5}[0-9]{0,2}$")] private static partial Regex CodeRx();

    public static readonly string[] Modes = ["custom", "quickplay", "arcade", "competitive", "other"];

    public static bool TryNormalizeCode(string? input, out string code)
    {
        code = (input ?? "").Trim().ToUpperInvariant();
        return CodeRx().IsMatch(code);
    }

    /// <summary>Region from the IP (if it falls in a catalog entry), else from the datacenter code.</summary>
    public static (Region? Region, string? EntryId) Infer(string code, string? ip, ValidatedCatalog? catalog)
    {
        if (catalog is null) return (null, null);
        if (!string.IsNullOrWhiteSpace(ip) && IpCodec.TryParseStrict(ip.Trim(), out var fam, out var value))
        {
            // Prefer a specific datacenter over protect-only safety nets.
            var hit = catalog.Entries.Where(e => e.Addresses.Contains(fam, value))
                .OrderBy(e => e.Document.ProtectOnly ? 1 : 0).FirstOrDefault();
            if (hit is not null) return (hit.Region, hit.Id);
        }
        var byCode = catalog.Entries.FirstOrDefault(e => string.Equals(e.Document.DatacenterCode, code, StringComparison.OrdinalIgnoreCase));
        return byCode is null ? (null, null) : (byCode.Region, byCode.Id);
    }

    public static ObservationSummary Summarize(IEnumerable<MatchObservation> observations)
    {
        int total = 0, eu = 0, me = 0, other = 0, unknown = 0;
        foreach (var o in observations)
        {
            total++;
            switch (o.InferredRegion)
            {
                case Region.EU: eu++; break;
                case Region.ME: me++; break;
                case null or Region.UNKNOWN: unknown++; break;
                default: other++; break;
            }
        }
        return new ObservationSummary(total, eu, me, other, unknown);
    }

    /// <summary>Masks the host part for diagnostics exports: 34.18.12.7 → 34.18.x.x</summary>
    public static string MaskIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return "";
        if (!IpCodec.TryParseStrict(ip.Trim(), out var fam, out _)) return "(invalid)";
        if (fam == IpFamily.V4)
        {
            var p = ip.Trim().Split('.');
            return $"{p[0]}.{p[1]}.x.x";
        }
        var parts = ip.Trim().Split(':');
        return string.Join(':', parts.Take(2)) + ":x:x";
    }
}
