namespace OW2RG.Core.Net;

/// <summary>
/// Special-purpose address space (RFC 6890 / IANA special registries) that must never appear in a
/// production server catalog or in a firewall block rule. Documentation ranges are listed separately
/// so tests can opt into them explicitly.
/// </summary>
public static class SpecialRanges
{
    public sealed record SpecialRange(CidrBlock Block, string Reason, bool IsDocumentation);

    public static readonly IReadOnlyList<SpecialRange> All =
    [
        R("0.0.0.0/8", "\"this network\" (RFC 791)"),
        R("10.0.0.0/8", "private network (RFC 1918)"),
        R("100.64.0.0/10", "carrier-grade NAT (RFC 6598)"),
        R("127.0.0.0/8", "loopback"),
        R("169.254.0.0/16", "link-local"),
        R("172.16.0.0/12", "private network (RFC 1918)"),
        R("192.0.0.0/24", "IETF protocol assignments"),
        R("192.0.2.0/24", "documentation TEST-NET-1 (RFC 5737)", doc: true),
        R("192.88.99.0/24", "deprecated 6to4 relay anycast"),
        R("192.168.0.0/16", "private network (RFC 1918)"),
        R("198.18.0.0/15", "benchmarking (RFC 2544)"),
        R("198.51.100.0/24", "documentation TEST-NET-2 (RFC 5737)", doc: true),
        R("203.0.113.0/24", "documentation TEST-NET-3 (RFC 5737)", doc: true),
        R("224.0.0.0/4", "multicast"),
        R("240.0.0.0/4", "reserved / limited broadcast"),
        R("::/128", "unspecified address"),
        R("::1/128", "loopback"),
        R("::ffff:0:0/96", "IPv4-mapped IPv6"),
        R("64:ff9b::/96", "NAT64 well-known prefix"),
        R("100::/64", "discard-only (RFC 6666)"),
        R("2001::/23", "IETF protocol assignments"),
        R("2001:db8::/32", "documentation (RFC 3849)", doc: true),
        R("2002::/16", "6to4"),
        R("fc00::/7", "unique local addresses"),
        R("fe80::/10", "link-local"),
        R("ff00::/8", "multicast"),
    ];

    /// <summary>Every special-purpose range (documentation included).</summary>
    public static readonly IpSet AllSpecial = IpSet.From(All.Select(r => r.Block));

    /// <summary>Special-purpose ranges except RFC 5737 / RFC 3849 documentation space.</summary>
    public static readonly IpSet NonDocumentation = IpSet.From(All.Where(r => !r.IsDocumentation).Select(r => r.Block));

    public static IpSet Forbidden(bool allowDocumentationRanges) =>
        allowDocumentationRanges ? NonDocumentation : AllSpecial;

    /// <summary>Returns the reason of the first special range that <paramref name="block"/> overlaps, or null.</summary>
    public static string? FindConflict(CidrBlock block, bool allowDocumentationRanges)
    {
        var iv = block.ToInterval();
        foreach (var r in All)
        {
            if (allowDocumentationRanges && r.IsDocumentation) continue;
            if (r.Block.Family != block.Family) continue;
            if (iv.Start <= r.Block.Last && r.Block.First <= iv.End) return $"{r.Block} {r.Reason}";
        }
        return null;
    }

    private static SpecialRange R(string cidr, string reason, bool doc = false) => new(CidrBlock.Parse(cidr), reason, doc);
}
