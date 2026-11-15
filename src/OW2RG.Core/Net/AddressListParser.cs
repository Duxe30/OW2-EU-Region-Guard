using System.Globalization;

namespace OW2RG.Core.Net;

public sealed record AddressListParseResult(IpSet Set, IReadOnlyList<string> Errors, bool ContainsWildcardOrKeyword)
{
    public bool Success => Errors.Count == 0 && !ContainsWildcardOrKeyword;
}

/// <summary>
/// Lenient parser for address lists in the formats Windows Firewall stores and returns
/// (comma separated): "1.2.3.4", "1.2.3.0/24", "1.2.3.0/255.255.255.0", "1.2.3.4-1.2.3.9",
/// IPv6 equivalents, plus keywords such as "*" or "LocalSubnet" which are reported, never expanded.
/// Used for firewall read-back verification and for importing community lists.
/// Catalog data itself must use the strict <see cref="CidrBlock.TryParse"/>.
/// </summary>
public static class AddressListParser
{
    private static readonly HashSet<string> Keywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "*", "Any", "LocalSubnet", "DNS", "DHCP", "WINS", "DefaultGateway", "Internet", "Intranet",
        "IntranetRemoteAccess", "PlayToDevice", "RemoteCorpNetwork", "Ply2Renders", "CaptivePortal",
    };

    public const int MaxTokens = 100_000;

    public static AddressListParseResult Parse(string? text)
    {
        var errors = new List<string>();
        var intervals = new List<IpInterval>();
        bool keyword = false;
        if (string.IsNullOrWhiteSpace(text)) return new(IpSet.Empty, ["empty address list"], false);

        var tokens = text.Split([',', '\n', '\r', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length > MaxTokens) return new(IpSet.Empty, [$"too many entries ({tokens.Length})"], false);

        foreach (var token in tokens)
        {
            if (Keywords.Contains(token))
            {
                keyword = true;
                continue;
            }
            if (TryParseToken(token, out var iv, out var err)) intervals.Add(iv);
            else errors.Add($"'{Truncate(token)}': {err}");
        }
        return new(IpSet.From(intervals), errors, keyword);
    }

    public static bool TryParseToken(string token, out IpInterval interval, out string? error)
    {
        interval = default;
        error = null;

        int dash = token.IndexOf('-');
        if (dash > 0)
        {
            var left = token[..dash].Trim();
            var right = token[(dash + 1)..].Trim();
            if (!IpCodec.TryParseStrict(left, out var f1, out var v1) || !IpCodec.TryParseStrict(right, out var f2, out var v2))
            {
                error = "invalid range endpoint";
                return false;
            }
            if (f1 != f2) { error = "range mixes IPv4 and IPv6"; return false; }
            if (v1 > v2) { error = "range start is after range end"; return false; }
            interval = new IpInterval(f1, v1, v2);
            return true;
        }

        int slash = token.IndexOf('/');
        if (slash < 0)
        {
            if (!IpCodec.TryParseStrict(token, out var f, out var v)) { error = "invalid address"; return false; }
            interval = new IpInterval(f, v, v);
            return true;
        }

        var addr = token[..slash];
        var suffix = token[(slash + 1)..];
        if (!IpCodec.TryParseStrict(addr, out var family, out var value)) { error = "invalid address"; return false; }
        int bits = IpFamilyInfo.Bits(family);
        int prefix;
        if (suffix.Contains('.'))
        {
            if (family != IpFamily.V4 || !IpCodec.TryParseStrict(suffix, out var mf, out var mask) || mf != IpFamily.V4)
            {
                error = "invalid subnet mask";
                return false;
            }
            if (!TryMaskToPrefix((uint)mask, out prefix)) { error = "non-contiguous subnet mask"; return false; }
        }
        else
        {
            if (suffix.Length is 0 or > 3 || !suffix.All(char.IsAsciiDigit)) { error = "invalid prefix length"; return false; }
            prefix = int.Parse(suffix, NumberStyles.None, CultureInfo.InvariantCulture);
            if (prefix > bits) { error = "prefix too long"; return false; }
        }
        UInt128 hostMask = IpFamilyInfo.LowMask(bits - prefix);
        UInt128 network = value & ~hostMask & IpFamilyInfo.MaxValue(family);
        interval = new IpInterval(family, network, network | hostMask);
        return true;
    }

    public static bool TryMaskToPrefix(uint mask, out int prefix)
    {
        prefix = (int)uint.LeadingZeroCount(~mask);
        uint expected = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return expected == mask;
    }

    private static string Truncate(string s) => s.Length <= 60 ? s : s[..57] + "...";
}
