using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace OW2RG.Core.Net;

/// <summary>Address family. IPv4 and IPv6 are never mixed inside one interval or set.</summary>
public enum IpFamily
{
    V4 = 4,
    V6 = 6,
}

public static class IpFamilyInfo
{
    public static int Bits(IpFamily family) => family == IpFamily.V4 ? 32 : 128;

    public static UInt128 MaxValue(IpFamily family) =>
        family == IpFamily.V4 ? (UInt128)uint.MaxValue : UInt128.MaxValue;

    /// <summary>Mask with the low <paramref name="hostBits"/> bits set. Safe for 0..128.</summary>
    public static UInt128 LowMask(int hostBits)
    {
        if (hostBits <= 0) return UInt128.Zero;
        if (hostBits >= 128) return UInt128.MaxValue;
        return (UInt128.One << hostBits) - UInt128.One;
    }
}

/// <summary>Converts between <see cref="IPAddress"/>/text and integer address values.</summary>
public static class IpCodec
{
    public static UInt128 ToValue(IPAddress address, out IpFamily family)
    {
        family = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IpFamily.V4,
            AddressFamily.InterNetworkV6 => IpFamily.V6,
            _ => throw new ArgumentException("Only IPv4 and IPv6 addresses are supported.", nameof(address)),
        };
        UInt128 value = UInt128.Zero;
        foreach (byte b in address.GetAddressBytes())
        {
            value = (value << 8) | b;
        }
        return value;
    }

    public static IPAddress ToAddress(IpFamily family, UInt128 value)
    {
        int length = family == IpFamily.V4 ? 4 : 16;
        var bytes = new byte[length];
        for (int i = length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
        return new IPAddress(bytes);
    }

    public static string Format(IpFamily family, UInt128 value) => ToAddress(family, value).ToString();

    /// <summary>
    /// Strict address parser. IPv4 must be four decimal octets without leading zeros
    /// (rejects "1.2", "0x7f.0.0.1", "010.0.0.1" which <see cref="IPAddress.TryParse(string?, out IPAddress?)"/> accepts).
    /// IPv6 must not carry a zone/scope id.
    /// </summary>
    public static bool TryParseStrict(string? text, out IpFamily family, out UInt128 value)
    {
        family = IpFamily.V4;
        value = UInt128.Zero;
        if (string.IsNullOrEmpty(text) || text.Length > 45) return false;

        if (text.Contains(':'))
        {
            if (text.Contains('%')) return false;
            foreach (char c in text)
            {
                bool ok = c == ':' || c == '.' || char.IsAsciiHexDigit(c);
                if (!ok) return false;
            }
            if (!IPAddress.TryParse(text, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            if (v6.ScopeId != 0) return false;
            value = ToValue(v6, out family);
            return true;
        }

        var parts = text.Split('.');
        if (parts.Length != 4) return false;
        uint acc = 0;
        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3) return false;
            if (part.Length > 1 && part[0] == '0') return false;
            foreach (char c in part)
            {
                if (c is < '0' or > '9') return false;
            }
            int octet = int.Parse(part, NumberStyles.None, CultureInfo.InvariantCulture);
            if (octet > 255) return false;
            acc = (acc << 8) | (uint)octet;
        }
        family = IpFamily.V4;
        value = acc;
        return true;
    }
}

/// <summary>Inclusive integer interval of addresses in a single family.</summary>
public readonly record struct IpInterval
{
    public IpInterval(IpFamily family, UInt128 start, UInt128 end)
    {
        if (start > end) throw new ArgumentException("Interval start must be <= end.");
        if (end > IpFamilyInfo.MaxValue(family)) throw new ArgumentOutOfRangeException(nameof(end), "Interval exceeds address family range.");
        Family = family;
        Start = start;
        End = end;
    }

    public IpFamily Family { get; }
    public UInt128 Start { get; }
    public UInt128 End { get; }

    public BigInteger Count => (BigInteger)End - (BigInteger)Start + BigInteger.One;

    public override string ToString() =>
        Start == End ? IpCodec.Format(Family, Start) : $"{IpCodec.Format(Family, Start)}-{IpCodec.Format(Family, End)}";
}

/// <summary>A canonical CIDR block (no host bits set).</summary>
public readonly record struct CidrBlock : IComparable<CidrBlock>
{
    public CidrBlock(IpFamily family, UInt128 network, int prefixLength)
    {
        int bits = IpFamilyInfo.Bits(family);
        if (prefixLength < 0 || prefixLength > bits) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        if (network > IpFamilyInfo.MaxValue(family)) throw new ArgumentOutOfRangeException(nameof(network));
        if ((network & IpFamilyInfo.LowMask(bits - prefixLength)) != UInt128.Zero)
            throw new ArgumentException("CIDR network has host bits set.", nameof(network));
        Family = family;
        Network = network;
        PrefixLength = prefixLength;
    }

    public IpFamily Family { get; }
    public UInt128 Network { get; }
    public int PrefixLength { get; }

    public UInt128 First => Network;
    public UInt128 Last => Network | IpFamilyInfo.LowMask(IpFamilyInfo.Bits(Family) - PrefixLength);
    public IpInterval ToInterval() => new(Family, First, Last);
    public BigInteger Count => ToInterval().Count;

    public override string ToString() => $"{IpCodec.Format(Family, Network)}/{PrefixLength.ToString(CultureInfo.InvariantCulture)}";

    public int CompareTo(CidrBlock other)
    {
        int c = Family.CompareTo(other.Family);
        if (c != 0) return c;
        c = Network.CompareTo(other.Network);
        return c != 0 ? c : PrefixLength.CompareTo(other.PrefixLength);
    }

    /// <summary>
    /// Strict CIDR parser for catalog data: "a.b.c.d/n" or "x::/n". A bare address is accepted as a
    /// host route (/32 or /128). Host bits must be zero — a typo such as 34.18.5.0/16 is rejected
    /// instead of being silently widened.
    /// </summary>
    public static bool TryParse(string? text, out CidrBlock block, out string? error)
    {
        block = default;
        error = null;
        if (string.IsNullOrWhiteSpace(text)) { error = "empty value"; return false; }
        if (text.Length > 64) { error = "value too long"; return false; }
        if (text.Trim() != text) { error = "leading/trailing whitespace"; return false; }

        string addressPart = text;
        int? prefix = null;
        int slash = text.IndexOf('/');
        if (slash >= 0)
        {
            addressPart = text[..slash];
            string prefixPart = text[(slash + 1)..];
            if (prefixPart.Length is 0 or > 3 || !prefixPart.All(char.IsAsciiDigit) || (prefixPart.Length > 1 && prefixPart[0] == '0'))
            {
                error = "invalid prefix length";
                return false;
            }
            prefix = int.Parse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture);
        }

        if (!IpCodec.TryParseStrict(addressPart, out var family, out var value))
        {
            error = "invalid IP address";
            return false;
        }

        int bits = IpFamilyInfo.Bits(family);
        int p = prefix ?? bits;
        if (p > bits) { error = $"prefix /{p} exceeds {bits} bits"; return false; }
        if ((value & IpFamilyInfo.LowMask(bits - p)) != UInt128.Zero)
        {
            error = "host bits are set (not a canonical network address)";
            return false;
        }
        block = new CidrBlock(family, value, p);
        return true;
    }

    public static CidrBlock Parse(string text) =>
        TryParse(text, out var b, out var e) ? b : throw new FormatException($"Invalid CIDR '{text}': {e}");
}
