using System.Collections;
using System.Numerics;
using OW2RG.Core.Net;

namespace OW2RG.Tests;

public class IpParsingTests
{
    [Theory]
    [InlineData("192.0.2.0/24", "192.0.2.0/24")]
    [InlineData("34.18.0.0/16", "34.18.0.0/16")]
    [InlineData("8.8.8.8", "8.8.8.8/32")]
    [InlineData("2600:1901:81c0::/44", "2600:1901:81c0::/44")]
    [InlineData("2001:DB8::/32", "2001:db8::/32")]
    [InlineData("0.0.0.0/0", "0.0.0.0/0")]
    [InlineData("::/0", "::/0")]
    public void Valid_cidrs_parse_canonically(string input, string expected)
    {
        Assert.True(CidrBlock.TryParse(input, out var b, out var err), err);
        Assert.Equal(expected, b.ToString());
    }

    [Theory]
    [InlineData("192.0.2.5/24")]          // host bits set
    [InlineData("34.18.5.0/16")]          // host bits set (typo that would silently widen)
    [InlineData("192.0.2.0/33")]
    [InlineData("192.0.2.0/")]
    [InlineData("192.0.2.0/024")]         // leading zero prefix
    [InlineData("1.2")]                   // IPAddress.TryParse accepts this, we must not
    [InlineData("010.0.0.0/8")]           // leading-zero octet (octal ambiguity)
    [InlineData("0x7f.0.0.1")]
    [InlineData("256.0.0.0/8")]
    [InlineData(" 1.2.3.0/24")]
    [InlineData("1.2.3.0/24 ")]
    [InlineData("fe80::1%3")]              // zone id
    [InlineData("2001:db8::/129")]
    [InlineData("")]
    [InlineData("hello")]
    [InlineData("1.2.3.4/-1")]
    public void Invalid_cidrs_are_rejected(string input)
    {
        Assert.False(CidrBlock.TryParse(input, out _, out var err));
        Assert.False(string.IsNullOrEmpty(err));
    }

    [Theory]
    [InlineData("34.18.0.0/255.255.0.0", "34.18.0.0", "34.18.255.255")]
    [InlineData("1.2.3.4", "1.2.3.4", "1.2.3.4")]
    [InlineData("157.175.0.0-157.175.255.255", "157.175.0.0", "157.175.255.255")]
    [InlineData("1.2.3.4/24", "1.2.3.0", "1.2.3.255")] // Windows semantics: subnet containing the address
    public void Windows_formats_parse_leniently(string token, string start, string end)
    {
        Assert.True(AddressListParser.TryParseToken(token, out var iv, out var err), err);
        Assert.Equal(start, IpCodec.Format(iv.Family, iv.Start));
        Assert.Equal(end, IpCodec.Format(iv.Family, iv.End));
    }

    [Fact]
    public void Keywords_and_wildcards_are_reported_never_expanded()
    {
        var r = AddressListParser.Parse("*");
        Assert.True(r.ContainsWildcardOrKeyword);
        Assert.False(r.Success);
        Assert.True(r.Set.IsEmpty);
        Assert.False(AddressListParser.Parse("LocalSubnet,1.2.3.0/24").Success);
    }

    [Fact]
    public void Non_contiguous_mask_is_rejected()
    {
        Assert.False(AddressListParser.TryParseToken("10.0.0.0/255.0.255.0", out _, out _));
    }
}

public class IntervalSetTests
{
    private static IpSet S(params string[] cidrs) => IpSet.From(cidrs.Select(CidrBlock.Parse));
    private static string[] C(IpSet s) => s.ToCidrs().Select(c => c.ToString()).ToArray();

    [Fact]
    public void Spec_example_subtracts_exactly()
    {
        var me = S("192.0.2.0/24");
        var eu = S("192.0.2.64/26");
        Assert.Equal(["192.0.2.0/26", "192.0.2.128/25"], C(me.Subtract(eu)));
    }

    [Fact]
    public void Adjacent_and_overlapping_ranges_merge_without_adding_addresses()
    {
        var s = S("10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24", "10.0.1.0/25");
        Assert.Equal(["10.0.0.0/23"], C(s));
        Assert.Equal(new BigInteger(512), s.AddressCountV4);

        var gap = S("10.0.0.0/24", "10.0.2.0/24");
        Assert.Equal(["10.0.0.0/24", "10.0.2.0/24"], C(gap)); // never bridged into 10.0.0.0/22
        Assert.Equal(new BigInteger(512), gap.AddressCountV4);
    }

    [Fact]
    public void Unaligned_interval_gets_minimal_exact_cover()
    {
        Assert.True(AddressListParser.TryParseToken("10.0.0.1-10.0.0.6", out var iv, out _));
        var set = IpSet.From([iv]);
        Assert.Equal(["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"], C(set));
    }

    [Fact]
    public void Families_are_isolated()
    {
        var v4 = S("192.0.2.0/24");
        var v6 = S("2001:db8::/32");
        var both = v4.Union(v6);
        Assert.Equal(v4.V4, both.V4);
        Assert.Equal(v6.V6, both.V6);
        Assert.True(both.Subtract(v6).V6.IsEmpty);
        Assert.Equal(v4.V4, both.Subtract(v6).V4);
        Assert.False(v4.Overlaps(v6));
        Assert.Throws<ArgumentException>(() => v4.V4.Union(v6.V6));
    }

    [Fact]
    public void Edges_of_address_space_are_handled()
    {
        var all4 = S("0.0.0.0/0");
        Assert.Equal(["0.0.0.0/0"], C(all4));
        Assert.Equal(["255.255.255.255/32"], C(all4.Subtract(S("0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4", "240.0.0.0/5",
            "248.0.0.0/6", "252.0.0.0/7", "254.0.0.0/8", "255.0.0.0/9", "255.128.0.0/10", "255.192.0.0/11", "255.224.0.0/12",
            "255.240.0.0/13", "255.248.0.0/14", "255.252.0.0/15", "255.254.0.0/16", "255.255.0.0/17", "255.255.128.0/18",
            "255.255.192.0/19", "255.255.224.0/20", "255.255.240.0/21", "255.255.248.0/22", "255.255.252.0/23", "255.255.254.0/24",
            "255.255.255.0/25", "255.255.255.128/26", "255.255.255.192/27", "255.255.255.224/28", "255.255.255.240/29",
            "255.255.255.248/30", "255.255.255.252/31", "255.255.255.254/32"))));
        var all6 = S("::/0");
        Assert.Equal(["::/0"], C(all6));
        Assert.Equal(BigInteger.Pow(2, 128), all6.AddressCountV6);
        Assert.Equal(["::/1"], C(all6.Subtract(S("8000::/1"))));
        var top = S("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127");
        Assert.True(all6.Subtract(top).V6.Intervals[^1].End < UInt128.MaxValue);
    }

    [Fact]
    public void Ipv6_subtraction_is_exact()
    {
        var a = S("2001:db8::/32");
        var b = S("2001:db8:8000::/33");
        Assert.Equal(["2001:db8::/33"], C(a.Subtract(b)));
    }
}

/// <summary>
/// Property-style tests: random sets inside a small IPv4 universe are checked against a brute-force bitmap,
/// for every operation and for the CIDR cover (exact + minimal).
/// </summary>
public class IntervalSetPropertyTests
{
    private const uint Base = 0x0A000000; // 10.0.0.0
    private const int Universe = 4096;    // 10.0.0.0 – 10.0.15.255

    private static (IpSet Set, BitArray Bits) RandomSet(Random rng)
    {
        var bits = new BitArray(Universe);
        var blocks = new List<CidrBlock>();
        int n = rng.Next(0, 8);
        for (int i = 0; i < n; i++)
        {
            int prefix = rng.Next(20, 33);
            int size = 1 << (32 - prefix);
            int start = rng.Next(0, Universe / size) * size;
            blocks.Add(new CidrBlock(IpFamily.V4, Base + (uint)start, prefix));
            for (int k = start; k < start + size; k++) bits[k] = true;
        }
        return (IpSet.From(blocks), bits);
    }

    private static BitArray ToBits(IpSet set)
    {
        var bits = new BitArray(Universe);
        foreach (var iv in set.V4.Intervals)
        {
            for (UInt128 a = iv.Start; a <= iv.End; a++)
            {
                int idx = (int)(a - Base);
                Assert.InRange(idx, 0, Universe - 1);
                bits[idx] = true;
            }
        }
        return bits;
    }

    private static void AssertSame(BitArray expected, IpSet actual)
    {
        var got = ToBits(actual);
        for (int i = 0; i < Universe; i++) Assert.True(expected[i] == got[i], $"bit {i} differs");
    }

    [Fact]
    public void Union_subtract_intersect_match_bruteforce()
    {
        var rng = new Random(20261107);
        for (int round = 0; round < 400; round++)
        {
            var (a, ab) = RandomSet(rng);
            var (b, bb) = RandomSet(rng);
            AssertSame(new BitArray(ab).Or(bb), a.Union(b));
            AssertSame(new BitArray(ab).And(new BitArray(bb).Not()), a.Subtract(b));
            AssertSame(new BitArray(ab).And(bb), a.Intersect(b));
            Assert.Equal(a.Subtract(b).IsEmpty, a.IsSubsetOf(b));
        }
    }

    [Fact]
    public void Block_set_invariants_hold_for_random_catalogs()
    {
        var rng = new Random(42);
        for (int round = 0; round < 400; round++)
        {
            var (candidate, _) = RandomSet(rng);
            var (protectedEu, _) = RandomSet(rng);
            var block = candidate.Subtract(protectedEu);
            Assert.False(block.Overlaps(protectedEu));       // netBlockSet ∩ protectedEU = ∅
            Assert.True(block.IsSubsetOf(candidate));         // netBlockSet ⊆ candidate
            Assert.Equal(candidate, block.Union(candidate.Intersect(protectedEu))); // nothing lost but the carve-out
        }
    }

    [Fact]
    public void Cidr_cover_is_exact_and_minimal()
    {
        var rng = new Random(7);
        for (int round = 0; round < 400; round++)
        {
            var (a, _) = RandomSet(rng);
            var (b, _) = RandomSet(rng);
            var set = a.Subtract(b);
            var cidrs = set.ToCidrs();
            Assert.Equal(set, IpSet.From(cidrs)); // exact: never broader, never narrower
            for (int i = 1; i < cidrs.Count; i++)
            {
                Assert.True(cidrs[i - 1].Last < cidrs[i].First, "CIDRs overlap or are unsorted");
                // minimal: two equal-size aligned siblings would have been merged into their parent
                var p = cidrs[i - 1];
                var q = cidrs[i];
                if (p.PrefixLength == q.PrefixLength && p.PrefixLength > 0)
                {
                    UInt128 parentMask = IpFamilyInfo.LowMask(32 - p.PrefixLength + 1);
                    bool siblings = (p.Network & ~parentMask) == (q.Network & ~parentMask) && p.Last + 1 == q.First;
                    Assert.False(siblings, $"{p} and {q} should have been merged");
                }
            }
        }
    }
}
