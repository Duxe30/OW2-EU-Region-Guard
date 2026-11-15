using System.Numerics;

namespace OW2RG.Core.Net;

/// <summary>
/// Immutable, normalized set of addresses for ONE address family:
/// intervals are sorted, disjoint and never adjacent (adjacent runs are merged).
/// All operations are exact; nothing is ever widened.
/// </summary>
public sealed class IntervalSet : IEquatable<IntervalSet>
{
    private readonly IpInterval[] _items;

    private IntervalSet(IpFamily family, IpInterval[] normalizedItems)
    {
        Family = family;
        _items = normalizedItems;
    }

    public IpFamily Family { get; }
    public IReadOnlyList<IpInterval> Intervals => _items;
    public bool IsEmpty => _items.Length == 0;

    public BigInteger AddressCount
    {
        get
        {
            BigInteger total = BigInteger.Zero;
            foreach (var iv in _items) total += iv.Count;
            return total;
        }
    }

    public static IntervalSet Empty(IpFamily family) => new(family, []);

    public static IntervalSet From(IpFamily family, IEnumerable<IpInterval> intervals)
    {
        var list = new List<IpInterval>();
        foreach (var iv in intervals)
        {
            if (iv.Family != family) throw new ArgumentException("Mixed address families in one IntervalSet.");
            list.Add(iv);
        }
        return new IntervalSet(family, Normalize(family, list));
    }

    public static IntervalSet From(IpFamily family, IEnumerable<CidrBlock> blocks) =>
        From(family, blocks.Select(b => b.ToInterval()));

    private static IpInterval[] Normalize(IpFamily family, List<IpInterval> list)
    {
        if (list.Count == 0) return [];
        list.Sort(static (a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));
        UInt128 max = IpFamilyInfo.MaxValue(family);
        var result = new List<IpInterval>(list.Count) { list[0] };
        for (int i = 1; i < list.Count; i++)
        {
            var current = list[i];
            var last = result[^1];
            bool touches = last.End == max || current.Start <= last.End + UInt128.One;
            if (touches)
            {
                if (current.End > last.End) result[^1] = new IpInterval(family, last.Start, current.End);
            }
            else
            {
                result.Add(current);
            }
        }
        return result.ToArray();
    }

    private void RequireSameFamily(IntervalSet other)
    {
        if (other.Family != Family) throw new ArgumentException("Cannot combine IPv4 and IPv6 interval sets.");
    }

    public IntervalSet Union(IntervalSet other)
    {
        RequireSameFamily(other);
        if (other.IsEmpty) return this;
        if (IsEmpty) return other;
        var all = new List<IpInterval>(_items.Length + other._items.Length);
        all.AddRange(_items);
        all.AddRange(other._items);
        return new IntervalSet(Family, Normalize(Family, all));
    }

    /// <summary>Exact set difference: this \ other.</summary>
    public IntervalSet Subtract(IntervalSet other)
    {
        RequireSameFamily(other);
        if (IsEmpty || other.IsEmpty) return this;
        var b = other._items;
        var result = new List<IpInterval>();
        int j = 0;
        foreach (var a in _items)
        {
            UInt128 curStart = a.Start;
            UInt128 curEnd = a.End;
            bool alive = true;
            while (j < b.Length && b[j].End < curStart) j++;
            for (int k = j; k < b.Length && b[k].Start <= curEnd; k++)
            {
                var cut = b[k];
                if (cut.Start > curStart) result.Add(new IpInterval(Family, curStart, cut.Start - UInt128.One));
                if (cut.End >= curEnd)
                {
                    alive = false;
                    break;
                }
                curStart = cut.End + UInt128.One;
            }
            if (alive) result.Add(new IpInterval(Family, curStart, curEnd));
        }
        return new IntervalSet(Family, Normalize(Family, result));
    }

    public IntervalSet Intersect(IntervalSet other)
    {
        RequireSameFamily(other);
        if (IsEmpty || other.IsEmpty) return Empty(Family);
        var a = _items;
        var b = other._items;
        var result = new List<IpInterval>();
        int i = 0, j = 0;
        while (i < a.Length && j < b.Length)
        {
            UInt128 lo = a[i].Start > b[j].Start ? a[i].Start : b[j].Start;
            UInt128 hi = a[i].End < b[j].End ? a[i].End : b[j].End;
            if (lo <= hi) result.Add(new IpInterval(Family, lo, hi));
            if (a[i].End < b[j].End) i++; else j++;
        }
        return new IntervalSet(Family, Normalize(Family, result));
    }

    public bool IsSubsetOf(IntervalSet other) => Subtract(other).IsEmpty;
    public bool Overlaps(IntervalSet other) => !Intersect(other).IsEmpty;

    public bool Contains(UInt128 address)
    {
        int lo = 0, hi = _items.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var iv = _items[mid];
            if (address < iv.Start) hi = mid - 1;
            else if (address > iv.End) lo = mid + 1;
            else return true;
        }
        return false;
    }

    /// <summary>
    /// Minimal exact CIDR cover. Each maximal interval is decomposed greedily into the largest aligned
    /// blocks it contains; greedy is optimal for a single interval and intervals here are never adjacent,
    /// so the total is the minimum possible. The cover equals the set exactly — never broader.
    /// </summary>
    public IReadOnlyList<CidrBlock> ToCidrs()
    {
        var output = new List<CidrBlock>();
        foreach (var iv in _items) Decompose(Family, iv.Start, iv.End, output);
        return output;
    }

    internal static void Decompose(IpFamily family, UInt128 start, UInt128 end, List<CidrBlock> output)
    {
        int bits = IpFamilyInfo.Bits(family);
        UInt128 s = start;
        while (true)
        {
            int alignBits = s == UInt128.Zero ? bits : Math.Min(bits, (int)UInt128.TrailingZeroCount(s));
            UInt128 span = end - s; // length - 1
            int lengthBits = span == UInt128.MaxValue ? 128 : (int)UInt128.Log2(span + UInt128.One);
            int k = Math.Min(alignBits, lengthBits);
            output.Add(new CidrBlock(family, s, bits - k));
            UInt128 blockLast = s + IpFamilyInfo.LowMask(k);
            if (blockLast >= end) break;
            s = blockLast + UInt128.One;
        }
    }

    public bool Equals(IntervalSet? other)
    {
        if (other is null || other.Family != Family || other._items.Length != _items.Length) return false;
        for (int i = 0; i < _items.Length; i++)
        {
            if (_items[i] != other._items[i]) return false;
        }
        return true;
    }

    public override bool Equals(object? obj) => Equals(obj as IntervalSet);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Family);
        foreach (var iv in _items) { hash.Add(iv.Start); hash.Add(iv.End); }
        return hash.ToHashCode();
    }

    public override string ToString() => IsEmpty ? "(empty)" : string.Join(", ", _items);
}

/// <summary>Dual-family address set. IPv4 and IPv6 are kept in separate, isolated interval sets.</summary>
public sealed class IpSet : IEquatable<IpSet>
{
    public static readonly IpSet Empty = new(IntervalSet.Empty(IpFamily.V4), IntervalSet.Empty(IpFamily.V6));

    public IpSet(IntervalSet v4, IntervalSet v6)
    {
        if (v4.Family != IpFamily.V4 || v6.Family != IpFamily.V6) throw new ArgumentException("Family mismatch.");
        V4 = v4;
        V6 = v6;
    }

    public IntervalSet V4 { get; }
    public IntervalSet V6 { get; }
    public bool IsEmpty => V4.IsEmpty && V6.IsEmpty;

    public static IpSet From(IEnumerable<CidrBlock> blocks)
    {
        var list = blocks as IList<CidrBlock> ?? blocks.ToList();
        return new IpSet(
            IntervalSet.From(IpFamily.V4, list.Where(b => b.Family == IpFamily.V4)),
            IntervalSet.From(IpFamily.V6, list.Where(b => b.Family == IpFamily.V6)));
    }

    public static IpSet From(IEnumerable<IpInterval> intervals)
    {
        var list = intervals as IList<IpInterval> ?? intervals.ToList();
        return new IpSet(
            IntervalSet.From(IpFamily.V4, list.Where(b => b.Family == IpFamily.V4)),
            IntervalSet.From(IpFamily.V6, list.Where(b => b.Family == IpFamily.V6)));
    }

    public static IpSet UnionAll(IEnumerable<IpSet> sets)
    {
        var v4 = new List<IpInterval>();
        var v6 = new List<IpInterval>();
        foreach (var s in sets)
        {
            v4.AddRange(s.V4.Intervals);
            v6.AddRange(s.V6.Intervals);
        }
        return new IpSet(IntervalSet.From(IpFamily.V4, v4), IntervalSet.From(IpFamily.V6, v6));
    }

    public IpSet Union(IpSet other) => new(V4.Union(other.V4), V6.Union(other.V6));
    public IpSet Subtract(IpSet other) => new(V4.Subtract(other.V4), V6.Subtract(other.V6));
    public IpSet Intersect(IpSet other) => new(V4.Intersect(other.V4), V6.Intersect(other.V6));
    public bool IsSubsetOf(IpSet other) => V4.IsSubsetOf(other.V4) && V6.IsSubsetOf(other.V6);
    public bool Overlaps(IpSet other) => V4.Overlaps(other.V4) || V6.Overlaps(other.V6);

    public bool Contains(IpFamily family, UInt128 address) =>
        family == IpFamily.V4 ? V4.Contains(address) : V6.Contains(address);

    /// <summary>Minimal exact CIDR cover; IPv4 blocks first, then IPv6, each ascending.</summary>
    public IReadOnlyList<CidrBlock> ToCidrs() => [.. V4.ToCidrs(), .. V6.ToCidrs()];

    public BigInteger AddressCountV4 => V4.AddressCount;
    public BigInteger AddressCountV6 => V6.AddressCount;

    public bool Equals(IpSet? other) => other is not null && V4.Equals(other.V4) && V6.Equals(other.V6);
    public override bool Equals(object? obj) => Equals(obj as IpSet);
    public override int GetHashCode() => HashCode.Combine(V4, V6);
    public override string ToString() => $"v4[{V4}] v6[{V6}]";
}
