using System.Text.Json.Serialization;

namespace OW2RG.Core.Catalog;

/// <summary>Hosting region taxonomy. Names match the JSON values exactly.</summary>
public enum Region
{
    EU,
    ME,
    NA,
    AS,
    OC,
    SA,
    UNKNOWN,
}

/// <summary>
/// How much the catalog trusts an entry.
/// observed     – matched against a live in-game NetGraph observation (datacenter code + IP + time).
/// corroborated – at least two reasonably independent sources agree (e.g. an official cloud-provider
///                feed confirms the location of the addresses and a community source ties the
///                datacenter code to that provider region).
/// community    – a single unconfirmed community list.
/// unverified   – illustration or unknown; never enforced.
/// </summary>
public enum Confidence
{
    [JsonStringEnumMemberName("observed")] Observed = 3,
    [JsonStringEnumMemberName("corroborated")] Corroborated = 2,
    [JsonStringEnumMemberName("community")] Community = 1,
    [JsonStringEnumMemberName("unverified")] Unverified = 0,
}

public sealed class ServerCatalogDocument
{
    public required int SchemaVersion { get; init; }
    public required string CatalogVersion { get; init; }
    public required DateTimeOffset GeneratedAtUtc { get; init; }
    public string? Generator { get; init; }
    public string? Description { get; init; }
    public List<FeedSnapshot> Feeds { get; init; } = [];
    public required List<CatalogEntryDocument> Entries { get; init; }
}

/// <summary>Fingerprint of an upstream data feed used to build the catalog.</summary>
public sealed class FeedSnapshot
{
    public required string Id { get; init; }
    public required string Url { get; init; }
    public DateTimeOffset? RetrievedAtUtc { get; init; }
    public string? PublisherTimestamp { get; init; }
    public string? Sha256 { get; init; }
    public int? PrefixCount { get; init; }
}

public sealed class SourceReference
{
    public required string Url { get; init; }
    /// <summary>official-provider-feed | community-list | netgraph-observation | registry-whois | other</summary>
    public required string Kind { get; init; }
    public DateTimeOffset? RetrievedAtUtc { get; init; }
    public string? Note { get; init; }
}

public sealed class HostingInfo
{
    /// <summary>aws | google-cloud | blizzard | other | unknown</summary>
    public required string Provider { get; init; }
    public List<string> ProviderRegions { get; init; } = [];
}

public sealed class CatalogEntryDocument
{
    public required string Id { get; init; }
    public string? DatacenterCode { get; init; }
    public required string Name { get; init; }
    public required Region Region { get; init; }
    public string? Country { get; init; }
    public HostingInfo? Hosting { get; init; }
    public required List<string> Cidrs { get; init; }
    public required Confidence Confidence { get; init; }
    public List<SourceReference> Sources { get; init; } = [];
    /// <summary>When these addresses were last checked against their sources.</summary>
    public DateTimeOffset? LastVerifiedAtUtc { get; init; }
    /// <summary>When a live in-game NetGraph observation last matched this entry.</summary>
    public DateTimeOffset? ObservedAtUtc { get; init; }
    public string? AcquisitionMethod { get; init; }
    /// <summary>
    /// True for networks that must never be auto-blocked even when their region is targeted, e.g.
    /// Blizzard-owned address space that may also carry login, voice or other backend services.
    /// </summary>
    public bool ExcludeFromBlocking { get; init; }
    public string? ExclusionReason { get; init; }
    /// <summary>Safety-net entries only protect (subtract) addresses and describe no single datacenter.</summary>
    public bool ProtectOnly { get; init; }
    public bool Enabled { get; init; } = true;
    public string? Notes { get; init; }
}
