using System.Text.Json;
using OW2RG.Core.Net;

namespace OW2RG.Core.Catalog;

/// <summary>
/// Reviewed, human-maintained mapping from Overwatch datacenter codes to where they are hosted.
/// The catalog is generated from this map plus the official provider feeds, so every address in the
/// catalog is reproducible and traceable.
/// </summary>
public sealed class DatacenterMapDocument
{
    public required int SchemaVersion { get; init; }
    public required string MapVersion { get; init; }
    public string? Description { get; init; }
    public required List<DatacenterMapEntry> Datacenters { get; init; }
}

public sealed class DatacenterMapEntry
{
    public required string Id { get; init; }
    public string? DatacenterCode { get; init; }
    public required string Name { get; init; }
    public required Region Region { get; init; }
    public string? Country { get; init; }
    /// <summary>aws | google-cloud | blizzard</summary>
    public required string Provider { get; init; }
    /// <summary>Provider region names; a trailing '*' matches a prefix (e.g. "europe-*").</summary>
    public List<string> ProviderRegions { get; init; } = [];
    /// <summary>For AWS: which services count (normally EC2). Null = all.</summary>
    public List<string>? ProviderServices { get; init; }
    /// <summary>Addresses not covered by a provider feed (e.g. Blizzard-owned networks).</summary>
    public List<string> StaticCidrs { get; init; } = [];
    public DateTimeOffset? StaticCidrsCheckedAtUtc { get; init; }
    /// <summary>explicit = a source names this provider region (or its ranges sit inside it); inferred = weaker; not-applicable = safety net.</summary>
    public required string CodeMapping { get; init; }
    public List<SourceReference> MappingSources { get; init; } = [];
    public bool ExcludeFromBlocking { get; init; }
    public string? ExclusionReason { get; init; }
    public bool ProtectOnly { get; init; }
    public bool Enabled { get; init; } = true;
    public string? Notes { get; init; }
}

public sealed record CatalogBuildResult(ServerCatalogDocument Catalog, IReadOnlyList<string> Report);

public static class CatalogBuilder
{
    public static DatacenterMapDocument ParseMap(ReadOnlySpan<byte> json)
    {
        if (json.Length > CatalogJson.MaxCatalogBytes) throw new CatalogLoadException("Datacenter map too large.");
        try
        {
            return JsonSerializer.Deserialize<DatacenterMapDocument>(json, CatalogJson.ReadOptions)
                   ?? throw new CatalogLoadException("Datacenter map is null.");
        }
        catch (JsonException ex)
        {
            throw new CatalogLoadException("Datacenter map JSON is invalid: " + ex.Message, ex);
        }
    }

    public static CatalogBuildResult Build(DatacenterMapDocument map, IReadOnlyList<ProviderFeed> feeds, DateTimeOffset retrievedAt, string generator)
    {
        var report = new List<string>();
        var entries = new List<CatalogEntryDocument>();

        foreach (var dc in map.Datacenters)
        {
            var blocks = new List<CidrBlock>();
            int feedPrefixes = 0;
            ProviderFeed? usedFeed = null;
            if (dc.Provider is "aws" or "google-cloud" && dc.ProviderRegions.Count > 0)
            {
                usedFeed = feeds.FirstOrDefault(f => f.Provider == dc.Provider);
                if (usedFeed is null)
                {
                    report.Add($"{dc.Id}: no {dc.Provider} feed supplied; entry has no feed addresses.");
                }
                else
                {
                    foreach (var p in usedFeed.Prefixes)
                    {
                        if (!dc.ProviderRegions.Any(r => RegionMatches(r, p.Region))) continue;
                        if (dc.ProviderServices is { Count: > 0 } svcs && !svcs.Contains(p.Service, StringComparer.Ordinal)) continue;
                        blocks.Add(p.Block);
                        feedPrefixes++;
                    }
                    if (feedPrefixes == 0) report.Add($"WARNING {dc.Id}: {dc.Provider} feed has no prefixes for {string.Join(",", dc.ProviderRegions)} (region renamed or retired?).");
                }
            }
            foreach (var s in dc.StaticCidrs)
            {
                if (!CidrBlock.TryParse(s, out var b, out var err)) throw new CatalogLoadException($"{dc.Id}: invalid static CIDR '{s}': {err}");
                blocks.Add(b);
            }

            var set = IpSet.From(blocks);
            var cidrs = set.ToCidrs().Select(c => c.ToString()).ToList();

            Confidence confidence;
            if (feedPrefixes > 0 && (dc.ProtectOnly || dc.CodeMapping == "explicit") && (dc.ProtectOnly || dc.MappingSources.Count > 0))
                confidence = Confidence.Corroborated;
            else if (cidrs.Count > 0 && dc.MappingSources.Count > 0)
                confidence = Confidence.Community;
            else
                confidence = Confidence.Unverified;

            var sources = new List<SourceReference>();
            if (usedFeed is not null && feedPrefixes > 0)
            {
                sources.Add(new SourceReference
                {
                    Url = usedFeed.Url,
                    Kind = "official-provider-feed",
                    RetrievedAtUtc = retrievedAt,
                    Note = $"{feedPrefixes} prefix(es) published by {ProviderName(dc.Provider)} for {string.Join(", ", dc.ProviderRegions)}" +
                           (dc.ProviderServices is { Count: > 0 } ? $" (service {string.Join("/", dc.ProviderServices)})" : "") +
                           $"; feed sha256 {usedFeed.Sha256[..16]}…, publisher time {usedFeed.PublisherTimestamp}.",
                });
            }
            sources.AddRange(dc.MappingSources);

            DateTimeOffset? verified = feedPrefixes > 0 ? retrievedAt : dc.StaticCidrsCheckedAtUtc;
            string method = feedPrefixes > 0
                ? (dc.StaticCidrs.Count > 0 ? "official-provider-feed+static-community-ranges" : dc.ProtectOnly ? "official-provider-feed" : "official-provider-feed+community-code-mapping")
                : "community-list";

            entries.Add(new CatalogEntryDocument
            {
                Id = dc.Id,
                DatacenterCode = dc.DatacenterCode,
                Name = dc.Name,
                Region = dc.Region,
                Country = dc.Country,
                Hosting = new HostingInfo { Provider = dc.Provider, ProviderRegions = dc.ProviderRegions.Select(r => r.TrimEnd('*').TrimEnd('-')).Distinct().ToList() },
                Cidrs = cidrs,
                Confidence = confidence,
                Sources = sources,
                LastVerifiedAtUtc = verified,
                AcquisitionMethod = method,
                ExcludeFromBlocking = dc.ExcludeFromBlocking,
                ExclusionReason = dc.ExclusionReason,
                ProtectOnly = dc.ProtectOnly,
                Enabled = dc.Enabled,
                Notes = dc.Notes,
            });
            report.Add($"{dc.Id,-28} {dc.Region,-3} {confidence,-12} {cidrs.Count,5} CIDR(s)  ({feedPrefixes} feed prefixes, {dc.StaticCidrs.Count} static)");
        }

        var catalog = new ServerCatalogDocument
        {
            SchemaVersion = CatalogValidator.SupportedSchemaVersion,
            CatalogVersion = $"{retrievedAt:yyyy.MM.dd}-map{map.MapVersion}",
            GeneratedAtUtc = retrievedAt,
            Generator = generator,
            Description = "Generated by OW2 EU Region Guard from the official AWS and Google Cloud IP range feeds plus a reviewed datacenter map. " +
                          "Blizzard publishes no official list; datacenter-code mappings are community-reported. Verify in game with NetGraph (Ctrl+Shift+N).",
            Feeds = feeds.Select(f => f.ToSnapshot(retrievedAt)).ToList(),
            Entries = entries,
        };
        return new CatalogBuildResult(catalog, report);
    }

    private static bool RegionMatches(string pattern, string region) =>
        pattern.EndsWith('*') ? region.StartsWith(pattern[..^1], StringComparison.Ordinal) : string.Equals(pattern, region, StringComparison.Ordinal);

    private static string ProviderName(string p) => p switch { "aws" => "AWS", "google-cloud" => "Google Cloud", _ => p };
}
