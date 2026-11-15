using System.Security.Cryptography;
using System.Text.Json;
using OW2RG.Core.Net;

namespace OW2RG.Core.Catalog;

/// <summary>One prefix published by a cloud provider, tagged with the provider's own region name.</summary>
public sealed record ProviderPrefix(string Provider, string Region, string Service, CidrBlock Block);

public sealed record ProviderFeed(string Id, string Url, string Provider, string? PublisherTimestamp, string Sha256, IReadOnlyList<ProviderPrefix> Prefixes)
{
    public FeedSnapshot ToSnapshot(DateTimeOffset retrievedAt) => new()
    {
        Id = Id,
        Url = Url,
        RetrievedAtUtc = retrievedAt,
        PublisherTimestamp = PublisherTimestamp,
        Sha256 = Sha256,
        PrefixCount = Prefixes.Count,
    };
}

/// <summary>
/// Parsers for the official, publicly documented IP range feeds:
///   AWS:          https://ip-ranges.amazonaws.com/ip-ranges.json   (docs: "AWS IP address ranges")
///   Google Cloud: https://www.gstatic.com/ipranges/cloud.json      (docs: "Google Cloud IP ranges")
/// Only data is read; nothing from the feed is ever executed. Malformed prefixes are skipped and counted.
/// </summary>
public static class CloudFeeds
{
    public const string AwsUrl = "https://ip-ranges.amazonaws.com/ip-ranges.json";
    public const string GoogleCloudUrl = "https://www.gstatic.com/ipranges/cloud.json";
    public const long MaxFeedBytes = 16 * 1024 * 1024;

    public static ProviderFeed ParseAws(ReadOnlySpan<byte> json, out int skipped)
    {
        skipped = 0;
        if (json.Length > MaxFeedBytes) throw new CatalogLoadException("AWS feed too large.");
        string sha = Convert.ToHexStringLower(SHA256.HashData(json));
        using var doc = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        string? created = root.TryGetProperty("createDate", out var cd) ? cd.GetString() : null;
        var list = new List<ProviderPrefix>();
        foreach (var (arrayName, field) in new[] { ("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix") })
        {
            if (!root.TryGetProperty(arrayName, out var arr) || arr.ValueKind != JsonValueKind.Array) continue;
            foreach (var p in arr.EnumerateArray())
            {
                string? cidr = p.TryGetProperty(field, out var c) ? c.GetString() : null;
                string? region = p.TryGetProperty("region", out var r) ? r.GetString() : null;
                string? service = p.TryGetProperty("service", out var s) ? s.GetString() : null;
                if (cidr is null || region is null || service is null || !CidrBlock.TryParse(cidr, out var block, out _)) { skipped++; continue; }
                list.Add(new ProviderPrefix("aws", region, service, block));
            }
        }
        return new ProviderFeed("aws-ip-ranges", AwsUrl, "aws", created, sha, list);
    }

    public static ProviderFeed ParseGoogleCloud(ReadOnlySpan<byte> json, out int skipped)
    {
        skipped = 0;
        if (json.Length > MaxFeedBytes) throw new CatalogLoadException("Google Cloud feed too large.");
        string sha = Convert.ToHexStringLower(SHA256.HashData(json));
        using var doc = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        string? created = root.TryGetProperty("creationTime", out var ct) ? ct.GetString() : null;
        var list = new List<ProviderPrefix>();
        if (root.TryGetProperty("prefixes", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var p in arr.EnumerateArray())
            {
                string? cidr = p.TryGetProperty("ipv4Prefix", out var v4) ? v4.GetString()
                             : p.TryGetProperty("ipv6Prefix", out var v6) ? v6.GetString() : null;
                string? scope = p.TryGetProperty("scope", out var sc) ? sc.GetString() : null;
                string service = p.TryGetProperty("service", out var sv) ? sv.GetString() ?? "" : "";
                if (cidr is null || scope is null || !CidrBlock.TryParse(cidr, out var block, out _)) { skipped++; continue; }
                list.Add(new ProviderPrefix("google-cloud", scope, service, block));
            }
        }
        return new ProviderFeed("google-cloud-ip-ranges", GoogleCloudUrl, "google-cloud", created, sha, list);
    }
}
