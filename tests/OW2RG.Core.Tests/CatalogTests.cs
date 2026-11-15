using System.Text;
using OW2RG.Core.Catalog;
using static OW2RG.Tests.TestData;

namespace OW2RG.Tests;

public class CatalogValidatorTests
{
    [Fact]
    public void Valid_catalog_has_no_errors()
    {
        var v = Validate(Catalog(Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24")));
        Assert.True(v.IsUsable, string.Join("\n", v.Issues));
        Assert.Single(v.Entries);
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("192.168.1.0/24")]
    [InlineData("127.0.0.0/8")]
    [InlineData("224.0.0.0/4")]
    [InlineData("fe80::/10")]
    [InlineData("::1/128")]
    [InlineData("100.64.0.0/10")]
    public void Reserved_ranges_are_rejected(string cidr)
    {
        var v = Validate(Catalog(Entry("me-a", Region.ME, Confidence.Corroborated, cidr)));
        Assert.False(v.IsUsable);
        Assert.Contains(v.Errors, i => i.Code == "special-range");
    }

    [Theory]
    [InlineData("192.0.2.0/24")]
    [InlineData("198.51.100.0/24")]
    [InlineData("2001:db8::/32")]
    public void Documentation_ranges_are_rejected_in_production_mode(string cidr)
    {
        var v = Validate(Catalog(Entry("me-a", Region.ME, Confidence.Corroborated, cidr)), allowDoc: false);
        Assert.False(v.IsUsable);
        Assert.True(Validate(Catalog(Entry("me-a", Region.ME, Confidence.Corroborated, cidr)), allowDoc: true).IsUsable);
    }

    [Theory]
    [InlineData("34.18.5.0/16", "invalid-cidr")]
    [InlineData("34.0.0.0/7", "cidr-too-broad")]
    [InlineData("0.0.0.0/0", "cidr-too-broad")]
    [InlineData("not-an-ip", "invalid-cidr")]
    public void Bad_cidrs_are_rejected(string cidr, string code)
    {
        var v = Validate(Catalog(Entry("me-a", Region.ME, Confidence.Corroborated, cidr)));
        Assert.Contains(v.Errors, i => i.Code == code);
    }

    [Fact]
    public void Duplicate_ids_and_duplicate_cidrs_are_handled()
    {
        var v = Validate(Catalog(
            Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24", "192.0.2.0/24"),
            Entry("me-a", Region.ME, Confidence.Corroborated, "198.51.100.0/24")));
        Assert.Contains(v.Errors, i => i.Code == "duplicate-id");
        Assert.Contains(v.Warnings, i => i.Code == "duplicate-cidr");
    }

    [Fact]
    public void Hostile_unicode_is_rejected()
    {
        var e = Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24");
        var hostile = new CatalogEntryDocument
        {
            Id = e.Id, Name = "Bahrain\u202Eevil", Region = e.Region, Cidrs = e.Cidrs, Confidence = e.Confidence, Sources = e.Sources, LastVerifiedAtUtc = e.LastVerifiedAtUtc,
        };
        Assert.Contains(Validate(Catalog(hostile)).Errors, i => i.Code == "hostile-text");
    }

    [Theory]
    [InlineData("Bahrain\nevil")]
    [InlineData("Bahrain\tevil")]
    [InlineData("Bahrain​evil")]
    public void Line_breaks_and_invisible_chars_are_rejected_in_single_line_fields(string name)
    {
        var e = Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24");
        var doc = new CatalogEntryDocument
        {
            Id = e.Id, Name = name, Region = e.Region, Cidrs = e.Cidrs, Confidence = e.Confidence, Sources = e.Sources, LastVerifiedAtUtc = e.LastVerifiedAtUtc,
        };
        Assert.Contains(Validate(Catalog(doc)).Errors, i => i.Code == "hostile-text");
    }

    [Fact]
    public void Line_breaks_are_allowed_in_notes_and_description()
    {
        var e = Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24");
        var doc = new CatalogEntryDocument
        {
            Id = e.Id, Name = e.Name, Region = e.Region, Cidrs = e.Cidrs, Confidence = e.Confidence, Sources = e.Sources, LastVerifiedAtUtc = e.LastVerifiedAtUtc,
            Notes = "line one\nline two\n\tindented",
        };
        var cat = Catalog(doc);
        var withDescription = new ServerCatalogDocument
        {
            SchemaVersion = cat.SchemaVersion, CatalogVersion = cat.CatalogVersion, GeneratedAtUtc = cat.GeneratedAtUtc, Entries = cat.Entries,
            Description = "multi\r\nline\tdescription",
        };
        var v = Validate(withDescription);
        Assert.True(v.IsUsable, string.Join("\n", v.Issues));
        Assert.DoesNotContain(v.Issues, i => i.Code == "hostile-text");
    }

    [Fact]
    public void Confidence_requires_real_https_provenance()
    {
        var e = Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24");
        var noSource = new CatalogEntryDocument
        {
            Id = e.Id, Name = e.Name, Region = e.Region, Cidrs = e.Cidrs, Confidence = e.Confidence, LastVerifiedAtUtc = e.LastVerifiedAtUtc,
            Sources = [new SourceReference { Url = "https://example.invalid/replace-with-real-source", Kind = "community-list" }],
        };
        var v = Validate(Catalog(noSource));
        Assert.Contains(v.Errors, i => i.Code == "missing-provenance");
        Assert.Contains(v.Warnings, i => i.Code == "source-url");
    }

    [Fact]
    public void Cross_region_overlaps_are_reported_as_conflicts()
    {
        var v = Validate(Catalog(
            Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24"),
            Entry("eu-a", Region.EU, Confidence.Community, "192.0.2.64/26")));
        Assert.Single(v.Conflicts);
        Assert.Contains(v.Warnings, i => i.Code == "region-conflict");
        Assert.True(v.IsUsable);
    }

    [Fact]
    public void Stale_entries_are_flagged_not_rejected()
    {
        var e = Entry("me-a", Region.ME, Confidence.Corroborated, "192.0.2.0/24");
        var old = new CatalogEntryDocument
        {
            Id = e.Id, Name = e.Name, Region = e.Region, Cidrs = e.Cidrs, Confidence = e.Confidence, Sources = e.Sources,
            LastVerifiedAtUtc = Now.AddDays(-90),
        };
        var v = Validate(Catalog(old));
        Assert.True(v.IsUsable);
        Assert.True(v.Entries[0].IsStale);
        Assert.Contains(v.Warnings, i => i.Code == "entry-stale");
    }
}

public class CatalogJsonTests
{
    private const string Minimal = """
        {"schemaVersion":1,"catalogVersion":"x","generatedAtUtc":"2026-11-07T00:00:00Z","entries":[
          {"id":"me-a","name":"A","region":"ME","cidrs":["192.0.2.0/24"],"confidence":"community",
           "sources":[{"url":"https://github.com/a/b","kind":"community-list"}]}]}
        """;

    [Fact]
    public void Minimal_catalog_round_trips()
    {
        var (doc, sha) = CatalogJson.Parse(Encoding.UTF8.GetBytes(Minimal));
        Assert.Equal(64, sha.Length);
        Assert.Equal(Region.ME, doc.Entries[0].Region);
        Assert.Equal(Confidence.Community, doc.Entries[0].Confidence);
        var again = CatalogJson.Parse(Encoding.UTF8.GetBytes(CatalogJson.Serialize(doc))).Document;
        Assert.Equal(doc.Entries[0].Cidrs, again.Entries[0].Cidrs);
        Assert.Contains("\"confidence\": \"community\"", CatalogJson.Serialize(doc));
    }

    [Fact]
    public void Unknown_properties_are_rejected()
    {
        string bad = Minimal.Replace("\"name\":\"A\"", "\"name\":\"A\",\"autoUpdateUrl\":\"https://evil\"");
        Assert.Throws<CatalogLoadException>(() => CatalogJson.Parse(Encoding.UTF8.GetBytes(bad)));
    }

    [Fact]
    public void Integer_enums_and_unknown_regions_are_rejected()
    {
        Assert.Throws<CatalogLoadException>(() => CatalogJson.Parse(Encoding.UTF8.GetBytes(Minimal.Replace("\"region\":\"ME\"", "\"region\":1"))));
        Assert.Throws<CatalogLoadException>(() => CatalogJson.Parse(Encoding.UTF8.GetBytes(Minimal.Replace("\"region\":\"ME\"", "\"region\":\"MARS\""))));
    }

    [Fact]
    public void Missing_required_fields_are_rejected()
    {
        Assert.Throws<CatalogLoadException>(() => CatalogJson.Parse(Encoding.UTF8.GetBytes(Minimal.Replace("\"cidrs\":[\"192.0.2.0/24\"],", ""))));
    }

    [Fact]
    public void Oversized_input_is_rejected_before_parsing()
    {
        var huge = new byte[CatalogJson.MaxCatalogBytes + 1];
        Assert.Throws<CatalogLoadException>(() => CatalogJson.Parse(huge));
    }

    [Fact]
    public void Comments_and_trailing_commas_are_rejected()
    {
        Assert.Throws<CatalogLoadException>(() => CatalogJson.Parse(Encoding.UTF8.GetBytes("// hi\n" + Minimal)));
        Assert.Throws<CatalogLoadException>(() => CatalogJson.Parse(Encoding.UTF8.GetBytes(Minimal.Replace("]}]}", "],}]}"))));
    }
}

public class CatalogBuilderTests
{
    private static ProviderFeed Feed(string provider, params (string Region, string Service, string Cidr)[] prefixes) =>
        new(provider + "-feed", provider == "aws" ? CloudFeeds.AwsUrl : CloudFeeds.GoogleCloudUrl, provider, "t", new string('b', 64),
            prefixes.Select(p => new ProviderPrefix(provider, p.Region, p.Service, OW2RG.Core.Net.CidrBlock.Parse(p.Cidr))).ToList());

    private static DatacenterMapDocument Map(params DatacenterMapEntry[] dcs) => new() { SchemaVersion = 1, MapVersion = "t", Datacenters = [.. dcs] };

    [Fact]
    public void Feed_addresses_with_explicit_mapping_are_corroborated_and_service_filtered()
    {
        var aws = Feed("aws", ("me-south-1", "EC2", "15.184.0.0/16"), ("me-south-1", "AMAZON", "15.0.0.0/8"), ("eu-west-1", "EC2", "34.240.0.0/13"));
        var map = Map(new DatacenterMapEntry
        {
            Id = "me-mes1", Name = "Bahrain", Region = Region.ME, Provider = "aws", ProviderRegions = ["me-south-1"], ProviderServices = ["EC2"],
            CodeMapping = "explicit", MappingSources = [new SourceReference { Url = "https://github.com/a/b", Kind = "community-list" }],
        });
        var r = CatalogBuilder.Build(map, [aws], Now, "test");
        var e = r.Catalog.Entries.Single();
        Assert.Equal(["15.184.0.0/16"], e.Cidrs);
        Assert.Equal(Confidence.Corroborated, e.Confidence);
        Assert.Equal("official-provider-feed", e.Sources[0].Kind);
        Assert.True(Validate(r.Catalog, allowDoc: false).IsUsable);
    }

    [Fact]
    public void Wildcard_regions_and_inferred_mappings()
    {
        var gcp = Feed("google-cloud", ("europe-west1", "Google Cloud", "34.76.0.0/14"), ("europe-north1", "Google Cloud", "34.88.0.0/16"), ("us-east4", "Google Cloud", "34.86.0.0/16"));
        var map = Map(
            new DatacenterMapEntry { Id = "eu-net", Name = "net", Region = Region.EU, Provider = "google-cloud", ProviderRegions = ["europe-*"], CodeMapping = "not-applicable", ProtectOnly = true },
            new DatacenterMapEntry { Id = "na-x", Name = "x", Region = Region.NA, Provider = "google-cloud", ProviderRegions = ["us-east4"], CodeMapping = "inferred",
                MappingSources = [new SourceReference { Url = "https://github.com/a/b", Kind = "community-list" }] });
        var r = CatalogBuilder.Build(map, [gcp], Now, "test");
        Assert.Equal(["34.76.0.0/14", "34.88.0.0/16"], r.Catalog.Entries[0].Cidrs);
        Assert.Equal(Confidence.Corroborated, r.Catalog.Entries[0].Confidence);
        Assert.Equal(Confidence.Community, r.Catalog.Entries[1].Confidence);
    }

    [Fact]
    public void Retired_region_yields_empty_unverified_entry_and_warning()
    {
        var gcp = Feed("google-cloud", ("europe-west1", "Google Cloud", "34.76.0.0/14"));
        var map = Map(new DatacenterMapEntry { Id = "me-gone", Name = "gone", Region = Region.ME, Provider = "google-cloud", ProviderRegions = ["me-nowhere1"], CodeMapping = "explicit",
            MappingSources = [new SourceReference { Url = "https://github.com/a/b", Kind = "community-list" }] });
        var r = CatalogBuilder.Build(map, [gcp], Now, "test");
        Assert.Empty(r.Catalog.Entries[0].Cidrs);
        Assert.Equal(Confidence.Unverified, r.Catalog.Entries[0].Confidence);
        Assert.Contains(r.Report, l => l.StartsWith("WARNING me-gone"));
    }
}
