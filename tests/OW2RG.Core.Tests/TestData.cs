using OW2RG.Core.Catalog;
using OW2RG.Core.Game;

namespace OW2RG.Tests;

/// <summary>Builders for synthetic catalogs. Uses RFC 5737 / RFC 3849 documentation addresses only.</summary>
internal static class TestData
{
    public static readonly DateTimeOffset Now = new(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);
    public const string GamePath = @"D:\Games\Overwatch\_retail_\Overwatch.exe";

    public static CatalogEntryDocument Entry(string id, Region region, Confidence confidence, params string[] cidrs) => new()
    {
        Id = id,
        DatacenterCode = id.Length <= 8 ? id.ToUpperInvariant().Replace("-", "") : null,
        Name = "Test " + id,
        Region = region,
        Cidrs = [.. cidrs],
        Confidence = confidence,
        Sources = confidence == Confidence.Unverified ? [] : [new SourceReference { Url = "https://github.com/owner/repo", Kind = "community-list" }],
        LastVerifiedAtUtc = Now.AddDays(-1),
    };

    public static ServerCatalogDocument Catalog(params CatalogEntryDocument[] entries) => new()
    {
        SchemaVersion = 1,
        CatalogVersion = "test-1",
        GeneratedAtUtc = Now.AddDays(-1),
        Entries = [.. entries],
    };

    public static ValidatedCatalog Validate(ServerCatalogDocument doc, bool allowDoc = true) =>
        CatalogValidator.Validate(doc, new string('a', 64), new CatalogValidationOptions { Now = Now, AllowDocumentationRanges = allowDoc });

    public static ValidatedGamePath Game(string path = GamePath)
    {
        var check = GamePathValidator.Validate(path, new FakeFiles(path));
        Assert.True(check.IsValid, string.Join("; ", check.Errors));
        return check.Path!;
    }

    public sealed class FakeFiles(params string[] existing) : IFileProbe
    {
        public long Size { get; init; } = 80L * 1024 * 1024;
        public bool FileExists(string path) => existing.Contains(path, StringComparer.OrdinalIgnoreCase);
        public long? FileLength(string path) => FileExists(path) ? Size : null;
    }
}
