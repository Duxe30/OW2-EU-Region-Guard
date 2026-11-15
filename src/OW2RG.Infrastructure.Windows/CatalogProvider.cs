using System.Reflection;
using OW2RG.Core.Catalog;

namespace OW2RG.Infrastructure.Windows;

public enum CatalogOrigin { UserApproved, BesideApp, Embedded, ExplicitFile }

public sealed record LoadedCatalog(ValidatedCatalog Catalog, CatalogOrigin Origin, string Location, IReadOnlyList<string> Notes)
{
    /// <summary>Token the elevated helper uses to load exactly the same catalog the user previewed.</summary>
    public string HelperToken => Origin == CatalogOrigin.Embedded ? "embedded" : Location;
}

/// <summary>
/// Resolves which catalog is active: a user-approved refresh (%LOCALAPPDATA%\OW2RG\catalog\servers.json),
/// else data\servers.json beside the app, else the copy embedded in the binary. A broken higher-priority
/// catalog is reported and skipped, never half-used.
/// </summary>
public static class CatalogProvider
{
    public const string EmbeddedCatalog = "OW2RG.data.servers.json";
    public const string EmbeddedMap = "OW2RG.data.datacenter-map.json";

    public static CatalogValidationOptions Options() => new() { Now = DateTimeOffset.UtcNow };

    public static LoadedCatalog LoadActive()
    {
        var notes = new List<string>();
        foreach (var (origin, path) in new[]
                 {
                     (CatalogOrigin.UserApproved, AppPaths.UserCatalog),
                     (CatalogOrigin.BesideApp, Path.Combine(AppContext.BaseDirectory, "data", "servers.json")),
                 })
        {
            if (!File.Exists(path)) continue;
            try
            {
                var (doc, sha) = CatalogJson.LoadFile(path);
                var v = CatalogValidator.Validate(doc, sha, Options());
                if (v.IsUsable) return new LoadedCatalog(v, origin, path, notes);
                notes.Add($"Skipped {origin} catalog at {path}: {v.Errors.First().Message}");
            }
            catch (CatalogLoadException ex)
            {
                notes.Add($"Skipped {origin} catalog at {path}: {ex.Message}");
            }
        }
        return LoadEmbedded(notes);
    }

    public static LoadedCatalog LoadByToken(string token)
    {
        if (token == "embedded") return LoadEmbedded([]);
        if (!Path.IsPathFullyQualified(token)) throw new CatalogLoadException("Catalog path must be absolute.");
        var (doc, sha) = CatalogJson.LoadFile(token);
        return new LoadedCatalog(CatalogValidator.Validate(doc, sha, Options()), CatalogOrigin.ExplicitFile, token, []);
    }

    public static LoadedCatalog LoadEmbedded(List<string> notes)
    {
        byte[] bytes = ReadEmbedded(EmbeddedCatalog) ?? throw new CatalogLoadException("No catalog is embedded in this build.");
        var (doc, sha) = CatalogJson.Parse(bytes);
        return new LoadedCatalog(CatalogValidator.Validate(doc, sha, Options()), CatalogOrigin.Embedded, "embedded in app", notes);
    }

    public static DatacenterMapDocument LoadEmbeddedMap() =>
        CatalogBuilder.ParseMap(ReadEmbedded(EmbeddedMap) ?? throw new CatalogLoadException("No datacenter map is embedded in this build."));

    public static byte[]? ReadEmbedded(string name)
    {
        using var s = typeof(CatalogProvider).Assembly.GetManifestResourceStream(name);
        if (s is null) return null;
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>Saves a catalog the user explicitly approved. It never changes installed rules by itself.</summary>
    public static string SaveUserApproved(ServerCatalogDocument doc)
    {
        AppPaths.Ensure(AppPaths.UserCatalogDir);
        LocalJson.WriteAtomic(AppPaths.UserCatalog, CatalogJson.Serialize(doc));
        return AppPaths.UserCatalog;
    }

    public static bool RemoveUserApproved()
    {
        if (!File.Exists(AppPaths.UserCatalog)) return false;
        File.Delete(AppPaths.UserCatalog);
        return true;
    }
}

/// <summary>Downloads the two official feeds over HTTPS with strict size and time limits. Data only.</summary>
public static class FeedDownloader
{
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler { AutomaticDecompression = System.Net.DecompressionMethods.All, PooledConnectionLifetime = TimeSpan.FromMinutes(2) };
        var c = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(45) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd($"OW2RG/{Assembly.GetExecutingAssembly().GetName().Version}");
        return c;
    }

    public static async Task<byte[]> DownloadAsync(string url, CancellationToken ct)
    {
        if (url is not (CloudFeeds.AwsUrl or CloudFeeds.GoogleCloudUrl)) throw new InvalidOperationException("Only the two official feeds may be downloaded.");
        using var response = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps) throw new InvalidOperationException("Feed was not served over HTTPS.");
        if (response.Content.Headers.ContentLength is > CloudFeeds.MaxFeedBytes) throw new InvalidOperationException("Feed is larger than the safety limit.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            ms.Write(buffer, 0, read);
            if (ms.Length > CloudFeeds.MaxFeedBytes) throw new InvalidOperationException("Feed exceeded the safety limit while downloading.");
        }
        return ms.ToArray();
    }

    public static async Task<IReadOnlyList<ProviderFeed>> DownloadBothAsync(CancellationToken ct)
    {
        var aws = DownloadAsync(CloudFeeds.AwsUrl, ct);
        var gcp = DownloadAsync(CloudFeeds.GoogleCloudUrl, ct);
        await Task.WhenAll(aws, gcp).ConfigureAwait(false);
        return [CloudFeeds.ParseAws(aws.Result, out _), CloudFeeds.ParseGoogleCloud(gcp.Result, out _)];
    }
}
