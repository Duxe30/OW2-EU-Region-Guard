using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OW2RG.Core.Catalog;

public sealed class CatalogLoadException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Strict JSON (de)serialization for the server catalog. Unknown properties are rejected.</summary>
public static class CatalogJson
{
    public const long MaxCatalogBytes = 4 * 1024 * 1024;

    public static readonly JsonSerializerOptions ReadOptions = CreateOptions(writeIndented: false);
    public static readonly JsonSerializerOptions WriteOptions = CreateOptions(writeIndented: true);

    private static JsonSerializerOptions CreateOptions(bool writeIndented)
    {
        var o = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = 16,
            WriteIndented = writeIndented,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            NumberHandling = JsonNumberHandling.Strict,
        };
        o.Converters.Add(new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false));
        return o;
    }

    public static (ServerCatalogDocument Document, string Sha256) Parse(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.Length == 0) throw new CatalogLoadException("Catalog file is empty.");
        if (utf8Json.Length > MaxCatalogBytes)
            throw new CatalogLoadException($"Catalog file is too large ({utf8Json.Length:N0} bytes; limit {MaxCatalogBytes:N0}).");
        string sha = Convert.ToHexStringLower(SHA256.HashData(utf8Json));
        try
        {
            var doc = JsonSerializer.Deserialize<ServerCatalogDocument>(utf8Json, ReadOptions)
                      ?? throw new CatalogLoadException("Catalog JSON is null.");
            return (doc, sha);
        }
        catch (JsonException ex)
        {
            throw new CatalogLoadException($"Catalog JSON is invalid: {ex.Message}", ex);
        }
    }

    public static (ServerCatalogDocument Document, string Sha256) LoadFile(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new CatalogLoadException($"Catalog file not found: {path}");
        if (info.Length > MaxCatalogBytes)
            throw new CatalogLoadException($"Catalog file is too large ({info.Length:N0} bytes; limit {MaxCatalogBytes:N0}).");
        return Parse(File.ReadAllBytes(path));
    }

    public static string Serialize(ServerCatalogDocument doc) => JsonSerializer.Serialize(doc, WriteOptions) + "\n";
}
