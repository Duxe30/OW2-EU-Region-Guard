using OW2RG.Core.Catalog;

namespace OW2RG.Core.Planning;

public enum ProfileId
{
    /// <summary>No restriction from this app: every OW2RG rule is removed.</summary>
    Default,
    /// <summary>Block eligible Middle East datacenters only.</summary>
    BlockMiddleEast,
    /// <summary>Block every eligible non-European datacenter (best effort, never a guarantee).</summary>
    PreferEurope,
}

public static class Profiles
{
    public static string Code(ProfileId p) => p switch
    {
        ProfileId.Default => "default",
        ProfileId.BlockMiddleEast => "block-me",
        ProfileId.PreferEurope => "prefer-eu",
        _ => throw new ArgumentOutOfRangeException(nameof(p)),
    };

    /// <summary>Short tag used inside rule names.</summary>
    public static string Tag(ProfileId p) => p switch
    {
        ProfileId.BlockMiddleEast => "ME",
        ProfileId.PreferEurope => "EU",
        _ => "DEF",
    };

    public static bool TryParse(string? code, out ProfileId profile)
    {
        switch (code?.Trim().ToLowerInvariant())
        {
            case "default": case "restore": case "none": profile = ProfileId.Default; return true;
            case "block-me": case "me": profile = ProfileId.BlockMiddleEast; return true;
            case "prefer-eu": case "eu": profile = ProfileId.PreferEurope; return true;
            default: profile = ProfileId.Default; return false;
        }
    }

    /// <summary>Is a datacenter in <paramref name="region"/> something this profile wants to block?</summary>
    public static bool Targets(ProfileId p, Region region) => p switch
    {
        ProfileId.BlockMiddleEast => region == Region.ME,
        ProfileId.PreferEurope => region is Region.ME or Region.NA or Region.AS or Region.OC or Region.SA,
        _ => false,
    };

    public static string DisplayName(ProfileId p) => p switch
    {
        ProfileId.Default => "Default (no blocks)",
        ProfileId.BlockMiddleEast => "Block Middle East",
        ProfileId.PreferEurope => "Prefer Europe (best effort)",
        _ => p.ToString(),
    };
}
