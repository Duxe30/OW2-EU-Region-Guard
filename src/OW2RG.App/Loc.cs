namespace OW2RG.App;

/// <summary>
/// UI string table. XAML binds to L[Key]; keeping every user-facing sentence here keeps wording consistent
/// between the dashboard, dialogs and the CLI's risk text.
/// </summary>
public sealed class Loc
{
    public static Loc Instance { get; } = new();

    public string this[string key] => En.TryGetValue(key, out var e) ? e : key;

    public string F(string key, params object[] args) => string.Format(this[key], args);

    private static readonly Dictionary<string, string> En = new()
    {
        ["AppTitle"] = "OW2 EU Region Guard",
        ["AppSubtitle"] = "Prefer European Overwatch 2 servers · unofficial · not endorsed by Blizzard",
        ["TabDashboard"] = "Dashboard",
        ["TabCatalog"] = "Server catalog",
        ["TabVerify"] = "Verify in game",
        ["TabDiagnostics"] = "Diagnostics",
        ["TabHelp"] = "Help & risks",

        ["CardGame"] = "GAME EXECUTABLE",
        ["Browse"] = "Browse…",
        ["Detect"] = "Detect again",
        ["GameNotSelected"] = "No valid Overwatch.exe selected",
        ["GameSource"] = "Found via: {0}",
        ["GameRunning"] = "Overwatch is running — apply from the main menu or after closing it, never during a match.",

        ["CardFirewall"] = "WINDOWS FIREWALL",
        ["FwOn"] = "Enabled · active network: {0}",
        ["FwOff"] = "OFF for the active network — rules would have no effect",
        ["FwUnavailable"] = "Firewall API unavailable",
        ["FwThirdParty"] = "Windows Firewall is bypassed: {0} is the active firewall, so rules would NOT be enforced. Turn off the Firewall component inside {0} first (this app never changes it).",
        ["AdminNo"] = "Admin: asked through UAC only when you apply or restore",
        ["AdminYes"] = "Admin: this window is already elevated",

        ["CardCatalog"] = "SERVER CATALOG",
        ["CatalogLine"] = "{0} · {1} day(s) old · {2}",
        ["CatalogQuality"] = "{0} corroborated · {1} community-only",
        ["RefreshFeeds"] = "Refresh from official feeds",
        ["UseBundled"] = "Use bundled catalog",
        ["AllowCommunity"] = "Allow community-only data (higher risk)",

        ["DesiredBehavior"] = "Desired server behavior",
        ["ProfDefaultTitle"] = "Default — no blocks",
        ["ProfDefaultDesc"] = "Removes every rule this app created. Nothing else in your firewall is touched.",
        ["ProfMeTitle"] = "Block Middle East",
        ["ProfMeBadge"] = "RECOMMENDED · LOWER RISK",
        ["ProfMeDesc"] = "Overwatch.exe cannot reach the Bahrain (MES1), Doha (GMEC1) and Dammam (GMEC2) game servers over UDP. European servers stay reachable.",
        ["ProfEuTitle"] = "Prefer Europe",
        ["ProfEuBadge"] = "BEST EFFORT · HIGHER RISK",
        ["ProfEuDesc"] = "Also blocks the known American, Asian, Oceanian and South American game servers. Still not a guarantee of Europe.",

        ["Preview"] = "Preview changes",
        ["Apply"] = "Apply profile",
        ["Restore"] = "RESTORE DEFAULT — remove all app rules",
        ["Refresh"] = "Refresh status",

        ["PreviewTitle"] = "PREVIEW",
        ["PreviewNone"] = "Press “Preview changes” to see exactly what would be written.",
        ["PreviewSummary"] = "{0} datacenter(s) · {1} network block(s) · {2} firewall rule(s) · {3} overlap(s) with Europe carved out · {4} contested left open",
        ["PreviewDefault"] = "Applying Default removes every OW2RG rule and nothing else.",
        ["NotEnforceable"] = "Cannot enforce: {0}",
        ["DryOk"] = "Windows accepted all {0} rule(s) in a dry check (nothing saved).",
        ["DryBad"] = "Windows rejected {0} rule(s) in the dry check — apply is disabled.",

        ["StatusNone"] = "No rules from this app",
        ["StatusActiveMe"] = "Active: Block Middle East",
        ["StatusActiveEu"] = "Active: Prefer Europe",
        ["StatusPartial"] = "Partial / unknown — press Restore or re-apply",
        ["StatusError"] = "Error",
        ["StatusRules"] = "{0} rule(s), {1} blocked network(s), plan {2}",
        ["OutdatedPlan"] = "Installed rules differ from the current catalog or game path — re-apply to update.",
        ["NotVerified"] = "Live match region: NOT verified — check NetGraph (Ctrl+Shift+N) in a Custom Game.",
        ["VerifiedSummary"] = "Your NetGraph reports with these rules: {0} match(es) — Europe {1}, Middle East {2}, other/unknown {3}.",

        ["RiskShort"] = "May disconnect you and can cause leaver penalties. Never test in Competitive. Influences matchmaking only — Europe is never guaranteed. Not endorsed by Blizzard.",

        ["ConfirmTitle"] = "Apply “{0}”?",
        ["ConfirmIntro"] = "These outbound UDP block rules will be added for {0} only:",
        ["ConfirmRisk1"] = "Blocking servers can disconnect you and may cause leaver penalties.",
        ["ConfirmRisk2"] = "It can only influence matchmaking. It never guarantees European servers.",
        ["ConfirmRisk3"] = "Test first in a Custom Game. Do not test in Competitive.",
        ["ConfirmRisk4"] = "Do not apply during a match; restart the game afterwards.",
        ["ConfirmRisk5"] = "This tool is unofficial and not endorsed by Blizzard.",
        ["ConfirmCheck"] = "I understand the risks and I am not in a match right now",
        ["ConfirmApply"] = "Apply (asks for administrator)",
        ["Cancel"] = "Cancel",
        ["CommunityTitle"] = "Allow community-only data?",
        ["CommunityBody"] = "Community-only entries come from a single unconfirmed list. They may be stale or wrong and can block servers you need. Use only for this catalog, after reading the Server catalog tab.",
        ["CommunityCheck"] = "I accept the higher risk for this catalog",
        ["Enable"] = "Enable",

        ["Working"] = "Working…",
        ["Cancelled"] = "Cancelled — nothing was changed.",
        ["ResultTitle"] = "Result",

        ["CatColRegion"] = "Region",
        ["CatColName"] = "Datacenter",
        ["CatColRanges"] = "Ranges",
        ["CatColConfidence"] = "Confidence",
        ["CatColVerified"] = "Last verified",
        ["CatColUse"] = "Use in current profile",
        ["CatColSources"] = "Sources",
        ["CatalogExplain"] = "Cloud datacenters come straight from Amazon's and Google's official IP-range feeds; the datacenter-code mapping is community-reported and cited per row. Europe is always protected. Blizzard-owned networks are never auto-blocked.",
        ["ReviewCatalogTitle"] = "Review refreshed catalog",
        ["ReviewCatalogIntro"] = "Built from the official AWS and Google Cloud feeds just now. Installed rules are NOT changed — you can re-apply afterwards.",
        ["UseThisCatalog"] = "Use this catalog",

        ["VerifyTitle"] = "Verify the real match datacenter",
        ["VerifyStep1"] = "1. Apply a profile while the game is closed (or at the main menu).",
        ["VerifyStep2"] = "2. Start Overwatch and join a Custom Game first — not Competitive.",
        ["VerifyStep3"] = "3. Press Ctrl+Shift+N. NetGraph shows the datacenter code (e.g. AMS1, GEN1, MES1) next to the server IP.",
        ["VerifyStep4"] = "4. Record it below. Test solo and in a party separately. One match proves nothing — collect several.",
        ["VerifyStep5"] = "5. If you cannot connect: press RESTORE DEFAULT immediately and stop queueing.",
        ["VerifyCode"] = "Datacenter code",
        ["VerifyIp"] = "Server IP (optional)",
        ["VerifyPing"] = "Ping ms (optional)",
        ["VerifyMode"] = "Mode",
        ["VerifyParty"] = "In a party",
        ["VerifySave"] = "Save observation",
        ["VerifyManual"] = "These are your manual observations. The app does not detect the match region by itself.",

        ["DiagOffline"] = "Run offline check",
        ["DiagLive"] = "Run live self-test (admin)",
        ["DiagExport"] = "Export diagnostics",
        ["DiagFolder"] = "Open data folder",
        ["DiagActivity"] = "RECENT ACTIVITY (local audit log)",
        ["DiagLiveExplain"] = "The live self-test asks your DNS server one normal question over UDP from this app, adds a temporary rule that blocks UDP from this app only, checks the answer is now blocked, removes the rule and checks it works again. Overwatch and other programs are not involved.",
        ["Copy"] = "Copy recovery command",

        ["HelpTitle"] = "How it works",
        ["Help1"] = "The app adds Windows Defender Firewall rules that are: outbound · block · UDP only · limited to Overwatch.exe · limited to the exact server networks shown in the preview. Your browser, Battle.net, Steam, Discord and Windows are never affected. Login and chat (TCP) are untouched.",
        ["Help2"] = "When the Middle East servers are unreachable for the game, the matchmaker tends to place you on the next best datacenter — usually Amsterdam (AMS1) or Finland (GEN1) from Iraq. This is influence, not control.",
        ["Help3"] = "Every European address published by Amazon or Google, plus Blizzard's Amsterdam network, is subtracted from every plan, so a European server can never be blocked by mistake.",
        ["Help4"] = "Rules stay until you press Restore Default. Emergency removal without this app (run as Administrator): scripts\\remove-own-rules.ps1 or: ow2rg-cli restore",
        ["HelpRisks"] = "RISKS",
        ["HelpNoTricks"] = "No VPN, no game-file changes, no injection, no memory reading, no packet tampering, no anti-cheat interaction.",
    };
}
