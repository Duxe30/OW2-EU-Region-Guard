using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using OW2RG.Core.Catalog;
using OW2RG.Core.Firewall;
using OW2RG.Core.Planning;
using OW2RG.Core.Verification;
using OW2RG.Infrastructure.Windows;

namespace OW2RG.App;

public sealed record PreviewRow(string Mark, string Kind, string Region, string Name, string Reason);
public sealed record CatalogRow(string Region, string Name, int Ranges, string Confidence, string Verified, string Use, string Sources, string Notes);
public sealed record ObservationRow(string When, string Code, string Region, string Mode, string Party, string Ping, string Profile);

public sealed class MainViewModel : ObservableObject
{
    private readonly GuardEngine _engine = GuardEngine.Create();
    private readonly UserSettings _settings = UserSettings.Load();
    private LoadedCatalog? _catalog;
    private BlockPlan? _plan;
    private bool _planDryValidated;
    private OwnedState? _state;
    private FirewallEnvironment? _env;

    public MainViewModel()
    {
        _selectedProfile =Profiles.TryParse(_settings.LastProfile, out var p) && p != ProfileId.Default ? p : ProfileId.BlockMiddleEast;

        BrowseCommand = new RelayCommand(Browse, () => !IsBusy);
        DetectCommand = new AsyncCommand(DetectGameAsync, () => !IsBusy);
        PreviewCommand = new AsyncCommand(PreviewAsync, () => !IsBusy);
        ApplyCommand = new AsyncCommand(ApplyAsync, () => !IsBusy && CanApply);
        RestoreCommand = new AsyncCommand(RestoreAsync, () => !IsBusy);
        RefreshCommand = new AsyncCommand(RefreshAllAsync, () => !IsBusy);
        RefreshFeedsCommand = new AsyncCommand(RefreshFeedsAsync, () => !IsBusy);
        UseBundledCommand = new AsyncCommand(UseBundledAsync, () => !IsBusy && _catalog?.Origin == CatalogOrigin.UserApproved);
        SaveObservationCommand = new RelayCommand(SaveObservation);
        OfflineCheckCommand = new AsyncCommand(OfflineCheckAsync, () => !IsBusy);
        LiveSelfTestCommand = new AsyncCommand(LiveSelfTestAsync, () => !IsBusy);
        ExportCommand = new AsyncCommand(ExportAsync, () => !IsBusy);
        OpenFolderCommand = new RelayCommand(() => { AppPaths.Ensure(AppPaths.Root); Process.Start(new ProcessStartInfo("explorer.exe", AppPaths.Root) { UseShellExecute = false }); });
        CopyRecoveryCommand = new RelayCommand(() => Clipboard.SetText(RecoveryCommandText));
    }

    public Loc L => Loc.Instance;
    public Window? Owner { get; set; }

    // ------------------------------------------------------------------ commands
    public ICommand BrowseCommand { get; }
    public ICommand DetectCommand { get; }
    public ICommand PreviewCommand { get; }
    public ICommand ApplyCommand { get; }
    public ICommand RestoreCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand RefreshFeedsCommand { get; }
    public ICommand UseBundledCommand { get; }
    public ICommand SaveObservationCommand { get; }
    public ICommand OfflineCheckCommand { get; }
    public ICommand LiveSelfTestCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand OpenFolderCommand { get; }
    public ICommand CopyRecoveryCommand { get; }

    /// <summary>Apply is only offered when the plan is enforceable, Windows accepted the rules and the game path is valid.</summary>
    public bool CanApply => _plan is { } p && (p.Profile == ProfileId.Default || (p.IsEnforceable && _planDryValidated && GameValid));

    public string RecoveryCommandText =>
        $"powershell -ExecutionPolicy Bypass -File \"{Path.Combine(AppContext.BaseDirectory, "scripts", "remove-own-rules.ps1")}\"";

    public string VersionText => "v" + GuardEngine.AppVersion;

    // ------------------------------------------------------------------ busy / result
    private bool _isBusy;
    public bool IsBusy { get => _isBusy; private set { if (Set(ref _isBusy, value)) CommandManager.InvalidateRequerySuggested(); } }
    /// <summary>Nested/overlapping operations keep the busy indicator on until the last one finishes.</summary>
    private int _busyDepth;
    /// <summary>Monotonic preview counter: a preview that was superseded while computing discards its result.</summary>
    private int _previewVersion;
    private string _busyText = "";
    public string BusyText { get => _busyText; set => Set(ref _busyText, value); }
    private string _resultText = "";
    public string ResultText { get => _resultText; set => Set(ref _resultText, value); }
    private string _resultKind = "none";
    public string ResultKind { get => _resultKind; set => Set(ref _resultKind, value); }
    public ObservableCollection<string> ResultSteps { get; } = [];

    // ------------------------------------------------------------------ game
    private string _gamePath = "";
    public string GamePath { get => _gamePath; set => Set(ref _gamePath, value); }
    private string _gameSourceText = "";
    public string GameSourceText { get => _gameSourceText; set => Set(ref _gameSourceText, value); }
    private string _gameProblems = "";
    public string GameProblems { get => _gameProblems; set => Set(ref _gameProblems, value); }
    private bool _gameValid;
    public bool GameValid { get => _gameValid; set => Set(ref _gameValid, value); }
    private bool _gameRunning;
    public bool GameRunning { get => _gameRunning; set => Set(ref _gameRunning, value); }

    // ------------------------------------------------------------------ firewall / catalog
    private string _firewallText = "";
    public string FirewallText { get => _firewallText; set => Set(ref _firewallText, value); }
    private bool _firewallOk;
    public bool FirewallOk { get => _firewallOk; set => Set(ref _firewallOk, value); }
    private string _adminText = "";
    public string AdminText { get => _adminText; set => Set(ref _adminText, value); }
    private string _catalogLine = "";
    public string CatalogLine { get => _catalogLine; set => Set(ref _catalogLine, value); }
    private string _catalogQuality = "";
    public string CatalogQuality { get => _catalogQuality; set => Set(ref _catalogQuality, value); }
    private string _catalogNotes = "";
    public string CatalogNotes { get => _catalogNotes; set => Set(ref _catalogNotes, value); }
    public ObservableCollection<CatalogRow> CatalogRows { get; } = [];

    private bool _allowCommunity;
    public bool AllowCommunity
    {
        get => _allowCommunity;
        set
        {
            if (value == _allowCommunity) return;
            if (value)
            {
                bool ok = ConfirmWindow.Ask(Owner, L["CommunityTitle"], L["CommunityBody"], [], L["CommunityCheck"], L["Enable"], L["Cancel"], danger: true);
                if (!ok) { Raise(); return; }
                _settings.CommunityOptInCatalogSha = _catalog?.Catalog.Sha256;
            }
            else
            {
                _settings.CommunityOptInCatalogSha = null;
            }
            SaveSettings();
            _allowCommunity = value;
            Raise();
            _ = PreviewAsync();
        }
    }

    // ------------------------------------------------------------------ profile
    private ProfileId _selectedProfile;
    public bool IsDefaultSelected { get => _selectedProfile == ProfileId.Default; set { if (value) SelectProfile(ProfileId.Default); } }
    public bool IsMeSelected { get => _selectedProfile == ProfileId.BlockMiddleEast; set { if (value) SelectProfile(ProfileId.BlockMiddleEast); } }
    public bool IsEuSelected { get => _selectedProfile == ProfileId.PreferEurope; set { if (value) SelectProfile(ProfileId.PreferEurope); } }

    private void SelectProfile(ProfileId p)
    {
        if (_selectedProfile == p) return;
        _selectedProfile = p;
        Raise(nameof(IsDefaultSelected)); Raise(nameof(IsMeSelected)); Raise(nameof(IsEuSelected));
        _settings.LastProfile = Profiles.Code(p);
        SaveSettings();
        _ = PreviewAsync();
    }

    // ------------------------------------------------------------------ preview
    private string _previewSummary = "";
    public string PreviewSummary { get => _previewSummary; set => Set(ref _previewSummary, value); }
    private string _previewKind = "none";
    public string PreviewKind { get => _previewKind; set => Set(ref _previewKind, value); }
    private string _dryText = "";
    public string DryText { get => _dryText; set => Set(ref _dryText, value); }
    public ObservableCollection<PreviewRow> PreviewRows { get; } = [];
    public ObservableCollection<string> PreviewRules { get; } = [];
    public ObservableCollection<string> PreviewWarnings { get; } = [];

    // ------------------------------------------------------------------ status
    private string _statusText = "";
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }
    private string _statusKind = "none";
    public string StatusKind { get => _statusKind; set => Set(ref _statusKind, value); }
    private string _statusDetail = "";
    public string StatusDetail { get => _statusDetail; set => Set(ref _statusDetail, value); }
    private string _verificationText = "";
    public string VerificationText { get => _verificationText; set => Set(ref _verificationText, value); }
    public ObservableCollection<string> StatusProblems { get; } = [];

    // ------------------------------------------------------------------ verify
    public string VerifyCode { get; set; } = "";
    public string VerifyIp { get; set; } = "";
    public string VerifyPing { get; set; } = "";
    public string VerifyMode { get; set; } = "custom";
    public bool VerifyParty { get; set; }
    public IReadOnlyList<string> Modes => ObservationAnalyzer.Modes;
    public ObservableCollection<ObservationRow> Observations { get; } = [];
    private string _observationSummary = "";
    public string ObservationSummary { get => _observationSummary; set => Set(ref _observationSummary, value); }

    // ------------------------------------------------------------------ diagnostics
    public ObservableCollection<string> DiagLines { get; } = [];
    public ObservableCollection<string> AuditLines { get; } = [];

    // =================================================================== flows

    public async Task InitializeAsync()
    {
        await RunBusy(L["Working"], async () =>
        {
            _catalog = await Task.Run(CatalogProvider.LoadActive);
            _allowCommunity = _settings.CommunityOptInCatalogSha is { } sha && sha == _catalog.Catalog.Sha256;
            Raise(nameof(AllowCommunity));
            await DetectGameCoreAsync(preferSaved: true);
            await BuildPreviewCoreAsync();
            await RefreshStateCoreAsync();
        });
        LoadObservations();
        LoadAudit();
    }

    private async Task RefreshAllAsync() => await RunBusy(L["Working"], async () =>
    {
        _catalog = await Task.Run(CatalogProvider.LoadActive);
        await BuildPreviewCoreAsync();
        await RefreshStateCoreAsync();
        LoadAudit();
    });

    private async Task DetectGameAsync() => await RunBusy(L["Working"], async () =>
    {
        await DetectGameCoreAsync(preferSaved: false);
        await BuildPreviewCoreAsync();
        await RefreshStateCoreAsync();
    });

    private async Task DetectGameCoreAsync(bool preferSaved)
    {
        if (preferSaved && _settings.GamePath is { } saved && GuardEngine.CheckGame(saved).IsValid)
        {
            SetGame(saved, "Saved selection");
            return;
        }
        var candidates = await Task.Run(GameLocator.FindCandidates);
        var best = candidates.FirstOrDefault(c => c.Check.IsValid);
        if (best is not null)
        {
            SetGame(best.Check.Path!.FullPath, best.Source);
            return;
        }
        var hint = candidates.FirstOrDefault();
        GamePath = hint?.Path ?? "";
        GameValid = false;
        GameSourceText = hint is null ? L["GameNotSelected"] : L.F("GameSource", hint.Source);
        GameProblems = hint is null ? "" : string.Join(" ", new[] { hint.Note }.Concat(hint.Check.Errors).Where(s => !string.IsNullOrEmpty(s)));
    }

    private void SetGame(string path, string source)
    {
        var check = GuardEngine.CheckGame(path);
        GamePath = path;
        GameValid = check.IsValid;
        GameSourceText = L.F("GameSource", source);
        GameProblems = string.Join(" ", check.Errors.Concat(check.Warnings));
        if (check.IsValid)
        {
            _settings.GamePath = check.Path!.FullPath;
            SaveSettings();
        }
    }

    private void Browse()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select _retail_\\Overwatch.exe",
            Filter = "Overwatch.exe|Overwatch.exe|Programs (*.exe)|*.exe",
            CheckFileExists = true,
            DereferenceLinks = true,
        };
        if (GameValid && Path.GetDirectoryName(GamePath) is { } dir && Directory.Exists(dir)) dlg.InitialDirectory = dir;
        if (dlg.ShowDialog(Owner) != true) return;
        var check = GuardEngine.CheckGame(dlg.FileName);
        if (!check.IsValid)
        {
            MessageBox.Show(Owner!, string.Join("\n", check.Errors), L["CardGame"], MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        SetGame(check.Path!.FullPath, "Manual selection");
        _ = PreviewAsync();
    }

    /// <summary>Build the plan first, then read the firewall, so the state comparison uses the plan being shown.</summary>
    private async Task PreviewAsync() => await RunBusy(L["Working"], async () =>
    {
        await BuildPreviewCoreAsync();
        await RefreshStateCoreAsync();
    });

    private async Task BuildPreviewCoreAsync()
    {
        if (_catalog is null) return;
        var catalog = _catalog;
        var profile = _selectedProfile;
        string? game = GameValid ? GamePath : null;
        bool community = AllowCommunity;
        int version = ++_previewVersion;
        var (plan, dry) = await Task.Run(() =>
        {
            var p = _engine.BuildPlan(profile, game, community, catalog);
            var d = p.IsEnforceable && p.Rules.Count > 0 ? _engine.DryValidate(p) : [];
            return (p, d);
        });
        if (version != _previewVersion) return; // a newer preview was requested meanwhile; its result wins
        _plan = plan;
        _planDryValidated = dry.All(d => d.Accepted);

        PreviewRows.Clear();
        foreach (var d in plan.Decisions.OrderBy(d => d.Role switch { EntryRole.Target => d.Eligible ? 0 : 1, EntryRole.Protected => 2, _ => 3 }).ThenBy(d => d.Entry.Region))
        {
            string mark = d.Eligible ? "BLOCK" : d.Role == EntryRole.Protected ? "KEEP" : "—";
            string kind = d.Eligible ? "block" : d.Role == EntryRole.Protected ? "keep" : "skip";
            PreviewRows.Add(new PreviewRow(mark, kind, d.Entry.Region.ToString(), d.Entry.DisplayName, d.Reason));
        }
        PreviewRules.Clear();
        foreach (var r in plan.Rules) PreviewRules.Add($"{r.Name}  ·  {r.RemoteAddresses.Count} network(s)  ·  UDP out → {r.RemoteAddressesText}");
        PreviewWarnings.Clear();
        foreach (var w in plan.Warnings) PreviewWarnings.Add(w);

        if (plan.Profile == ProfileId.Default)
        {
            PreviewSummary = L["PreviewDefault"];
            PreviewKind = "ok";
            DryText = "";
        }
        else if (!plan.IsEnforceable)
        {
            PreviewSummary = L.F("NotEnforceable", plan.NotEnforceableReason ?? "");
            PreviewKind = "error";
            DryText = "";
        }
        else
        {
            PreviewSummary = L.F("PreviewSummary", plan.TargetDatacenterCount, plan.BlockedCidrCount, plan.Rules.Count,
                plan.RemovedByEuProtection.ToCidrs().Count, plan.RemovedAsContested.ToCidrs().Count);
            PreviewKind = "ok";
            DryText = _planDryValidated ? L.F("DryOk", dry.Count) : L.F("DryBad", dry.Count(d => !d.Accepted));
            if (!_planDryValidated) PreviewKind = "error";
        }
        UpdateStatusTexts();
        LoadCatalogRows();
        Raise(nameof(CanApply));
        CommandManager.InvalidateRequerySuggested();
    }

    private async Task RefreshStateCoreAsync()
    {
        string? game = GameValid ? GamePath : null;
        var plan = _plan;
        (_env, _state) = await Task.Run(() =>
        {
            var env = _engine.Store.ReadEnvironment();
            OwnedState st;
            try { st = _engine.ReadState(plan, game); }
            catch (Exception ex) { st = new OwnedState { State = GuardState.Error, Problems = [ex.Message] }; }
            return (env, st);
        });
        GameRunning = await Task.Run(GameLocator.IsGameRunning);
        UpdateStatusTexts();
    }

    private void UpdateStatusTexts()
    {
        if (_env is { } env)
        {
            FirewallOk = env.RulesWouldTakeEffect;
            FirewallText = !env.ApiAvailable ? L["FwUnavailable"]
                : env.ThirdPartyFirewalls.Count > 0 ? L.F("FwThirdParty", string.Join(", ", env.ThirdPartyFirewalls))
                : env.CurrentProfilesEnabled ? L.F("FwOn", FirewallEnvironment.ProfileNames(env.CurrentProfileTypes)) : L["FwOff"];
            AdminText = env.IsElevated ? L["AdminYes"] : L["AdminNo"];
        }
        if (_catalog is { } c)
        {
            var d = c.Catalog.Document;
            int age = Math.Max(0, (int)(DateTimeOffset.UtcNow - d.GeneratedAtUtc).TotalDays);
            CatalogLine = L.F("CatalogLine", d.GeneratedAtUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), age, c.Origin);
            var withAddr = c.Catalog.Entries.Where(e => e.HasAddresses && !e.Document.ProtectOnly).ToList();
            CatalogQuality = L.F("CatalogQuality", withAddr.Count(e => e.Confidence >= Confidence.Corroborated), withAddr.Count(e => e.Confidence == Confidence.Community));
            CatalogNotes = string.Join(" ", c.Notes.Concat(c.Catalog.Warnings.Where(w => w.Code is "catalog-stale").Select(w => w.Message)));
        }
        if (_state is { } s)
        {
            StatusKind = s.State switch { GuardState.NoOwnRules => "none", GuardState.Active => "active", GuardState.Partial => "partial", _ => "error" };
            StatusText = s.State switch
            {
                GuardState.NoOwnRules => L["StatusNone"],
                GuardState.Active when s.Profile == ProfileId.BlockMiddleEast => L["StatusActiveMe"],
                GuardState.Active when s.Profile == ProfileId.PreferEurope => L["StatusActiveEu"],
                GuardState.Partial => L["StatusPartial"],
                _ => L["StatusError"],
            };
            StatusDetail = s.State == GuardState.Active ? L.F("StatusRules", s.RuleCount, s.BlockedNetworkCount, s.PlanHash12 ?? "?") : "";
            StatusProblems.Clear();
            foreach (var p in s.Problems) StatusProblems.Add(p);
            if (s.State == GuardState.Active && (s.MatchesCurrentPlan == false || s.TargetsCurrentGamePath == false)) StatusProblems.Insert(0, L["OutdatedPlan"]);

            var obs = ObservationStore.Load().Where(o => s.PlanHash12 is not null && o.ActivePlanHash12 == s.PlanHash12).ToList();
            var sum = ObservationAnalyzer.Summarize(obs);
            VerificationText = s.State != GuardState.Active ? "" : sum.Total == 0 ? L["NotVerified"] : L.F("VerifiedSummary", sum.Total, sum.Europe, sum.MiddleEast, sum.Other + sum.Unknown);
        }
    }

    private async Task ApplyAsync()
    {
        await PreviewAsync();
        var plan = _plan;
        var catalog = _catalog;
        if (plan is null || catalog is null) return;

        if (plan.Profile == ProfileId.Default)
        {
            await RestoreAsync();
            return;
        }
        if (!plan.IsEnforceable || !_planDryValidated || !GameValid)
        {
            ShowResult("error", PreviewSummary, []);
            return;
        }
        if (_env is { RulesWouldTakeEffect: false } env)
        {
            ShowResult("error", string.Join(" ", env.Problems), []);
            return;
        }

        var lines = new List<string>
        {
            $"• {PreviewSummary}",
            $"• {string.Join(", ", plan.Decisions.Where(d => d.Eligible).Select(d => d.Entry.DisplayName))}",
            "",
            "⚠ " + L["ConfirmRisk1"], "⚠ " + L["ConfirmRisk2"], "⚠ " + L["ConfirmRisk3"], "⚠ " + L["ConfirmRisk4"], "⚠ " + L["ConfirmRisk5"],
        };
        if (GameRunning) lines.Insert(0, "⚠ " + L["GameRunning"]);
        string title = L.F("ConfirmTitle", plan.Profile == ProfileId.BlockMiddleEast ? L["ProfMeTitle"] : L["ProfEuTitle"]);
        if (!ConfirmWindow.Ask(Owner, title, L.F("ConfirmIntro", GamePath), lines, L["ConfirmCheck"], L["ConfirmApply"], L["Cancel"], danger: true)) return;

        string exe = Environment.ProcessPath!;
        string game = GamePath;
        bool community = AllowCommunity;
        await RunBusy(L["Working"], async () =>
        {
            var result = await Task.Run(() => _engine.Apply(exe, plan, catalog, game, community));
            ShowHelperResult(result);
            await RefreshStateCoreAsync();
            LoadAudit();
        });
    }

    private async Task RestoreAsync()
    {
        string exe = Environment.ProcessPath!;
        await RunBusy(L["Working"], async () =>
        {
            var result = await Task.Run(() => _engine.Restore(exe));
            ShowHelperResult(result);
            await RefreshStateCoreAsync();
            LoadAudit();
        });
    }

    private async Task RefreshFeedsAsync()
    {
        if (_catalog is null) return;
        (CatalogBuildResult Build, ValidatedCatalog Validated)? built = null;
        string? error = null;
        await RunBusy(L["Working"], async () =>
        {
            try { built = await GuardEngine.BuildCatalogFromFeedsAsync(CancellationToken.None); }
            catch (Exception ex) { error = ex.Message; }
        });
        if (error is not null || built is null) { ShowResult("error", error ?? "Download failed.", []); return; }
        var (build, validated) = built.Value;
        if (!validated.IsUsable)
        {
            ShowResult("error", "Refreshed catalog failed validation: " + string.Join(" | ", validated.Errors.Take(3).Select(e => e.Message)), []);
            return;
        }
        var diff = GuardEngine.DiffCatalogs(_catalog.Catalog, validated);
        var lines = diff.Concat([""]).Concat(build.Catalog.Feeds.Select(f => $"{f.Id}: {f.PrefixCount} prefixes · published {f.PublisherTimestamp} · sha256 {f.Sha256?[..16]}…")).ToList();
        if (!ConfirmWindow.Ask(Owner, L["ReviewCatalogTitle"], L["ReviewCatalogIntro"], lines, null, L["UseThisCatalog"], L["Cancel"], danger: false)) return;
        CatalogProvider.SaveUserApproved(build.Catalog);
        await RefreshAllAsync();
        ShowResult("ok", $"Catalog {build.Catalog.CatalogVersion} saved. Installed rules were not changed.", []);
    }

    private async Task UseBundledAsync()
    {
        CatalogProvider.RemoveUserApproved();
        await RefreshAllAsync();
    }

    private void SaveObservation()
    {
        if (!ObservationAnalyzer.TryNormalizeCode(VerifyCode, out var code)) { ShowResult("error", "Datacenter code should look like AMS1, GEN1, MES1, GMEC2.", []); return; }
        string? ip = string.IsNullOrWhiteSpace(VerifyIp) ? null : VerifyIp.Trim();
        if (ip is not null && !Core.Net.IpCodec.TryParseStrict(ip, out _, out _)) { ShowResult("error", "That IP address is not valid.", []); return; }
        int? ping = int.TryParse(VerifyPing, NumberStyles.None, CultureInfo.InvariantCulture, out var pv) && pv < 2000 ? pv : null;
        var (region, entry) = ObservationAnalyzer.Infer(code, ip, _catalog?.Catalog);
        var list = ObservationStore.Load();
        list.Add(new MatchObservation
        {
            AtUtc = DateTimeOffset.UtcNow, DatacenterCode = code, RemoteIp = ip, PingMs = ping, Mode = VerifyMode, InParty = VerifyParty,
            ActiveProfile = _state?.Profile is { } p ? Profiles.Code(p) : "none", ActivePlanHash12 = _state?.PlanHash12,
            InferredRegion = region, MatchedEntryId = entry,
        });
        ObservationStore.Save(list);
        VerifyCode = VerifyIp = VerifyPing = "";
        Raise(nameof(VerifyCode)); Raise(nameof(VerifyIp)); Raise(nameof(VerifyPing));
        LoadObservations();
        UpdateStatusTexts();
        ShowResult("ok", $"{code} → {region?.ToString() ?? "?"} saved.", []);
    }

    private async Task OfflineCheckAsync() => await RunBusy(L["Working"], async () =>
    {
        var report = await Task.Run(() => SelfTest.RunOffline(_engine.Store));
        DiagLines.Clear();
        foreach (var l in report.Lines()) DiagLines.Add(l);
        var cands = await Task.Run(GameLocator.FindCandidates);
        foreach (var c in cands) DiagLines.Add($"[{(c.Check.IsValid ? "OK" : "--")}] {c.Source}: {c.Path} {c.Note}");
        if (_catalog is not null) foreach (var i in _catalog.Catalog.Issues.Take(20)) DiagLines.Add(i.ToString());
    });

    private async Task LiveSelfTestAsync()
    {
        string exe = Environment.ProcessPath!;
        await RunBusy(L["Working"], async () =>
        {
            var r = await Task.Run(() => _engine.LiveSelfTest(exe));
            DiagLines.Clear();
            DiagLines.Add($"{r.Status}: {r.Summary}");
            if (r.SelfTest is { } st) foreach (var l in st.Lines()) DiagLines.Add(l);
            ShowHelperResult(r);
            await RefreshStateCoreAsync();
            LoadAudit();
        });
    }

    private async Task ExportAsync() => await RunBusy(L["Working"], async () =>
    {
        if (_catalog is null) return;
        string? game = GameValid ? GamePath : null;
        var catalog = _catalog;
        string path = await Task.Run(() => _engine.ExportDiagnostics(catalog, game, includePersonal: false));
        ShowResult("ok", "Diagnostics (redacted) written to " + path, []);
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = false });
    });

    // =================================================================== helpers

    private void ShowHelperResult(HelperResult r)
    {
        string kind = r.Status switch
        {
            "Succeeded" or "NoChangesNeeded" or "Passed" or "Completed" => "ok",
            "Cancelled" => "warn",
            "Refused" or "FailedRolledBack" => "warn",
            _ => "error",
        };
        var steps = new List<string>();
        if (r.Outcome is { } o)
        {
            steps.AddRange(o.Steps);
            steps.AddRange(o.Errors.Select(e => "! " + e));
            if (o.RecoveryHint is not null) steps.Add("RECOVERY: " + o.RecoveryHint);
        }
        if (r.SelfTest is { } st) steps.AddRange(st.Lines());
        ShowResult(kind, r.Status == "Cancelled" ? L["Cancelled"] : r.Summary, steps);
    }

    private void ShowResult(string kind, string text, IEnumerable<string> steps)
    {
        ResultKind = kind;
        ResultText = text;
        ResultSteps.Clear();
        foreach (var s in steps) ResultSteps.Add(s);
    }

    private void LoadCatalogRows()
    {
        CatalogRows.Clear();
        if (_catalog is null) return;
        var decisions = _plan?.Decisions.ToDictionary(d => d.Entry.Id) ?? [];
        foreach (var e in _catalog.Catalog.Entries.OrderBy(e => e.Region).ThenBy(e => e.Document.ProtectOnly))
        {
            string use = decisions.TryGetValue(e.Id, out var d) ? (d.Eligible ? "BLOCK" : d.Role == EntryRole.Protected ? "PROTECTED" : "—") + " · " + d.Reason : "";
            string verified = (e.Document.LastVerifiedAtUtc ?? e.Document.ObservedAtUtc)?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "never";
            string sources = string.Join("\n", e.Document.Sources.Select(s => $"[{s.Kind}] {s.Url}{(s.Note is null ? "" : " — " + s.Note)}"));
            CatalogRows.Add(new CatalogRow(e.Region.ToString(), e.DisplayName, e.Cidrs.Count,
                e.Document.ProtectOnly ? "safety net" : e.Confidence.ToString().ToLowerInvariant(), verified, use, sources, e.Document.Notes ?? e.Document.ExclusionReason ?? ""));
        }
    }

    private void LoadObservations()
    {
        var list = ObservationStore.Load();
        Observations.Clear();
        foreach (var o in Enumerable.Reverse(list).Take(100))
            Observations.Add(new ObservationRow(o.AtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture), o.DatacenterCode,
                o.InferredRegion?.ToString() ?? "?", o.Mode, o.InParty ? "party" : "solo", o.PingMs?.ToString(CultureInfo.InvariantCulture) ?? "", o.ActiveProfile ?? ""));
        ObservationSummary = ObservationAnalyzer.Summarize(list).Describe();
    }

    private void LoadAudit()
    {
        AuditLines.Clear();
        foreach (var line in JsonlAuditLog.Tail(AppPaths.AuditLog, 30).Reverse()) AuditLines.Add(line);
    }

    private void SaveSettings()
    {
        try { _settings.Save(); } catch { /* settings are a convenience only */ }
    }

    private async Task RunBusy(string text, Func<Task> work)
    {
        if (++_busyDepth == 1) IsBusy = true;
        BusyText = text;
        try
        {
            await work();
        }
        catch (Exception ex)
        {
            ShowResult("error", ex.Message, []);
        }
        finally
        {
            if (--_busyDepth == 0)
            {
                IsBusy = false;
                BusyText = "";
            }
        }
    }
}
