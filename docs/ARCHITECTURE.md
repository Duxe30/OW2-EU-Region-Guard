# Architecture

```text
src/
  OW2RG.Core                      pure .NET 10, no Windows / COM / registry / UI
    Net/        IpCodec, CidrBlock, IntervalSet, IpSet, AddressListParser, SpecialRanges
    Catalog/    model, strict JSON, CatalogValidator, CloudFeeds (AWS/GCP parsers), CatalogBuilder
    Game/       GamePathValidator → ValidatedGamePath (only constructible by the validator)
    Planning/   Profiles, BlockPlanBuilder → BlockPlan (rules, fragments + provenance, hash)
    Firewall/   FirewallRuleSpec (factory-only), IFirewallRuleStore, OwnedOnlyFirewallStore,
                FirewallApplyService (snapshot / stage / verify / commit / rollback), OwnedStateInspector
    Verification/ manual NetGraph observations
  OW2RG.Infrastructure.Windows    Windows adapters
    Firewall/   ComFirewallStore (INetFwPolicy2 / INetFwRule via IDispatch), dry validation
    GameLocator (running process, Steam libraryfolders.vdf, Battle.net product.db, uninstall registry, folders)
    CatalogProvider + FeedDownloader, Storage (%LOCALAPPDATA%\OW2RG), Elevation, Helper, SelfTest, GuardEngine
  OW2RG.App                       WPF / MVVM desktop UI (asInvoker)
  OW2RG.Cli                       ow2rg-cli: status, preview, apply, restore, doctor, catalog, selftest, observe
tests/
  OW2RG.Core.Tests                133 unit, property and fake-firewall tests
  OW2RG.Windows.Tests             helper protocol, argv quoting vs CommandLineToArgvW, read-only COM, opt-in live test
```

## Data flow

```text
official AWS feed ─┐
official GCP feed ─┼─ CatalogBuilder ─ servers.json ─ CatalogValidator ─ ValidatedCatalog
datacenter-map.json┘                                                        │
                                   GamePathValidator ─ ValidatedGamePath ───┤
                                                     profile + opt-ins ─────┤
                                                                            ▼
                                                                    BlockPlanBuilder
                                   candidates − Europe − contested − special-purpose
                                                    → minimal exact CIDR cover → chunked rule specs
                                                                            │
                         preview (counts, per-entry reasons, carve-outs, Windows dry-validation)
                                                                            │  user confirms + UAC
                                                                            ▼
                                                     FirewallApplyService (elevated helper)
                                                                            │
                                                                ComFirewallStore → Windows Firewall
                                                                            │
                                     OwnedStateInspector ← read-back (firewall = source of truth)
```

## Key decisions

**Interval algebra on `UInt128`.** IPv4 and IPv6 live in separate `IntervalSet`s; union, subtract and intersect
are exact sweeps over sorted, merged intervals; output is the minimal exact CIDR cover (greedy per maximal interval,
which is optimal because maximal intervals are never adjacent). Nothing is ever widened. Verified against a
brute-force bitmap in randomized tests.

**Protection beats blocking, by subtraction.** Windows Firewall evaluates block before allow, so an "allow Europe"
rule cannot undo a wider block. Instead European space is removed from the block set before any rule exists.
Protection uses *every* EU entry regardless of confidence (protecting more is always safe) plus safety nets made
from all European regions in the official feeds.

**Contested space is never blocked.** If an address is claimed by any non-targeted region (including UNKNOWN, or an
entry marked `excludeFromBlocking`), it is left open.

**Catalog from official feeds.** The Middle East datacenters run on AWS and Google Cloud, which publish their own
region IP lists. The catalog is regenerated from those feeds plus a reviewed code→region map, with feed SHA-256s
recorded. This replaces hand-copied community lists that go stale and overlap (one older Singapore list contained
European Google Cloud slivers).

**Elevation.** The UI and CLI run as the normal user. Mutations start an elevated copy of the same EXE through the
standard UAC prompt (`runas`) with a strict argument protocol: operation, profile, game path, catalog location,
community opt-in and the **expected plan hash**. The elevated side re-validates everything, rebuilds the plan
itself and refuses if the hash differs from what the user previewed. It never receives rule text from the
unelevated side. Result JSON goes to a fixed folder named by a GUID.

**COM, not netsh.** Firewall calls go through `HNetCfg.FwPolicy2` / `HNetCfg.FWRule` with typed property
assignment — no shell, no string-built command lines. An unsaved `FWRule` object validates property values on
assignment, which gives a no-admin, no-change **dry validation** of every planned rule.

**Firewall is the source of truth.** State shown in the UI is reconstructed from the installed `OW2RG-*` rules
(profile, plan hash and part numbers are encoded in name and description), not from a settings cache.

## Rule naming

`OW2RG-<ME|EU>-<part>-<planhash12>` — e.g. `OW2RG-ME-01-43cc5627a4dc`. Same plan → same names → idempotent apply.
Self-test rules: `OW2RG-SELFTEST-<random>`. Grouping: `OW2 EU Region Guard`.

## Local files (%LOCALAPPDATA%\OW2RG)

`user-settings.json` (game path, opt-in, language), `observations.json`, `audit.log.jsonl` (no credentials, no
packet data), `snapshots\` (pre-change copies of OW2RG rules), `catalog\servers.json` (only after you approve a
refresh), `results\`, `exports\`. Nothing is sent anywhere; the only network calls are the two official feeds,
and only when you press **Refresh from official feeds**.
