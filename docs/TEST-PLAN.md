# Test plan and results

Environment: Windows 11 Pro 10.0.26200 x64, .NET SDK 10.0.403 (runtime 10.0.14), non-elevated user shell,
Windows Defender Firewall on (active profile: Public), 2026-11-07.

Command: `powershell -ExecutionPolicy Bypass -File scripts\build.ps1` (restore → build Release → test → publish).

## Automated results

| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| OW2RG.Core.Tests | **133** | 0 | 0 |
| OW2RG.Windows.Tests | **20** | 0 | 1 (opt-in live firewall test) |

Build: 0 warnings, 0 errors.

### Core (pure, no Windows dependency)

- Strict IPv4/IPv6 CIDR parsing; rejection of host bits, leading zeros, `1.2`, hex octets, zone IDs, bad prefixes.
- Windows read-back formats (`a.b.c.d/m.m.m.m`, ranges, keywords never expanded, non-contiguous masks rejected).
- Spec example: `192.0.2.0/24 − 192.0.2.64/26 = 192.0.2.0/26 + 192.0.2.128/25`.
- Adjacent/overlapping merges add no addresses; gaps are never bridged; IPv4/IPv6 isolation; edges of both spaces.
- **Property tests vs brute-force bitmap** (400 rounds each): union/subtract/intersect exact; `block ∩ EU = ∅`;
  `block ⊆ candidate`; CIDR cover exact and minimal (no mergeable siblings).
- Catalog validation: reserved/private/multicast/link-local rejected; documentation ranges only in test mode;
  too-broad prefixes; duplicate IDs/CIDRs; hostile Unicode (bidi overrides, zero-width); `example.invalid`
  provenance; cross-region conflicts; stale data flagged not rejected; unknown JSON properties, integer enums,
  comments, trailing commas, oversized input and missing fields rejected.
- Planner: EU carve-out, contested space left open (even when the other claimant is unverified), excluded
  Blizzard networks never blocked, community data only with opt-in, unverified never, empty catalog honestly
  "not enforceable", missing game → no rules, deterministic hash/names, chunking ≤ char limit with exact cover,
  200 random catalogs × 2 profiles never violate invariants.
- Game path: relative, launcher, Battle.net, svchost, Windows dir, `..`, `%VAR%`, UNC, `\\?\`, ADS, `/`, wrong
  name, trailing-space segment, missing file → rejected; Steam and Battle.net layouts accepted.
- Fake firewall (holds foreign rules, allows duplicate names, rewrites CIDRs like Windows):
  block-me writes only outbound/block/UDP/program-scoped rules; second apply is a no-op; profile switch replaces
  only obsolete OW2RG rules; moving the game replaces stale rules; restore removes only own rules (foreign rules
  byte-identical); **failure injected at the 1st/2nd add, enable and remove → full rollback to the snapshot**;
  rollback failure → loud `FailedRollbackIncomplete` + recovery command; refused when firewall off or Group Policy
  overrides; refused without durable snapshot; tampered same-name rule replaced not duplicated; guard refuses
  foreign names; crash leftovers (disabled rules, missing part) detected as Partial and healed by re-apply.
- **Shipped catalog**: valid in production mode, zero cross-region conflicts; block-me targets exactly MES1, GMEC1,
  GMEC2 (all corroborated); no plan (either profile, with/without community data) touches any European or
  Blizzard-owned address; spot checks (AMS1/GEN1/europe-west4 open, Bahrain/Doha/Dammam blocked, Tel Aviv open
  without opt-in, 8.8.8.8 open).

### Windows (real APIs, no system changes)

- Helper protocol round-trip; 8 malformed/hostile requests rejected (unknown op, bad GUID, extra args, default
  profile, relative catalog, short hash, injected `--exec`, duplicate keys).
- Argument quoting checked against the real `CommandLineToArgvW` (spaces, quotes, trailing backslashes, empty).
- Embedded catalog and datacenter map load and validate.
- Game locator runs and returns only validated or explained candidates.
- Real `INetFwPolicy2` readable without admin; owned-rule enumeration returns only `OW2RG-*`.
- `RemoveRules` on a name that does not exist returns 0 and `SetEnabled` reports "not found" — both via `INetFwRules.Item`, no enumeration, no elevation.
- Catalog text: line breaks / tabs / zero-width characters rejected in single-line fields, allowed in `notes` and `description`; cross-region conflicts are explained in plan warnings for both profiles.
- **Windows accepted every rule of both real plans** in a dry check (unsaved `HNetCfg.FWRule` objects), and the
  number of OW2RG rules before/after is identical (nothing persisted).
- COM store refuses to touch `Core Networking - DNS (UDP-Out)`.

## Manual checks performed (2026-11-07)

| Check | Result |
|---|---|
| `ow2rg-cli doctor --probe-limits` | all PASS; block-me 85 blocks in 2 rules, prefer-eu 366 blocks in 7 rules, Windows accepted 2/2 and 7/7; unsaved rule object accepted 20,000 CIDRs (288,817 chars) |
| `ow2rg-cli preview --profile block-me` | 3 datacenters, 85 networks, 720,656 IPv4 addresses, 0 EU overlaps, 0 contested; rule text 655 + 807 chars |
| Published single-file EXEs without any .NET on PATH | `status`, `selftest` (offline) OK |
| `--helper` without elevation | exits 5 "NotElevated", writes result JSON; malformed helper args exit 6 |
| `scripts\remove-own-rules.ps1 -WhatIf` | "No OW2RG-* rules found" |
| UI smoke (`OW2RG.exe --ui-smoke`) dashboard/catalog/verify tabs | rendered, exit 0 |
| Game detection on this PC | found Steam library entry, correctly reported "nothing downloaded yet" and refused to enforce |
| **Live self-test, published `ow2rg-cli.exe`, real UAC elevation** (user approved) | **PASS** — see below |

### Live firewall self-test (2026-11-07, real Windows Firewall, elevated via UAC)

```text
[PASS] Firewall active for current profile: yes
[PASS] Baseline (no rule): DNS question to 192.168.x.1 (home router) → answered in 12 ms
[PASS] Create + read back rule(s): 2 rule(s): OUT, BLOCK, UDP, program=…\ow2rg-cli.exe
[PASS] Rule enforced by Windows: same DNS question from this program is now blocked (no answer within 2.5 s)
[PASS] Remove rule(s) (cleanup): removed 2; no self-test rule left behind
[PASS] Traffic restored after removal: DNS question to 192.168.x.1 (home router) → answered in 2 ms
```

Independent check afterwards: `Get-NetFirewallRule -All | ? DisplayName -like 'OW2RG-*'` → **0 rules**.

A first version of the self-test only sent UDP to 192.0.2.1 and reported "inconclusive": blocked UDP sends return
success on Windows (silent drop). The test was changed to the round trip above, which proved enforcement.

### Field failure found after the first release (2026-11-07) and the fix

On another PC, `Apply` (block-me) failed at the first `INetFwRules.Add` with `0x80070057 E_INVALIDARG` and rolled
back cleanly ("Apply failed and was rolled back; your previous OW2RG rules are restored exactly"). Cause: the rule
*description* used ` | ` as a separator, and Windows stores rules as one `|`-delimited registry string, so `|` is
illegal in Name/Description/Grouping. Property assignment accepts it (which is why the dry check passed) and only
`Add` rejects it. The live self-test had not caught it because its description had no `|`.

Fix: one shared `FirewallRuleSpec.Describe(...)` builder using `;` separators, `FirewallRuleSpec` refuses `|` and
control characters outright, the live self-test now writes the **same description format** as profile rules, and a
unit test asserts no generated rule text contains `|`. Lesson recorded: the dry validation proves address/program
syntax only; Add-time validation needs the live self-test.

### 1.0.1 (2026-11-15): third-party firewall detection

On the build PC the live self-test, which had passed on 2026-11-07, **failed**: rules were stored and read back
exactly, yet the blocked DNS question was still answered. Windows Security Center showed **Kaspersky** registered as
the active firewall product (`productState` 266240, bit 0x1000 set). After the user turned off Kaspersky's Firewall
component (`productState` 262144), the self-test passed again (blocked after 3 s). Windows Defender Firewall keeps
its rules but stops enforcing them while a third-party firewall is active.

Shipped: `SecurityCenter.ActiveThirdPartyFirewalls()` → `FirewallEnvironment.ThirdPartyFirewalls`; Apply is refused
with an explanation, the dashboard says "Windows Firewall is bypassed: … is the active firewall", `doctor` and both
self-tests report it. New fake-firewall test `Third_party_firewall_makes_apply_refuse_with_an_explanation`.
Core tests: 135 passed; Windows tests: 20 passed, 1 skipped.

## Not verified

| Item | Status |
|---|---|
| Full elevated `apply` / `restore` of a real profile against Overwatch.exe | the user applied block-me successfully on their gaming PC on 2026-11-07; not run on the build PC (game not installed) |
| Live game verification (NetGraph datacenter after applying) | **not performed** — Overwatch not downloaded on this PC |
| Windows 10, high-DPI 150–200 %, Group Policy-managed PC, third-party firewall | not tested |
| Persisted RemoteAddresses limit per rule | unknown; plans use ≤ 1,000 chars per rule (well under what the API accepts on assignment) |

## How to run the remaining checks

```powershell
# 1. Live firewall self-test (admin; creates and removes ONE harmless rule):
.\ow2rg-cli.exe selftest --live
# 2. Opt-in live test suite (elevated shell, ideally a disposable VM):
$env:OW2RG_LIVE_FIREWALL_TESTS = '1'; dotnet test tests\OW2RG.Windows.Tests -c Release
# 3. In game: see VERIFY-IN-GAME.md
```
