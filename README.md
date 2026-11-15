# OW2 EU Region Guard

[![build](https://github.com/Duxe30/OW2-EU-Region-Guard/actions/workflows/build.yml/badge.svg)](https://github.com/Duxe30/OW2-EU-Region-Guard/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/Duxe30/OW2-EU-Region-Guard?include_prereleases)](https://github.com/Duxe30/OW2-EU-Region-Guard/releases)

**Download:** grab `OW2-EU-Region-Guard-win-x64.zip` from the [Releases page](https://github.com/Duxe30/OW2-EU-Region-Guard/releases), unzip anywhere, run `OW2RG.exe`.

Prefer European Overwatch 2 match servers from Iraq (or anywhere near the Middle East) by making the
Middle East game datacenters unreachable **for Overwatch.exe only**, with ordinary Windows Defender
Firewall rules.

> **Unofficial. Not affiliated with or endorsed by Blizzard.**
> Blocking servers **may disconnect you and can cause leaver penalties**. It can only **influence**
> matchmaking — it never guarantees European servers. Test first in a **Custom Game**, never in Competitive.

No VPN · no game-file changes · no injection · no memory reading · no packet tampering · no anti-cheat interaction.

## What it does

| Profile | Effect |
|---|---|
| **Block Middle East** *(recommended)* | Overwatch.exe cannot reach Bahrain **MES1**, Doha **GMEC1** and Dammam **GMEC2** over UDP. |
| **Prefer Europe** *(higher risk)* | Also blocks the known American, Asian, Oceanian and South American game datacenters. |
| **Default** | Removes every rule this app created (`OW2RG-*`). Nothing else is touched. |

Every rule is: **outbound · block · UDP · scoped to the exact `_retail_\Overwatch.exe` path · scoped to explicit
server networks**. Your browser, Battle.net, Steam, Discord, Windows and the game's TCP traffic (login, chat,
patching) are never affected.

### Where the addresses come from

Blizzard publishes no server list. The Middle East datacenters run on public clouds, and **Amazon and Google
publish their own official IP ranges per region**. The app combines:

1. the official feeds — `ip-ranges.amazonaws.com/ip-ranges.json` and `gstatic.com/ipranges/cloud.json`, and
2. a reviewed map from datacenter code to cloud region (`data/datacenter-map.json`), where every mapping cites the
   community source it came from.

Result (catalog built 2026-11-07): MES1 = AWS `me-south-1` (62 networks), GMEC1 = Google `me-central1` (8),
GMEC2 = Google `me-central2` (17). See [data/sources.md](data/sources.md).

**Europe is protected by construction.** Every address Google or Amazon places in Europe, plus Blizzard's Amsterdam
network, is subtracted from every plan, so even a dirty list can never block a European server. Blizzard-owned
networks are never auto-blocked (they may carry login/voice services).

## Use it (Windows 10/11 x64)

1. Unzip `OW2-EU-Region-Guard-win-x64.zip` anywhere (no installer, no .NET install needed).
2. **Close Overwatch** (or stay in the main menu — never apply during a match).
3. Run `OW2RG.exe`. It finds `_retail_\Overwatch.exe` from Steam / Battle.net / the registry, or use **Browse…**.
4. Choose **Block Middle East** → **Preview changes**. Check the list: BLOCK = Bahrain/Doha/Dammam, KEEP = Europe.
5. **Apply profile** → tick "I understand…" → approve the Windows administrator (UAC) prompt.
6. Start Overwatch, join a **Custom Game**, press **Ctrl+Shift+N**, read the datacenter code (e.g. `AMS1`, `GEN1`).
   Record it in the **Verify in game** tab. Play several matches before drawing conclusions.
7. Anything wrong (can't connect, voice issues)? Press **RESTORE DEFAULT** at the bottom of the window.

### Emergency removal without the app

Run PowerShell **as Administrator**:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\remove-own-rules.ps1
```

It removes only rules whose name starts with `OW2RG-`. Or: `ow2rg-cli restore`.

## Command line

```text
ow2rg-cli status                       real firewall state, game, catalog
ow2rg-cli preview --profile block-me   exact rules, dry-validated by Windows (nothing saved)
ow2rg-cli apply   --profile block-me   asks for UAC, then applies with rollback on failure
ow2rg-cli restore                      remove all and only OW2RG-* rules
ow2rg-cli doctor                       full read-only check
ow2rg-cli selftest --live              prove enforcement: DNS answered → blocked → answered (own process only)
ow2rg-cli catalog build --out x.json   rebuild the catalog from the official feeds
ow2rg-cli observe add --code AMS1      log a NetGraph observation
```

## Build from source

Requires the .NET 10 SDK.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

Restores, builds, runs all tests and publishes self-contained single-file `OW2RG.exe` and `ow2rg-cli.exe` to
`artifacts\OW2-EU-Region-Guard-win-x64\` plus a zip with a SHA-256 file.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, data flow, elevation design
- [docs/FIREWALL-SAFETY.md](docs/FIREWALL-SAFETY.md) — exactly what is written, invariants, rollback, recovery
- [docs/VERIFY-IN-GAME.md](docs/VERIFY-IN-GAME.md) — how to check the real match datacenter
- [docs/TEST-PLAN.md](docs/TEST-PLAN.md) — automated tests, results, what was not verified
- [data/sources.md](data/sources.md) — provenance of every address

## Known limitations

- **Influence, not control.** Party matchmaking, queue population and Blizzard changes can still put you on a Middle
  East server or give longer queues.
- Only UDP is blocked. If a datacenter is reached over TCP for game traffic, this profile does not affect it.
- Datacenter-to-cloud-region mappings are community-reported. Cloud address ownership is official; the claim that
  Overwatch uses that region for a given code is not. Refresh the catalog from the official feeds periodically
  (**Refresh from official feeds** in the app).
- The app never detects the match region by itself; only your NetGraph reading confirms it.

MIT licensed. See [NOTICE.md](NOTICE.md).
