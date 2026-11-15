# Catalog sources and provenance

`servers.json` is **generated**, not hand-edited:

```powershell
ow2rg-cli catalog build --map data\datacenter-map.json --out data\servers.json            # downloads both feeds
ow2rg-cli catalog build --map data\datacenter-map.json --aws aws.json --gcp gcp.json --out data\servers.json
```

Shipped build: **2026-11-07**

| Feed | Publisher timestamp | Prefixes | SHA-256 |
|---|---|---|---|
| https://ip-ranges.amazonaws.com/ip-ranges.json | 2026-11-07-03-07-05 | 17,799 | `db904c129f1cd1f0507f82132daa5807a4b57bfbeabf0966815294c02f7141e3` |
| https://www.gstatic.com/ipranges/cloud.json | 2026-11-06T18:16:44 | 1,153 | `e406adf64f75becc860f52ba46758440b54825f58687e7e80d5f509b79c60e75` |

## Two separate claims per entry

1. **Where the addresses are** — official. Amazon and Google publish which prefixes belong to which region.
2. **Which Overwatch datacenter code uses that region** — community-reported. Blizzard publishes no list.

`corroborated` therefore means: the location is confirmed by the provider's own feed **and** at least one community
source ties the datacenter code to that provider region. `community` means the code↔region link is weaker or
ambiguous (or the addresses are not in any official feed). `observed` is reserved for a live NetGraph match.

## Middle East (blocked by "Block Middle East")

| Code | Hosting | Confidence | Evidence |
|---|---|---|---|
| MES1 Bahrain | AWS `me-south-1` (EC2) | corroborated | MINA list `cfg - Other - Bahrain - MES1.txt` and egohero `servers.json` (2026-08-26) list 15.184.0.0/16, 15.185.0.0/16, 157.175.0.0/16, 16.24.0.0/16 — all four are AWS me-south-1 EC2 prefixes in the official feed. |
| GMEC1 Doha | Google `me-central1` | corroborated | MINA `cfg - Other - Qatar - GMEC1.txt` = exactly me-central1's IPv4 prefixes (feed has since added two). |
| GMEC2 Dammam | Google `me-central2` | corroborated | Dropship `scripts/ips/overwatch.js` maps `gmec2` → `google/me-central2`; MINA KSA list contains those prefixes. |
| (no code) Tel Aviv | Google `me-west1` | community | Community GMEC2 lists include me-west1 prefixes; no datacenter code is known. Not enforced unless you opt in. |

Not included: AWS `me-central-1` (UAE) and `me-west-1` — no evidence Overwatch uses them.

## Europe (always protected, never blocked)

| Entry | Hosting | Evidence |
|---|---|---|
| AMS1 Amsterdam | Blizzard 5.42.168.0/21, 5.42.184.0/21, 64.224.26.0/23 | Dropship (64.224.26.0/23), MINA AMS1 + EU lists |
| GEN1 Finland | Google `europe-north1` | Dropship maps gen1 → europe-north1; MINA GEN1 ranges are all europe-north1 |
| Safety net | every Google `europe-*` region | official feed |
| Safety net | every AWS `eu-*` region (EC2) | official feed |

Mapping community ranges onto the official feeds showed why the safety net matters: an older community GSG1
(Singapore) list contains slivers of `europe-north1`, `europe-west3/4/6` and `europe-central2`. A plan built from
that list would have blocked parts of Finland. Plans here are built from the provider region, and Europe is
subtracted anyway.

## Other regions ("Prefer Europe" only)

GUE4 → `us-east4` (Dropship), ORD1 → `us-central1` (egohero ranges ~98 % inside), GSG1 → `asia-southeast1`,
GTK1 → `asia-northeast1`, GBR1 → `southamerica-east1` (Dropship), GAN3 → `asia-northeast3`, TPE1 → `asia-east1`
(community lists): corroborated. GUW2 (us-west1..4) and SYD2 (australia-southeast1/2): ambiguous → community.
Blizzard-owned ORD1/LAX1/LAS1/TPE1/SYD2 networks are listed but **never blocked** (`excludeFromBlocking`).
ICN1 is omitted (Dropship removed it in 2026-08; Korea uses a separate client).

## Sources consulted

- Blizzard: https://us.forums.blizzard.com/en/overwatch/t/information-about-the-global-play-server-selection/618941
- Blizzard forum (2026): https://us.forums.blizzard.com/en/overwatch/t/fix-the-servers/1012817
- MINA Overwatch Server Selector (last push 2025-02-21): https://github.com/foryVERX/Overwatch-Server-Selector
- Dropship (last push 2026-08-20): https://github.com/stowmyy/dropship
- OW2 Server Picker (catalog updated 2026-08-26): https://github.com/egohero/ow2-server-picker

## Freshness

The app warns when the catalog is older than 30 days. **Refresh from official feeds** in the app (or
`catalog build`) re-downloads both feeds, rebuilds, validates, shows you a diff and only saves after you approve.
It never changes installed rules on its own.
