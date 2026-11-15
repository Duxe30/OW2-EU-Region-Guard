# Notice

**OW2 EU Region Guard is not affiliated with, endorsed by, or supported by Blizzard Entertainment.**
Overwatch and Battle.net are trademarks of Blizzard Entertainment, Inc. AWS is a trademark of Amazon.com, Inc.
Google Cloud is a trademark of Google LLC.

## Original implementation

All source code in this repository was written for this project. The community projects below were consulted
**only** for publicly visible facts (datacenter codes, which cloud region a code maps to, and known pitfalls).
No code, binaries or assets were copied from them.

| Project | License | Used for |
|---|---|---|
| [foryVERX/Overwatch-Server-Selector](https://github.com/foryVERX/Overwatch-Server-Selector) | none stated | datacenter code ↔ address facts (MES1, GMEC1, GMEC2, AMS1, GEN1, GAN3) |
| [stowmyy/dropship](https://github.com/stowmyy/dropship) | GPL-3.0 | code ↔ Google Cloud scope facts (gmec2, gen1, gue4, gsg1, gtk1, gbr1) and Blizzard network facts |
| [egohero/ow2-server-picker](https://github.com/egohero/ow2-server-picker) | MIT | datacenter facts; pitfalls (overlapping lists, port blast radius, launcher vs client) |

Facts (addresses, region names) are not copyrightable; they are cited per entry in `data/sources.md` and inside
`data/servers.json`.

## Data

IP ranges are taken from the official, publicly documented provider feeds:

- AWS — https://ip-ranges.amazonaws.com/ip-ranges.json (AWS "IP address ranges" documentation)
- Google Cloud — https://www.gstatic.com/ipranges/cloud.json (Google Cloud "IP ranges" documentation)

## Runtime

Self-contained builds include the .NET runtime (MIT, © .NET Foundation and Contributors).
