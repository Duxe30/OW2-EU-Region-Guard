# Firewall safety

## Exactly what is written

Each rule has **all** of these properties and nothing else:

| Property | Value |
|---|---|
| Name | `OW2RG-<ME|EU>-<nn>-<planhash12>` |
| Grouping | `OW2 EU Region Guard` |
| Direction | Outbound (`NET_FW_RULE_DIR_OUT` = 2) |
| Action | Block (`NET_FW_ACTION_BLOCK` = 0) |
| Protocol | UDP (17) |
| Program | the validated absolute path of `_retail_\Overwatch.exe` |
| Remote addresses | explicit CIDRs from the plan (never `*`, never broader than /8 IPv4 or /16 IPv6) |
| Remote / local ports, local addresses | any (no guessed port ranges) |
| Profiles | Domain + Private + Public |
| Description | `Managed by OW2 EU Region Guard <ver>; profile=…; plan=…; part=i/n; catalog=…; tiers=…; remove via …` — never contains `\|` |

Windows stores every rule as a single `|`-delimited string in the registry
(`HKLM\...\FirewallRules`), so `|` is forbidden in Name, Description and Grouping. The COM object accepts such a
value on assignment, and only `INetFwRules.Add` rejects it (`E_INVALIDARG`). The first release used ` | ` as a
separator in descriptions and failed exactly there on a user's PC; apply rolled back cleanly. `FirewallRuleSpec`
now refuses `|` and control characters, and the live self-test writes the same description format as real rules.

`FirewallRuleSpec` can only be built through factory methods that enforce these invariants, and the game path type
(`ValidatedGamePath`) can only be produced by the validator, which refuses: relative paths, UNC/device paths,
`..`, `%` (Windows expands environment variables), alternate data streams, trailing dots/spaces, anything not named
`Overwatch.exe`, `Overwatch Launcher.exe`, Battle.net, Steam, svchost, explorer and anything under `Windows\`.

## What is never done

- No change to firewall enabled state, profiles, default inbound/outbound actions, or `netsh advfirewall reset`.
- No rule without a program, no inbound rule, no allow rule, no wildcard remote address.
- No read, change or deletion of any rule whose name does not start with `OW2RG-` (enforced twice: in
  `OwnedOnlyFirewallStore` and inside `ComFirewallStore`).
- No shell, no netsh, no PowerShell in the firewall path. No downloads of code. No UAC bypass.

## Overlap safety invariants (checked on every plan; a violation throws)

```text
block ∩ Europe        = ∅
block ⊆ candidates
block ∩ contested     = ∅     (claimed by any non-targeted region, UNKNOWN or excluded network)
block ∩ special-use   = ∅     (RFC 1918, loopback, multicast, documentation, ...)
∪ rule addresses      = block (exact cover, nothing added or lost)
```

## Apply transaction

Windows Firewall has no multi-rule transaction, so the app compensates:

1. Refuse if the plan is not enforceable, the active profile's firewall is off, or Group Policy overrides local rules.
2. Read all `OW2RG-*` rules; **persist a snapshot** to `%LOCALAPPDATA%\OW2RG\snapshots` (refuse if that fails).
3. Diff: keep identical rules, remove tampered same-name rules first, stage new rules **disabled**.
4. Read back every staged rule and compare field by field (addresses compared as sets, since Windows rewrites
   `a.b.c.d/16` as `a.b.c.d/255.255.0.0`).
5. Enable new rules, remove obsolete `OW2RG-*` rules.
6. Final read-back: exactly the planned rules, all matching.
7. On any failure: remove what was added, re-create what was removed (only if it still satisfies every invariant),
   verify against the snapshot, and report `FailedRolledBack` — or `FailedRollbackIncomplete` with the recovery
   command if even rollback failed.

Apply is idempotent: the same plan produces the same names, and a second apply reports "already active".

## Recovery

| Situation | Action |
|---|---|
| Normal | **RESTORE DEFAULT** button (always visible) or `ow2rg-cli restore` |
| App broken / deleted | Admin PowerShell: `scripts\remove-own-rules.ps1` (exact `OW2RG-` prefix, by internal rule ID) |
| No scripts at all | *Windows Defender Firewall with Advanced Security* → Outbound Rules → sort by name → delete `OW2RG-…` |

Restore needs no catalog and no game path, works when the firewall is off, and retries once per rule.

## Self-test

`ow2rg-cli selftest --live` (or Diagnostics → *Run live self-test*) proves enforcement with a round trip:

1. From the test program itself, ask the PC's own DNS server one ordinary question (`example.com`, type A) over UDP — it must be answered.
2. Add two `OW2RG-SELFTEST-*` rules: UDP block **from the test program only** to that one DNS server, and to `192.0.2.1` (RFC 5737).
3. Ask again — it must go unanswered.
4. Remove the rules in a `finally` block, verify none remain, ask again — it must be answered.

Every other program (and Overwatch) keeps working throughout, because the rules are scoped to the test EXE.

Observed on Windows 11: a UDP `sendto` that the firewall blocks still **returns success** — the datagram is dropped
silently. A send-only probe therefore cannot prove enforcement; the round trip can.
