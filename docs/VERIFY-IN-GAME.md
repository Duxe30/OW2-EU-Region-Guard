# Verify in game

Installing rules is **not** proof that your matches are in Europe. Only NetGraph tells you.

1. Apply the profile while Overwatch is closed (or sitting in the main menu). Never during a match.
2. Start Overwatch. First test in a **Custom Game** (or Practice vs AI). Do **not** test in Competitive.
3. Press **Ctrl + Shift + N**. NetGraph shows the datacenter code next to the server IP.
   - Europe: `AMS1` (Amsterdam), `GEN1` (Finland), historically also `CDG1` and others.
   - Middle East: `MES1` (Bahrain), `GMEC1` (Doha), `GMEC2` (Dammam).
4. Record it: app → **Verify in game** tab, or `ow2rg-cli observe add --code AMS1 --ping 85 --mode custom`.
   Add the IP if you want the app to match it against the catalog.
5. Repeat over several matches, solo and in a party separately (parties can be matched differently).
6. If you cannot connect, get kicked to the menu, or voice chat breaks: **RESTORE DEFAULT** immediately and stop
   queueing. Then check the Diagnostics tab or run `ow2rg-cli doctor`.

## Reading the results

The dashboard shows "Your NetGraph reports with these rules: N match(es) — Europe x, Middle East y …", counting only
observations recorded while the current plan was active. Fewer than 5 matches is too few to conclude anything.

If you still land on `MES1`/`GMEC1`/`GMEC2` with **Block Middle East** active:

- Refresh the catalog from the official feeds (the server may sit in a new prefix).
- Note the server IP and run `ow2rg-cli observe add --code MES1 --ip <ip>`; the IP shows whether it is inside a
  catalog entry.
- The datacenter may be reached over a path this profile does not block (TCP, or a new region). Report it rather
  than widening blocks blindly.

## Live game verification status of this release

**Not performed** by the developer: Overwatch was not installed on the build machine (Steam listed it but nothing
was downloaded). Everything up to the Windows Firewall API was tested; see TEST-PLAN.md.
