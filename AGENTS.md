# AGENTS.md — Wi-Fi Wanderer

Context file for AI agents and humans picking this project up. Keep it current: update the
**Status** and **Progress log** sections whenever something meaningful changes. The
chronological work log with checkboxes lives in `docs/PROGRESS.md`.

## What this is

`wifi-wanderer` — a macOS command-line Wi-Fi scanner with a live TUI. Scans all 2.4/5/6 GHz
channels, shows BSSID, RSSI, SSID, encryption, beacon count and a **manufacturer** column
resolved from the BSSID OUI and enriched from beacon information elements. Sorts by signal by
default with options for every other column. Public repo: https://github.com/dyfnz/wifi-wanderer

Requested by the owner (2026-09-25) with these requirements:
- CLI for macOS; scan 2.4, 5 and 6 GHz (if available); live output.
- Columns: BSSID, RSSI, SSID/ESSID, encryption, beacon frames captured during the scan.
- BSSIDs resolved to MAC OUI → "Manufacturer" column. Enrich beyond OUI where APs broadcast
  their own name/manufacturer (WPS, vendor IEs, etc.).
- Sort by signal strength by default; options for other columns.
- Modern TUI look (Claude Code / OpenClaw style), colours, a scanning animation.
- Progress documented in AGENTS.md and other context files; committed to a public repo on the
  `dyfnz` GitHub account; README fully documents function and switches.

## Architecture

Single Swift executable, no third-party dependencies. Built with plain `swiftc` via the
Makefile (SwiftPM manifest also present, but the CLT SwiftPM on the dev machine cannot link
manifests, so `make` is the supported path).

```
main.swift          entry: options → OUI load (background) → interface → source → once/TUI loop
Options.swift       hand-rolled arg parser + help text (kept in sync with README)
Model.swift         Network, Band, Security, VendorSource, SortKey, Store (NSLock-guarded)
ScanSource.swift    CoreWLAN scanForNetworks on a thread every --interval; counts sightings
MonitorSource.swift tcpdump -I subprocess → pcap/pcapng stream parser → radiotap → 802.11 mgmt
                    → IEParser; channel hopper thread (CWInterface.setWLANChannel), adaptive
                    dwell; --pcap replay path uses the same parser
IEParser.swift      IE walker: SSID, DS param, country, HT/VHT/HE/EHT (phy + width), RSN/WPA
                    → Security, WPS (manufacturer/model/device), Aironet + Aruba AP name,
                    vendor OUIs; IEParser.apply merges facts into a Network
OUI.swift           OUIDatabase (manuf parser, 24/28/36-bit tables, embedded __oui_db section,
                    ~/.cache override, --update-oui), VendorIEClassifier, SSIDHints
Render.swift        frame(): header box, status/spinner line, notice, responsive columns, rows,
                    footer; staticTable() for --once; visible() does filter+sort
ANSI.swift          Style (truecolor/256 fallback, palette, gradient), TextWidth (wcwidth-ish)
Terminal.swift      raw mode (TCSANOW + flush), TIOCGWINSZ, key decoding, signal flags
Location.swift      CLLocationManager request + run-loop pumping; host app name for hints
Export.swift        JSON (JSONSerialization) and CSV
Info.plist          embedded as __TEXT,__info_plist (bundle id dev.dyfnz.wifi-wanderer +
                    NSLocation*UsageDescription) so macOS can prompt for Location
Resources/manuf     Wireshark manuf DB (~3 MB), embedded as __TEXT,__oui_db at link time
```

Threads: main (TUI loop, 10 fps, differential redraw inside `\e[?2026h/l`), scan thread or
{pcap reader, stderr reader, hopper}, OUI loader. All shared state goes through `Store`.

## Key decisions (and why)

- **Swift + CoreWLAN, zero deps.** Native access to scan results and channel switching; one
  self-contained binary. Hand-rolled TUI rather than a framework to avoid dependency fetches.
- **Two modes.** macOS 14+ redacts SSID/BSSID from CoreWLAN unless the process has Location
  Services authorization — verified on the dev machine (VS Code terminal, status
  `notDetermined`, no prompt shown even with embedded Info.plist). Monitor mode via
  `tcpdump -I` needs root but needs no Location permission and yields real beacon frames, so
  it is the "true" mode; scan mode is the no-root fallback whose count column is "Seen×".
- **Beacon parsing in-process from a pcap stream** (not tcpdump's text output) so we get RSN/
  WPS/vendor IEs for security classification and manufacturer enrichment.
- **Embedded OUI DB via `-sectcreate`** instead of SwiftPM resources: no bundle to lose when the
  binary is copied to /usr/local/bin; zero compile-time cost. Read back with
  `getsectiondata(_dyld_get_image_header(0), "__TEXT", "__oui_db")` (a copied header pointer
  does not work).
- **Manufacturer provenance markers** (✓ declared, none OUI, ≈ vendor IE, ? SSID) so users can
  judge confidence; JSON exposes every raw enrichment field.
- **Adaptive dwell**: after the first sweep, quiet channels get 80 ms instead of `--dwell`.
- **`tcsetattr` uses TCSANOW** — TCSAFLUSH blocked forever under a pty harness on macOS.
- **Startup flushes stdin** and the Location wait is 1.5 s so keys typed during startup don't
  quit the TUI; a later Location grant is picked up on the next scan.

## Build / test

```sh
make                                   # ./wifi-wanderer (release, -O)
make debug                             # -Onone -g
./wifi-wanderer --pcap tests/sample.pcap --once            # parser smoke test (all enrichments)
./wifi-wanderer --pcap tests/sample.pcapng --once --json   # pcapng path + JSON
./wifi-wanderer -l 3c:22:fb -l 00:50:c2:00:3a:ff           # OUI 24-bit + 36-bit lookups
KEYS='ssrm/arch\rq' python3 tests/tui_drive.py 140 20 2 -- ./wifi-wanderer --pcap tests/sample.pcap
KEYS='q' python3 tests/tui_drive.py 110 12 5 -- ./wifi-wanderer     # live scan mode in a pty
python3 tests/make_sample_pcap.py     # regenerate synthetic captures after parser changes
```

`tests/tui_drive.py` runs the binary in a pseudo-terminal, types `KEYS` (escape sequences
allowed, e.g. `\x1b[B`), and prints the reconstructed last frame without colours.

## Status (2026-09-25)

Working and verified on the dev machine (macOS 26.6, Apple silicon, Swift 6.4 CLT):
- Build via Makefile; `--help`, `--version`, `--lookup`, `--once`, `--json`, `--csv`.
- Scan mode live TUI (shows the Location redaction banner here since VS Code isn't authorized).
- Replay mode (`--pcap`) with synthetic pcap + pcapng: security classes, WPS, Aironet, Aruba,
  vendor-IE inference, chipset hint, SSID hint, 6 GHz HE operation, hidden SSID via probe
  response, unicode SSIDs, sorting/filtering/scrolling/keys, responsive layout, ASCII mode.

**Not yet verified (needs an interactive sudo session):**
- Monitor mode end to end: `sudo ./wifi-wanderer --monitor`. Specifically whether
  `CWInterface.setWLANChannel` succeeds while tcpdump holds monitor mode, whether Apple's
  tcpdump emits pcap or pcapng on stdout (both are handled), and radiotap field layout on this
  driver. If hopping fails the status line shows "channel hop failed" and capture continues on
  the current channel.
- The Location Services prompt on a terminal app that is allowed to show it (Terminal/iTerm).

## Known limitations / ideas

- Scan mode without Location permission cannot correlate rows across rounds (no BSSID), so
  Seen× stays 1 and rows are replaced every round.
- 6 GHz channel list depends on the Mac's radio; the dev machine has none, so the 6 GHz hop
  path is only exercised by the synthetic capture.
- Meraki / Ruckus / Mist / UniFi vendor IEs are only attributed by OUI; their AP-name formats
  are not parsed (add cases in `IEParser.parseVendor`).
- Possible follow-ups: per-row RSSI sparkline, channel utilisation view, `--interface` list
  command, Homebrew formula, signed/notarized release binaries.

## Progress log

- 2026-09-25 09:00 — Probed CoreWLAN: 113 networks visible but SSID/BSSID nil (Location not
  authorized); no 6 GHz on this Mac; Location prompt does not appear from a VS Code terminal.
- 2026-09-25 09:13 — Skeleton, Package.swift, Info.plist, embedded Wireshark manuf DB.
- 2026-09-25 09:25 — All modules written; SwiftPM manifest link failure on CLT → Makefile.
- 2026-09-25 09:30 — Embedded OUI section lookup fixed (real dyld header pointer); HE 6 GHz
  operation offsets fixed; synthetic capture generator; `--lookup`, `--pcap` added.
- 2026-09-25 09:40 — pty harness; sorting/filter/scroll/ASCII verified; tcsetattr hang fixed;
  startup input flush; adaptive dwell + sweep estimate in status line.
- 2026-09-25 09:50 — README, AGENTS.md, PROGRESS.md, LICENSE; initial commit and push.
