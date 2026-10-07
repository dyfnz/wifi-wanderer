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
MonitorSource.swift radio power-cycle to drop the association → tune to the first channel →
                    tcpdump -I subprocess (one per band: the tap is band-locked, so the hopper
                    closes and relaunches it at each band boundary) → pcap/pcapng stream
                    parser → radiotap → 802.11 mgmt → IEParser; hopper thread
                    (CWInterface.setWLANChannel), adaptive dwell; graceful stop waits for
                    tcpdump to release monitor mode, then for auto-join; --pcap replay path
                    uses the same parser
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
- **Drop the Wi-Fi link with a radio power-cycle, never `disassociate()`.** Verified on macOS
  26.6: `setWLANChannel` returns -3903 (kA11NotSupportedErr) while associated, and `tcpdump -I`
  delivers zero frames until the station link is gone — the tap must also be opened *after*
  the link drops. `CWInterface.disassociate()` works but suspends macOS auto-join (like
  "Disconnect" in the Wi-Fi menu); afterwards neither a power-cycle nor a join from a
  terminal process (`associate(to:)`, `networksetup -setairportnetwork`, both → -3900 tmpErr,
  SSIDs are redacted without Location permission) reconnects — only the Wi-Fi menu does. A
  `setPower(false/true)` cycle leaves the radio unassociated with auto-join armed, tcpdump
  grabs monitor mode in the gap, and macOS rejoins ~9 s after we release it.
- **One tcpdump per band — the monitor tap is band-locked.** Measured on macOS 26.6 with a
  tap held open while stepping channels: tuned 6→116→11→36→1→149, the radiotap frequencies
  were 2437, 2437, 2462, 2462, 2412, 2412 MHz — every 5 GHz tune (20/40/80 MHz alike) was
  accepted and reported by `wlanChannel()` but the receiver stayed on the last 2.4 GHz
  channel. Opening the tap while tuned to 116 inverted it: 5 GHz hops followed, 2.4 GHz
  tunes were ignored. So `start()` tunes to `hopList[0]` before launching tcpdump, and the
  hopper does close → tune → relaunch whenever the next channel is in a different band
  (hopList is sorted by band, so that is once per band per sweep, ~0.45 s each, included in
  the status line's s/sweep estimate). Symptom before the fix: only 2.4 GHz rows while the
  status line happily showed 5 GHz channels.
- **Graceful stop** (`q`/Esc/Ctrl-C/SIGINT/SIGTERM): stop hopping → terminate tcpdump and wait
  for it to exit (SIGKILL after 3 s) → wait up to 12 s for auto-join, power-cycle once more if
  needed. tcpdump exiting is what takes the radio out of monitor mode; if the process dies
  hard, tcpdump gets SIGPIPE on its next write and exits too.
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

## Status (2026-10-07)

Working and verified on the dev machine (macOS 26.6, Apple silicon, Swift 6.4 CLT):
- Build via Makefile; `--help`, `--version`, `--lookup`, `--once`, `--json`, `--csv`.
- Scan mode live TUI (shows the Location redaction banner here since VS Code isn't authorized).
- Replay mode (`--pcap`) with synthetic pcap + pcapng: security classes, WPS, Aironet, Aruba,
  vendor-IE inference, chipset hint, SSID hint, 6 GHz HE operation, hidden SSID via probe
  response, unicode SSIDs, sorting/filtering/scrolling/keys, responsive layout, ASCII mode.

- Monitor mode end to end (2026-10-07, without sudo: the dev account is in `access_bpf`):
  power-cycle → tcpdump (Apple tcpdump 4.99.1 emits classic pcap, DLT 127, radiotap parsed
  fine) → 38-channel hop with a tcpdump relaunch per band → 2.4 and 5 GHz beacons (29 APs on
  ch 1/6/11/36/44/116/149 in 30 s, 5.1 s/sweep), manufacturer/security enrichment on live
  APs → `q` quit → tcpdump gone → Wi-Fi auto-rejoined before exit.

- Owner confirmed monitor mode (2.4 + 5 GHz, reconnect on quit) and the MHz column working on
  the dev Mac (2026-10-07).

**Not yet verified:**
- Monitor mode on a 6 GHz-capable Mac (owner plans to test on another laptop): the per-band
  tcpdump relaunch and the 6 GHz hop list are only exercised by the synthetic capture here.
- The Location Services prompt on a terminal app that is allowed to show it (Terminal/iTerm).
- Whether running as root (sudo) changes SSID redaction or lets `associate(to:)` succeed.

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
- 2026-10-07 10:15 — Owner ran `sudo --monitor`: "channel hop failed (kA11NotSupportedErr)",
  0 beacons. Root cause: interface still associated; CoreWLAN refuses `setWLANChannel` and
  the monitor tap is silent while associated (reproduced with a 10 s raw tcpdump: empty pcap).
- 2026-10-07 10:40 — First fix used `disassociate()` + explicit rejoin: capture worked but the
  Mac never reconnected (auto-join suspended; CLI joins → tmpErr). Owner had to rejoin by hand
  twice. Replaced with a radio power-cycle before tcpdump; auto-join reconnects in ~9 s.
- 2026-10-07 10:55 — Graceful stop waits for tcpdump exit and for the reconnect; stderr
  reader no longer flags tcpdump's "data link type" line as an error. Verified live.
- 2026-10-07 11:15 — Owner: only 2.4 GHz rows although the hopper showed 5 GHz channels.
  Measured with a second process + raw tcpdump: the radio does retune, but the monitor tap
  only receives the band it was opened on. Fix: tune before opening, relaunch tcpdump at
  each band change. 5 GHz APs now appear; sweep ≈ 5 s.
- 2026-10-07 11:30 — Channel bandwidth column `MHz` made mandatory (was optional `W`), new
  SortKey `.width` (`--sort width|bw|bandwidth|mhz`).
- 2026-10-07 11:45 — Owner tested again: working well. Committed and pushed. Next: 6 GHz laptop.
