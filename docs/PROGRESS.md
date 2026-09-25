# Progress log

Chronological record of work on Wi-Fi Wanderer. Newest entries at the bottom. Tick items as
they land; add a dated line for anything notable (decisions, blockers, verification results).

## Checklist

- [x] Project scaffold, Makefile build (swiftc, no deps)
- [x] CoreWLAN scan mode with live TUI
- [x] Monitor mode: tcpdump subprocess, pcap/pcapng + radiotap + 802.11 parser, channel hopper
- [x] Adaptive channel dwell
- [x] OUI database (Wireshark manuf, 24/28/36-bit) embedded in the binary; `--update-oui`; `--lookup`
- [x] Manufacturer enrichment: WPS, Aironet/Aruba AP names, vendor IEs, chipset hint, SSID hint, provenance markers
- [x] Security classification from RSN/WPA IEs (Open/WEP/WPA/WPA2/WPA2-3/WPA3/Enterprise/OWE)
- [x] Sorting by every column (CLI + keys), reverse, filter, hidden toggle, scroll, pause, reset
- [x] Responsive layout, ASCII fallback, NO_COLOR, 256-colour fallback
- [x] `--once`, `--json`, `--csv`, `--pcap` replay
- [x] Synthetic capture generator and pty-driven TUI test harness
- [x] README with every switch; AGENTS.md; LICENSE
- [x] Public GitHub repo under dyfnz
- [ ] Verify monitor mode end to end with sudo (channel hop while tcpdump holds monitor mode)
- [ ] Verify Location Services prompt from Terminal.app / iTerm
- [ ] Parse Meraki / Ruckus / UniFi AP-name vendor IEs
- [ ] Release binary (signed/notarized) and Homebrew tap

## Log

- 2026-09-25 — Started. Requirements captured from the owner; name set to "Wi-Fi Wanderer".
- 2026-09-25 — Findings: macOS 26 redacts SSID/BSSID (and even `system_profiler` output)
  without Location authorization; `sudo` is not passwordless in the agent session, so monitor
  mode could not be run live. Built a synthetic pcap/pcapng generator to test the parser.
- 2026-09-25 — SwiftPM on the Command Line Tools cannot link package manifests (even a fresh
  `swift package init` fails); switched to a Makefile driving `swiftc` directly.
- 2026-09-25 — Fixed: embedded section lookup needed `_dyld_get_image_header(0)`; HE
  Operation 6 GHz offsets; `tcsetattr(TCSAFLUSH)` hang under a pty; keys typed during startup
  quitting the TUI (now flushed).
- 2026-09-25 — Added adaptive dwell (80 ms on quiet channels after the first sweep) and the
  "N ch · X s/sweep" estimate after the owner asked how often the app hops.
- 2026-09-25 — Docs written; first commit pushed to github.com/dyfnz/wifi-wanderer.
