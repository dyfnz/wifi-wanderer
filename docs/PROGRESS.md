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
- [x] Verify monitor mode end to end (channel hop while tcpdump holds monitor mode) — 2026-10-07
- [x] Drop the Wi-Fi link before capture without breaking auto-join; reconnect on graceful quit
- [x] 5 GHz capture: relaunch tcpdump per band (monitor tap is band-locked on macOS 26)
- [ ] Verify monitor mode on a 6 GHz-capable Mac (per-band relaunch for the third band)
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
- 2026-10-07 — Owner's first live `sudo --monitor` run: every hop failed with
  kA11NotSupportedErr and no beacons arrived. Cause: the interface was still associated.
  macOS refuses `setWLANChannel` while associated and the monitor-mode tap delivers nothing
  until the link is gone (and the tap must be opened after the link drops).
- 2026-10-07 — Dead end: `CWInterface.disassociate()` fixes capture but suspends auto-join, and
  a terminal process cannot rejoin (`associate(to:)` / `networksetup` → -3900 tmpErr; SSIDs
  redacted without Location permission). Only the Wi-Fi menu recovers. Owner rejoined by hand.
- 2026-10-07 — Fix: power-cycle the radio (`setPower`) before launching tcpdump; auto-join
  stays armed and reconnects ~9 s after quit. Graceful stop (q/Esc/Ctrl-C) now waits for
  tcpdump to exit (releasing monitor mode) and for the reconnect. Verified live without sudo
  (dev account is in `access_bpf`): 38-channel sweep, 700+ beacons, reconnect confirmed.
- 2026-10-07 — Owner spotted that only 2.4 GHz networks were listed while the status line
  hopped through 5 GHz. Confirmed with a parallel CoreWLAN probe that the radio really
  retunes, then with a raw tcpdump tap held open across tunes: received frequencies follow
  2.4 GHz tunes only; every 5 GHz tune (any width) is accepted but ignored. Opening the tap
  on 5 GHz inverts it. Fix: `start()` tunes to the first channel before launching tcpdump and
  the hopper closes/relaunches tcpdump at each band boundary (once per band per sweep).
  Verified: 29 APs on ch 1/6/11/36/44/116/149 in 30 s, 5.1 s/sweep, reconnect still fine.
- 2026-10-07 — Owner asked for a channel-bandwidth column. The old optional `W` column (first
  to be dropped on narrow terminals) is now the always-shown `MHz` column, sortable via
  `--sort width` (aliases bw/bandwidth/mhz) and the s/S cycle.
- 2026-10-07 — Owner re-tested monitor mode and the new column: working well. Committed and
  pushed to GitHub. Pending: a run on a laptop with a 6 GHz radio.
