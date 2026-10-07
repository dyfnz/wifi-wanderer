# Wi-Fi Wanderer

A live, colourful Wi-Fi channel scanner for the macOS terminal. It watches every 2.4 GHz,
5 GHz and (where the Mac's radio supports it) 6 GHz channel and shows each access point's
**BSSID, RSSI, SSID, encryption, beacon count, and manufacturer** in a continuously
updating table that looks and feels like a modern TUI app.

```
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ ◉ Wi-Fi Wanderer  v0.1.0                                                                             en0 · monitor mode · 2.4 GHz · 5 GHz · 6 GHz │
│ ⠼ hopping ch 44 ▰▰▰▰▰▱▱▱▱▱▱▱ 38 ch · 4.2s/sweep  ·  00:01:12  ·  1,904 beacons  ·  sweep 9  ·  sort RSSI ↓                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
   #  SSID                       BSSID              Manufacturer            Device                 Ch    W  Band  RSSI↓      Security  Beacons   Last
 ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
   1  Archer-Home                3c:52:a1:aa:bb:01  TP-Link ✓               Archer AX55             6   40  2.4   ▂▄▆█  -47  WPA2/3        142     1s
   2  Archer-Home-5G             3c:52:a1:aa:bb:02  TP-Link ✓               Archer AX55            36   80  5     ▂▄▆█  -51  WPA2/3        138     1s
   3  Wanderer-6E                9c:3e:53:ee:00:06  Apple, Inc.                                    37  160  6     ▂▄▆█  -55  WPA3          130     2s
   4  Café ☕ Wi‑Fi 日本          18:b4:30:aa:00:08  Google ✓                Nest Wifi Pro           9   40  2.4   ▂▄▆·  -60  WPA2/3        122     1s
   5  CoffeeShop                 0a:1b:2c:3d:4e:5f  Ubiquiti Inc ≈          Broadcom chip         149   80  5     ▂▄▆·  -62  WPA2           95     3s
   6  <hidden>                   f0:a7:31:dd:00:04  TP-Link Systems Inc                           157   80  5     ▂▄··  -66  OWE            75     3s
   7  CorpNet                    00:b0:e1:aa:00:01  Cisco Systems, Inc      LOBBY-AP-01            44   80  5     ▂▄··  -67  WPA2-Ent       68    now
   8  Aruba-Secure               00:0b:86:bb:00:02  Hewlett Packard Enter…  AP-3F-EAST            100   80  5     ▂▄··  -74  WPA3-Ent       52     4s
   9  NETGEAR-Guest              02:11:22:33:44:55  Netgear ?                                       1   40  2.4   ▂···  -77  Open           39     2s
  10  OldPrinter                 00:a0:c5:cc:00:03  Zyxel Communications …                         11   20  2.4   ····  -89  WEP            16     6s

 q quit  s/S sort  r reverse  ↑↓ scroll  p pause  c reset  h hide hidden  m detail  / filter                                      10 shown · 10 total
```
*(Rendered from the bundled sample capture: `wifi-wanderer --pcap tests/sample.pcap`.)*

## Features

- **Every channel, every band.** Monitor mode hops through all channels the Mac's radio
  supports on 2.4, 5 and 6 GHz; scan mode lets the Wi-Fi firmware sweep them for you.
- **Real beacon counts.** In monitor mode the tool captures raw 802.11 beacon frames and counts
  them per BSSID (probe responses are counted separately and also reveal hidden SSIDs).
- **Manufacturer column with provenance.** Every BSSID is resolved against the IEEE registry
  (24-, 28- and 36-bit blocks, via Wireshark's `manuf` database, embedded in the binary), and
  the beacon itself is mined for better answers:
  - **WPS information element** — Manufacturer, Model Name, Model Number and Device Name that
    most consumer routers broadcast (`TP-Link · Archer AX55`).
  - **Cisco Aironet IE** and **Aruba vendor IE** — the AP's configured hostname.
  - **Vendor-specific IEs** — every vendor OUI found in the beacon is resolved too, so a
    randomised BSSID can still be attributed (chipset vendors such as Broadcom, Qualcomm,
    MediaTek and Realtek are reported separately as a chipset hint).
  - **SSID naming patterns** (`NETGEAR…`, `Archer…`, `eero…`, `DIRECT-…`) as a last resort.

  The column marks where the name came from: `✓` declared by the AP, no mark for the OUI
  registry, `≈` inferred from vendor IEs, `?` inferred from the SSID.
- **Live TUI.** Rounded header, braille spinner, channel-sweep progress bar, signal bars,
  colour-coded bands/security/signal, rows flash as new beacons arrive, stale rows dim out,
  differential redraw with synchronized output so nothing flickers. Adapts to any terminal
  width and degrades to plain ASCII (`--ascii`) or no colour (`--no-color`, `NO_COLOR`).
- **Sort by anything.** Signal strength by default; any column from the command line or live
  with keys. Filter by SSID/BSSID/vendor, hide hidden networks, scroll, pause, reset counters.
- **Scriptable.** `--once` prints a table; `--json` / `--csv` dump everything, including the
  raw enrichment fields (WPS strings, AP name, vendor IEs, chipset, PHY generation).
- **Replay.** `--pcap file` reads a saved capture (pcap or pcapng, radiotap or raw 802.11)
  through the exact same pipeline, no root required.
- **Self-contained.** One binary, no runtime dependencies, no Homebrew packages. The OUI
  database is linked into the executable; `--update-oui` fetches a newer one.

## Requirements

- macOS 13 or newer on Apple silicon or Intel (developed on macOS 26).
- Xcode Command Line Tools (`xcode-select --install`) to build. No SwiftPM dependencies.
- Monitor mode needs root (`sudo`) — or membership of the `access_bpf` group that Wireshark's
  ChmodBPF installs — because it uses `tcpdump -I` to put the radio in monitor mode. It drops
  the Wi-Fi connection for the duration (macOS refuses channel changes and delivers no
  monitor-mode frames while associated) and macOS auto-joins again when you quit with `q`,
  `Esc` or Ctrl-C; the app waits for that before exiting.

## Install

```sh
git clone https://github.com/dyfnz/wifi-wanderer.git
cd wifi-wanderer
make                      # builds ./wifi-wanderer with swiftc
sudo make install         # copies it to /usr/local/bin (PREFIX=... to change)
```

`swift build -c release` also works if your SwiftPM installation is healthy; the Makefile
exists because the Command Line Tools' SwiftPM manifest library is broken on some machines.

## Usage

```
wifi-wanderer [options]                 live TUI, passive CoreWLAN scanning (no root)
sudo wifi-wanderer --monitor [options]  live TUI, monitor-mode beacon capture (real beacon counts)
wifi-wanderer --once [--json|--csv]     one pass, print and exit
wifi-wanderer --pcap capture.pcap       replay a saved capture
wifi-wanderer --lookup 3c:22:fb         look up a MAC / OUI prefix
```

### The two capture modes

| | Scan mode (default) | Monitor mode (`--monitor`, root) |
|---|---|---|
| How | Asks CoreWLAN for a scan every `--interval` seconds; the firmware sweeps all bands | Captures raw beacons with `tcpdump -I` while hopping channels with CoreWLAN |
| Beacons column | **Seen×** — number of scan rounds the BSSID appeared in | **Beacons** — actual beacon frames captured |
| Wi-Fi stays connected | Yes | No (restored on exit) |
| Needs Location Services | Yes, to see SSID/BSSID (see below) | No |
| WPS / AP-name enrichment | Only if macOS hands over the beacon IEs (it does once Location is granted) | Always |

Channel hopping in monitor mode dwells `--dwell` ms (default 250) on each channel. After the
first full sweep, channels where no beacon was heard get a short 80 ms visit so the sweep
stays quick (`--no-adaptive` turns this off). The status line shows the channel count and the
estimated seconds per sweep. A typical Mac exposes 13 + 25 channels on 2.4/5 GHz (about 10 s
for the first sweep, 4–5 s afterwards); 6 GHz-capable Macs add up to 59 more. On macOS the
monitor tap only receives the band it was opened on, so the capture is restarted once per
band on every sweep (that is the brief pause you may notice at the band boundary).

Monitor mode and your Wi-Fi connection: macOS will not change channel while the interface is
associated, and on recent macOS the monitor-mode tap stays silent until the station link is
gone. Wi-Fi Wanderer therefore power-cycles the radio before starting the capture (the notice
line says so) and, on quit, waits for macOS auto-join to reconnect you — about 10 s. It
deliberately avoids CoreWLAN's `disassociate()`, which suspends auto-join the same way
"Disconnect" in the Wi-Fi menu does, after which only the Wi-Fi menu can rejoin.

### Location Services (scan mode)

Since macOS 14, apps without Location Services access get scan results with the SSID and BSSID
stripped, so the table shows `<hidden>` and `—`. Wi-Fi Wanderer asks for authorization on
launch (it embeds an Info.plist so macOS can show the prompt). If no prompt appears, enable it
manually: **System Settings › Privacy & Security › Location Services**, then switch on your
terminal app (Terminal, iTerm, Warp, VS Code, …) — the permission belongs to the app the
process runs under. Or skip all that with `sudo wifi-wanderer --monitor`.

### Options

```
CAPTURE
  -i, --interface <name>   Wi-Fi interface (default: the system Wi-Fi interface, usually en0)
  -m, --monitor            Capture raw 802.11 beacons in monitor mode via tcpdump and hop
                           channels. Requires root. Disconnects Wi-Fi while running.
      --dwell <ms>         Monitor mode: time spent on each channel (default 250). After the
                           first sweep, quiet channels get a short 80 ms visit (adaptive).
      --no-adaptive        Monitor mode: always dwell the full time on every channel
  -n, --interval <sec>     Scan mode: seconds between CoreWLAN scans (default 1)
  -b, --band <list>        Only these bands, e.g. 2.4,5 or 6 (default: all supported)
  -c, --channels <list>    Only these channels, e.g. 1,6,11,36-48 (default: all supported)
  -d, --duration <sec>     Stop after this many seconds (default: run until q / Ctrl-C)
      --expire <sec>       Drop networks not seen for this long (default 120, 0 = never)
      --no-location        Do not request Location Services authorization

DISPLAY
  -s, --sort <key>         rssi (default) | ssid | bssid | manufacturer | channel | width |
                           band | security | beacons | seen | first
  -r, --reverse            Reverse the sort direction
  -f, --filter <text>      Only SSIDs containing <text> (case-insensitive)
      --no-hidden          Hide networks that do not broadcast an SSID
      --rows <n>           Limit the number of rows drawn
      --no-color           Disable colours (also honours NO_COLOR)
      --ascii              Use plain ASCII instead of box-drawing / block characters

OUTPUT
  -1, --once               Single pass (scan mode: one scan; monitor: capture for --duration,
                           default 10 s), print, exit. Implied when stdout is not a terminal.
  -j, --json               Print a JSON document of all networks on exit (or with --once)
      --csv                Print CSV on exit (or with --once)

OUI DATABASE
      --oui <path>         Use this Wireshark-format `manuf` file
      --update-oui         Download the latest manuf file to ~/.cache/wifi-wanderer/manuf and exit
  -l, --lookup <mac>       Print the manufacturer for a MAC address / OUI prefix and exit (repeatable)

REPLAY
      --pcap <file>        Instead of capturing, replay beacons from a pcap/pcapng file
                           (radiotap or raw 802.11 link type), e.g. one saved with
                           tcpdump -I -i en0 -w beacons.pcap. Needs no root.

OTHER
      --tcpdump <path>     tcpdump binary for monitor mode (default /usr/sbin/tcpdump)
  -h, --help               Show this help
  -V, --version            Show version
```

### Keys in the live view

| Key | Action |
|---|---|
| `q`, `Esc`, `Ctrl-C` | Quit (prints JSON/CSV afterwards if `--json`/`--csv` was given) |
| `s` / `S` | Next / previous sort column |
| `1`–`9`, `0` | Sort by RSSI, SSID, BSSID, Manufacturer, Channel, Band, Security, Beacons, Last seen; `0` = channel width |
| `r` | Reverse sort direction |
| `↑` `↓` `PgUp` `PgDn` `Home` `End` (or `j` `k` `g` `G`) | Scroll |
| `p` or `Space` | Pause / resume capture |
| `c` | Reset beacon counters |
| `h` | Toggle hidden-SSID rows |
| `m` | Toggle the Device column (WPS model / AP name / chipset) |
| `/` … `Enter` | Set a filter (SSID, BSSID or manufacturer substring); `x` clears it |

### Columns

| Column | Meaning |
|---|---|
| SSID | Network name; `<hidden>` when not broadcast (monitor mode fills it in from probe responses) |
| BSSID | Access point MAC address |
| Manufacturer | Best attribution with a provenance mark (`✓` declared, `≈` vendor IE, `?` SSID hint, none = OUI registry) |
| Device | WPS model name/number, device name, or Cisco/Aruba AP name; chipset hint when nothing else |
| Ch | Primary channel |
| MHz | Channel bandwidth (20/40/80/160 MHz from the HT/VHT/HE/EHT operation elements; `—` when the AP does not say) |
| Band | 2.4, 5 or 6 GHz |
| RSSI | Signal bars and dBm, coloured from green (≥ −55) to red (< −85) |
| Security | Open, WEP, WPA, WPA/2, WPA2, WPA2/3 (transition), WPA3, WPA2-Ent, WPA3-Ent, OWE |
| Beacons / Seen× | Beacon frames captured (monitor/replay) or scan rounds seen in (scan) |
| Last | Time since the last frame / sighting; rows dim after 20 s and expire after `--expire` |

### Examples

```sh
sudo wifi-wanderer -m                          # everything, sorted by signal
sudo wifi-wanderer -m -b 5,6 --dwell 150       # 5/6 GHz only, faster hop
sudo wifi-wanderer -m -c 1,6,11 -s beacons     # the three classic 2.4 GHz channels, busiest first
wifi-wanderer -s manufacturer                  # no root, grouped by vendor
wifi-wanderer --once --json > networks.json    # snapshot for scripts
sudo wifi-wanderer -m --once -d 30 --csv > survey.csv
wifi-wanderer --pcap tests/sample.pcap         # replay the bundled sample capture
wifi-wanderer -l 3c:22:fb -l 00:50:c2:00:3a:ff # OUI lookups (24/28/36-bit aware)
```

### JSON fields

Each network carries: `bssid`, `ssid`, `hidden`, `channel`, `band_ghz`, `width_mhz`,
`rssi_dbm`, `rssi_min_dbm`, `rssi_max_dbm`, `noise_dbm`, `security`, `beacons`,
`probe_responses`, `beacon_interval_tu`, `first_seen`, `last_seen`, `manufacturer`,
`manufacturer_source`, `oui_vendor`, `oui_vendor_short`, `locally_administered`,
`wps_manufacturer`, `wps_model_name`, `wps_model_number`, `wps_device_name`, `ap_name`,
`vendor_ie_vendors`, `chipset_vendors`, `ssid_hint`, `phy` (`n`/`ac`/`ax`/`be`), `country`.

## How it works

- **Scan mode** uses CoreWLAN's `scanForNetworks`, mapping `CWNetwork` fields to the table and
  parsing `informationElementData` when macOS provides it.
- **Monitor mode** spawns `tcpdump -I -i en0 -w - -U -y IEEE802_11_RADIO 'type mgt and
  (subtype beacon or subtype probe-resp)'`, parses the pcap/pcapng stream in-process
  (radiotap → 802.11 management header → information elements: SSID, DS/HE operation, RSN,
  WPA, WPS, HT/VHT/HE/EHT capabilities, Aironet, vendor-specific), and hops channels by
  calling `CWInterface.setWLANChannel` on a timer.
- **OUI lookup** parses Wireshark's `manuf` file into 24/28/36-bit prefix tables at startup
  (about 58 000 entries, ~100 ms). Lookup order: `--oui`, `$WIFI_WANDERER_OUI`,
  `~/.cache/wifi-wanderer/manuf`, the embedded copy, then any system Wireshark copy.
- The Info.plist and the OUI database are linked into the Mach-O as `__TEXT` sections, so the
  binary is a single file and macOS can attribute the Location prompt to it.

## Development

```
Sources/WiFiWanderer/
  main.swift          CLI entry, mode selection, TUI event loop
  Options.swift       argument parsing and help text
  Model.swift         Network/Band/Security/SortKey types and the thread-safe Store
  ScanSource.swift    CoreWLAN scan loop
  MonitorSource.swift tcpdump monitor mode, pcap/pcapng + radiotap parsing, channel hopper, replay
  IEParser.swift      802.11 information element parser (security, WPS, AP names, PHY, width)
  OUI.swift           manuf database loader/lookup, vendor-IE classifier, SSID hints
  Render.swift        TUI frame and static table rendering
  ANSI.swift          colours, gradients, unicode width, padding
  Terminal.swift      raw mode, window size, key decoding, signals
  Location.swift      Location Services authorization
  Export.swift        JSON / CSV
tests/
  make_sample_pcap.py synthetic beacon capture generator (pcap + pcapng)
  tui_drive.py        drives the TUI in a pseudo-terminal and dumps the frame
```

```sh
make                                              # build
python3 tests/make_sample_pcap.py                 # regenerate tests/sample.pcap(ng)
./wifi-wanderer --pcap tests/sample.pcap --once   # parser smoke test
KEYS='ssr/arch\rq' python3 tests/tui_drive.py 140 20 2 -- ./wifi-wanderer --pcap tests/sample.pcap
```

See `AGENTS.md` for architecture notes, decisions and the progress log.

## Credits and licence

MIT licence. The manufacturer database is the `manuf` file generated by the
[Wireshark](https://www.wireshark.org/) project from the IEEE OUI/MA-M/MA-S registries.
