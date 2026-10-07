import Foundation

let appName = "Wi-Fi Wanderer"
let appVersion = "0.1.0"
let appBinary = "wifi-wanderer"

struct Options {
    var interface: String?
    var monitor = false
    var dwellMs = 250
    var adaptive = true
    var intervalSec = 1.0
    var durationSec: Double? = nil
    var bands: Set<Band>? = nil
    var channels: Set<Int>? = nil
    var sort: SortKey = .rssi
    var reverse = false
    var once = false
    var json = false
    var csv = false
    var filter: String? = nil
    var showHidden = true
    var expireSec = 120.0
    var color = true
    var ascii = false
    var ouiPath: String? = nil
    var updateOUI = false
    var noLocation = false
    var showHelp = false
    var showVersion = false
    var tcpdumpPath = "/usr/sbin/tcpdump"
    var maxRows: Int? = nil
    var pcapPath: String? = nil
    var lookup: [String] = []

    static func parse(_ args: [String]) throws -> Options {
        var o = Options()
        if ProcessInfo.processInfo.environment["NO_COLOR"] != nil { o.color = false }
        var i = 0
        func value(_ flag: String) throws -> String {
            i += 1
            guard i < args.count else { throw OptionError("\(flag) requires a value") }
            return args[i]
        }
        while i < args.count {
            var a = args[i]
            var inlineValue: String? = nil
            if a.hasPrefix("--"), let eq = a.firstIndex(of: "=") { inlineValue = String(a[a.index(after: eq)...]); a = String(a[..<eq]) }
            func v(_ flag: String) throws -> String { if let iv = inlineValue { return iv }; return try value(flag) }
            switch a {
            case "-h", "--help": o.showHelp = true
            case "-V", "--version": o.showVersion = true
            case "-i", "--interface": o.interface = try v(a)
            case "-m", "--monitor": o.monitor = true
            case "--no-adaptive": o.adaptive = false
            case "--dwell":
                guard let n = Int(try v(a)), n >= 20, n <= 10_000 else { throw OptionError("--dwell must be 20…10000 (ms)") }
                o.dwellMs = n
            case "-n", "--interval":
                guard let d = Double(try v(a)), d >= 0.2 else { throw OptionError("--interval must be ≥ 0.2 seconds") }
                o.intervalSec = d
            case "-d", "--duration":
                guard let d = Double(try v(a)), d > 0 else { throw OptionError("--duration must be a positive number of seconds") }
                o.durationSec = d
            case "-b", "--band", "--bands":
                var set = Set<Band>()
                for part in try v(a).split(separator: ",") {
                    switch part.trimmingCharacters(in: .whitespaces).lowercased() {
                    case "2.4", "2", "2.4ghz", "2g", "24": set.insert(.ghz2_4)
                    case "5", "5ghz", "5g": set.insert(.ghz5)
                    case "6", "6ghz", "6g", "6e": set.insert(.ghz6)
                    default: throw OptionError("unknown band '\(part)'; use 2.4, 5 or 6")
                    }
                }
                o.bands = set
            case "-c", "--channels", "--channel":
                var set = Set<Int>()
                for part in try v(a).split(separator: ",") {
                    let p = part.trimmingCharacters(in: .whitespaces)
                    if let dash = p.firstIndex(of: "-"), let lo = Int(p[..<dash]), let hi = Int(p[p.index(after: dash)...]), lo <= hi {
                        for c in lo...hi { set.insert(c) }
                    } else if let c = Int(p) { set.insert(c) }
                    else { throw OptionError("bad channel spec '\(p)'") }
                }
                o.channels = set
            case "-s", "--sort":
                let s = try v(a)
                guard let k = SortKey.parse(s) else { throw OptionError("unknown sort key '\(s)'; choose from \(SortKey.allCases.map { $0.rawValue }.joined(separator: ", "))") }
                o.sort = k
            case "-r", "--reverse": o.reverse = true
            case "-1", "--once": o.once = true
            case "-j", "--json": o.json = true
            case "--csv": o.csv = true
            case "-f", "--filter": o.filter = try v(a)
            case "--no-hidden": o.showHidden = false
            case "--expire":
                guard let d = Double(try v(a)), d >= 0 else { throw OptionError("--expire must be ≥ 0 (seconds, 0 = never)") }
                o.expireSec = d
            case "--no-color", "--no-colour": o.color = false
            case "--color", "--colour": o.color = true
            case "--ascii": o.ascii = true
            case "--oui": o.ouiPath = try v(a)
            case "--update-oui": o.updateOUI = true
            case "--no-location": o.noLocation = true
            case "--tcpdump": o.tcpdumpPath = try v(a)
            case "--pcap": o.pcapPath = try v(a)
            case "-l", "--lookup": o.lookup.append(try v(a))
            case "--rows":
                guard let n = Int(try v(a)), n > 0 else { throw OptionError("--rows must be a positive integer") }
                o.maxRows = n
            default:
                throw OptionError("unknown option '\(a)' (try --help)")
            }
            i += 1
        }
        return o
    }

    static let help = """
    \(appName) \(appVersion) — live Wi-Fi channel scanner for macOS

    USAGE
      \(appBinary) [options]                 live TUI, passive CoreWLAN scanning (no root)
      sudo \(appBinary) --monitor [options]  live TUI, monitor-mode beacon capture (real beacon counts)
      \(appBinary) --once [--json|--csv]     one pass, print a table / JSON / CSV and exit

    COLUMNS
      SSID · BSSID · Manufacturer · Device · Ch · Band · RSSI · Security · Beacons · Seen
      Manufacturer markers:  ✓ declared by the AP (WPS/vendor IE)   (none) BSSID OUI registry
                             ≈ inferred from vendor IEs in beacon   ? inferred from SSID pattern

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

    KEYS (live view)
      q / Esc / Ctrl-C  quit        s / S   next / previous sort column     r  reverse sort
      ↑ ↓ PgUp PgDn     scroll      p       pause / resume                  c  reset counters
      h  toggle hidden SSIDs        m       toggle manufacturer detail (Device / source)
      /  set SSID filter (type, Enter)      x  clear filter
      1-9 / 0           sort by column (0 = channel width)

    NOTES
      macOS hides SSID and BSSID from apps without Location Services access. On first run you
      may get a Location prompt; if names show as <hidden> and BSSIDs as —, enable Location
      Services for your terminal app in System Settings › Privacy & Security › Location
      Services, or use monitor mode (sudo \(appBinary) --monitor), which needs no permission.
    """
}

struct OptionError: Error, CustomStringConvertible {
    let description: String
    init(_ s: String) { description = s }
}
