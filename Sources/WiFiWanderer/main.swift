import Foundation
import CoreWLAN

// MARK: - Entry point

func fail(_ msg: String, code: Int32 = 2) -> Never {
    FileHandle.standardError.write(Data(("\(appBinary): " + msg + "\n").utf8))
    exit(code)
}

let options: Options
do { options = try Options.parse(Array(CommandLine.arguments.dropFirst())) }
catch { fail("\(error)") }

if options.showHelp { print(Options.help); exit(0) }
if options.showVersion { print("\(appName) \(appVersion)"); exit(0) }

Style.colorEnabled = options.color && (Terminal.isTTY || ProcessInfo.processInfo.environment["CLICOLOR_FORCE"] != nil)
Style.unicode = !options.ascii

if options.updateOUI {
    print("Downloading \(OUIDatabase.downloadURL.absoluteString) …")
    switch OUIDatabase.update() {
    case .success(let s): print("OK: \(s)"); exit(0)
    case .failure(let e): fail("update failed: \(e.localizedDescription)", code: 1)
    }
}

// OUI database loads in the background; sources pick it up as soon as it is ready.
var ouiDB: OUIDatabase?
let ouiLock = NSLock()
func currentOUI() -> OUIDatabase? { ouiLock.lock(); defer { ouiLock.unlock() }; return ouiDB }
Thread {
    let db = OUIDatabase.load(explicitPath: options.ouiPath)
    ouiLock.lock(); ouiDB = db; ouiLock.unlock()
}.start()

if !options.lookup.isEmpty {
    while currentOUI() == nil { Thread.sleep(forTimeInterval: 0.01) }
    let db = currentOUI()!
    var code: Int32 = 0
    for m in options.lookup {
        // Accept full MACs or bare prefixes such as "3c:22:fb" / "3C22FB"
        var hex = m.filter { $0.isHexDigit }
        if hex.count < 6 { fail("'\(m)' is not a MAC address or OUI prefix") }
        hex += String(repeating: "0", count: max(0, 12 - hex.count))
        let bytes = OUIDatabase.parseMAC(String(hex.prefix(12)))!
        let local = (bytes[0] & 0x02) != 0
        if let v = db.lookup(bytes) {
            print("\(OUIDatabase.format(bytes))  \(v.full)" + (v.short != v.full ? "  [\(v.short)]" : "") + (local ? "  (locally administered bit set)" : ""))
        } else {
            print("\(OUIDatabase.format(bytes))  unknown" + (local ? "  (locally administered / randomized address)" : ""))
            code = 1
        }
    }
    FileHandle.standardError.write(Data("oui database: \(db.source) (\(db.entryCount) entries)\n".utf8))
    exit(code)
}

var iface: CWInterface? = nil
if options.pcapPath == nil {
    do { iface = try WiFi.interface(named: options.interface) } catch { fail("\(error)") }
    if !(iface!.powerOn()) { fail("Wi-Fi is powered off on \(iface!.interfaceName ?? "the interface"); turn it on first", code: 1) }
}

let store = Store()
let bandsSupported = iface.map(WiFi.supportedBands) ?? [.ghz2_4: 14, .ghz5: 1, .ghz6: 1]
let interactive = Terminal.isTTY && !options.once && !(options.json && !Terminal.isTTY)
let once = options.once || !Terminal.isTTY

var location: LocationGate? = nil
let source: Source
if let pcap = options.pcapPath {
    guard FileManager.default.isReadableFile(atPath: pcap) else { fail("cannot read \(pcap)", code: 1) }
    source = MonitorSource(iface: nil, pcapPath: pcap, store: store, dwellMs: options.dwellMs, tcpdumpPath: options.tcpdumpPath,
                           bands: options.bands, channels: options.channels, oui: currentOUI)
} else if options.monitor {
    guard MonitorSource.hasCapturePrivileges() else {
        fail("monitor mode needs root (or BPF access): run  sudo \(appBinary) --monitor", code: 1)
    }
    guard FileManager.default.isExecutableFile(atPath: options.tcpdumpPath) else { fail("tcpdump not found at \(options.tcpdumpPath)", code: 1) }
    source = MonitorSource(iface: iface!, store: store, dwellMs: options.dwellMs, adaptive: options.adaptive, tcpdumpPath: options.tcpdumpPath,
                           bands: options.bands, channels: options.channels, oui: currentOUI)
} else {
    if !options.noLocation {
        let gate = LocationGate()
        if !gate.authorized && interactive {
            Terminal.write(Style.paint("Requesting Location Services access so macOS reveals SSIDs and BSSIDs…\n", Style.dim))
        }
        gate.request(timeout: gate.status == .notDetermined ? 1.5 : 0)
        location = gate
    }
    source = ScanSource(iface: iface!, store: store, interval: options.intervalSec, oui: currentOUI)
}

// Wait briefly for the OUI database so the first frame has vendors.
let ouiDeadline = Date().addingTimeInterval(1.5)
while currentOUI() == nil && Date() < ouiDeadline { Thread.sleep(forTimeInterval: 0.02) }

let view = ViewState(options: options)
view.hostApp = LocationGate.hostAppName()
view.showDetail = options.monitor || options.pcapPath != nil

func finish(printOutput: Bool) -> Never {
    source.stop()
    let now = Date()
    let nets = Render.visible(store.snapshot(), view, now: now)
    if printOutput {
        if options.json {
            print(Export.json(nets, store: store, mode: source.modeName, iface: source.interfaceName))
        } else if options.csv {
            print(Export.csv(nets), terminator: "")
        } else {
            let w = Terminal.isTTY ? Terminal.size().cols : 200
            print(Render.staticTable(nets, mode: source.modeName, width: w, detail: true, now: now), terminator: "")
            if store.redacted {
                print(Style.paint("\nNote: macOS hid SSID/BSSID. Allow Location Services for \(view.hostApp), or run: sudo \(appBinary) --monitor", Style.warn))
            }
            if let e = store.lastError { print(Style.paint("\nError: \(e)", Style.danger)) }
        }
    }
    exit(0)
}

Terminal.installSignalHandlers()

// MARK: - One-shot mode
if once {
    let duration = options.durationSec ?? (options.monitor ? 10 : 0)
    if let scan = source as? ScanSource {
        scan.scanOnce()
        if duration > 0 {
            let end = Date().addingTimeInterval(duration)
            while Date() < end && Terminal.interrupted == 0 { Thread.sleep(forTimeInterval: options.intervalSec); scan.scanOnce() }
        }
    } else if let replay = source as? MonitorSource, options.pcapPath != nil {
        replay.start()
        while !replay.finished && Terminal.interrupted == 0 { Thread.sleep(forTimeInterval: 0.05) }
    } else {
        source.start()
        let end = Date().addingTimeInterval(duration)
        while Date() < end && Terminal.interrupted == 0 { Thread.sleep(forTimeInterval: 0.1); location?.pump() }
    }
    finish(printOutput: true)
}

// MARK: - Live TUI
source.start()
Terminal.enterRaw()
Terminal.enterAltScreen()
var lastSize = Terminal.size()
let deadline = options.durationSec.map { Date().addingTimeInterval($0) }
var lastFrame: [String] = []

func cleanupTerminal() {
    Terminal.exitAltScreen()
    Terminal.restore()
}

while true {
    if Terminal.interrupted != 0 { break }
    if let d = deadline, Date() >= d { break }
    if Terminal.resized != 0 { Terminal.resized = 0; lastSize = Terminal.size(); lastFrame = []; Terminal.write("\u{1b}[2J") }
    location?.pump()

    var quit = false
    for k in Terminal.readKeys() {
        if view.editingFilter {
            switch k {
            case .enter: view.filter = view.filterDraft.isEmpty ? nil : view.filterDraft; view.editingFilter = false; view.scroll = 0
            case .escape: view.editingFilter = false
            case .char(let c):
                if c == "\u{7f}" || c == "\u{8}" { if !view.filterDraft.isEmpty { view.filterDraft.removeLast() } }
                else if c == "\u{3}" { quit = true }
                else if !c.isNewline { view.filterDraft.append(c) }
            default: break
            }
            continue
        }
        switch k {
        case .char("q"), .char("Q"), .char("\u{3}"), .escape: quit = true
        case .char("s"):
            let all = SortKey.allCases; view.sort = all[(all.firstIndex(of: view.sort)! + 1) % all.count]; view.reverse = false
        case .char("S"):
            let all = SortKey.allCases; view.sort = all[(all.firstIndex(of: view.sort)! + all.count - 1) % all.count]; view.reverse = false
        case .char("r"), .char("R"): view.reverse.toggle()
        case .char("p"), .char("P"), .char(" "): view.paused.toggle(); source.paused = view.paused
        case .char("c"), .char("C"): store.resetCounts()
        case .char("h"), .char("H"): view.showHidden.toggle(); view.scroll = 0
        case .char("m"), .char("M"), .char("d"), .char("D"): view.showDetail.toggle()
        case .char("/"): view.editingFilter = true; view.filterDraft = view.filter ?? ""
        case .char("x"), .char("X"): view.filter = nil; view.scroll = 0
        case .up, .char("k"): view.scroll = max(0, view.scroll - 1)
        case .down, .char("j"): view.scroll += 1
        case .pageUp: view.scroll = max(0, view.scroll - max(1, lastSize.rows - 8))
        case .pageDown: view.scroll += max(1, lastSize.rows - 8)
        case .home, .char("g"): view.scroll = 0
        case .end, .char("G"): view.scroll = Int.max / 2
        case .char("1"): view.sort = .rssi; view.reverse = false
        case .char("2"): view.sort = .ssid; view.reverse = false
        case .char("3"): view.sort = .bssid; view.reverse = false
        case .char("4"): view.sort = .manufacturer; view.reverse = false
        case .char("5"): view.sort = .channel; view.reverse = false
        case .char("6"): view.sort = .band; view.reverse = false
        case .char("7"): view.sort = .security; view.reverse = false
        case .char("8"): view.sort = .beacons; view.reverse = false
        case .char("9"): view.sort = .seen; view.reverse = false
        case .char("0"): view.sort = .width; view.reverse = false
        default: break
        }
    }
    if quit { break }

    view.tick += 1
    let frame = Render.frame(store: store, source: source, view: view, size: lastSize, bandsSupported: bandsSupported, now: Date())
    // Differential redraw inside a synchronized-output block to avoid flicker.
    var out = "\u{1b}[?2026h"
    for (i, line) in frame.lines.enumerated() where i >= lastFrame.count || lastFrame[i] != line {
        out += "\u{1b}[\(i + 1);1H" + line + "\u{1b}[K"
    }
    out += "\u{1b}[?2026l"
    Terminal.write(out)
    lastFrame = frame.lines
    Thread.sleep(forTimeInterval: 0.1)
}

cleanupTerminal()
finish(printOutput: options.json || options.csv)
