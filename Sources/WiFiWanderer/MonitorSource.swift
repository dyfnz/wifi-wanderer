import Foundation
import CoreWLAN

/// Active source: puts the interface in monitor mode through tcpdump, parses the pcap stream
/// (radiotap + 802.11 management frames) and hops channels with CoreWLAN.
final class MonitorSource: Source {
    var modeName: String { pcapPath == nil ? "monitor" : "replay" }
    let interfaceName: String
    private(set) var finished = false
    private let pcapPath: String?
    var paused = false
    private(set) var currentChannel: Int?
    private(set) var hopIndex = 0
    var hopCount: Int { hopList.count }
    /// Estimated seconds for one full sweep with the current per-channel dwell times.
    var sweepSeconds: Double { hopList.indices.reduce(0) { $0 + dwellFor(index: $1) } }
    private let adaptive: Bool
    private var channelHeard: [Int: Int] = [:]   // channel number → beacons heard on it
    private var sweeps = 0

    private let iface: CWInterface?
    private let store: Store
    private let oui: () -> OUIDatabase?
    private let dwell: TimeInterval
    private let tcpdumpPath: String
    private let hopList: [CWChannel]
    private var process: Process?
    private var running = false
    private var buffer = Data()
    private var pcap: PcapState = .header
    private var linkType: Int = 127
    private var bigEndian = false
    private var pcapng = false

    private enum PcapState { case header, records }

    init(iface: CWInterface?, pcapPath: String? = nil, store: Store, dwellMs: Int, adaptive: Bool = true, tcpdumpPath: String, bands: Set<Band>?, channels: Set<Int>?, oui: @escaping () -> OUIDatabase?) {
        self.iface = iface; self.pcapPath = pcapPath; self.store = store; self.dwell = Double(dwellMs) / 1000; self.adaptive = adaptive; self.tcpdumpPath = tcpdumpPath; self.oui = oui
        self.interfaceName = pcapPath.map { ($0 as NSString).lastPathComponent } ?? (iface?.interfaceName ?? "en0")
        // Build the hop list: one 20 MHz entry per channel number, filtered by band/channel options.
        var best: [String: CWChannel] = [:]
        for ch in (pcapPath == nil ? iface?.supportedWLANChannels() : nil) ?? [] {
            let b = WiFi.band(of: ch)
            if let bands = bands, !bands.contains(b) { continue }
            if let channels = channels, !channels.contains(ch.channelNumber) { continue }
            let k = "\(b.rawValue)-\(ch.channelNumber)"
            if let cur = best[k] {
                if WiFi.width(of: ch) < WiFi.width(of: cur) { best[k] = ch }
            } else { best[k] = ch }
        }
        hopList = best.values.sorted { (a, b) in
            let ba = WiFi.band(of: a), bb = WiFi.band(of: b)
            return ba != bb ? ba < bb : a.channelNumber < b.channelNumber
        }
    }

    static func hasCapturePrivileges() -> Bool {
        if geteuid() == 0 { return true }
        return access("/dev/bpf0", R_OK | W_OK) == 0
    }

    func start() {
        running = true
        if let path = pcapPath { startReplay(path); return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tcpdumpPath)
        p.arguments = ["-I", "-i", interfaceName, "-U", "-w", "-", "-s", "0", "-y", "IEEE802_11_RADIO",
                       "type mgt and (subtype beacon or subtype probe-resp)"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        p.terminationHandler = { [weak self] proc in
            guard let self = self, self.running else { return }
            self.store.setError("tcpdump exited (status \(proc.terminationStatus)); no capture")
        }
        do { try p.run() } catch {
            store.setError("cannot start tcpdump: \(error.localizedDescription)")
            return
        }
        process = p
        let reader = Thread { [self] in
            let fh = out.fileHandleForReading
            while running {
                let d = fh.availableData
                if d.isEmpty { break }
                feed(d)
            }
        }
        reader.name = "pcap-reader"; reader.start()
        let errReader = Thread { [self] in
            let fh = err.fileHandleForReading
            while running {
                let d = fh.availableData
                if d.isEmpty { break }
                let s = String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                if s.isEmpty { continue }
                if s.lowercased().contains("listening on") { store.setNote(nil) }
                else if s.lowercased().contains("tcpdump:") || s.lowercased().contains("error") || s.lowercased().contains("permission") {
                    store.setError(s.components(separatedBy: "\n").first)
                }
            }
        }
        errReader.name = "tcpdump-stderr"; errReader.start()
        let hopper = Thread { [self] in hopLoop() }
        hopper.name = "hopper"; hopper.start()
    }

    /// Replay a saved capture, in chunks so the live view animates.
    private func startReplay(_ path: String) {
        guard let fh = FileHandle(forReadingAtPath: path) else {
            store.setError("cannot open \(path)"); finished = true; return
        }
        let t = Thread { [self] in
            while running {
                let d = fh.readData(ofLength: 32 * 1024)
                if d.isEmpty { break }
                feed(d)
                Thread.sleep(forTimeInterval: 0.03)
            }
            store.bumpRound()
            store.setNote("replay finished: \(path)")
            finished = true
        }
        t.name = "pcap-replay"; t.start()
    }

    func stop() {
        running = false
        if let p = process, p.isRunning { p.terminate() }
        process = nil
    }

    // MARK: channel hopping

    /// Full dwell on channels where beacons were heard; a short visit on quiet ones after the first sweep.
    private func dwellFor(index: Int) -> Double {
        guard adaptive, sweeps >= 1, index < hopList.count else { return dwell }
        let ch = hopList[index].channelNumber
        return (channelHeard[ch] ?? 0) > 0 ? dwell : min(dwell, 0.08)
    }

    private func hopLoop() {
        guard !hopList.isEmpty else { store.setError("no channels to hop (check --band/--channels)"); return }
        Thread.sleep(forTimeInterval: 0.5)   // let tcpdump take the interface first
        var failures = 0
        while running {
            if paused { Thread.sleep(forTimeInterval: 0.1); continue }
            let ch = hopList[hopIndex % hopList.count]
            do {
                try iface?.setWLANChannel(ch)
                currentChannel = ch.channelNumber
                if failures > 0 { failures = 0; store.setError(nil) }
            } catch {
                failures += 1
                if failures == 3 {
                    store.setError("channel hop failed (\(error.localizedDescription)) — capturing on the current channel only")
                }
            }
            Thread.sleep(forTimeInterval: dwellFor(index: hopIndex))
            hopIndex = (hopIndex + 1) % hopList.count
            if hopIndex == 0 { sweeps += 1; store.bumpRound() }
        }
    }

    // MARK: pcap stream parsing

    private func feed(_ d: Data) {
        buffer.append(d)
        var consumed = 0
        buffer.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var off = 0
            while true {
                if pcap == .header {
                    guard raw.count - off >= 24 else { break }
                    let magic = raw.loadUnaligned(fromByteOffset: off, as: UInt32.self)
                    switch magic {
                    case 0xa1b2c3d4, 0xa1b23c4d: bigEndian = false
                    case 0xd4c3b2a1, 0x4d3cb2a1: bigEndian = true
                    case 0x0a0d0d0a:
                        pcapng = true
                        let bom = raw.loadUnaligned(fromByteOffset: off + 8, as: UInt32.self)
                        bigEndian = (bom == 0x4d3c2b1a)
                        pcap = .records
                        continue
                    default:
                        store.setError("unrecognised capture stream (magic \(String(magic, radix: 16)))")
                        off = raw.count; break
                    }
                    linkType = Int(u32(raw, off + 20))
                    off += 24
                    pcap = .records
                    continue
                }
                if pcapng {
                    guard raw.count - off >= 8 else { break }
                    let type = u32(raw, off), total = Int(u32(raw, off + 4))
                    guard total >= 12, raw.count - off >= total else { break }
                    if type == 1 { linkType = Int(u16(raw, off + 8)) }          // Interface Description Block
                    else if type == 6 {                                           // Enhanced Packet Block
                        let capLen = Int(u32(raw, off + 20))
                        if 28 + capLen <= total { handleFrame(UnsafeRawBufferPointer(rebasing: raw[(off + 28)..<(off + 28 + capLen)])) }
                    } else if type == 3 {                                         // Simple Packet Block
                        let len = min(Int(u32(raw, off + 8)), total - 16)
                        handleFrame(UnsafeRawBufferPointer(rebasing: raw[(off + 12)..<(off + 12 + len)]))
                    }
                    off += total
                    continue
                }
                guard raw.count - off >= 16 else { break }
                let inclLen = Int(u32(raw, off + 8))
                guard raw.count - off >= 16 + inclLen else { break }
                handleFrame(UnsafeRawBufferPointer(rebasing: raw[(off + 16)..<(off + 16 + inclLen)]))
                off += 16 + inclLen
            }
            consumed = off
        }
        if consumed > 0 { buffer.removeSubrange(0..<consumed) }
    }

    private func u16(_ r: UnsafeRawBufferPointer, _ o: Int) -> UInt16 {
        let v = r.loadUnaligned(fromByteOffset: o, as: UInt16.self); return bigEndian ? v.byteSwapped : v
    }
    private func u32(_ r: UnsafeRawBufferPointer, _ o: Int) -> UInt32 {
        let v = r.loadUnaligned(fromByteOffset: o, as: UInt32.self); return bigEndian ? v.byteSwapped : v
    }

    // MARK: frame handling

    private func handleFrame(_ frame: UnsafeRawBufferPointer) {
        var rt = Radiotap.Info()
        var body = frame
        if linkType == 127 {
            guard let info = Radiotap.parse(frame) else { return }
            rt = info
            guard frame.count > info.length else { return }
            body = UnsafeRawBufferPointer(rebasing: frame[info.length...])
        }
        if rt.fcsPresent && body.count > 4 { body = UnsafeRawBufferPointer(rebasing: body[..<(body.count - 4)]) }
        guard body.count >= 36 else { return }
        let fc0 = body[0]
        let type = (fc0 >> 2) & 0x3, subtype = (fc0 >> 4) & 0xF
        guard type == 0, subtype == 8 || subtype == 5 else { return }
        let isBeacon = subtype == 8
        let bssidBytes = Array(body[16..<22])
        let bssid = OUIDatabase.format(bssidBytes)
        let interval = Int(body[32]) | (Int(body[33]) << 8)
        let cap = Int(body[34]) | (Int(body[35]) << 8)
        var facts = IEParser.parse(UnsafeRawBufferPointer(rebasing: body[36...]))
        facts.privacy = (cap & 0x10) != 0
        store.bumpFrames(beacon: isBeacon)

        let now = Date()
        var band: Band = .unknown
        var channel = 0
        if let f = rt.frequency { band = Band.from(frequencyMHz: f); channel = Channel.from(frequencyMHz: f) }
        if let c6 = facts.heOperation6GHzChannel, band == .ghz6 || band == .unknown { channel = c6; band = .ghz6 }
        else if let ds = facts.dsChannel, band != .ghz6 { channel = ds; if band == .unknown { band = Band.guess(channel: ds) } }
        if channel == 0, let cur = currentChannel { channel = cur; band = hopList.first(where: { $0.channelNumber == cur }).map(WiFi.band) ?? Band.guess(channel: cur) }
        if pcapPath != nil { currentChannel = channel }
        if isBeacon, channel != 0 { channelHeard[channel, default: 0] += 1 }
        let rssi = rt.signal ?? -100
        let db = oui()

        store.upsert(bssid) { rec in
            if rec == nil {
                rec = Network(key: bssid, bssid: bssid, ssid: facts.ssid, channel: channel, band: band, widthMHz: facts.widthMHz,
                              rssi: rssi, noise: rt.noise, security: facts.security, beaconInterval: interval,
                              firstSeen: now, lastSeen: now, lastCountChange: now, rssiMin: rssi, rssiMax: rssi)
                rec!.locallyAdministered = (bssidBytes[0] & 0x02) != 0
                if let v = db?.lookup(bssidBytes) { rec!.ouiVendor = v.full; rec!.ouiVendorShort = v.short }
            }
            guard var r = rec else { return }
            if let s = facts.ssid, !s.isEmpty { r.ssid = s }          // probe responses reveal hidden SSIDs
            if rt.signal != nil { r.rssi = rssi; r.rssiMin = min(r.rssiMin, rssi); r.rssiMax = max(r.rssiMax, rssi) }
            if let n = rt.noise { r.noise = n }
            if channel != 0 { r.channel = channel; r.band = band }
            r.security = facts.security
            r.beaconInterval = interval
            if isBeacon { r.beacons += 1 } else { r.probeResponses += 1 }
            r.lastSeen = now; r.lastCountChange = now
            if r.ouiVendor == nil, let v = db?.lookup(bssidBytes) { r.ouiVendor = v.full; r.ouiVendorShort = v.short }
            IEParser.apply(facts, to: &r, oui: db)
            rec = r
        }
    }
}

/// Minimal radiotap header parser: extracts signal, noise, frequency and flags from the first
/// presence word (enough for every macOS capture seen so far).
enum Radiotap {
    struct Info { var length = 0; var signal: Int?; var noise: Int?; var frequency: Int?; var fcsPresent = false }

    // (size, alignment) for radiotap fields 0…27
    private static let fields: [(Int, Int)] = [
        (8, 8), (1, 1), (1, 1), (4, 2), (2, 2), (1, 1), (1, 1), (2, 2), (2, 2), (2, 2), (1, 1), (1, 1), (1, 1), (1, 1),
        (2, 2), (2, 2), (1, 1), (1, 1), (8, 4), (3, 1), (8, 4), (12, 2), (12, 8), (12, 2), (12, 2), (6, 2), (1, 1), (4, 2),
    ]

    static func parse(_ b: UnsafeRawBufferPointer) -> Info? {
        guard b.count >= 8, b[0] == 0 else { return nil }
        var info = Info()
        let len = Int(b[2]) | (Int(b[3]) << 8)
        guard len >= 8, len <= b.count else { return nil }
        info.length = len
        var present: [UInt32] = []
        var off = 4
        while off + 4 <= len {
            let w = b.loadUnaligned(fromByteOffset: off, as: UInt32.self).littleEndian
            present.append(w); off += 4
            if w & 0x8000_0000 == 0 { break }
            if present.count > 8 { return info }
        }
        let first = present.first ?? 0
        for bit in 0..<28 where first & (1 << UInt32(bit)) != 0 {
            let (size, align) = fields[bit]
            off = (off + align - 1) / align * align
            guard off + size <= len else { break }
            switch bit {
            case 1: info.fcsPresent = (b[off] & 0x10) != 0
            case 3: info.frequency = Int(b[off]) | (Int(b[off + 1]) << 8)
            case 5: info.signal = Int(Int8(bitPattern: b[off]))
            case 6: info.noise = Int(Int8(bitPattern: b[off]))
            default: break
            }
            off += size
        }
        return info
    }
}
