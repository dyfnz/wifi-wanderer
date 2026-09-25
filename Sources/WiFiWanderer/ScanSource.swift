import Foundation
import CoreWLAN

/// Shared source protocol: something that feeds the Store in the background.
protocol Source: AnyObject {
    var modeName: String { get }
    var interfaceName: String { get }
    var paused: Bool { get set }
    var currentChannel: Int? { get }
    var hopIndex: Int { get }
    var hopCount: Int { get }
    func start()
    func stop()
}

enum WiFi {
    static func interface(named name: String?) throws -> CWInterface {
        let client = CWWiFiClient.shared()
        if let name = name {
            guard let i = client.interface(withName: name) else { throw OptionError("no Wi-Fi interface named '\(name)' (available: \((client.interfaceNames() ?? []).joined(separator: ", ")))") }
            return i
        }
        guard let i = client.interface() else { throw OptionError("no Wi-Fi interface found") }
        return i
    }

    static func band(of ch: CWChannel) -> Band {
        switch ch.channelBand {
        case .band2GHz: return .ghz2_4
        case .band5GHz: return .ghz5
        case .band6GHz: return .ghz6
        default: return Band.guess(channel: ch.channelNumber)
        }
    }

    static func width(of ch: CWChannel) -> Int {
        switch ch.channelWidth {
        case .width20MHz: return 20
        case .width40MHz: return 40
        case .width80MHz: return 80
        case .width160MHz: return 160
        default: return 0
        }
    }

    /// Bands the interface can tune, and their channel counts.
    static func supportedBands(_ iface: CWInterface) -> [Band: Int] {
        var out: [Band: Set<Int>] = [:]
        for ch in iface.supportedWLANChannels() ?? [] { out[band(of: ch), default: []].insert(ch.channelNumber) }
        return out.mapValues { $0.count }
    }

    static func security(of n: CWNetwork) -> Security {
        if n.supportsSecurity(.wpa3Enterprise) { return .wpa3Ent }
        if n.supportsSecurity(.wpa3Transition) { return .wpa23 }
        if n.supportsSecurity(.wpa3Personal) { return .wpa3 }
        if n.supportsSecurity(.wpa2Enterprise) || n.supportsSecurity(.enterprise) || n.supportsSecurity(.wpaEnterpriseMixed) { return .wpa2Ent }
        if n.supportsSecurity(.wpaEnterprise) { return .wpaEnt }
        if n.supportsSecurity(.wpaPersonalMixed) { return .wpaMix }
        if n.supportsSecurity(.wpa2Personal) || n.supportsSecurity(.personal) { return .wpa2 }
        if n.supportsSecurity(.wpaPersonal) { return .wpa }
        if n.supportsSecurity(.oweTransition) { return .oweTransition }
        if n.supportsSecurity(.OWE) { return .owe }
        if n.supportsSecurity(.dynamicWEP) || n.supportsSecurity(.WEP) { return .wep }
        if n.supportsSecurity(.none) { return .open }
        return .unknown
    }
}

/// Passive source: repeated CoreWLAN scans. Counts "sightings" per scan round in `beacons`.
final class ScanSource: Source {
    let modeName = "scan"
    let interfaceName: String
    var paused = false
    var currentChannel: Int? { nil }
    var hopIndex: Int { 0 }
    var hopCount: Int { 0 }

    private let iface: CWInterface
    private let store: Store
    private let oui: () -> OUIDatabase?
    private let interval: TimeInterval
    private var running = false
    private var thread: Thread?

    init(iface: CWInterface, store: Store, interval: TimeInterval, oui: @escaping () -> OUIDatabase?) {
        self.iface = iface; self.store = store; self.interval = interval; self.oui = oui
        self.interfaceName = iface.interfaceName ?? "en0"
    }

    func start() {
        running = true
        let t = Thread { [self] in
            while running {
                if !paused { scanOnce() }
                let deadline = Date().addingTimeInterval(interval)
                while running && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
            }
        }
        t.name = "scan"; t.start(); thread = t
    }

    func stop() { running = false }

    /// One synchronous scan round.
    func scanOnce() {
        let nets: Set<CWNetwork>
        do { nets = try iface.scanForNetworks(withSSID: nil) }
        catch { store.setError("scan failed: \(error.localizedDescription)"); return }
        store.setError(nil)
        let now = Date()
        let db = oui()
        var anyBSSID = false
        var anon = 0
        // Networks without a BSSID cannot be tracked across rounds; replace them wholesale.
        store.removeAll { $0.bssid == nil }
        for n in nets {
            let ch = n.wlanChannel
            let key: String
            if let b = n.bssid?.lowercased() { key = b; anyBSSID = true } else { anon += 1; key = "anon-\(anon)" }
            store.upsert(key) { rec in
                if rec == nil {
                    rec = Network(key: key, bssid: n.bssid?.lowercased(), ssid: n.ssid, channel: ch?.channelNumber ?? 0,
                                  band: ch.map(WiFi.band) ?? .unknown, widthMHz: ch.map(WiFi.width) ?? 0,
                                  rssi: n.rssiValue, noise: n.noiseMeasurement == 0 ? nil : n.noiseMeasurement,
                                  security: WiFi.security(of: n), beaconInterval: n.beaconInterval,
                                  firstSeen: now, lastSeen: now, lastCountChange: now, rssiMin: n.rssiValue, rssiMax: n.rssiValue)
                    if let b = n.bssid, let mac = OUIDatabase.parseMAC(b) {
                        rec!.locallyAdministered = (mac[0] & 0x02) != 0
                        if let v = db?.lookup(mac) { rec!.ouiVendor = v.full; rec!.ouiVendorShort = v.short }
                    }
                    if let cc = n.countryCode { rec!.countryCode = cc }
                }
                guard var r = rec else { return }
                if let s = n.ssid { r.ssid = s }
                r.rssi = n.rssiValue
                r.rssiMin = min(r.rssiMin, n.rssiValue); r.rssiMax = max(r.rssiMax, n.rssiValue)
                if n.noiseMeasurement != 0 { r.noise = n.noiseMeasurement }
                if let ch = ch { r.channel = ch.channelNumber; r.band = WiFi.band(of: ch); let w = WiFi.width(of: ch); if w > 0 { r.widthMHz = w } }
                r.security = WiFi.security(of: n)
                r.beaconInterval = n.beaconInterval
                r.beacons += 1
                r.lastSeen = now; r.lastCountChange = now
                if r.ouiVendor == nil, let b = r.bssid, let v = db?.lookup(b) { r.ouiVendor = v.full; r.ouiVendorShort = v.short }
                if let ie = n.informationElementData, !ie.isEmpty {
                    ie.withUnsafeBytes { IEParser.apply(IEParser.parse($0), to: &r, oui: db) }
                } else if r.ssidHint == nil {
                    r.ssidHint = SSIDHints.hint(for: r.ssid)
                }
                rec = r
            }
        }
        store.setRedacted(!nets.isEmpty && !anyBSSID)
        store.bumpRound()
    }
}
