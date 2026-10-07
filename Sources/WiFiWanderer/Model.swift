import Foundation

enum Band: Int, Comparable, Codable {
    case ghz2_4 = 0, ghz5 = 1, ghz6 = 2, unknown = 9
    static func < (a: Band, b: Band) -> Bool { a.rawValue < b.rawValue }
    var label: String {
        switch self { case .ghz2_4: return "2.4"; case .ghz5: return "5"; case .ghz6: return "6"; case .unknown: return "?" }
    }
    var longLabel: String { self == .unknown ? "unknown" : label + " GHz" }

    static func from(frequencyMHz f: Int) -> Band {
        if f >= 2400 && f < 2500 { return .ghz2_4 }
        if f >= 5000 && f < 5925 { return .ghz5 }
        if f >= 5925 && f <= 7125 { return .ghz6 }
        return .unknown
    }
    /// Best-effort band from a channel number alone (6 GHz overlaps 2.4/5 GHz numbering).
    static func guess(channel: Int) -> Band { channel <= 14 ? .ghz2_4 : .ghz5 }
}

enum Channel {
    static func from(frequencyMHz f: Int) -> Int {
        if f == 2484 { return 14 }
        if f >= 2412 && f <= 2472 { return (f - 2407) / 5 }
        if f == 5935 { return 2 }
        if f >= 5955 && f <= 7115 { return (f - 5950) / 5 }
        if f >= 5000 && f < 5925 { return (f - 5000) / 5 }
        return 0
    }
}

struct Security: Comparable, Codable, Hashable {
    let label: String
    let tier: Int          // 0 open, 1 wep, 2 wpa, 3 wpa2, 4 wpa2/3 mix, 5 wpa3, 6 owe, 9 unknown

    static let open   = Security(label: "Open", tier: 0)
    static let wep    = Security(label: "WEP", tier: 1)
    static let wpa    = Security(label: "WPA", tier: 2)
    static let wpaMix = Security(label: "WPA/2", tier: 2)
    static let wpa2   = Security(label: "WPA2", tier: 3)
    static let wpa23  = Security(label: "WPA2/3", tier: 4)
    static let wpa3   = Security(label: "WPA3", tier: 5)
    static let wpaEnt  = Security(label: "WPA-Ent", tier: 2)
    static let wpa2Ent = Security(label: "WPA2-Ent", tier: 3)
    static let wpa3Ent = Security(label: "WPA3-Ent", tier: 5)
    static let owe    = Security(label: "OWE", tier: 6)
    static let oweTransition = Security(label: "OWE-Tr", tier: 6)
    static let unknown = Security(label: "?", tier: 9)

    static func < (a: Security, b: Security) -> Bool { a.tier != b.tier ? a.tier < b.tier : a.label < b.label }
}

/// Where a manufacturer attribution came from, in decreasing confidence.
enum VendorSource: Int, Codable, Comparable {
    case declared = 0   // WPS / vendor IE explicitly names the maker
    case oui = 1        // BSSID OUI lookup
    case vendorIE = 2   // vendor-specific IE OUIs in the beacon
    case ssid = 3       // SSID naming pattern
    case none = 9
    static func < (a: VendorSource, b: VendorSource) -> Bool { a.rawValue < b.rawValue }
    var marker: String {
        switch self { case .declared: return "✓"; case .oui: return ""; case .vendorIE: return "≈"; case .ssid: return "?"; case .none: return "" }
    }
    var asciiMarker: String {
        switch self { case .declared: return "*"; case .oui: return ""; case .vendorIE: return "~"; case .ssid: return "?"; case .none: return "" }
    }
    var description: String {
        switch self {
        case .declared: return "declared by the AP (WPS/vendor IE)"
        case .oui: return "BSSID OUI registry"
        case .vendorIE: return "inferred from vendor IEs in beacon"
        case .ssid: return "inferred from SSID pattern"
        case .none: return "unknown"
        }
    }
}

/// Everything we learned about one BSSID.
struct Network {
    let key: String
    var bssid: String?          // nil when macOS redacts it (no Location permission)
    var ssid: String?           // nil = hidden / not broadcast
    var channel: Int
    var band: Band
    var widthMHz: Int           // 0 = unknown
    var rssi: Int
    var noise: Int?
    var security: Security
    var beaconInterval: Int?    // TU (1.024 ms)
    var beacons: Int = 0        // beacon frames (monitor) or scan sightings (scan mode)
    var probeResponses: Int = 0
    var firstSeen: Date
    var lastSeen: Date
    var lastCountChange: Date
    var rssiMin: Int
    var rssiMax: Int
    var phy: String?            // "b/g/n", "ax", "be"...
    var countryCode: String?

    // Manufacturer enrichment
    var ouiVendor: String?          // from BSSID
    var ouiVendorShort: String?
    var locallyAdministered: Bool = false
    var wpsManufacturer: String?
    var wpsModelName: String?
    var wpsModelNumber: String?
    var wpsDeviceName: String?
    var apName: String?             // Cisco Aironet / Aruba AP name
    var vendorIEVendors: [String] = []   // non-chipset OUIs seen in vendor IEs
    var chipsetVendors: [String] = []
    var ssidHint: String?

    /// Best manufacturer string plus where it came from.
    var manufacturer: (name: String, source: VendorSource) {
        if let m = wpsManufacturer, !m.isEmpty { return (m, .declared) }
        if let o = ouiVendor, !o.isEmpty { return (o, .oui) }
        if let v = vendorIEVendors.first { return (v, .vendorIE) }
        if let h = ssidHint { return (h, .ssid) }
        if let c = chipsetVendors.first { return ("\(c) chipset", .vendorIE) }
        if locallyAdministered { return ("(locally administered)", .none) }
        return (bssid == nil ? "—" : "unknown", .none)
    }

    /// Model / AP name detail, if the AP told us.
    var device: String? {
        var parts: [String] = []
        if let n = apName, !n.isEmpty { parts.append(n) }
        if let m = wpsModelName, !m.isEmpty { parts.append(m) }
        else if let m = wpsModelNumber, !m.isEmpty { parts.append(m) }
        if let d = wpsDeviceName, !d.isEmpty, !parts.contains(d) { parts.append(d) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    var displaySSID: String { ssid.map { $0.isEmpty ? "<hidden>" : $0 } ?? "<hidden>" }
    var isHidden: Bool { ssid == nil || ssid!.isEmpty }
}

enum SortKey: String, CaseIterable {
    case rssi, ssid, bssid, manufacturer, channel, width, band, security, beacons, seen, first

    var title: String {
        switch self {
        case .rssi: return "RSSI"; case .ssid: return "SSID"; case .bssid: return "BSSID"; case .manufacturer: return "Manufacturer"
        case .channel: return "Channel"; case .width: return "Width"; case .band: return "Band"; case .security: return "Security"; case .beacons: return "Beacons"
        case .seen: return "Last seen"; case .first: return "First seen"
        }
    }
    /// Natural direction: true = descending
    var descendingByDefault: Bool { self == .rssi || self == .beacons || self == .seen }

    static func parse(_ s: String) -> SortKey? {
        let k = s.lowercased()
        if let d = SortKey(rawValue: k) { return d }
        switch k {
        case "signal", "strength", "dbm": return .rssi
        case "name", "essid": return .ssid
        case "mac": return .bssid
        case "vendor", "oui", "maker", "mfr", "manuf": return .manufacturer
        case "ch", "chan": return .channel
        case "bw", "bandwidth", "mhz", "chwidth": return .width
        case "sec", "enc", "encryption", "auth": return .security
        case "count", "frames", "beacon": return .beacons
        case "last", "lastseen", "age": return .seen
        case "firstseen": return .first
        default: return nil
        }
    }
}

/// Thread-safe store of networks.
final class Store {
    private let lock = NSLock()
    private var byKey: [String: Network] = [:]
    private(set) var rounds = 0
    private(set) var frames = 0
    private(set) var beaconFrames = 0
    private(set) var redacted = false      // macOS hid SSID/BSSID
    private(set) var lastError: String?
    private(set) var statusNote: String?
    let started = Date()

    func withLock<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }

    var count: Int { withLock { byKey.count } }
    func snapshot() -> [Network] { withLock { Array(byKey.values) } }

    func upsert(_ key: String, _ build: (inout Network?) -> Void) {
        withLock {
            var n = byKey[key]
            build(&n)
            if let n = n { byKey[key] = n }
        }
    }
    func removeAll(where pred: (Network) -> Bool) { withLock { byKey = byKey.filter { !pred($0.value) } } }
    func resetCounts() {
        withLock {
            for (k, var n) in byKey { n.beacons = 0; n.probeResponses = 0; byKey[k] = n }
            frames = 0; beaconFrames = 0; rounds = 0
        }
    }
    func bumpRound() { withLock { rounds += 1 } }
    func bumpFrames(beacon: Bool) { withLock { frames += 1; if beacon { beaconFrames += 1 } } }
    func setRedacted(_ v: Bool) { withLock { redacted = v } }
    func setError(_ e: String?) { withLock { lastError = e } }
    func setNote(_ n: String?) { withLock { statusNote = n } }
}
