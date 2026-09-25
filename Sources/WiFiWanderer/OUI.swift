import Foundation
import MachO

/// MAC address block → vendor name lookup, built from the Wireshark `manuf` file
/// (24-, 28- and 36-bit IEEE registry blocks). The database is embedded in the binary at
/// link time and can be overridden/updated on disk.
final class OUIDatabase {
    struct Vendor { let short: String; let full: String }

    private var tables: [Int: [UInt64: Vendor]] = [:]   // mask bits → (prefix → vendor)
    private var maskLengths: [Int] = []                   // descending
    private(set) var entryCount = 0
    private(set) var source = "none"

    static let downloadURL = URL(string: "https://www.wireshark.org/download/automated/data/manuf")!
    static var cacheDir: URL {
        let base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".cache/wifi-wanderer", isDirectory: true)
        return base
    }
    static var cacheFile: URL { cacheDir.appendingPathComponent("manuf") }

    /// Load order: explicit path → $WIFI_WANDERER_OUI → ~/.cache/wifi-wanderer/manuf → embedded → system Wireshark copies.
    static func load(explicitPath: String?) -> OUIDatabase {
        let db = OUIDatabase()
        var candidates: [(String, () -> Data?)] = []
        if let p = explicitPath { candidates.append((p, { FileManager.default.contents(atPath: p) })) }
        if let p = ProcessInfo.processInfo.environment["WIFI_WANDERER_OUI"] { candidates.append((p, { FileManager.default.contents(atPath: p) })) }
        candidates.append((cacheFile.path, { FileManager.default.contents(atPath: cacheFile.path) }))
        candidates.append(("embedded", { embeddedSection("__oui_db") }))
        for p in ["/opt/homebrew/share/wireshark/manuf", "/usr/local/share/wireshark/manuf", "/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf"] {
            candidates.append((p, { FileManager.default.contents(atPath: p) }))
        }
        for (name, loader) in candidates {
            if let data = loader(), db.parse(data) > 0 { db.source = name; return db }
        }
        return db
    }

    static func embeddedSection(_ name: String) -> Data? {
        var size: UInt = 0
        // Image 0 is the main executable; getsectiondata needs the real (slid) header address.
        guard let raw = _dyld_get_image_header(0) else { return nil }
        let header = UnsafeRawPointer(raw).assumingMemoryBound(to: mach_header_64.self)
        guard let ptr = getsectiondata(header, "__TEXT", name, &size), size > 0 else { return nil }
        return Data(bytes: ptr, count: Int(size))
    }

    /// Download the latest manuf file into the cache. Returns a human-readable result.
    static func update() -> Result<String, Error> {
        let sem = DispatchSemaphore(value: 0)
        var result: Result<String, Error> = .failure(NSError(domain: "oui", code: 1, userInfo: [NSLocalizedDescriptionKey: "no response"]))
        let task = URLSession.shared.dataTask(with: downloadURL) { data, resp, err in
            defer { sem.signal() }
            if let err = err { result = .failure(err); return }
            guard let data = data, let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
                result = .failure(NSError(domain: "oui", code: 2, userInfo: [NSLocalizedDescriptionKey: "HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0)"])); return
            }
            let probe = OUIDatabase()
            let n = probe.parse(data)
            guard n > 1000 else {
                result = .failure(NSError(domain: "oui", code: 3, userInfo: [NSLocalizedDescriptionKey: "downloaded file did not look like a manuf database (\(n) entries)"])); return
            }
            do {
                try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
                try data.write(to: cacheFile, options: .atomic)
                result = .success("saved \(n) entries (\(data.count / 1024) KB) to \(cacheFile.path)")
            } catch { result = .failure(error) }
        }
        task.resume()
        sem.wait()
        return result
    }

    /// Parse manuf text. Returns number of entries parsed.
    @discardableResult
    func parse(_ data: Data) -> Int {
        var count = 0
        var tables: [Int: [UInt64: Vendor]] = [:]
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var i = 0
            let n = bytes.count
            while i < n {
                var j = i
                while j < n && bytes[j] != 0x0A { j += 1 }
                defer { i = j + 1 }
                if j - i < 8 || bytes[i] == 0x23 /* # */ { continue }
                // Column 1: prefix up to tab
                var k = i
                var value: UInt64 = 0
                var hexDigits = 0
                var maskBits = -1
                while k < j && bytes[k] != 0x09 {
                    let c = bytes[k]
                    if c == 0x2F /* / */ {
                        var m = 0; k += 1
                        while k < j && bytes[k] != 0x09 { if bytes[k] >= 0x30 && bytes[k] <= 0x39 { m = m * 10 + Int(bytes[k] - 0x30) }; k += 1 }
                        maskBits = m
                        break
                    }
                    var d = -1
                    if c >= 0x30 && c <= 0x39 { d = Int(c - 0x30) }
                    else if c >= 0x41 && c <= 0x46 { d = Int(c - 0x41 + 10) }
                    else if c >= 0x61 && c <= 0x66 { d = Int(c - 0x61 + 10) }
                    if d >= 0 { value = (value << 4) | UInt64(d); hexDigits += 1 }
                    k += 1
                }
                guard hexDigits >= 6 else { continue }
                if maskBits < 0 { maskBits = hexDigits * 4 }
                // Normalise value to a 48-bit address then take the top `maskBits`
                let addr48 = value << UInt64((12 - hexDigits) * 4)
                guard maskBits > 0 && maskBits <= 48 else { continue }
                let prefix = addr48 >> UInt64(48 - maskBits)
                // Columns 2/3
                while k < j && bytes[k] == 0x09 { k += 1 }
                var s = k
                while k < j && bytes[k] != 0x09 { k += 1 }
                let short = String(decoding: UnsafeBufferPointer(rebasing: bytes[s..<k]), as: UTF8.self).trimmingCharacters(in: .whitespaces)
                while k < j && bytes[k] == 0x09 { k += 1 }
                s = k
                let full = String(decoding: UnsafeBufferPointer(rebasing: bytes[s..<j]), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                let vendor = Vendor(short: short, full: full.isEmpty ? short : full)
                tables[maskBits, default: [:]][prefix] = vendor
                count += 1
            }
        }
        if count > 0 {
            self.tables = tables
            self.maskLengths = tables.keys.sorted(by: >)
            self.entryCount = count
        }
        return count
    }

    /// Look up a MAC given as 6 bytes.
    func lookup(_ mac: [UInt8]) -> Vendor? {
        guard mac.count == 6 else { return nil }
        var addr: UInt64 = 0
        for b in mac { addr = (addr << 8) | UInt64(b) }
        for bits in maskLengths {
            let prefix = addr >> UInt64(48 - bits)
            if let v = tables[bits]?[prefix] { return v }
        }
        return nil
    }

    func lookup(_ macString: String) -> Vendor? {
        guard let mac = OUIDatabase.parseMAC(macString) else { return nil }
        return lookup(mac)
    }

    static func parseMAC(_ s: String) -> [UInt8]? {
        let hex = s.filter { $0.isHexDigit }
        guard hex.count == 12 else { return nil }
        var out: [UInt8] = []
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            out.append(b); idx = next
        }
        return out
    }

    static func format(_ mac: [UInt8]) -> String { mac.map { String(format: "%02x", $0) }.joined(separator: ":") }
}

/// Well-known OUIs that appear in vendor-specific IEs but do not identify the AP maker.
enum VendorIEClassifier {
    /// Generic/protocol OUIs (ignored entirely)
    static let generic: Set<UInt32> = [
        0x0050F2, // Microsoft (WPS, WMM, WPA1)
        0x000FAC, // IEEE 802.11
        0x506F9A, // Wi-Fi Alliance (P2P, Hotspot 2.0, MBO)
    ]

    /// Chipset / silicon vendors: useful context but not the AP brand.
    static let chipset: [UInt32: String] = [
        0x001018: "Broadcom", 0x00904C: "Broadcom", 0x0010F7: "Broadcom",
        0x00037F: "Qualcomm Atheros", 0x8CFDF0: "Qualcomm", 0x001374: "Atheros", 0x00B052: "Qualcomm",
        0x000CE7: "MediaTek", 0x000C43: "Ralink/MediaTek", 0x00E04C: "Realtek",
        0x001B21: "Intel", 0x8086F2: "Intel", 0x00A0C6: "Qualcomm", 0x005043: "Marvell", 0x002686: "Quantenna",
        0x00408C: "Axis", 0x00179A: "D-Link (chip)",
    ]
}

/// SSID naming conventions that hint at the maker. Lowest-confidence source.
enum SSIDHints {
    static let patterns: [(prefix: String, vendor: String)] = [
        ("NETGEAR", "Netgear"), ("ORBI", "Netgear (Orbi)"), ("Nighthawk", "Netgear"),
        ("TP-Link", "TP-Link"), ("TP-LINK", "TP-Link"), ("Archer", "TP-Link"), ("Deco", "TP-Link"), ("Tapo", "TP-Link"),
        ("Linksys", "Linksys"), ("Velop", "Linksys"),
        ("ASUS", "ASUS"), ("RT-AX", "ASUS"), ("ZenWiFi", "ASUS"),
        ("eero", "eero (Amazon)"), ("Google", "Google"), ("NEST", "Google Nest"),
        ("ATT", "AT&T gateway"), ("ATTWiFi", "AT&T"), ("Fios", "Verizon Fios"), ("Verizon", "Verizon"),
        ("xfinity", "Comcast Xfinity"), ("XFINITY", "Comcast Xfinity"), ("Xfinity", "Comcast Xfinity"),
        ("SpectrumSetup", "Spectrum gateway"), ("MySpectrumWiFi", "Spectrum gateway"), ("Spectrum", "Spectrum"),
        ("CenturyLink", "CenturyLink"), ("Cox", "Cox"), ("Optimum", "Optimum"), ("STARLINK", "Starlink"), ("Starlink", "Starlink"),
        ("DIRECT-", "Wi-Fi Direct device"), ("HP-Print", "HP printer"), ("HP-Setup", "HP"), ("EPSON", "Epson"), ("Canon", "Canon"), ("Brother", "Brother"),
        ("Sonos", "Sonos"), ("Roku", "Roku"), ("Ring", "Ring"), ("Tesla", "Tesla"), ("Chromecast", "Google"),
        ("Ubiquiti", "Ubiquiti"), ("UniFi", "Ubiquiti"), ("MikroTik", "MikroTik"), ("Meraki", "Cisco Meraki"), ("Aruba", "Aruba"),
        ("Arris", "Arris"), ("SmartRG", "SmartRG"), ("dlink", "D-Link"), ("D-Link", "D-Link"), ("Belkin", "Belkin"), ("Wyze", "Wyze"),
        ("Amazon", "Amazon"), ("Blink", "Amazon Blink"), ("Vizio", "Vizio"), ("SAMSUNG", "Samsung"), ("LG_", "LG"), ("Philips", "Philips"),
        ("GL-", "GL.iNet"), ("OpenWrt", "OpenWrt"), ("Synology", "Synology"), ("Ecobee", "ecobee"), ("Nanoleaf", "Nanoleaf"),
    ]
    static func hint(for ssid: String?) -> String? {
        guard let s = ssid, !s.isEmpty else { return nil }
        let lower = s.lowercased()
        for p in patterns where lower.hasPrefix(p.prefix.lowercased()) { return p.vendor }
        // DIRECT-xx-<Model> gives the model of a Wi-Fi Direct device
        return nil
    }
}
