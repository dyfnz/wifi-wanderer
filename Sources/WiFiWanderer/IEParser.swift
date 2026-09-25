import Foundation

/// Facts extracted from the information elements of a beacon / probe response / CoreWLAN IE blob.
struct IEFacts {
    var ssid: String?
    var hidden = false
    var dsChannel: Int?
    var privacy = false
    var rsn: RSNInfo?
    var wpa1: RSNInfo?
    var wpsManufacturer: String?
    var wpsModelName: String?
    var wpsModelNumber: String?
    var wpsDeviceName: String?
    var apName: String?
    var vendorOUIs: [UInt32] = []
    var countryCode: String?
    var ht = false, vht = false, he = false, eht = false
    var heOperation6GHzChannel: Int?
    var widthMHz: Int = 0

    var phy: String? {
        if eht { return "be" }
        if he { return "ax" }
        if vht { return "ac" }
        if ht { return "n" }
        return nil
    }

    var security: Security {
        if let r = rsn {
            if r.akms.contains(18) && !r.akms.contains(where: { $0 == 2 || $0 == 8 }) { return .owe }
            let sae = r.akms.contains(8) || r.akms.contains(9) || r.akms.contains(24) || r.akms.contains(25)
            let psk = r.akms.contains(2) || r.akms.contains(4) || r.akms.contains(6)
            let eap = r.akms.contains(where: { [1, 3, 5, 11, 12, 13].contains($0) })
            let suiteB = r.akms.contains(12) || r.akms.contains(13)
            if sae && psk { return .wpa23 }
            if sae { return .wpa3 }
            if suiteB { return .wpa3Ent }
            if eap && r.akms.contains(5) && !r.akms.contains(1) { return .wpa3Ent }   // 802.1X-SHA256 only
            if eap { return .wpa2Ent }
            if psk { return wpa1 != nil ? .wpaMix : .wpa2 }
            return .wpa2
        }
        if let w = wpa1 {
            if w.akms.contains(1) { return .wpaEnt }
            return .wpa
        }
        return privacy ? .wep : .open
    }
}

struct RSNInfo {
    var version = 0
    var groupCipher = 0
    var pairwise: [Int] = []
    var akms: [Int] = []
}

enum IEParser {
    /// Parse a run of `id, len, data…` elements.
    static func parse(_ b: UnsafeRawBufferPointer) -> IEFacts {
        var f = IEFacts()
        var i = 0
        let n = b.count
        while i + 2 <= n {
            let id = Int(b[i]); let len = Int(b[i + 1])
            guard i + 2 + len <= n else { break }
            let d = UnsafeRawBufferPointer(rebasing: b[(i + 2)..<(i + 2 + len)])
            switch id {
            case 0:
                if len == 0 || d.allSatisfy({ $0 == 0 }) { f.hidden = true; f.ssid = nil }
                else { f.ssid = TextWidth.sanitize(String(decoding: d, as: UTF8.self)) }
            case 3:
                if len >= 1 { f.dsChannel = Int(d[0]) }
            case 7:
                if len >= 2 { let cc = String(decoding: UnsafeRawBufferPointer(rebasing: d[0..<2]), as: UTF8.self); if cc.allSatisfy({ $0.isLetter }) { f.countryCode = cc.uppercased() } }
            case 45: f.ht = true
                if len >= 2, d[0] & 0x02 != 0 { f.widthMHz = max(f.widthMHz, 40) } else { f.widthMHz = max(f.widthMHz, 20) }
            case 48: f.rsn = parseRSN(d, wpa1: false)
            case 191: f.vht = true
            case 192:
                if len >= 1 { let w = d[0]; f.widthMHz = max(f.widthMHz, w == 0 ? 0 : (w == 1 ? 80 : 160)) }
            case 61:
                if len >= 2 { f.widthMHz = max(f.widthMHz, (d[1] & 0x04) != 0 ? 40 : 20) }
            case 133:
                // Cisco Aironet IE: AP name at offset 10, 16 bytes
                if len >= 26 {
                    let nameBytes = Array(d[10..<26]).prefix { $0 != 0 }
                    let s = String(decoding: nameBytes, as: UTF8.self)
                    if !s.isEmpty && s.allSatisfy({ $0.isASCII && !$0.isNewline }) { f.apName = TextWidth.sanitize(s) }
                }
            case 221:
                parseVendor(d, &f)
            case 255:
                if len >= 1 {
                    switch d[0] {
                    case 35: f.he = true
                    case 36:
                        // HE Operation: d[1...3] = HE Operation Parameters, d[4] = BSS colour,
                        // d[5...6] = basic MCS/NSS, then optional VHT op info (3), co-hosted BSSID (1),
                        // 6 GHz Operation Information (5). Flags: B14 VHT present, B15 co-hosted, B17 6 GHz present.
                        if len >= 7, d[3] & 0x02 != 0 {
                            var off = 7
                            if d[2] & 0x40 != 0 { off += 3 }
                            if d[2] & 0x80 != 0 { off += 1 }
                            if len >= off + 5 {
                                f.heOperation6GHzChannel = Int(d[off])
                                let cw = Int(d[off + 1] & 0x03)
                                f.widthMHz = max(f.widthMHz, [20, 40, 80, 160][cw])
                            }
                        }
                    case 108: f.eht = true
                    default: break
                    }
                }
            default: break
            }
            i += 2 + len
        }
        return f
    }

    static func parseRSN(_ d: UnsafeRawBufferPointer, wpa1: Bool) -> RSNInfo {
        var r = RSNInfo()
        var i = 0
        func u16() -> Int? { guard i + 2 <= d.count else { return nil }; let v = Int(d[i]) | (Int(d[i + 1]) << 8); i += 2; return v }
        func suite() -> Int? { guard i + 4 <= d.count else { return nil }; let t = Int(d[i + 3]); i += 4; return t }
        r.version = u16() ?? 0
        r.groupCipher = suite() ?? 0
        if let pc = u16() { for _ in 0..<min(pc, 16) { if let s = suite() { r.pairwise.append(s) } } }
        if let ac = u16() { for _ in 0..<min(ac, 16) { if let s = suite() { r.akms.append(s) } } }
        return r
    }

    static func parseVendor(_ d: UnsafeRawBufferPointer, _ f: inout IEFacts) {
        guard d.count >= 4 else { return }
        let oui = (UInt32(d[0]) << 16) | (UInt32(d[1]) << 8) | UInt32(d[2])
        let type = d[3]
        if !f.vendorOUIs.contains(oui) { f.vendorOUIs.append(oui) }
        switch (oui, type) {
        case (0x0050F2, 1):   // WPA1
            f.wpa1 = parseRSN(UnsafeRawBufferPointer(rebasing: d[4...]), wpa1: true)
        case (0x0050F2, 4):   // WPS
            parseWPS(UnsafeRawBufferPointer(rebasing: d[4...]), &f)
        case (0x000B86, 1):   // Aruba AP name
            let s = String(decoding: d[4...].prefix { $0 != 0 }, as: UTF8.self)
            if !s.isEmpty { f.apName = TextWidth.sanitize(s) }
        default: break
        }
    }

    static func parseWPS(_ d: UnsafeRawBufferPointer, _ f: inout IEFacts) {
        var i = 0
        while i + 4 <= d.count {
            let t = (Int(d[i]) << 8) | Int(d[i + 1])
            let l = (Int(d[i + 2]) << 8) | Int(d[i + 3])
            i += 4
            guard i + l <= d.count else { break }
            let v = UnsafeRawBufferPointer(rebasing: d[i..<(i + l)])
            func str() -> String? {
                let s = TextWidth.sanitize(String(decoding: v.prefix { $0 != 0 }, as: UTF8.self)).trimmingCharacters(in: .whitespaces)
                return s.isEmpty ? nil : s
            }
            switch t {
            case 0x1021: f.wpsManufacturer = str()
            case 0x1023: f.wpsModelName = str()
            case 0x1024: f.wpsModelNumber = str()
            case 0x1011: f.wpsDeviceName = str()
            default: break
            }
            i += l
        }
        // Some vendors put a placeholder; treat as unknown.
        for key in [\IEFacts.wpsManufacturer, \IEFacts.wpsModelName, \IEFacts.wpsModelNumber, \IEFacts.wpsDeviceName] {
            if let s = f[keyPath: key]?.lowercased(), ["unknown", "n/a", "none", "default", "manufacturer", "model", "model name", "device name", " "].contains(s) {
                f[keyPath: key] = nil
            }
        }
    }

    /// Apply parsed facts onto a network record (shared by scan and monitor sources).
    static func apply(_ f: IEFacts, to n: inout Network, oui: OUIDatabase?) {
        if let m = f.wpsManufacturer { n.wpsManufacturer = m }
        if let m = f.wpsModelName { n.wpsModelName = m }
        if let m = f.wpsModelNumber { n.wpsModelNumber = m }
        if let m = f.wpsDeviceName { n.wpsDeviceName = m }
        if let a = f.apName { n.apName = a }
        if let p = f.phy { n.phy = p }
        if let cc = f.countryCode { n.countryCode = cc }
        if f.widthMHz > 0 && n.widthMHz == 0 { n.widthMHz = f.widthMHz }
        if let oui = oui {
            for v in f.vendorOUIs {
                if VendorIEClassifier.generic.contains(v) { continue }
                if let chip = VendorIEClassifier.chipset[v] {
                    if !n.chipsetVendors.contains(chip) { n.chipsetVendors.append(chip) }
                    continue
                }
                let bytes: [UInt8] = [UInt8(v >> 16), UInt8((v >> 8) & 0xff), UInt8(v & 0xff), 0, 0, 0]
                if let vendor = oui.lookup(bytes) {
                    let name = vendor.full
                    if !n.vendorIEVendors.contains(name) { n.vendorIEVendors.append(name) }
                }
            }
        }
        if n.ssidHint == nil { n.ssidHint = SSIDHints.hint(for: n.ssid) }
    }
}
