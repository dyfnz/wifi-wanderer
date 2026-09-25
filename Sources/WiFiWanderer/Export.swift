import Foundation

enum Export {
    static let iso: ISO8601DateFormatter = { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f }()

    static func json(_ nets: [Network], store: Store, mode: String, iface: String) -> String {
        var list: [[String: Any]] = []
        for n in nets {
            let m = n.manufacturer
            var d: [String: Any] = [
                "bssid": n.bssid as Any,
                "ssid": n.ssid as Any,
                "hidden": n.isHidden,
                "channel": n.channel,
                "band_ghz": n.band.label,
                "width_mhz": n.widthMHz,
                "rssi_dbm": n.rssi,
                "rssi_min_dbm": n.rssiMin,
                "rssi_max_dbm": n.rssiMax,
                "noise_dbm": n.noise as Any,
                "security": n.security.label,
                "beacons": n.beacons,
                "probe_responses": n.probeResponses,
                "beacon_interval_tu": n.beaconInterval as Any,
                "first_seen": iso.string(from: n.firstSeen),
                "last_seen": iso.string(from: n.lastSeen),
                "manufacturer": m.name,
                "manufacturer_source": m.source.description,
                "oui_vendor": n.ouiVendor as Any,
                "oui_vendor_short": n.ouiVendorShort as Any,
                "locally_administered": n.locallyAdministered,
                "wps_manufacturer": n.wpsManufacturer as Any,
                "wps_model_name": n.wpsModelName as Any,
                "wps_model_number": n.wpsModelNumber as Any,
                "wps_device_name": n.wpsDeviceName as Any,
                "ap_name": n.apName as Any,
                "vendor_ie_vendors": n.vendorIEVendors,
                "chipset_vendors": n.chipsetVendors,
                "ssid_hint": n.ssidHint as Any,
                "phy": n.phy as Any,
                "country": n.countryCode as Any,
            ]
            d = d.mapValues { ($0 as? String?) == .some(nil) ? NSNull() : $0 }
            list.append(d)
        }
        let doc: [String: Any] = [
            "tool": appBinary, "version": appVersion, "mode": mode, "interface": iface,
            "started": iso.string(from: store.started), "finished": iso.string(from: Date()),
            "scan_rounds": store.rounds, "frames": store.frames, "beacon_frames": store.beaconFrames,
            "networks": list,
        ]
        let data = (try? JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys])) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    static func csv(_ nets: [Network]) -> String {
        func q(_ s: String?) -> String {
            guard let s = s else { return "" }
            if s.contains(",") || s.contains("\"") || s.contains("\n") { return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
            return s
        }
        var out = "bssid,ssid,manufacturer,manufacturer_source,device,channel,band_ghz,width_mhz,rssi_dbm,noise_dbm,security,beacons,probe_responses,phy,first_seen,last_seen\n"
        for n in nets {
            let m = n.manufacturer
            out += [q(n.bssid), q(n.ssid), q(m.name), q(m.source.description), q(n.device), "\(n.channel)", n.band.label, "\(n.widthMHz)", "\(n.rssi)",
                    n.noise.map(String.init) ?? "", n.security.label, "\(n.beacons)", "\(n.probeResponses)", q(n.phy),
                    iso.string(from: n.firstSeen), iso.string(from: n.lastSeen)].joined(separator: ",") + "\n"
        }
        return out
    }
}
