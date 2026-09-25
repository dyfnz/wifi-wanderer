import Foundation

/// Live-view state that the renderer needs besides the store.
final class ViewState {
    var sort: SortKey
    var reverse: Bool
    var scroll = 0
    var paused = false
    var showHidden: Bool
    var showDetail = false
    var filter: String?
    var editingFilter = false
    var filterDraft = ""
    var tick = 0
    var bands: Set<Band>?
    var channels: Set<Int>?
    var maxRows: Int?
    var expire: TimeInterval
    var locationText: String?
    var hostApp = ""

    init(options o: Options) {
        sort = o.sort; reverse = o.reverse; showHidden = o.showHidden; filter = o.filter
        bands = o.bands; channels = o.channels; maxRows = o.maxRows; expire = o.expireSec
    }

    var descending: Bool { sort.descendingByDefault != reverse }
}

struct Column {
    let title: String
    let key: SortKey?
    var width: Int
    let align: TextWidth.Align
    let optional: Int   // 0 = always shown; higher = dropped first when narrow
}

enum Render {
    static let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    static let asciiSpinner = ["|", "/", "-", "\\"]

    // MARK: data preparation

    static func visible(_ nets: [Network], _ v: ViewState, now: Date) -> [Network] {
        var rows = nets
        if v.expire > 0 { rows = rows.filter { now.timeIntervalSince($0.lastSeen) <= v.expire } }
        if !v.showHidden { rows = rows.filter { !$0.isHidden } }
        if let b = v.bands { rows = rows.filter { b.contains($0.band) } }
        if let c = v.channels { rows = rows.filter { c.contains($0.channel) } }
        if let f = v.filter, !f.isEmpty {
            let lf = f.lowercased()
            rows = rows.filter { ($0.ssid ?? "").lowercased().contains(lf) || ($0.bssid ?? "").contains(lf) || $0.manufacturer.name.lowercased().contains(lf) }
        }
        rows.sort { a, b in
            let r: Bool
            switch v.sort {
            case .rssi: r = a.rssi != b.rssi ? a.rssi < b.rssi : a.key < b.key
            case .ssid:
                let x = a.displaySSID.lowercased(), y = b.displaySSID.lowercased()
                r = x != y ? x < y : a.key < b.key
            case .bssid: r = (a.bssid ?? "~") < (b.bssid ?? "~")
            case .manufacturer:
                let x = a.manufacturer.name.lowercased(), y = b.manufacturer.name.lowercased()
                r = x != y ? x < y : a.rssi > b.rssi
            case .channel: r = a.channel != b.channel ? a.channel < b.channel : a.rssi > b.rssi
            case .band: r = a.band != b.band ? a.band < b.band : (a.channel != b.channel ? a.channel < b.channel : a.rssi > b.rssi)
            case .security: r = a.security != b.security ? a.security < b.security : a.rssi > b.rssi
            case .beacons: r = a.beacons != b.beacons ? a.beacons < b.beacons : a.rssi < b.rssi
            case .seen: r = a.lastSeen != b.lastSeen ? a.lastSeen < b.lastSeen : a.rssi < b.rssi
            case .first: r = a.firstSeen != b.firstSeen ? a.firstSeen < b.firstSeen : a.rssi < b.rssi
            }
            return v.descending ? !r && !(equalKey(a, b, v.sort)) : r
        }
        return rows
    }

    private static func equalKey(_ a: Network, _ b: Network, _ k: SortKey) -> Bool {
        switch k {
        case .rssi: return a.rssi == b.rssi && a.key == b.key
        case .ssid: return a.displaySSID.lowercased() == b.displaySSID.lowercased() && a.key == b.key
        case .bssid: return (a.bssid ?? "~") == (b.bssid ?? "~")
        case .manufacturer: return a.manufacturer.name.lowercased() == b.manufacturer.name.lowercased() && a.rssi == b.rssi
        case .channel: return a.channel == b.channel && a.rssi == b.rssi
        case .band: return a.band == b.band && a.channel == b.channel && a.rssi == b.rssi
        case .security: return a.security == b.security && a.rssi == b.rssi
        case .beacons: return a.beacons == b.beacons && a.rssi == b.rssi
        case .seen: return a.lastSeen == b.lastSeen && a.rssi == b.rssi
        case .first: return a.firstSeen == b.firstSeen && a.rssi == b.rssi
        }
    }

    // MARK: cell formatting

    static func rssiColor(_ r: Int) -> Style.RGB {
        switch r { case (-55)...: return Style.sigBest; case (-65)...(-56): return Style.sigGood; case (-75)...(-66): return Style.sigFair; case (-85)...(-76): return Style.sigWeak; default: return Style.sigPoor }
    }
    static func rssiBar(_ r: Int) -> String {
        let level = r >= -55 ? 4 : (r >= -65 ? 3 : (r >= -75 ? 2 : (r >= -85 ? 1 : 0)))
        if Style.unicode {
            let blocks = ["▂", "▄", "▆", "█"]
            return (0..<4).map { $0 < level ? blocks[$0] : "·" }.joined()
        }
        return (0..<4).map { $0 < level ? "#" : "." }.joined()
    }
    static func bandColor(_ b: Band) -> Style.RGB { switch b { case .ghz2_4: return Style.band24; case .ghz5: return Style.band5; case .ghz6: return Style.band6; case .unknown: return Style.dim } }
    static func securityColor(_ s: Security) -> Style.RGB {
        switch s.tier { case 0: return Style.secOpen; case 1: return Style.secWEP; case 2: return Style.secWPA; case 3, 4: return Style.secWPA2; case 5: return Style.secWPA3; case 6: return Style.secOWE; default: return Style.dim }
    }
    static func age(_ d: Date, now: Date) -> String {
        let s = Int(now.timeIntervalSince(d))
        if s < 1 { return "now" }
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m\(s % 60 == 0 ? "" : "\(s % 60)s")" }
        return "\(s / 3600)h\((s % 3600) / 60)m"
    }
    static func clock(_ t: TimeInterval) -> String {
        let s = Int(t); return String(format: "%02d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
    }
    static func thousands(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal; f.groupingSeparator = ","; return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    // MARK: layout

    static func columns(width: Int, mode: String, detail: Bool) -> [Column] {
        var cols: [Column] = [
            Column(title: "#", key: nil, width: 3, align: .right, optional: 0),
            Column(title: "SSID", key: .ssid, width: 24, align: .left, optional: 0),
            Column(title: "BSSID", key: .bssid, width: 17, align: .left, optional: 0),
            Column(title: "Manufacturer", key: .manufacturer, width: 22, align: .left, optional: 0),
            Column(title: "Device", key: nil, width: 20, align: .left, optional: detail ? 2 : 99),
            Column(title: "Ch", key: .channel, width: 3, align: .right, optional: 0),
            Column(title: "W", key: nil, width: 3, align: .right, optional: 3),
            Column(title: "Band", key: .band, width: 4, align: .left, optional: 0),
            Column(title: "RSSI", key: .rssi, width: 9, align: .left, optional: 0),
            Column(title: "Security", key: .security, width: 8, align: .left, optional: 0),
            Column(title: mode == "scan" ? "Seen×" : "Beacons", key: .beacons, width: 7, align: .right, optional: 0),
            Column(title: "Last", key: .seen, width: 5, align: .right, optional: 1),
        ]
        cols = cols.filter { $0.optional < 99 }
        func total(_ c: [Column]) -> Int { c.reduce(0) { $0 + $1.width } + (c.count - 1) * 2 + 2 }
        // Drop optional columns until it fits, then shrink flexible ones.
        var level = 3
        while total(cols) > width && level > 0 { cols = cols.filter { $0.optional != level }; level -= 1 }
        var over = total(cols) - width
        if over > 0 {
            for (idx, name) in [(cols.firstIndex { $0.title == "Device" }, 10), (cols.firstIndex { $0.title == "Manufacturer" }, 10), (cols.firstIndex { $0.title == "SSID" }, 8)] {
                guard let i = idx, over > 0 else { continue }
                let can = cols[i].width - name
                let take = min(can, over)
                if take > 0 { cols[i].width -= take; over -= take }
            }
        } else if over < 0 {
            // Give spare room to SSID and Manufacturer (and Device)
            var spare = -over
            let targets = [cols.firstIndex { $0.title == "SSID" }, cols.firstIndex { $0.title == "Manufacturer" }, cols.firstIndex { $0.title == "Device" }].compactMap { $0 }
            let caps = [40, 36, 30]
            var progress = true
            while spare > 0 && progress {
                progress = false
                for (k, i) in targets.enumerated() where cols[i].width < caps[min(k, caps.count - 1)] && spare > 0 {
                    cols[i].width += 1; spare -= 1; progress = true
                }
            }
        }
        return cols
    }

    // MARK: frame

    struct Frame { var lines: [String]; var totalRows: Int; var shownRange: Range<Int> }

    static func frame(store: Store, source: Source, view: ViewState, size: (cols: Int, rows: Int), bandsSupported: [Band: Int], now: Date) -> Frame {
        let W = max(size.cols, 40)
        let H = max(size.rows, 8)
        let u = Style.unicode
        var lines: [String] = []

        // Header box
        let tl = u ? "╭" : "+", tr = u ? "╮" : "+", bl = u ? "╰" : "+", br = u ? "╯" : "+", hz = u ? "─" : "-", vt = u ? "│" : "|"
        let bc = Style.fg(Style.border)
        func boxLine(_ content: String, plainWidth: Int) -> String {
            let pad = max(0, W - 4 - plainWidth)
            return bc + vt + Style.reset + " " + content + String(repeating: " ", count: pad) + " " + bc + vt + Style.reset
        }
        lines.append(bc + tl + String(repeating: hz, count: W - 2) + tr + Style.reset)

        let logo = u ? "◉ " : "* "
        let titlePlain = logo + appName + "  v" + appVersion
        let title = Style.paint(logo, Style.accent) + Style.gradient(appName, [Style.brandA, Style.brandB, Style.brandC]) + Style.paint("  v" + appVersion, Style.dim)
        let bandText = [Band.ghz2_4, .ghz5, .ghz6].map { b -> String in
            let n = bandsSupported[b] ?? 0
            return n > 0 ? "\(b.label) GHz" : "\(b.label) GHz n/a"
        }
        let rightPlain = "\(source.interfaceName) · \(source.modeName) mode · " + bandText.joined(separator: " · ")
        let right = Style.paint(source.interfaceName, Style.text, bold: true) + Style.paint(" · ", Style.dim)
            + Style.paint(source.modeName + " mode", source.modeName == "monitor" ? Style.ok : Style.brandA) + Style.paint(" · ", Style.dim)
            + [Band.ghz2_4, .ghz5, .ghz6].map { b -> String in
                let n = bandsSupported[b] ?? 0
                return n > 0 ? Style.paint("\(b.label) GHz", bandColor(b)) : Style.paint("\(b.label) GHz n/a", Style.dim)
            }.joined(separator: Style.paint(" · ", Style.dim))
        let gap = max(1, W - 4 - TextWidth.width(titlePlain) - TextWidth.width(rightPlain))
        lines.append(boxLine(title + String(repeating: " ", count: gap) + right, plainWidth: TextWidth.width(titlePlain) + gap + TextWidth.width(rightPlain)))

        // Status line with spinner
        let sp = view.paused ? (u ? "⏸" : "||") : (u ? spinner[view.tick % spinner.count] : asciiSpinner[view.tick % asciiSpinner.count])
        var statusPlain = ""
        var status = ""
        func add(_ plain: String, _ styled: String) { statusPlain += plain; status += styled }
        add(sp + " ", Style.paint(sp, Style.accent, bold: true) + " ")
        if view.paused {
            add("paused", Style.paint("paused", Style.warn, bold: true))
        } else if source.modeName == "monitor" {
            let ch = source.currentChannel.map { "ch \($0)" } ?? "starting"
            add("hopping " + ch + " ", Style.paint("hopping ", Style.text) + Style.paint(ch, Style.brandA, bold: true) + " ")
            let n = max(1, source.hopCount)
            let slots = 12
            let pos = source.hopIndex * slots / n
            let bar = (0..<slots).map { $0 <= pos ? (u ? "▰" : "=") : (u ? "▱" : "-") }.joined()
            add(bar, Style.paint(bar, Style.brandB))
            if let m = source as? MonitorSource, m.hopCount > 0 {
                let t = String(format: " %d ch · %.1fs/sweep", m.hopCount, m.sweepSeconds)
                add(t, Style.paint(t, Style.dim))
            }
        } else {
            add("scanning", Style.paint("scanning", Style.text))
        }
        let sep = "  ·  "
        let sepS = Style.paint(sep, Style.dim)
        let elapsed = clock(now.timeIntervalSince(store.started))
        add(sep + elapsed, sepS + Style.paint(elapsed, Style.muted))
        if source.modeName == "monitor" {
            let f = thousands(store.beaconFrames) + " beacons"
            add(sep + f, sepS + Style.paint(f, Style.text))
            let s = "sweep " + String(store.rounds)
            add(sep + s, sepS + Style.paint(s, Style.muted))
        } else {
            let s = "round " + String(store.rounds)
            add(sep + s, sepS + Style.paint(s, Style.text))
        }
        let sortText = "sort " + view.sort.title + (view.descending ? (u ? " ↓" : " v") : (u ? " ↑" : " ^"))
        add(sep + sortText, sepS + Style.paint(sortText, Style.brandC))
        lines.append(boxLine(status, plainWidth: TextWidth.width(statusPlain)))

        // Optional notice line
        var notice: (String, Style.RGB)? = nil
        if let e = store.lastError { notice = (e, Style.danger) }
        else if store.redacted {
            notice = ("SSID/BSSID hidden by macOS → allow Location Services for \(view.hostApp) in System Settings › Privacy & Security, or run: sudo \(appBinary) --monitor", Style.warn)
        } else if let n = store.statusNote { notice = (n, Style.muted) }
        if let (text, color) = notice {
            let icon = u ? "⚠ " : "! "
            let t = TextWidth.truncate(icon + text, W - 4)
            lines.append(boxLine(Style.paint(t, color), plainWidth: TextWidth.width(t)))
        }
        lines.append(bc + bl + String(repeating: hz, count: W - 2) + br + Style.reset)

        // Table
        let cols = columns(width: W, mode: source.modeName, detail: view.showDetail)
        var headPlain = " "
        var head = " "
        for (i, c) in cols.enumerated() {
            let isSort = c.key == view.sort
            let arrow = isSort ? (view.descending ? (u ? "↓" : "v") : (u ? "↑" : "^")) : ""
            var titleText = c.title + arrow
            if TextWidth.width(titleText) > c.width { titleText = String(c.title.prefix(max(0, c.width - 1))) + arrow }
            let t = TextWidth.pad(titleText, c.width, c.align)
            headPlain += t
            head += isSort ? Style.paint(t, Style.accent, bold: true) : Style.paint(t, Style.header, bold: true)
            if i < cols.count - 1 { headPlain += "  "; head += "  " }
        }
        lines.append(head + Style.reset)
        lines.append(Style.paint(" " + String(repeating: u ? "╌" : "-", count: min(W - 2, TextWidth.width(headPlain))), Style.border))

        let all = visible(store.snapshot(), view, now: now)
        let footerLines = view.editingFilter ? 2 : 1
        var avail = H - lines.count - footerLines - 1
        if let m = view.maxRows { avail = min(avail, m) }
        avail = max(1, avail)
        let maxScroll = max(0, all.count - avail)
        if view.scroll > maxScroll { view.scroll = maxScroll }
        let start = view.scroll
        let end = min(all.count, start + avail)

        for (idx, n) in all[start..<end].enumerated() {
            let rowNo = start + idx + 1
            let stale = now.timeIntervalSince(n.lastSeen) > 20
            let flash = now.timeIntervalSince(n.lastCountChange) < 0.35
            var line = " "
            for (i, c) in cols.enumerated() {
                var cell: String
                switch c.title {
                case "#": cell = Style.paint(TextWidth.pad(String(rowNo), c.width, .right), Style.dim)
                case "SSID":
                    let t = TextWidth.pad(n.displaySSID, c.width, .left)
                    cell = n.isHidden ? Style.paint(t, Style.dim, italic: true) : Style.paint(t, stale ? Style.muted : Style.text, bold: !stale)
                case "BSSID":
                    let t = TextWidth.pad(n.bssid ?? (u ? "—" : "-"), c.width, .left)
                    cell = Style.paint(t, n.bssid == nil ? Style.dim : Style.muted)
                case "Manufacturer":
                    let m = n.manufacturer
                    let marker = u ? m.source.marker : m.source.asciiMarker
                    let name = marker.isEmpty ? m.name : m.name + " " + marker
                    let t = TextWidth.pad(name, c.width, .left)
                    switch m.source {
                    case .declared: cell = Style.paint(t, Style.ok)
                    case .oui: cell = Style.paint(t, stale ? Style.muted : Style.text)
                    case .vendorIE, .ssid: cell = Style.paint(t, Style.muted, italic: true)
                    case .none: cell = Style.paint(t, Style.dim)
                    }
                case "Device":
                    let d = n.device ?? (n.chipsetVendors.isEmpty ? "" : n.chipsetVendors.joined(separator: "/") + " chip")
                    cell = Style.paint(TextWidth.pad(d, c.width, .left), n.device != nil ? Style.text : Style.dim)
                case "Ch": cell = Style.paint(TextWidth.pad(n.channel == 0 ? "?" : String(n.channel), c.width, .right), Style.text)
                case "W": cell = Style.paint(TextWidth.pad(n.widthMHz == 0 ? "" : String(n.widthMHz), c.width, .right), Style.muted)
                case "Band": cell = Style.paint(TextWidth.pad(n.band.label, c.width, .left), bandColor(n.band), bold: true)
                case "RSSI":
                    let t = rssiBar(n.rssi) + " " + TextWidth.pad(String(n.rssi), 4, .right)
                    cell = Style.paint(TextWidth.pad(t, c.width, .left), rssiColor(n.rssi), bold: !stale, dim: stale)
                case "Security": cell = Style.paint(TextWidth.pad(n.security.label, c.width, .left), securityColor(n.security), bold: n.security.tier == 0)
                case "Beacons", "Seen×":
                    let t = TextWidth.pad(thousands(n.beacons), c.width, .right)
                    cell = flash ? Style.paint(t, Style.accent, bold: true) : Style.paint(t, Style.text)
                case "Last":
                    let a = age(n.lastSeen, now: now)
                    cell = Style.paint(TextWidth.pad(a, c.width, .right), stale ? Style.warn : Style.dim)
                default: cell = TextWidth.pad("", c.width)
                }
                line += cell
                if i < cols.count - 1 { line += "  " }
            }
            lines.append(line + Style.reset)
        }
        if all.isEmpty {
            let msg = store.rounds == 0 && store.frames == 0 ? "listening for networks…" : "no networks match the current filters"
            lines.append(" " + Style.paint(msg, Style.dim, italic: true))
        }
        // Fill
        while lines.count < H - footerLines { lines.append("") }
        lines = Array(lines.prefix(H - footerLines))

        // Footer
        if view.editingFilter {
            let prompt = "filter: " + view.filterDraft
            lines.append(" " + Style.paint("/", Style.accent, bold: true) + Style.paint(prompt, Style.text) + Style.paint((u ? "▏" : "_") + "  Enter apply · Esc cancel", Style.dim))
        }
        var foot = " "
        var footPlain = " "
        func key(_ k: String, _ label: String) {
            foot += Style.paint(k, Style.accent, bold: true) + Style.paint(" " + label + "  ", Style.dim)
            footPlain += k + " " + label + "  "
        }
        key("q", "quit"); key("s/S", "sort"); key("r", "reverse"); key(u ? "↑↓" : "^v", "scroll"); key("p", view.paused ? "resume" : "pause")
        key("c", "reset"); key("h", view.showHidden ? "hide hidden" : "show hidden"); key("m", "detail"); key("/", "filter")
        var tail = "\(all.count) shown"
        if all.count > avail { tail = "rows \(start + 1)–\(end) of \(all.count)" }
        if let f = view.filter, !f.isEmpty { tail += " · filter \"\(f)\"" }
        tail += " · \(store.count) total"
        let pad = max(1, W - TextWidth.width(footPlain) - TextWidth.width(tail) - 1)
        foot += String(repeating: " ", count: pad) + Style.paint(tail, Style.muted)
        lines.append(foot + Style.reset)
        return Frame(lines: lines, totalRows: all.count, shownRange: start..<end)
    }

    /// Plain (non-alternate-screen) table for --once and non-TTY output.
    static func staticTable(_ nets: [Network], mode: String, width: Int, detail: Bool, now: Date) -> String {
        let cols = columns(width: width, mode: mode, detail: detail)
        var out = ""
        var head = ""
        for (i, c) in cols.enumerated() { head += Style.paint(TextWidth.pad(c.title, c.width, c.align), Style.header, bold: true); if i < cols.count - 1 { head += "  " } }
        out += head + Style.reset + "\n"
        for (idx, n) in nets.enumerated() {
            var line = ""
            for (i, c) in cols.enumerated() {
                let cell: String
                switch c.title {
                case "#": cell = Style.paint(TextWidth.pad(String(idx + 1), c.width, .right), Style.dim)
                case "SSID": cell = n.isHidden ? Style.paint(TextWidth.pad(n.displaySSID, c.width), Style.dim, italic: true) : Style.paint(TextWidth.pad(n.displaySSID, c.width), Style.text, bold: true)
                case "BSSID": cell = Style.paint(TextWidth.pad(n.bssid ?? "-", c.width), Style.muted)
                case "Manufacturer":
                    let m = n.manufacturer
                    let marker = Style.unicode ? m.source.marker : m.source.asciiMarker
                    cell = Style.paint(TextWidth.pad(marker.isEmpty ? m.name : m.name + " " + marker, c.width), m.source == .declared ? Style.ok : (m.source == .oui ? Style.text : Style.muted))
                case "Device": cell = Style.paint(TextWidth.pad(n.device ?? "", c.width), Style.text)
                case "Ch": cell = TextWidth.pad(String(n.channel), c.width, .right)
                case "W": cell = Style.paint(TextWidth.pad(n.widthMHz == 0 ? "" : String(n.widthMHz), c.width, .right), Style.muted)
                case "Band": cell = Style.paint(TextWidth.pad(n.band.label, c.width), bandColor(n.band), bold: true)
                case "RSSI": cell = Style.paint(TextWidth.pad(rssiBar(n.rssi) + " " + TextWidth.pad(String(n.rssi), 4, .right), c.width), rssiColor(n.rssi))
                case "Security": cell = Style.paint(TextWidth.pad(n.security.label, c.width), securityColor(n.security))
                case "Beacons", "Seen×": cell = TextWidth.pad(thousands(n.beacons), c.width, .right)
                case "Last": cell = Style.paint(TextWidth.pad(age(n.lastSeen, now: now), c.width, .right), Style.dim)
                default: cell = TextWidth.pad("", c.width)
                }
                line += cell
                if i < cols.count - 1 { line += "  " }
            }
            out += line + Style.reset + "\n"
        }
        return out
    }
}
