import Foundation

/// Terminal styling helpers. All width math is done on plain text; styles are applied last.
enum Style {
    static var colorEnabled = true
    static var unicode = true
    static var trueColor: Bool = {
        let ct = ProcessInfo.processInfo.environment["COLORTERM"]?.lowercased() ?? ""
        if ct.contains("truecolor") || ct.contains("24bit") { return true }
        let prog = ProcessInfo.processInfo.environment["TERM_PROGRAM"]?.lowercased() ?? ""
        // Apple Terminal only supports the 256-colour palette.
        if prog == "apple_terminal" { return false }
        return ["iterm.app", "vscode", "warpterminal", "ghostty", "wezterm", "alacritty", "kitty", "hyper", "tabby"].contains(prog)
    }()

    static var reset: String { colorEnabled ? "\u{1b}[0m" : "" }

    struct RGB { let r: Int; let g: Int; let b: Int
        init(_ hex: UInt32) { r = Int((hex >> 16) & 0xff); g = Int((hex >> 8) & 0xff); b = Int(hex & 0xff) }
        init(r: Int, g: Int, b: Int) { self.r = r; self.g = g; self.b = b }
        func mix(_ o: RGB, _ t: Double) -> RGB {
            RGB(r: Int(Double(r) + (Double(o.r) - Double(r)) * t),
                g: Int(Double(g) + (Double(o.g) - Double(g)) * t),
                b: Int(Double(b) + (Double(o.b) - Double(b)) * t))
        }
    }

    // Palette
    static let accent   = RGB(0xF97316) // coral/orange (spinner, highlights)
    static let brandA   = RGB(0x22D3EE) // cyan
    static let brandB   = RGB(0xA78BFA) // violet
    static let brandC   = RGB(0xF472B6) // pink
    static let dim      = RGB(0x6B7280)
    static let border   = RGB(0x3F3F46)
    static let header   = RGB(0xA1A1AA)
    static let text     = RGB(0xE5E7EB)
    static let muted    = RGB(0x9CA3AF)
    static let band24   = RGB(0x22D3EE)
    static let band5    = RGB(0x60A5FA)
    static let band6    = RGB(0xC084FC)
    static let sigBest  = RGB(0x22C55E)
    static let sigGood  = RGB(0xA3E635)
    static let sigFair  = RGB(0xFACC15)
    static let sigWeak  = RGB(0xFB923C)
    static let sigPoor  = RGB(0xEF4444)
    static let secOpen  = RGB(0xEF4444)
    static let secWEP   = RGB(0xF97316)
    static let secWPA   = RGB(0xFACC15)
    static let secWPA2  = RGB(0x4ADE80)
    static let secWPA3  = RGB(0x2DD4BF)
    static let secOWE   = RGB(0x22D3EE)
    static let warn     = RGB(0xFBBF24)
    static let danger   = RGB(0xF87171)
    static let ok       = RGB(0x34D399)

    static func fg(_ c: RGB) -> String {
        guard colorEnabled else { return "" }
        if trueColor { return "\u{1b}[38;2;\(c.r);\(c.g);\(c.b)m" }
        return "\u{1b}[38;5;\(to256(c))m"
    }
    static func bg(_ c: RGB) -> String {
        guard colorEnabled else { return "" }
        if trueColor { return "\u{1b}[48;2;\(c.r);\(c.g);\(c.b)m" }
        return "\u{1b}[48;5;\(to256(c))m"
    }
    static var bold: String { colorEnabled ? "\u{1b}[1m" : "" }
    static var faint: String { colorEnabled ? "\u{1b}[2m" : "" }
    static var italic: String { colorEnabled ? "\u{1b}[3m" : "" }
    static var underline: String { colorEnabled ? "\u{1b}[4m" : "" }
    static var reverse: String { colorEnabled ? "\u{1b}[7m" : "" }

    static func to256(_ c: RGB) -> Int {
        // Greys
        if abs(c.r - c.g) < 8 && abs(c.g - c.b) < 8 {
            if c.r < 8 { return 16 }
            if c.r > 248 { return 231 }
            return 232 + Int((Double(c.r) - 8) / 247 * 24)
        }
        func q(_ v: Int) -> Int { v < 48 ? 0 : (v < 115 ? 1 : (v - 35) / 40) }
        return 16 + 36 * q(c.r) + 6 * q(c.g) + q(c.b)
    }

    static func paint(_ s: String, _ c: RGB, bold b: Bool = false, dim d: Bool = false, italic i: Bool = false) -> String {
        guard colorEnabled else { return s }
        return fg(c) + (b ? bold : "") + (d ? faint : "") + (i ? italic : "") + s + reset
    }

    /// Colour each character along a gradient.
    static func gradient(_ s: String, _ stops: [RGB]) -> String {
        guard colorEnabled, stops.count >= 2 else { return s }
        let chars = Array(s)
        guard chars.count > 1 else { return paint(s, stops[0], bold: true) }
        var out = bold
        for (i, ch) in chars.enumerated() {
            let t = Double(i) / Double(chars.count - 1) * Double(stops.count - 1)
            let idx = min(Int(t), stops.count - 2)
            let c = stops[idx].mix(stops[idx + 1], t - Double(idx))
            out += fg(c) + String(ch)
        }
        return out + reset
    }
}

/// Unicode display width helpers (approximate wcwidth).
enum TextWidth {
    static func scalarWidth(_ u: Unicode.Scalar) -> Int {
        let v = u.value
        if v == 0 { return 0 }
        if v < 0x20 || (v >= 0x7f && v < 0xa0) { return 0 }
        // Combining marks, ZWJ, variation selectors
        if (0x0300...0x036F).contains(v) || (0x1AB0...0x1AFF).contains(v) || (0x1DC0...0x1DFF).contains(v)
            || (0x20D0...0x20FF).contains(v) || (0xFE00...0xFE0F).contains(v) || (0xFE20...0xFE2F).contains(v)
            || v == 0x200B || v == 0x200C || v == 0x200D || (0xE0100...0xE01EF).contains(v) { return 0 }
        // Wide ranges
        if (0x1100...0x115F).contains(v) || (0x2E80...0x303E).contains(v) || (0x3041...0x33FF).contains(v)
            || (0x3400...0x4DBF).contains(v) || (0x4E00...0x9FFF).contains(v) || (0xA000...0xA4CF).contains(v)
            || (0xAC00...0xD7A3).contains(v) || (0xF900...0xFAFF).contains(v) || (0xFE30...0xFE4F).contains(v)
            || (0xFF00...0xFF60).contains(v) || (0xFFE0...0xFFE6).contains(v)
            || (0x1F300...0x1F64F).contains(v) || (0x1F680...0x1F6FF).contains(v) || (0x1F900...0x1F9FF).contains(v)
            || (0x1FA70...0x1FAFF).contains(v) || (0x20000...0x3FFFD).contains(v) { return 2 }
        return 1
    }

    static func width(_ s: String) -> Int {
        var w = 0
        for ch in s {
            // A grapheme cluster's width is that of its first non-zero scalar (emoji ZWJ sequences count once)
            var cw = 0
            for u in ch.unicodeScalars { let sw = scalarWidth(u); if sw > 0 { cw = max(cw, sw) } }
            w += cw
        }
        return w
    }

    /// Truncate to `max` columns, appending an ellipsis if cut.
    static func truncate(_ s: String, _ max: Int) -> String {
        guard max > 0 else { return "" }
        if width(s) <= max { return s }
        let ell = Style.unicode ? "…" : "~"
        var out = ""
        var w = 0
        for ch in s {
            let cw = width(String(ch))
            if w + cw > max - 1 { break }
            out.append(ch)
            w += cw
        }
        return out + ell
    }

    enum Align { case left, right, center }

    static func pad(_ s: String, _ w: Int, _ align: Align = .left) -> String {
        let t = truncate(s, w)
        let missing = w - width(t)
        guard missing > 0 else { return t }
        switch align {
        case .left: return t + String(repeating: " ", count: missing)
        case .right: return String(repeating: " ", count: missing) + t
        case .center:
            let l = missing / 2
            return String(repeating: " ", count: l) + t + String(repeating: " ", count: missing - l)
        }
    }

    /// Make a string printable (strip control characters).
    static func sanitize(_ s: String) -> String {
        String(s.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7f && !(0x80...0x9f).contains($0.value) }.map(Character.init))
    }
}
