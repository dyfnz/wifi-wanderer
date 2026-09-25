import Foundation
import Darwin

enum Key: Equatable {
    case char(Character)
    case up, down, left, right, pageUp, pageDown, home, end, escape, enter
}

/// Raw-mode terminal handling, window size, key decoding and signal flags.
enum Terminal {
    private static var saved: termios?
    static var interrupted: Int32 = 0
    static var resized: Int32 = 0

    static var isTTY: Bool { isatty(STDOUT_FILENO) == 1 && isatty(STDIN_FILENO) == 1 }

    static func size() -> (cols: Int, rows: Int) {
        var ws = winsize()
        if ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0, ws.ws_col > 0, ws.ws_row > 0 {
            return (Int(ws.ws_col), Int(ws.ws_row))
        }
        let env = ProcessInfo.processInfo.environment
        return (Int(env["COLUMNS"] ?? "") ?? 100, Int(env["LINES"] ?? "") ?? 30)
    }

    static func installSignalHandlers() {
        signal(SIGINT) { _ in Terminal.interrupted = 1 }
        signal(SIGTERM) { _ in Terminal.interrupted = 1 }
        signal(SIGHUP) { _ in Terminal.interrupted = 1 }
        signal(SIGWINCH) { _ in Terminal.resized = 1 }
        signal(SIGPIPE, SIG_IGN)
    }

    static func enterRaw() {
        guard isatty(STDIN_FILENO) == 1 else { return }
        var t = termios()
        tcgetattr(STDIN_FILENO, &t)
        saved = t
        t.c_lflag &= ~tcflag_t(ECHO | ICANON | IEXTEN | ISIG)
        t.c_iflag &= ~tcflag_t(IXON | ICRNL | BRKINT | INPCK | ISTRIP)
        t.c_oflag |= tcflag_t(OPOST)
        withUnsafeMutableBytes(of: &t.c_cc) { cc in cc[Int(VMIN)] = 0; cc[Int(VTIME)] = 0 }
        tcsetattr(STDIN_FILENO, TCSANOW, &t)
        tcflush(STDIN_FILENO, TCIFLUSH)   // drop keys typed during startup
    }

    static func restore() {
        if var t = saved { tcsetattr(STDIN_FILENO, TCSANOW, &t); saved = nil }
    }

    static func enterAltScreen() { write("\u{1b}[?1049h\u{1b}[?25l\u{1b}[H\u{1b}[2J") }
    static func exitAltScreen() { write("\u{1b}[?25h\u{1b}[?1049l") }

    static func write(_ s: String) {
        var data = Array(s.utf8)
        var off = 0
        while off < data.count {
            let n = data.withUnsafeMutableBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress! + off, $0.count - off) }
            if n <= 0 { if errno == EINTR { continue }; break }
            off += n
        }
    }

    /// Non-blocking read of pending keys.
    static func readKeys() -> [Key] {
        var buf = [UInt8](repeating: 0, count: 64)
        let n = read(STDIN_FILENO, &buf, buf.count)
        guard n > 0 else { return [] }
        var keys: [Key] = []
        var i = 0
        while i < n {
            let b = buf[i]
            if b == 0x1b {
                if i + 2 < n && buf[i + 1] == 0x5b /* [ */ {
                    let c = buf[i + 2]
                    switch c {
                    case 0x41: keys.append(.up); i += 3; continue
                    case 0x42: keys.append(.down); i += 3; continue
                    case 0x43: keys.append(.right); i += 3; continue
                    case 0x44: keys.append(.left); i += 3; continue
                    case 0x48: keys.append(.home); i += 3; continue
                    case 0x46: keys.append(.end); i += 3; continue
                    case 0x35, 0x36:
                        if i + 3 < n && buf[i + 3] == 0x7e { keys.append(c == 0x35 ? .pageUp : .pageDown); i += 4; continue }
                    default: break
                    }
                }
                keys.append(.escape); i += 1; continue
            }
            if b == 0x0d || b == 0x0a { keys.append(.enter); i += 1; continue }
            if b == 0x03 { keys.append(.char("\u{3}")); i += 1; continue }
            // Decode one UTF-8 scalar
            var len = 1
            if b & 0xE0 == 0xC0 { len = 2 } else if b & 0xF0 == 0xE0 { len = 3 } else if b & 0xF8 == 0xF0 { len = 4 }
            let end = min(i + len, n)
            if let s = String(bytes: buf[i..<end], encoding: .utf8), let ch = s.first { keys.append(.char(ch)) }
            i = end
        }
        return keys
    }
}
