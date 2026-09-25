import Foundation
import CoreLocation

/// macOS only reveals SSID/BSSID to processes that hold Location Services authorization.
/// This asks for it and keeps the manager alive so a later grant takes effect on the next scan.
final class LocationGate: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private(set) var status: CLAuthorizationStatus = .notDetermined
    private var changed = false

    override init() {
        super.init()
        manager.delegate = self
        status = manager.authorizationStatus
    }

    var authorized: Bool { status == .authorizedAlways || status == .authorized }

    var statusText: String {
        switch status {
        case .notDetermined: return "not determined"
        case .restricted: return "restricted"
        case .denied: return "denied"
        case .authorizedAlways, .authorized: return "authorized"
        @unknown default: return "unknown"
        }
    }

    /// Request authorization and pump the run loop briefly so a prompt can be answered.
    func request(timeout: TimeInterval) {
        guard CLLocationManager.locationServicesEnabled() else { return }
        status = manager.authorizationStatus
        guard status == .notDetermined else { return }
        manager.requestAlwaysAuthorization()
        manager.requestWhenInUseAuthorization()
        manager.startUpdatingLocation()
        let deadline = Date().addingTimeInterval(timeout)
        while !changed && Date() < deadline {
            RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        status = manager.authorizationStatus
    }

    /// Pump the main run loop so authorization callbacks arrive during the TUI loop.
    func pump() { RunLoop.main.run(mode: .default, before: Date()) }

    func locationManagerDidChangeAuthorization(_ m: CLLocationManager) {
        status = m.authorizationStatus
        if status != .notDetermined { changed = true }
    }
    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {}
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) { manager.stopUpdatingLocation() }

    /// Name of the app that macOS attributes this terminal session to (for the hint text).
    static func hostAppName() -> String {
        let env = ProcessInfo.processInfo.environment
        if let p = env["TERM_PROGRAM"] {
            switch p.lowercased() {
            case "apple_terminal": return "Terminal"
            case "iterm.app": return "iTerm"
            case "vscode": return "Visual Studio Code (or Cursor/Code Helper)"
            case "warpterminal": return "Warp"
            default: return p
            }
        }
        return "your terminal app"
    }
}
