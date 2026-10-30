//  TweakForce — ManagerApp/Services/DiagnosticsService.swift
//  EN: Builds a human-readable system diagnostics report.
//  RU: Формирует человекочитаемый отчёт диагностики системы.
import Foundation

final class DiagnosticsService {
    static let shared = DiagnosticsService()
    func collect(_ completion: @escaping (String) -> Void) {
        var lines: [String] = ["=== TweakForce диагностика ==="]
        DaemonBridge.shared.status { status in
            if let s = status, (s["ok"] as? Bool) == true {
                lines.append("daemon: АКТИВЕН (pid \(s["pid"] ?? "?"))")
                lines.append("порт: \(s["port"] ?? "?")")
            } else {
                lines.append("daemon: НЕДОСТУПЕН")
            }
            let apps = ConfigManager.shared.loadApps()
            lines.append("\nПриложения (\(apps.count)):")
            for a in apps {
                lines.append("  \(a.bundleID): inj=\(a.injectionEnabled) hide=\(a.hideEnabled)")
            }
            let tw = ConfigManager.shared.loadActiveTweaks()
            lines.append("\nАктивные твики (\(tw.count)):")
            tw.forEach { lines.append("  \($0.path)") }
            DaemonBridge.shared.getLog { log in
                lines.append("\n=== Хвост лога daemon ===\n\(log)")
                completion(lines.joined(separator: "\n"))
            }
        }
    }
}
