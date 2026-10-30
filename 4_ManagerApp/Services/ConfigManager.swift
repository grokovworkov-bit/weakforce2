//  TweakForce — ManagerApp/Services/ConfigManager.swift
//  EN: Reads/writes config/tweakforce.json. Provides apps + active tweaks and
//      independent injection/hiding setters.
//  RU: Читает/пишет config/tweakforce.json. Отдаёт приложения + активные твики
//      и независимые сеттеры injection/hiding.
import Foundation

final class ConfigManager {
    static let shared = ConfigManager()
    private let candidates = [
        "/var/jb/etc/tweakforce.json",
        "/var/jb/var/mobile/Library/TweakForce/tweakforce.json",
    ]

    private var path: String {
        candidates.first { FileManager.default.fileExists(atPath: $0) } ?? candidates[0]
    }

    private func load() -> [String: Any] {
        guard let data = FileManager.default.contents(atPath: path),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            NSLog("[TweakForce] ConfigManager: cannot read \(path)")
            return [:]
        }
        return json
    }

    private func save(_ json: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted) else {
            NSLog("[TweakForce] ConfigManager: serialize failed"); return
        }
        do { try data.write(to: URL(fileURLWithPath: path), options: .atomic) }
        catch { NSLog("[TweakForce] ConfigManager: write failed \(error)") }
    }

    func loadApps() -> [AppEntry] {
        let json = load()
        guard let apps = json["apps"] as? [String: Any] else { return [] }
        var out: [AppEntry] = []
        for (bundle, raw) in apps {
            if bundle.hasPrefix("//") { continue }
            guard let cfg = raw as? [String: Any] else { continue }
            out.append(AppEntry(bundleID: bundle,
                                name: (bundle as NSString).lastPathComponent,
                                injectionEnabled: (cfg["injection"] as? Bool) ?? false,
                                hideEnabled: (cfg["hiding"] as? Bool) ?? false))
        }
        return out.sorted { $0.bundleID < $1.bundleID }
    }

    func loadActiveTweaks() -> [TweakEntry] {
        let json = load()
        var set = Set<String>()
        if let g = json["global_dylibs"] as? [String: Any], let paths = g["paths"] as? [String] {
            paths.forEach { set.insert($0) }
        }
        if let apps = json["apps"] as? [String: Any] {
            for (b, raw) in apps where !b.hasPrefix("//") {
                if let cfg = raw as? [String: Any], (cfg["injection"] as? Bool) ?? false,
                   let d = cfg["dylibs"] as? [String] { d.forEach { set.insert($0) } }
            }
        }
        return set.sorted().map { TweakEntry(path: $0, enabled: true) }
    }

    private func mutate(bundleID: String, key: String, value: Bool) {
        var json = load()
        var apps = (json["apps"] as? [String: Any]) ?? [:]
        var app = (apps[bundleID] as? [String: Any]) ??
                  ["injection": false, "hiding": false, "dylibs": [], "values": [:]]
        app[key] = value
        apps[bundleID] = app
        json["apps"] = apps
        save(json)
    }
    func setInjection(_ on: Bool, bundleID: String) { mutate(bundleID: bundleID, key: "injection", value: on) }
    func setHiding(_ on: Bool, bundleID: String)    { mutate(bundleID: bundleID, key: "hiding", value: on) }
}
