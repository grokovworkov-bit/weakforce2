//  TweakForce — TestApp/DiagnosticViewController.swift
//  EN: Real-time injection signs: framework loaded (_dyld_image_count), daemon
//      ping, swizzled methods, daemon log, all process env vars.
//  RU: Реалтайм-признаки инъекции: framework загружен (_dyld_image_count), ping
//      daemon, подменённые методы, лог daemon, все env процесса.
import UIKit
import MachO

final class DiagnosticViewController: UIViewController {
    private let textView = UITextView()
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Диагностика"
        view.backgroundColor = .systemBackground
        textView.isEditable = false
        textView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.frame = view.bounds
        textView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(textView)
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .refresh,
                                                            target: self, action: #selector(refresh))
        refresh()
    }

    @objc private func refresh() {
        var lines: [String] = ["=== TweakForce TestApp ==="]
        // Loaded images / Загруженные образы
        let count = _dyld_image_count()
        var frameworkLoaded = false
        var images: [String] = []
        for i in 0..<count {
            if let c = _dyld_get_image_name(i) {
                let name = String(cString: c)
                images.append((name as NSString).lastPathComponent)
                if name.contains("TweakForceHooks") { frameworkLoaded = true }
            }
        }
        lines.append("Framework загружен: \(frameworkLoaded ? "ДА" : "НЕТ")")
        lines.append("Образов в процессе: \(count)")
        // DYLD env
        let dyld = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] ?? "(нет)"
        lines.append("DYLD_INSERT_LIBRARIES: \(dyld)")
        // Device name (may be spoofed by a hook) / Имя устройства (может быть подменено)
        lines.append("UIDevice.name: \(UIDevice.current.name)")
        lines.append("UIDevice.systemVersion: \(UIDevice.current.systemVersion)")
        // Env vars
        lines.append("\n=== ENV ===")
        for (k, v) in ProcessInfo.processInfo.environment.sorted(by: { $0.key < $1.key }) {
            lines.append("\(k)=\(v)")
        }
        lines.append("\n=== Загруженные образы ===")
        lines.append(images.joined(separator: "\n"))
        textView.text = lines.joined(separator: "\n")
    }
}
