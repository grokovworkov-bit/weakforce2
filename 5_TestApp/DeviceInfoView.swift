//  TweakForce — TestApp/DeviceInfoView.swift
//  EN: Shows device data that data-spoofing hooks can override (name, model,
//      system version, identifierForVendor). Mirrors what AIDA64 reads.
//  RU: Показывает данные устройства, которые могут подменять хуки (имя, модель,
//      версия системы, identifierForVendor). Отражает то, что читает AIDA64.
import UIKit

final class DeviceInfoView: UIViewController {
    private let textView = UITextView()
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Устройство"
        view.backgroundColor = .systemBackground
        textView.isEditable = false
        textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.frame = view.bounds
        textView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(textView)
        refresh()
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .refresh,
                                                            target: self, action: #selector(refresh))
    }
    @objc private func refresh() {
        let d = UIDevice.current
        var sysinfo = utsname(); uname(&sysinfo)
        let machine = withUnsafeBytes(of: &sysinfo.machine) { raw -> String in
            let p = raw.baseAddress!.assumingMemoryBound(to: CChar.self)
            return String(cString: p)
        }
        textView.text = """
        === Данные устройства (подменяемые хуками) ===
        name:               \(d.name)
        model:              \(d.model)
        systemName:         \(d.systemName)
        systemVersion:      \(d.systemVersion)
        identifierForVendor:\(d.identifierForVendor?.uuidString ?? "nil")
        uname.machine:      \(machine)

        EN: If TweakForce hooks are active, these values reflect the overrides
            from tweakforce.json (values.device_name_override, etc).
        RU: Если хуки TweakForce активны, значения отражают переопределения из
            tweakforce.json (values.device_name_override и т.д.).
        """
    }
}
