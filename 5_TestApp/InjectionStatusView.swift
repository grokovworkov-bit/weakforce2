//  TweakForce — TestApp/InjectionStatusView.swift
//  EN: Real-time big green/red banner: injected or not, daemon alive or not.
//  RU: Реалтайм большой зелёный/красный баннер: внедрено или нет, daemon жив.
import UIKit
import MachO

final class InjectionStatusView: UIViewController {
    private let banner = UILabel()
    private var timer: Timer?
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Статус"
        view.backgroundColor = .systemBackground
        banner.frame = view.bounds.insetBy(dx: 20, dy: 80)
        banner.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        banner.numberOfLines = 0
        banner.textAlignment = .center
        banner.font = .boldSystemFont(ofSize: 20)
        view.addSubview(banner)
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in self?.update() }
        update()
    }
    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); timer?.invalidate() }
    private func update() {
        var injected = false
        for i in 0..<_dyld_image_count() {
            if let c = _dyld_get_image_name(i), String(cString: c).contains("TweakForceHooks") { injected = true; break }
        }
        let daemon = CFMessagePortCreateRemote(nil, "com.tweakforce.daemon" as CFString) != nil
        if injected {
            banner.text = "✅ INJECTED\n\ndaemon: \(daemon ? "активен" : "недоступен")"
            banner.backgroundColor = .systemGreen.withAlphaComponent(0.2)
            banner.textColor = .systemGreen
        } else {
            banner.text = "❌ NOT INJECTED\n\ndaemon: \(daemon ? "активен" : "недоступен")"
            banner.backgroundColor = .systemRed.withAlphaComponent(0.2)
            banner.textColor = .systemRed
        }
    }
}
