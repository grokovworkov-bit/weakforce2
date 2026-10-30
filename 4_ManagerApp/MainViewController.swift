//  TweakForce — ManagerApp/MainViewController.swift
//  EN: Table with 3 sections: Daemon status, Apps (independent injection/hide
//      toggles), Active tweaks. Toggling injection writes config + signals daemon.
//  RU: Таблица с 3 секциями: статус daemon, приложения (независимые тумблеры
//      injection/hide), активные твики. Переключение injection пишет конфиг +
//      сигналит daemon.
import UIKit

final class MainViewController: UITableViewController {
    private var apps: [AppEntry] = []
    private var tweaks: [TweakEntry] = []
    private var daemonStatus = InjectionStatus(daemonAlive: false, detail: "проверка…")

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "TweakForce"
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "c")
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .refresh,
                                                            target: self, action: #selector(reload))
        reload()
    }

    @objc private func reload() {
        apps = ConfigManager.shared.loadApps()
        tweaks = ConfigManager.shared.loadActiveTweaks()
        DaemonBridge.shared.ping { [weak self] alive in
            self?.daemonStatus = InjectionStatus(daemonAlive: alive,
                                                 detail: alive ? "daemon активен" : "daemon недоступен")
            self?.tableView.reloadData()
        }
    }

    // MARK: Table
    override func numberOfSections(in tableView: UITableView) -> Int { 3 }
    override func tableView(_ t: UITableView, titleForHeaderInSection s: Int) -> String? {
        ["Статус daemon", "Приложения (injection / hide)", "Активные твики"][s]
    }
    override func tableView(_ t: UITableView, numberOfRowsInSection s: Int) -> Int {
        switch s { case 0: return 1; case 1: return apps.count; default: return max(tweaks.count, 1) }
    }

    override func tableView(_ t: UITableView, cellForRowAt ip: IndexPath) -> UITableViewCell {
        let cell = t.dequeueReusableCell(withIdentifier: "c", for: ip)
        cell.accessoryView = nil; cell.selectionStyle = .none
        switch ip.section {
        case 0:
            cell.textLabel?.text = daemonStatus.detail
            cell.imageView?.image = UIImage(systemName: "circle.fill")?
                .withTintColor(daemonStatus.daemonAlive ? .systemGreen : .systemRed, renderingMode: .alwaysOriginal)
            let btn = UIButton(type: .system)
            btn.setTitle("Перезапустить", for: .normal)
            btn.addTarget(self, action: #selector(restartDaemon), for: .touchUpInside)
            btn.sizeToFit(); cell.accessoryView = btn
        case 1:
            let app = apps[ip.row]
            cell.textLabel?.text = "\(app.name)\n\(app.bundleID)"
            cell.textLabel?.numberOfLines = 2
            // Two independent switches rendered via a stack.
            let inj = labeledSwitch("Inj", on: app.injectionEnabled, tag: ip.row * 2)
            let hid = labeledSwitch("Hide", on: app.hideEnabled, tag: ip.row * 2 + 1)
            let stack = UIStackView(arrangedSubviews: [inj, hid])
            stack.axis = .horizontal; stack.spacing = 8; stack.sizeToFit()
            cell.accessoryView = stack
        default:
            cell.textLabel?.text = tweaks.isEmpty ? "нет загруженных твиков"
                                                  : tweaks[ip.row].path
            cell.textLabel?.numberOfLines = 2
        }
        return cell
    }

    private func labeledSwitch(_ title: String, on: Bool, tag: Int) -> UIView {
        let sw = UISwitch(); sw.isOn = on; sw.tag = tag
        sw.addTarget(self, action: #selector(toggle(_:)), for: .valueChanged)
        let lbl = UILabel(); lbl.text = title; lbl.font = .systemFont(ofSize: 10)
        let v = UIStackView(arrangedSubviews: [lbl, sw]); v.axis = .vertical; v.alignment = .center
        v.sizeToFit(); return v
    }

    @objc private func toggle(_ sw: UISwitch) {
        let row = sw.tag / 2, isInjection = (sw.tag % 2 == 0)
        guard row < apps.count else { return }
        var app = apps[row]
        if isInjection {
            app.injectionEnabled = sw.isOn
            ConfigManager.shared.setInjection(sw.isOn, bundleID: app.bundleID)
            DaemonBridge.shared.setTweak(bundleID: app.bundleID, enabled: sw.isOn) { _ in }
        } else {
            app.hideEnabled = sw.isOn
            ConfigManager.shared.setHiding(sw.isOn, bundleID: app.bundleID)
        }
        apps[row] = app
    }

    @objc private func restartDaemon() {
        DaemonBridge.shared.restartDaemon { [weak self] _ in self?.reload() }
    }
}
