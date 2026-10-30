//  TweakForce — ManagerApp/TweakListViewController.swift
//  EN: Lists configured tweaks (dylibs) and their enabled state per app.
//  RU: Список настроенных твиков (dylib) и их состояния по приложениям.
import UIKit

final class TweakListViewController: UITableViewController {
    private var tweaks: [TweakEntry] = []
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Твики"
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "t")
        tweaks = ConfigManager.shared.loadActiveTweaks()
    }
    override func tableView(_ t: UITableView, numberOfRowsInSection s: Int) -> Int { max(tweaks.count, 1) }
    override func tableView(_ t: UITableView, cellForRowAt ip: IndexPath) -> UITableViewCell {
        let cell = t.dequeueReusableCell(withIdentifier: "t", for: ip)
        if tweaks.isEmpty { cell.textLabel?.text = "Твики не настроены"; return cell }
        let tw = tweaks[ip.row]
        cell.textLabel?.text = (tw.path as NSString).lastPathComponent
        cell.detailTextLabel?.text = tw.enabled ? "включён" : "выключен"
        cell.accessoryType = tw.enabled ? .checkmark : .none
        return cell
    }
}
