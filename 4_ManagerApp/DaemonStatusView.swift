//  TweakForce — ManagerApp/DaemonStatusView.swift
//  EN: Reusable view showing a green/red daemon indicator + uptime.
//  RU: Переиспользуемое view с зелёным/красным индикатором daemon + uptime.
import UIKit

final class DaemonStatusView: UIView {
    private let dot = UIView()
    private let label = UILabel()
    init() {
        super.init(frame: .zero)
        dot.layer.cornerRadius = 6
        dot.translatesAutoresizingMaskIntoConstraints = false
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(dot); addSubview(label)
        NSLayoutConstraint.activate([
            dot.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            dot.centerYAnchor.constraint(equalTo: centerYAnchor),
            dot.widthAnchor.constraint(equalToConstant: 12),
            dot.heightAnchor.constraint(equalToConstant: 12),
            label.leadingAnchor.constraint(equalTo: dot.trailingAnchor, constant: 8),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
        update(alive: false, detail: "проверка…")
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }
    func update(alive: Bool, detail: String) {
        dot.backgroundColor = alive ? .systemGreen : .systemRed
        label.text = detail
    }
}
