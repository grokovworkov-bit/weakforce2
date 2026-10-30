//  TweakForce — ManagerApp/DiagnosticsViewController.swift
//  EN: Full-system diagnostics: daemon ping, config validity, log tail.
//  RU: Диагностика всей системы: ping daemon, валидность конфига, хвост лога.
import UIKit

final class DiagnosticsViewController: UIViewController {
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
                                                            target: self, action: #selector(run))
        run()
    }
    @objc private func run() {
        DiagnosticsService.shared.collect { [weak self] report in
            DispatchQueue.main.async { self?.textView.text = report }
        }
    }
}
