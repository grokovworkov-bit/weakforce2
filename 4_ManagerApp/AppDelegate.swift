//  TweakForce — ManagerApp/AppDelegate.swift
//  EN: Entry point of the TweakForce Manager app (sideloaded; TrollStore or
//      Xcode signing — NOT App Store). Sets up the main window + tab UI.
//  RU: Точка входа Manager-приложения TweakForce (сайдлоад; TrollStore или
//      подпись Xcode — НЕ App Store). Настраивает окно и вкладки.
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        let tabs = UITabBarController()
        tabs.viewControllers = [
            UINavigationController(rootViewController: MainViewController()),
            UINavigationController(rootViewController: TweakListViewController()),
            UINavigationController(rootViewController: DiagnosticsViewController()),
        ]
        window.rootViewController = tabs
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
}
