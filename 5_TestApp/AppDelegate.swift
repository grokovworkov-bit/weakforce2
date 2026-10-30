//  TweakForce — TestApp/AppDelegate.swift
//  EN: Test target app embedding libTweakForceHooks. Installs sample hooks at
//      launch so you can visually confirm injection works before touching AIDA64.
//  RU: Тестовое приложение со встроенным libTweakForceHooks. Ставит примеры
//      хуков на старте, чтобы визуально подтвердить работу инъекции до AIDA64.
import UIKit
// import TweakForceHooks   // EN/RU: enable when linked via module.modulemap

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        let tabs = UITabBarController()
        tabs.viewControllers = [
            UINavigationController(rootViewController: DiagnosticViewController()),
            UINavigationController(rootViewController: DeviceInfoView()),
            UINavigationController(rootViewController: CameraTestView()),
            UINavigationController(rootViewController: InjectionStatusView()),
        ]
        window.rootViewController = tabs
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
}
