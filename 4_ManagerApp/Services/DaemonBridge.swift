//  TweakForce — ManagerApp/Services/DaemonBridge.swift
//  EN: CFMessagePort client to the daemon ("com.tweakforce.daemon"). All calls
//      are async on a background queue; completion on the caller's discretion.
//  RU: Клиент CFMessagePort к daemon ("com.tweakforce.daemon"). Все вызовы
//      асинхронны на фоновой очереди.
import Foundation
import CoreFoundation

final class DaemonBridge {
    static let shared = DaemonBridge()
    private let portName = "com.tweakforce.daemon"
    private let queue = DispatchQueue(label: "com.tweakforce.manager.bridge")

    private func send(_ payload: [String: Any], completion: @escaping ([String: Any]?) -> Void) {
        queue.async {
            guard let port = CFMessagePortCreateRemote(nil, self.portName as CFString) else {
                NSLog("[TweakForce] daemon port unavailable"); completion(nil); return
            }
            guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
                completion(nil); return
            }
            var response: Unmanaged<CFData>?
            let rc = CFMessagePortSendRequest(port, Int32(0x1), data as CFData, 2.0, 2.0,
                                              CFRunLoopMode.defaultMode.rawValue, &response)
            var dict: [String: Any]? = nil
            if rc == kCFMessagePortSuccess, let respData = response?.takeRetainedValue() as Data? {
                dict = (try? JSONSerialization.jsonObject(with: respData)) as? [String: Any]
            } else {
                NSLog("[TweakForce] daemon send failed rc=\(rc)")
            }
            completion(dict)
        }
    }

    func ping(_ completion: @escaping (Bool) -> Void) {
        send(["cmd": "PING"]) { completion(($0?["ok"] as? Bool) ?? false) }
    }
    func status(_ completion: @escaping ([String: Any]?) -> Void) {
        send(["cmd": "GET_STATUS"], completion: completion)
    }
    func setTweak(bundleID: String, enabled: Bool, completion: @escaping (Bool) -> Void) {
        send(["cmd": "SET_TWEAK_FOR_APP", "bundle": bundleID, "enabled": enabled]) {
            completion(($0?["ok"] as? Bool) ?? false)
        }
    }
    func injectNow(bundleID: String, pid: Int, completion: @escaping (Bool) -> Void) {
        send(["cmd": "INJECT_NOW", "bundle": bundleID, "pid": pid]) {
            completion(($0?["ok"] as? Bool) ?? false)
        }
    }
    func getLog(bytes: Int = 8192, completion: @escaping (String) -> Void) {
        send(["cmd": "GET_LOG", "bytes": bytes]) { completion(($0?["log"] as? String) ?? "") }
    }
    // EN: Ask launchd (via daemon) to restart; here we just re-ping as a stub
    //     because unloading our own helper requires running outside the app sandbox.
    // RU: Просим перезапуск; здесь — повторный ping, т.к. выгрузка helper'а
    //     требует запуска вне песочницы приложения.
    func restartDaemon(_ completion: @escaping (Bool) -> Void) {
        NSLog("[TweakForce] restartDaemon: use install.sh / launchctl kickstart on-device")
        ping(completion)
    }
}
