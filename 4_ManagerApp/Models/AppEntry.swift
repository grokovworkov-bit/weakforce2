//  TweakForce — ManagerApp/Models/AppEntry.swift
//  EN: One installed app row with INDEPENDENT injection & hide toggles.
//  RU: Одна строка приложения с НЕЗАВИСИМЫМИ тумблерами injection и hide.
import Foundation
struct AppEntry {
    let bundleID: String
    let name: String
    var injectionEnabled: Bool
    var hideEnabled: Bool
}
