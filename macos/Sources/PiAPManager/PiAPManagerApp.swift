import SwiftUI
import AppKit

/// Çıkışta BLE bağlantısını düzgün kapat (bluetoothd eski oturumu tutmasın).
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var app: AppState?
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        app?.ble.disconnect()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { NSApp.reply(toApplicationShouldTerminate: true) }
        return .terminateLater
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct PiAPManagerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var app = AppState()
    var body: some Scene {
        WindowGroup("PiAP Manager") {
            ContentView().environmentObject(app).onAppear { delegate.app = app }
        }
        .defaultSize(width: 900, height: 600)
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}
