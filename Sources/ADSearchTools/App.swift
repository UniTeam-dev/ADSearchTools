import ADKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct ADSearchToolsApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    init() {
        #if DEBUG
        if CommandLine.arguments.contains("--selftest") { Task { await SelfTest.run() } }
        #endif
    }

    var body: some Scene {
        Window("ADSearchTools", id: "main") {
            Group {
                if model.dir == nil {
                    ConnectView().frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    MainView().frame(minWidth: 900, minHeight: 560)
                }
            }
            .environmentObject(model)
        }
        .defaultSize(width: 1280, height: 780)
        .commands {
            SidebarCommands()
            AppCommands(model: model)
        }
    }
}

struct AppCommands: Commands {
    @ObservedObject var model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Новый пользователь…") { model.sheet = .newUser(model.creationParent()) }
                .keyboardShortcut("n")
                .disabled(model.dir == nil)
            Button("Новая группа…") { model.sheet = .newGroup(model.creationParent()) }.disabled(model.dir == nil)
            Button("Новый компьютер…") { model.sheet = .newComputer(model.creationParent(computer: true)) }.disabled(model.dir == nil)
            Button("Новое подразделение (OU)…") { model.sheet = .newOU(model.creationParent()) }.disabled(model.dir == nil)
            Divider()
            Button("Отключиться от домена") { model.disconnect() }.disabled(model.dir == nil)
        }
        CommandGroup(after: .toolbar) {
            Button("Список") { model.useTable = false }.keyboardShortcut("1")
            Button("Таблица") { model.useTable = true }.keyboardShortcut("2")
            Button(model.showDetail ? "Скрыть панель деталей" : "Показать панель деталей") { model.showDetail.toggle() }
                .keyboardShortcut("i", modifiers: [.command, .option])
            Divider()
            Button("Обновить") { model.reload(); model.refreshCounts() }
                .keyboardShortcut("r")
                .disabled(model.dir == nil)
        }
        CommandMenu("Действие") {
            RowMenu(ids: model.selection).environmentObject(model)
        }
    }
}
