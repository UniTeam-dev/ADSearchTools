import ADKit
import SwiftUI

struct MainView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage("detailWidth") private var detailWidth = 420.0

    var body: some View {
        NavigationSplitView {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 200, ideal: 240, max: 320)
        } detail: {
            // macOS 13's NavigationSplitView can't hide a third column, so list + detail share the detail column.
            // Plain SwiftUI layout (not HSplitView): NSSplitView ignored the minimums and pushed content off-window.
            GeometryReader { geo in
                let limits: ClosedRange<Double> = 320...max(320, min(680, Double(geo.size.width) - 300))
                let w = min(max(detailWidth, limits.lowerBound), limits.upperBound)
                HStack(spacing: 0) {
                    ObjectListView().frame(maxWidth: .infinity, maxHeight: .infinity)
                    if model.showDetail {
                        ResizeHandle(width: $detailWidth, current: w, limits: limits)
                        DetailPanel().frame(width: w).frame(maxHeight: .infinity)
                    }
                }
            }
        }
        .searchable(text: $model.query, placement: .toolbar, prompt: "Поиск в \(model.info?.dnsName ?? "домене")")
        .toolbar { MainToolbar() }
        .sheet(item: $model.sheet) { SheetHost(kind: $0) }
        .confirmationDialog(confirmTitle, isPresented: confirmShown, titleVisibility: .visible, presenting: model.confirm) { c in
            switch c {
            case .delete(let objs): Button("Удалить", role: .destructive) { model.delete(objs) }
            case .disable(let objs): Button("Отключить", role: .destructive) { model.setEnabled(objs, false) }
            }
            Button("Отменить", role: .cancel) {}
        } message: { c in
            switch c {
            case .delete(let objs):
                Text((objs.count == 1 ? objs[0].dn : objs.map(\.name).joined(separator: ", ")) + "\n\nОбъект будет удалён из домена. Отменить это действие нельзя.")
            case .disable(let objs):
                Text((objs.count == 1 ? "" : objs.map(\.name).joined(separator: ", ") + "\n\n") + "Вход в домен станет невозможен. Членство в группах и атрибуты сохранятся, учётную запись можно включить снова.")
            }
        }
        .alert(item: $model.error) { e in
            Alert(title: Text(e.title), message: Text(e.message + (e.technical.isEmpty ? "" : "\n\n" + e.technical)),
                  primaryButton: .default(Text("OK")),
                  secondaryButton: .default(Text("Скопировать подробности")) { copyToPasteboard("\(e.title)\n\(e.message)\n\(e.technical)") })
        }
        .overlay(alignment: .bottom) {
            if let t = model.toast {
                Label(t, systemImage: "checkmark.circle.fill")
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(.regularMaterial, in: Capsule())
                    .overlay(Capsule().strokeBorder(.separator))
                    .padding(.bottom, 18)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .accessibilityAddTraits(.updatesFrequently)
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.toast)
    }

    private var confirmShown: Binding<Bool> {
        Binding(get: { model.confirm != nil }, set: { if !$0 { model.confirm = nil } })
    }

    private var confirmTitle: String {
        switch model.confirm {
        case .delete(let o): o.count == 1 ? "Удалить «\(o[0].name)»?" : "Удалить \(Fmt.objects(o.count))?"
        case .disable(let o): o.count == 1 ? "Отключить «\(o[0].name)»?" : "Отключить \(Fmt.objects(o.count))?"
        case nil: ""
        }
    }
}

/// 1 pt separator with a wider invisible grab area; dragging left widens the panel on its right.
struct ResizeHandle: View {
    @Binding var width: Double
    let current: Double
    let limits: ClosedRange<Double>
    @State private var start: Double?

    var body: some View {
        Rectangle()
            .fill(Color(nsColor: .separatorColor))
            .frame(width: 1)
            .overlay(
                Color.clear
                    .frame(width: 9)
                    .contentShape(Rectangle())
                    .onHover { $0 ? NSCursor.resizeLeftRight.push() : NSCursor.pop() }
                    .gesture(DragGesture(minimumDistance: 1)
                        .onChanged { v in
                            let base = start ?? current
                            start = base
                            width = min(max(base - v.translation.width, limits.lowerBound), limits.upperBound)
                        }
                        .onEnded { _ in start = nil })
            )
            .accessibilityHidden(true)
    }
}

struct MainToolbar: ToolbarContent {
    @EnvironmentObject var model: AppModel

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .navigation) {
            NewObjectMenu()
            Picker("Вид", selection: $model.useTable) {
                Label("Список", systemImage: "list.bullet").tag(false)
                Label("Таблица", systemImage: "tablecells").tag(true)
            }
            .pickerStyle(.segmented)
            .help("Вид списка")
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Button { model.reload(); model.refreshCounts() } label: { Label("Обновить", systemImage: "arrow.clockwise") }
                .help("Обновить (⌘R)")
            Button { model.showDetail.toggle() } label: { Label("Панель деталей", systemImage: "sidebar.right") }
                .help("Показать или скрыть панель деталей (⌥⌘I)")
        }
    }
}

struct NewObjectMenu: View {
    @EnvironmentObject var model: AppModel
    var label = true

    var body: some View {
        Menu {
            Section("Создать в \(DN.path(model.creationParent()).last ?? model.info?.dnsName ?? "")") {
                Button { model.sheet = .newUser(model.creationParent()) } label: { Label("Пользователь…", systemImage: "person") }
                Button { model.sheet = .newGroup(model.creationParent()) } label: { Label("Группа…", systemImage: "person.2") }
                Button { model.sheet = .newComputer(model.creationParent(computer: true)) } label: { Label("Компьютер…", systemImage: "desktopcomputer") }
                Button { model.sheet = .newOU(model.creationParent()) } label: { Label("Подразделение (OU)…", systemImage: "folder") }
            }
        } label: {
            Label("Создать", systemImage: "plus")
        }
        .help("Создать объект")
    }
}

// MARK: - Sidebar

struct TreeItem: Identifiable, Hashable {
    let obj: ADObject
    let kids: [TreeItem]?
    var id: String { obj.dn }
}

struct Sidebar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List(selection: $model.place) {
            Section("Быстрые фильтры") {
                quick(.locked, "Заблокированные", "lock.fill", .orange)
                quick(.disabled, "Отключённые", "nosign", .secondary)
                quick(.expiring, "Пароль скоро истекает", "clock.fill", .yellow)
            }
            if let info = model.info {
                Section(info.dnsName) {
                    OutlineGroup(items(info.baseDN), children: \.kids) { item in
                        Label {
                            Text(item.obj.rdnName)
                        } icon: {
                            Image(systemName: item.obj.kind == .ou ? "folder.fill" : "folder").foregroundStyle(Color.accentColor)
                        }
                        .tag(Place.container(item.obj.dn))
                        .contextMenu {
                            Button("Свойства") { model.open(item.obj.dn) }
                            Button("Скопировать DN") { copyToPasteboard(item.obj.dn) }
                        }
                        // Prefetch one level ahead so disclosure arrows are right before the user expands.
                        .onAppear { model.loadTree(item.obj.dn) }
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) { ConnectionFooter() }
    }

    private func quick(_ f: QuickFilter, _ title: String, _ icon: String, _ color: Color) -> some View {
        Label { Text(title) } icon: { Image(systemName: icon).foregroundStyle(color) }
            .badge(model.counts[f] ?? 0)
            .tag(Place.quick(f))
    }

    /// Unloaded → [] (expandable), loaded-empty → nil (leaf).
    private func items(_ dn: String) -> [TreeItem] {
        (model.tree[dn] ?? []).map { o in
            let kids = model.tree[o.dn]
            return TreeItem(obj: o, kids: kids.map { $0.isEmpty ? nil : items(o.dn) } ?? [])
        }
    }
}

struct ConnectionFooter: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            if model.reconnecting {
                Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Переподключение…").fontWeight(.medium).foregroundStyle(.orange)
                    Text(model.info?.dcHost ?? "").font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Circle().fill(.green).frame(width: 7, height: 7).padding(.top, 5)
                VStack(alignment: .leading, spacing: 1) {
                    Text(model.info?.dcHost ?? "").fontWeight(.medium)
                    Text("Подключено · \(model.dir?.config.user ?? "")").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
        .font(.callout)
        .lineLimit(1)
        .padding(10)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Object list

struct ObjectListView: View {
    @EnvironmentObject var model: AppModel
    @State private var sort = [KeyPathComparator(\ADObject.name)]

    var body: some View {
        VStack(spacing: 0) {
            if model.reconnecting {
                Label("Соединение с \(model.info?.dcHost ?? "DC") потеряно. Переподключение… Данные могут быть устаревшими.",
                      systemImage: "arrow.triangle.2.circlepath")
                    .font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(Color.orange.opacity(0.15))
            }
            header
            Divider()
            content
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(crumbs).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.head)
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(title).font(.title2.weight(.bold)).lineLimit(1)
                if !model.isSearching, case .container(let dn) = model.place {
                    Button { model.open(dn) } label: { Image(systemName: "info.circle") }
                        .buttonStyle(.borderless)
                        .help("Свойства «\(title)»")
                }
                Text(model.loading ? "Загрузка…" : countText).foregroundStyle(.secondary)
                if model.loading { ProgressView().controlSize(.small) }
                Spacer()
            }
            if showKindPicker {
                // A segmented control never shrinks below its labels; in a narrow column fall back to icons.
                ViewThatFits(in: .horizontal) {
                    kindPicker(icons: false)
                    kindPicker(icons: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private func kindPicker(icons: Bool) -> some View {
        Picker("Тип объектов", selection: $model.kind) {
            Text("Все").tag(KindFilter.all)
            kindLabel("Люди", "person", icons).tag(KindFilter.people)
            kindLabel("Группы", "person.2", icons).tag(KindFilter.groups)
            kindLabel("Компьютеры", "desktopcomputer", icons).tag(KindFilter.computers)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
    }

    @ViewBuilder
    private func kindLabel(_ title: String, _ icon: String, _ iconOnly: Bool) -> some View {
        if iconOnly { Image(systemName: icon).help(title).accessibilityLabel(title) } else { Text(title) }
    }

    private var showKindPicker: Bool {
        if model.isSearching { return true }
        if case .container = model.place { return true }
        return false
    }

    private var title: String {
        if model.isSearching { return "Результаты поиска" }
        switch model.place {
        case .quick(.locked): return "Заблокированные"
        case .quick(.disabled): return "Отключённые"
        case .quick(.expiring): return "Пароль скоро истекает"
        case .container(let dn): return DN.path(dn).last ?? model.info?.dnsName ?? ""
        case nil: return ""
        }
    }

    private var crumbs: String {
        if model.isSearching { return "Везде в \(model.info?.dnsName ?? "") · имя, логин, email" }
        switch model.place {
        case .container(let dn): return ([model.info?.dnsName ?? ""] + DN.path(dn)).joined(separator: " › ")
        case .quick(.expiring): return "Пароль истекает в ближайшие 14 дней"
        case .quick: return "Все пользователи \(model.info?.dnsName ?? "")"
        case nil: return ""
        }
    }

    private var countText: String {
        let n = model.visibleItems.count
        return model.isSearching ? "найдено: \(n)" + (n >= 500 ? " (показаны первые 500)" : "") : Fmt.objects(n)
    }

    @ViewBuilder
    private var content: some View {
        let rows = model.visibleItems
        if rows.isEmpty && !model.loading {
            EmptyState(searching: model.isSearching, query: model.query)
        } else if model.useTable {
            Table(rows.sorted(using: sort), selection: $model.selection, sortOrder: $sort) {
                TableColumn("Имя", value: \.name) { o in
                    HStack(spacing: 6) {
                        Image(systemName: o.symbol).foregroundStyle(.secondary).frame(width: 16)
                        Text(o.name)
                    }
                    .opacity(o.isDisabled ? 0.55 : 1)
                }
                TableColumn("Тип", value: \.typeName) { Text($0.typeName).foregroundStyle(.secondary) }
                TableColumn("Статус", value: \.statusText) { o in
                    if o.status != nil { StatusBadge(status: o.status, text: o.statusText) } else { Text(o.statusText).foregroundStyle(.secondary) }
                }
                TableColumn("Описание", value: \.descriptionSort) { Text($0.descriptionSort).foregroundStyle(.secondary) }
                TableColumn("Изменён", value: \.changedSort) { Text(Fmt.date($0.whenChanged)).foregroundStyle(.secondary) }
            }
            .contextMenu(forSelectionType: String.self) { ids in RowMenu(ids: ids) } primaryAction: { ids in openRows(ids) }
        } else {
            List(rows, selection: $model.selection) { o in
                ObjectRow(obj: o)
            }
            .listStyle(.inset(alternatesRowBackgrounds: false))
            .contextMenu(forSelectionType: String.self) { ids in RowMenu(ids: ids) } primaryAction: { ids in openRows(ids) }
        }
    }

    private func openRows(_ ids: Set<String>) {
        guard ids.count == 1, let o = model.items.first(where: { ids.contains($0.dn) }) else { return }
        if o.isContainer { model.navigate(into: o) } else { model.showDetail = true }
    }
}

struct ObjectRow: View {
    let obj: ADObject

    var body: some View {
        HStack(spacing: 10) {
            Avatar(obj: obj, size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text(obj.name).fontWeight(.medium).lineLimit(1)
                Text(obj.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            StatusBadge(status: obj.status, text: obj.statusText)
        }
        .padding(.vertical, 3)
        .opacity(obj.isDisabled ? 0.6 : 1)
        .accessibilityElement(children: .combine)
    }
}

struct EmptyState: View {
    let searching: Bool
    let query: String
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: searching ? "magnifyingglass" : "folder").font(.system(size: 40, weight: .thin)).foregroundStyle(.secondary)
            if searching {
                Text(query.count < 2 ? "Введите хотя бы 2 символа" : "Ничего не найдено по запросу «\(query)»").font(.headline)
                Text("Поиск идёт по всему домену: имя, логин и email. Проверьте написание или введите логин целиком.")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center)
            } else if case .quick = model.place {
                Text("Таких учётных записей нет").font(.headline)
            } else {
                Text("Здесь нет объектов").font(.headline)
                Text("Создайте пользователя, группу или компьютер кнопкой «+» в панели инструментов.")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button("Новый пользователь…") { model.sheet = .newUser(model.creationParent()) }.padding(.top, 4)
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Context menu for one or several rows — also reused for the "Действие" menu bar menu.
struct RowMenu: View {
    let ids: Set<String>
    @EnvironmentObject var model: AppModel

    var body: some View {
        let objs = model.items.filter { ids.contains($0.dn) }
        let users = objs.filter { $0.kind == .user || $0.kind == .computer }
        if objs.isEmpty {
            NewObjectMenu()
        } else {
            if objs.count == 1, objs[0].isContainer {
                Button("Открыть") { model.navigate(into: objs[0]) }
                Divider()
            }
            if users.contains(where: \.isLocked) {
                Button { model.unlock(users.filter(\.isLocked)) } label: { Label("Разблокировать", systemImage: "lock.open") }
            }
            if objs.count == 1, objs[0].kind == .user {
                Button { model.sheet = .reset(objs[0]) } label: { Label("Сбросить пароль…", systemImage: "key") }
            }
            if users.contains(where: \.isDisabled) {
                Button { model.setEnabled(users.filter(\.isDisabled), true) } label: { Label("Включить", systemImage: "checkmark.circle") }
            }
            if users.contains(where: { !$0.isDisabled }) {
                Button { model.confirm = .disable(users.filter { !$0.isDisabled }) } label: { Label("Отключить", systemImage: "nosign") }
            }
            Divider()
            if objs.allSatisfy({ [.user, .computer, .group, .contact].contains($0.kind) }) {
                Button { model.sheet = .addToGroups(objs) } label: { Label("Добавить в группу…", systemImage: "person.badge.plus") }
            }
            if objs.allSatisfy({ $0.kind != .container && $0.kind != .domain }) {
                Button { model.sheet = .move(objs) } label: { Label("Переместить…", systemImage: "folder") }
            }
            Divider()
            if objs.count == 1 {
                Button("Скопировать DN") { copyToPasteboard(objs[0].dn) }
                if let sam = objs[0].sam { Button("Скопировать логин") { copyToPasteboard(sam) } }
                Divider()
            }
            Button(role: .destructive) { model.confirm = .delete(objs) } label: { Label("Удалить…", systemImage: "trash") }
                .keyboardShortcut(.delete, modifiers: .command)
        }
    }
}
