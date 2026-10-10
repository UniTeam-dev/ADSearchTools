import ADKit
import SwiftUI

struct DetailPanel: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.openOverride == nil && model.selection.count > 1 {
                MultiSummary(objs: model.selectedObjects)
            } else if let o = model.detail {
                ObjectDetail(obj: o).id(o.dn)
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "sidebar.right").font(.system(size: 36, weight: .thin)).foregroundStyle(.secondary)
                    Text("Выберите объект").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

// MARK: - Header and actions

struct ActionButton: View {
    let title: String
    let symbol: String
    var prominent = false
    var role: ButtonRole?
    let action: () -> Void

    var body: some View {
        Button(role: role, action: action) { ActionLabel(title: title, symbol: symbol, prominent: prominent) }
            .buttonStyle(.plain)
            .help(title)
    }
}

struct ActionLabel: View {
    let title: String
    let symbol: String
    var prominent = false

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .medium))
                .frame(width: 34, height: 34)
                .foregroundStyle(prominent ? Color.white : Color.primary)
                .background(prominent ? Color.accentColor : Color.secondary.opacity(0.15), in: Circle())
            Text(title).font(.caption).foregroundStyle(.secondary).lineLimit(1)
        }
        .frame(minWidth: 64)
        .contentShape(Rectangle())
    }
}

struct ObjectDetail: View {
    let obj: ADObject
    @EnvironmentObject var model: AppModel
    @State private var tab: Tab

    init(obj: ADObject, initialTab: Tab = .profile) {
        self.obj = obj
        _tab = State(initialValue: initialTab)
    }

    enum Tab: String { case profile, account, groups, members, memberOf, general, attrs }

    private var tabs: [(Tab, String)] {
        switch obj.kind {
        case .user: [(.profile, "Профиль"), (.account, "Учётная запись"), (.groups, "Группы"), (.attrs, "Атрибуты")]
        case .group: [(.general, "Общие"), (.members, "Участники"), (.memberOf, "Член групп"), (.attrs, "Атрибуты")]
        case .computer: [(.general, "Общие"), (.memberOf, "Член групп"), (.attrs, "Атрибуты")]
        default: [(.general, "Общие"), (.attrs, "Атрибуты")]
        }
    }

    var body: some View {
        VStack(spacing: 12) {
            header
            actions
            Picker("Раздел", selection: $tab) {
                ForEach(tabs, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 14)
            content.frame(maxHeight: .infinity)
        }
        .padding(.top, 16)
        .onAppear { if !tabs.contains(where: { $0.0 == tab }) { tab = obj.kind == .group ? .members : tabs[0].0 } }
    }

    private var header: some View {
        VStack(spacing: 4) {
            Avatar(obj: obj, size: 56)
            Text(obj.name).font(.title3.weight(.bold)).multilineTextAlignment(.center).textSelection(.enabled)
            Text(headerSubtitle).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            StatusBadge(status: obj.status, text: obj.statusText).padding(.top, 2)
        }
        .padding(.horizontal, 14)
    }

    private var headerSubtitle: String {
        switch obj.kind {
        case .user: return [obj.title, obj.department].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ").ifEmpty(obj.sam ?? "")
        case .computer: return [obj.entry.string("operatingSystem"), obj.entry.string("operatingSystemVersion")].compactMap { $0 }.joined(separator: " ").ifEmpty("Компьютер")
        case .group: return obj.subtitle
        default: return obj.typeName + " · " + ([model.info?.dnsName ?? ""] + DN.path(DN.parent(obj.dn))).joined(separator: " / ")
        }
    }

    @ViewBuilder
    private var actions: some View {
        HStack(alignment: .top, spacing: 6) {
            switch obj.kind {
            case .user:
                if obj.isLocked {
                    ActionButton(title: "Разблокировать", symbol: "lock.open", prominent: true) { model.unlock([obj]) }
                } else if obj.isDisabled {
                    ActionButton(title: "Включить", symbol: "checkmark.circle", prominent: true) { model.setEnabled([obj], true) }
                }
                ActionButton(title: "Пароль", symbol: "key", prominent: !obj.isLocked && !obj.isDisabled) { model.sheet = .reset(obj) }
                ActionButton(title: "Переместить", symbol: "folder") { model.sheet = .move([obj]) }
            case .group:
                ActionButton(title: "Участники", symbol: "person.badge.plus", prominent: true) { model.sheet = .addMembers(obj) }
                ActionButton(title: "Переместить", symbol: "folder") { model.sheet = .move([obj]) }
            case .computer:
                ActionButton(title: obj.isDisabled ? "Включить" : "Отключить", symbol: obj.isDisabled ? "checkmark.circle" : "power") {
                    if obj.isDisabled { model.setEnabled([obj], true) } else { model.confirm = .disable([obj]) }
                }
                ActionButton(title: "Переместить", symbol: "folder") { model.sheet = .move([obj]) }
            default:
                Menu {
                    Button("Пользователь…") { model.sheet = .newUser(obj.dn) }
                    Button("Группа…") { model.sheet = .newGroup(obj.dn) }
                    Button("Компьютер…") { model.sheet = .newComputer(obj.dn) }
                    Button("Подразделение (OU)…") { model.sheet = .newOU(obj.dn) }
                } label: { ActionLabel(title: "Создать", symbol: "plus") }
                    .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()
                if obj.kind == .ou { ActionButton(title: "Переместить", symbol: "folder") { model.sheet = .move([obj]) } }
            }
            Menu {
                if obj.kind == .user {
                    if obj.isDisabled { Button("Включить") { model.setEnabled([obj], true) } } else { Button("Отключить…") { model.confirm = .disable([obj]) } }
                }
                if [.user, .computer, .group].contains(obj.kind) { Button("Добавить в группу…") { model.sheet = .addToGroups([obj]) } }
                Divider()
                Button("Скопировать DN") { copyToPasteboard(obj.dn) }
                if let sam = obj.sam { Button("Скопировать логин") { copyToPasteboard(sam) } }
                if obj.kind != .domain {
                    Divider()
                    Button("Удалить…", role: .destructive) { model.confirm = .delete([obj]) }
                }
            } label: { ActionLabel(title: "Ещё", symbol: "ellipsis") }
                .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()
        }
    }

    @ViewBuilder
    private var content: some View {
        switch tab {
        case .profile:
            EditableForm(obj: obj, sections: [
                .init("Имя", [.edit("Имя", "givenName"), .edit("Фамилия", "sn"), .edit("Отображаемое имя", "displayName")]),
                .init("Контакты", [.edit("Email", "mail"), .edit("Телефон", "telephoneNumber"), .edit("Мобильный", "mobile")]),
                .init("Организация", [.edit("Отдел", "department"), .edit("Должность", "title"), .edit("Компания", "company"), .link("Менеджер", obj.manager)]),
                .init("Описание", [.edit("Описание", "description")]),
            ])
        case .account: AccountForm(obj: obj)
        case .groups, .memberOf: RelatedList(obj: obj, members: false)
        case .members: RelatedList(obj: obj, members: true)
        case .attrs: AttributesView(obj: obj)
        case .general: GeneralForm(obj: obj)
        }
    }
}

extension String {
    func ifEmpty(_ s: String) -> String { isEmpty ? s : self }
}

// MARK: - Editable form

struct FormSpec {
    enum Row {
        case edit(String, String)    // label, attribute
        case info(String, String)    // label, value
        case link(String, String?)   // label, DN
    }
    let title: String
    let rows: [Row]
    init(_ title: String, _ rows: [Row]) { self.title = title; self.rows = rows }
}

/// Grouped form whose `.edit` rows are text fields; a Save/Cancel bar appears once anything changed.
struct EditableForm<Extra: View>: View {
    let obj: ADObject
    let sections: [FormSpec]
    @ViewBuilder var extra: () -> Extra
    @EnvironmentObject var model: AppModel
    @State private var draft: [String: String] = [:]

    init(obj: ADObject, sections: [FormSpec], @ViewBuilder extra: @escaping () -> Extra = { EmptyView() }) {
        self.obj = obj
        self.sections = sections
        self.extra = extra
    }

    private var original: [String: String] {
        var d: [String: String] = [:]
        for s in sections { for r in s.rows { if case .edit(_, let a) = r { d[a] = obj.entry.strings(a).joined(separator: "; ") } } }
        return d
    }

    private var changed: [String: String?] {
        let o = original
        return draft.filter { o[$0.key] != $0.value }.mapValues { Optional($0.trimmingCharacters(in: .whitespaces)) }
    }

    var body: some View {
        Form {
            ForEach(sections, id: \.title) { s in
                Section(s.title) {
                    ForEach(Array(s.rows.enumerated()), id: \.offset) { _, row in rowView(row) }
                }
            }
            extra()
        }
        .formStyle(.grouped)
        .safeAreaInset(edge: .bottom) {
            if !changed.isEmpty {
                HStack {
                    Text("Изменено полей: \(changed.count)").foregroundStyle(.secondary)
                    Spacer()
                    Button("Отменить") { draft = original }
                    Button("Сохранить") {
                        let c = changed, dn = obj.dn
                        model.perform("Не удалось сохранить изменения", success: "Изменения сохранены") { try await $0.update(dn, c) }
                    }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
                }
                .padding(10)
                .background(.bar)
            }
        }
        .onAppear { draft = original }
        .onChange(of: obj) { _ in draft = original }
    }

    @ViewBuilder
    private func rowView(_ row: FormSpec.Row) -> some View {
        switch row {
        case .edit(let label, let attr):
            TextField(label, text: Binding(get: { draft[attr] ?? "" }, set: { draft[attr] = $0 }), prompt: Text("Не задано"))
        case .info(let label, let value):
            LabeledContent(label) { Text(value).textSelection(.enabled) }
        case .link(let label, let dn):
            LabeledContent(label) {
                if let dn { Button(DN.name(dn)) { model.open(dn) }.buttonStyle(.link) } else { Text("Не задан").foregroundStyle(.secondary) }
            }
        }
    }
}

struct GeneralForm: View {
    let obj: ADObject
    @EnvironmentObject var model: AppModel
    @State private var count: Int?

    var body: some View {
        switch obj.kind {
        case .group:
            EditableForm(obj: obj, sections: [
                .init("Группа", [.edit("Описание", "description"), .edit("Email", "mail"), .link("Владелец", obj.entry.string("managedBy"))]),
            ]) {
                Section("Тип") {
                    if let t = obj.groupType {
                        Picker("Тип группы", selection: Binding(get: { GroupType.isSecurity(t) }, set: { sec in
                            let dn = obj.dn
                            model.perform("Не удалось сменить тип группы", success: "Тип группы изменён") { try await $0.setGroupSecurity(dn, security: sec, current: t) }
                        })) {
                            Text("Безопасность").tag(true)
                            Text("Распространение").tag(false)
                        }
                        LabeledContent("Область") { Text(GroupType.scope(t).map(ADObject.scopeName) ?? "—") }
                            .help("Область группы в AD меняется только по цепочке через «Универсальную», поэтому здесь только для чтения.")
                    }
                }
            }
        case .computer:
            EditableForm(obj: obj, sections: [
                .init("Компьютер", [
                    .info("DNS-имя", obj.entry.string("dNSHostName") ?? "—"),
                    .info("Операционная система", obj.entry.string("operatingSystem") ?? "—"),
                    .info("Версия ОС", obj.entry.string("operatingSystemVersion") ?? "—"),
                    .info("Последняя активность", Fmt.approx(obj.lastActivity)),
                ]),
                .init("Описание и расположение", [.edit("Описание", "description"), .info("Расположение", location)]),
            ])
        default:
            EditableForm(obj: obj, sections: [
                .init(obj.typeName, [.info("Имя", obj.rdnName), .edit("Описание", "description"),
                                     .info("Объектов внутри", count.map(String.init) ?? "…"), .info("Расположение", location)]),
            ])
            .task(id: obj.dn) { count = try? await model.dir?.count(in: obj.dn) }
        }
    }

    private var location: String { ([model.info?.dnsName ?? ""] + DN.path(DN.parent(obj.dn))).joined(separator: " / ") }
}

// MARK: - Account

struct AccountForm: View {
    let obj: ADObject
    @EnvironmentObject var model: AppModel
    @State private var expiry = Date().addingTimeInterval(30 * 86400)

    var body: some View {
        Form {
            Section("Вход") {
                LabeledContent("Логин (sAMAccountName)") { Text(verbatim: "\(model.info?.netbios ?? "")\\\(obj.sam ?? "")").font(.body.monospaced()).textSelection(.enabled) }
                LabeledContent("UPN") { Text(obj.upn ?? "—").font(.body.monospaced()).textSelection(.enabled) }
            }
            Section("Состояние") {
                LabeledContent("Статус") {
                    HStack {
                        if obj.status != nil { StatusBadge(status: obj.status, text: obj.statusText) } else { Label("Активна", systemImage: "checkmark.circle.fill").foregroundStyle(.green) }
                        if obj.isLocked { Button("Разблокировать") { model.unlock([obj]) } }
                        else if obj.isDisabled { Button("Включить") { model.setEnabled([obj], true) } }
                        else if obj.isPasswordExpired { Button("Сбросить пароль…") { model.sheet = .reset(obj) } }
                    }
                }
                if obj.isLocked { LabeledContent("Время блокировки") { Text(Fmt.date(obj.lockoutTime)) } }
                LabeledContent {
                    Text(Fmt.approx(obj.lastActivity))
                } label: {
                    HStack(spacing: 4) {
                        Text("Последняя активность")
                        Image(systemName: "info.circle").foregroundStyle(.secondary)
                            .help("Точность до 14 дней: AD реплицирует lastLogonTimestamp с задержкой.")
                    }
                }
            }
            Section("Пароль") {
                LabeledContent("Пароль установлен") { Text(obj.mustChangePassword ? "Нужно сменить при входе" : Fmt.date(obj.pwdLastSet.flatMap(ADTime.date(fileTime:)))) }
                LabeledContent("Пароль истекает") {
                    Text(obj.passwordNeverExpires ? "Никогда" : obj.passwordExpiry.map { Fmt.date($0) } ?? "—")
                }
                Toggle("Сменить пароль при следующем входе", isOn: Binding(get: { obj.mustChangePassword }, set: { on in
                    let dn = obj.dn
                    model.perform("Не удалось изменить", success: "Сохранено") { try await $0.setMustChangePassword(dn, on) }
                }))
                .disabled(obj.passwordNeverExpires)
                .help(obj.passwordNeverExpires ? "Недоступно, пока включено «Срок действия пароля не ограничен»." : "")
                Toggle("Срок действия пароля не ограничен", isOn: Binding(get: { obj.passwordNeverExpires }, set: { on in
                    let dn = obj.dn
                    model.perform("Не удалось изменить", success: "Сохранено") { try await $0.setPasswordNeverExpires(dn, on) }
                }))
                .disabled(obj.mustChangePassword)
                .help(obj.mustChangePassword ? "Недоступно, пока включено «Сменить пароль при следующем входе»." : "")
            }
            Section("Учётная запись") {
                Toggle("Срок действия не ограничен", isOn: Binding(get: { obj.accountExpires == nil }, set: { never in
                    let dn = obj.dn, date = expiry
                    model.perform("Не удалось изменить срок", success: "Сохранено") { try await $0.setAccountExpires(dn, never ? nil : date) }
                }))
                if let e = obj.accountExpires {
                    LabeledContent("Действует до") { Text(Fmt.date(e)) }
                    HStack {
                        DatePicker("Новая дата", selection: $expiry, displayedComponents: [.date, .hourAndMinute])
                        Button("Применить") {
                            let dn = obj.dn, date = expiry
                            model.perform("Не удалось изменить срок", success: "Сохранено") { try await $0.setAccountExpires(dn, date) }
                        }
                    }
                    .onAppear { expiry = e }
                }
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Groups / members

struct RelatedList: View {
    let obj: ADObject
    let members: Bool
    @EnvironmentObject var model: AppModel
    @State private var items: [ADObject] = []
    @State private var loading = true
    @State private var filter = ""
    @State private var sel = Set<String>()
    @State private var err: UIError?

    private var filtered: [ADObject] {
        filter.isEmpty ? items : items.filter { $0.name.localizedCaseInsensitiveContains(filter) || ($0.sam ?? "").localizedCaseInsensitiveContains(filter) }
    }

    /// The primary group is computed from primaryGroupID and can't be removed via `member`.
    private func isPrimary(_ g: ADObject) -> Bool { !members && !obj.entry.strings("memberOf").contains(g.dn) }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField(members ? "Поиск участников" : "Поиск по группам", text: $filter).textFieldStyle(.plain)
            }
            .padding(7)
            .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 7))
            .padding(.horizontal, 14).padding(.bottom, 6)

            if let err { ErrorBox(title: err.title, message: err.message, technical: err.technical).padding(.horizontal, 14) }

            List(filtered, selection: $sel) { o in
                HStack {
                    ObjectRow(obj: o)
                    if isPrimary(o) { Text("Основная группа").font(.caption).foregroundStyle(.secondary) }
                }
                .contextMenu { Button("Открыть") { model.open(o.dn) } }
            }
            .listStyle(.inset)
            .overlay { if loading { ProgressView() } else if items.isEmpty { Text(members ? "В группе нет участников" : "Не состоит в группах").foregroundStyle(.secondary) } }

            HStack {
                Text(members ? "Участников: \(items.count)" : "Групп: \(items.count)").foregroundStyle(.secondary)
                Spacer()
                Button(members ? "Удалить" : "Удалить из группы", action: remove)
                    .disabled(sel.isEmpty || items.contains { sel.contains($0.dn) && isPrimary($0) })
                Button(members ? "Добавить…" : "Добавить в группу…") { model.sheet = members ? .addMembers(obj) : .addToGroups([obj]) }
            }
            .padding(10)
        }
        .task(id: "\(obj.dn)|\(model.revision)") { await load() }
    }

    private func load() async {
        guard let dir = model.dir else { return }
        loading = true
        do {
            items = members ? try await dir.members(of: obj.dn) : try await dir.groups(of: obj)
            err = nil
        } catch { err = UIError("Не удалось загрузить список", error) }
        loading = false
    }

    private func remove() {
        let picked = items.filter { sel.contains($0.dn) }
        Task {
            for o in picked {
                let e = members ? await model.removeMember(o.dn, from: obj.dn) : await model.removeMember(obj.dn, from: o.dn)
                if let e { err = e; break }
            }
            sel = []
            model.showToast(picked.count == 1 ? "Удалено из «\(members ? obj.name : picked[0].name)»" : "Удалено: \(picked.count)")
            await load()
        }
    }
}

// MARK: - Attribute editor

struct AttributesView: View {
    let obj: ADObject
    @EnvironmentObject var model: AppModel
    @State private var filter = ""
    @State private var sel: String?

    static let readOnly: Set<String> = ["objectguid", "objectsid", "whencreated", "whenchanged", "usncreated", "usnchanged", "distinguishedname",
                                        "instancetype", "ntsecuritydescriptor", "dscorepropagationdata", "memberof", "objectcategory",
                                        "msds-user-account-control-computed", "msds-userpasswordexpirytimecomputed", "lastlogon",
                                        "lastlogontimestamp", "badpwdcount", "badpasswordtime", "logoncount", "pwdlastset", "unicodepwd",
                                        "primarygroupid", "samaccounttype", "name", "cn", "ou"]

    private var rows: [(String, String, Bool)] {
        obj.entry.attrs.keys.sorted().filter { filter.isEmpty || $0.localizedCaseInsensitiveContains(filter) }.map { k in
            let (v, bin) = Self.format(k, obj.entry.values(k))
            return (k, v, bin || Self.readOnly.contains(k) || k.contains(";range="))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "line.3.horizontal.decrease.circle").foregroundStyle(.secondary)
                TextField("Фильтр по имени атрибута", text: $filter).textFieldStyle(.plain)
            }
            .padding(7)
            .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 7))
            .padding(.horizontal, 14).padding(.bottom, 6)

            List(rows, id: \.0, selection: $sel) { k, v, ro in
                HStack(alignment: .firstTextBaseline) {
                    Text(displayName(k)).font(.callout.monospaced()).frame(width: 170, alignment: .leading).lineLimit(1).truncationMode(.middle)
                    Text(v).font(.callout).foregroundStyle(ro ? .secondary : .primary).lineLimit(3).textSelection(.enabled)
                    Spacer(minLength: 0)
                    if ro { Image(systemName: "lock").font(.caption).foregroundStyle(.tertiary).help("Только для чтения") }
                }
                .contextMenu {
                    Button("Скопировать значение") { copyToPasteboard(v) }
                    if !ro { Button("Изменить…") { edit(k) } }
                }
            }
            .listStyle(.inset)
            .contextMenu(forSelectionType: String.self) { _ in } primaryAction: { ids in if let k = ids.first, !isRO(k) { edit(k) } }

            HStack {
                Text("Атрибутов: \(obj.entry.attrs.count)").foregroundStyle(.secondary)
                Spacer()
                Button("Добавить…") { model.sheet = .editAttribute(obj, name: "", values: []) }
                Button("Изменить…") { if let sel { edit(sel) } }.disabled(sel == nil || sel.map(isRO) == true)
            }
            .padding(10)
        }
    }

    private func isRO(_ k: String) -> Bool { rows.first { $0.0 == k }?.2 ?? true }

    /// Keep the server's casing for the editor (keys are lower-cased in LDAPEntry).
    private func displayName(_ k: String) -> String { Self.canonical[k] ?? k }

    private func edit(_ k: String) {
        model.sheet = .editAttribute(obj, name: displayName(k), values: obj.entry.strings(k))
    }

    static let canonical: [String: String] = Dictionary(uniqueKeysWithValues: [
        "sAMAccountName", "userPrincipalName", "displayName", "givenName", "telephoneNumber", "userAccountControl", "objectClass",
        "objectGUID", "objectSid", "whenCreated", "whenChanged", "distinguishedName", "memberOf", "pwdLastSet", "lastLogonTimestamp",
        "accountExpires", "lockoutTime", "physicalDeliveryOfficeName", "streetAddress", "postalCode", "employeeID", "managedBy",
        "groupType", "dNSHostName", "operatingSystem", "operatingSystemVersion", "servicePrincipalName", "homeDirectory", "homeDrive",
        "scriptPath", "profilePath", "proxyAddresses", "extensionAttribute1", "thumbnailPhoto", "primaryGroupID", "badPwdCount",
        "logonCount", "badPasswordTime", "lastLogon", "instanceType", "objectCategory", "uSNCreated", "uSNChanged",
        "nTSecurityDescriptor", "dSCorePropagationData", "lastLogoff", "codePage", "countryCode", "sAMAccountType", "wWWHomePage", "ipPhone",
        "facsimileTelephoneNumber", "homePhone", "employeeNumber", "employeeType", "info",
    ].map { ($0.lowercased(), $0) })

    static let fileTimes: Set<String> = ["pwdlastset", "lastlogontimestamp", "lastlogon", "lockouttime", "accountexpires",
                                         "badpasswordtime", "msds-userpasswordexpirytimecomputed", "lastlogoff"]

    /// Human-readable rendering: GUID/SID, FILETIME and GeneralizedTime dates, decoded flags, hex for binary.
    static func format(_ k: String, _ vals: [Data]) -> (String, Bool) {
        switch k {
        case "objectguid": return (vals.first.flatMap(ADBinary.guid) ?? "", true)
        case "objectsid": return (vals.first.flatMap(ADBinary.sid) ?? "", true)
        case "useraccountcontrol", "msds-user-account-control-computed":
            return (vals.compactMap { Int(String(decoding: $0, as: UTF8.self)) }.map { UAC(rawValue: $0).description }.joined(separator: "; "), false)
        case "grouptype":
            let v = vals.first.flatMap { Int32(String(decoding: $0, as: UTF8.self)) } ?? 0
            return ("\(v) · \(GroupType.isSecurity(v) ? "безопасность" : "распространение"), \(GroupType.scope(v).map(ADObject.scopeName) ?? "—")", false)
        default: break
        }
        if fileTimes.contains(k), let raw = vals.first.flatMap({ Int64(String(decoding: $0, as: UTF8.self)) }) {
            return (ADTime.date(fileTime: raw).map { Fmt.date($0) + " (\(raw))" } ?? (raw == 0 ? "0 (не задано)" : "Никогда (\(raw))"), false)
        }
        if k == "whencreated" || k == "whenchanged" || k == "dscorepropagationdata" {
            return (vals.prefix(3).map { s in ADTime.date(generalized: String(decoding: s, as: UTF8.self)).map { Fmt.date($0) } ?? "" }.joined(separator: "; "), true)
        }
        let isBinary = vals.contains { d in
            guard let s = String(data: d, encoding: .utf8) else { return true }
            return s.unicodeScalars.contains { $0.value < 0x20 && $0 != "\n" && $0 != "\r" && $0 != "\t" }
        }
        if isBinary { return (vals.map { ADBinary.hex($0, limit: 24) }.joined(separator: "; "), true) }
        let strings = vals.map { String(decoding: $0, as: UTF8.self) }
        return (strings.prefix(20).joined(separator: "; ") + (strings.count > 20 ? " … (ещё \(strings.count - 20))" : ""), false)
    }
}

// MARK: - Multi-selection

struct MultiSummary: View {
    let objs: [ADObject]
    @EnvironmentObject var model: AppModel

    var body: some View {
        let accounts = objs.filter { $0.kind == .user || $0.kind == .computer }
        let active = accounts.filter { !$0.isDisabled }, disabled = accounts.filter(\.isDisabled), locked = accounts.filter(\.isLocked)
        VStack(spacing: 14) {
            HStack(spacing: -10) {
                ForEach(objs.prefix(5)) { Avatar(obj: $0, size: 44).overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 2)) }
            }
            Text("Выбрано: \(Fmt.objects(objs.count))").font(.title3.weight(.bold))
            Text(objs.prefix(6).map(\.name).joined(separator: ", ") + (objs.count > 6 ? "…" : "")).foregroundStyle(.secondary).multilineTextAlignment(.center)

            Form {
                Section("Действия с выбранными") {
                    if !locked.isEmpty { row("Разблокировать", "lock.open", "\(locked.count) заблок.") { model.unlock(locked) } }
                    if !active.isEmpty { row("Отключить", "nosign", "\(active.count) активн.") { model.confirm = .disable(active) } }
                    if !disabled.isEmpty { row("Включить", "checkmark.circle", "\(disabled.count) отключ.") { model.setEnabled(disabled, true) } }
                    if objs.allSatisfy({ [.user, .computer, .group, .contact].contains($0.kind) }) {
                        row("Добавить в группу…", "person.badge.plus", "") { model.sheet = .addToGroups(objs) }
                    }
                    if objs.allSatisfy({ $0.kind != .container && $0.kind != .domain }) {
                        row("Переместить…", "folder", "") { model.sheet = .move(objs) }
                    }
                }
                Section {
                    Button(role: .destructive) { model.confirm = .delete(objs) } label: {
                        Label("Удалить \(Fmt.objects(objs.count))…", systemImage: "trash").foregroundStyle(.red)
                    }
                    .buttonStyle(.plain)
                }
            }
            .formStyle(.grouped)
        }
        .padding(.top, 24)
    }

    private func row(_ title: String, _ icon: String, _ hint: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Label(title, systemImage: icon)
                Spacer()
                Text(hint).foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
