import ADKit
import SwiftUI

struct SheetHost: View {
    let kind: SheetKind

    var body: some View {
        switch kind {
        case .reset(let o): ResetPasswordSheet(obj: o)
        case .newUser(let p): NewUserSheet(parent: p)
        case .newGroup(let p): NewGroupSheet(parent: p)
        case .newComputer(let p): NewComputerSheet(parent: p)
        case .newOU(let p): NewOUSheet(parent: p)
        case .move(let objs): MoveSheet(objs: objs)
        case .addToGroups(let objs): PickerSheet(mode: .groups(objs))
        case .addMembers(let g): PickerSheet(mode: .members(g))
        case .editAttribute(let o, let n, let v): EditAttributeSheet(obj: o, name: n, text: v.joined(separator: "\n"))
        }
    }
}

/// Shared chrome: title, inline error, Cancel + primary button. The primary action returns an error to keep the sheet open.
struct SheetFrame<Content: View>: View {
    let title: String
    var subtitle = ""
    let primary: String
    var enabled = true
    var destructive = false
    var width: CGFloat = 440
    @Binding var error: UIError?
    let action: () async -> UIError?
    @ViewBuilder let content: () -> Content
    @Environment(\.dismiss) private var dismiss
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title3.weight(.bold))
                if !subtitle.isEmpty { Text(subtitle).foregroundStyle(.secondary) }
            }
            content()
            if let error { ErrorBox(title: error.title, message: error.message, technical: error.technical, symbol: "xmark.octagon.fill", color: .red) }
            HStack {
                if busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Отменить", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(primary) {
                    busy = true
                    Task {
                        error = await action()
                        busy = false
                        if error == nil { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .tint(destructive ? .red : .accentColor)
                .disabled(!enabled || busy)
            }
        }
        .padding(20)
        .frame(width: width)
    }
}

@MainActor private func location(_ dn: String, _ model: AppModel) -> String {
    ([model.info?.dnsName ?? ""] + DN.path(dn)).joined(separator: " › ")
}

struct PasswordFields: View {
    @Binding var password: String
    @Binding var repeated: String
    let policy: String

    var body: some View {
        SecureField("Пароль", text: $password)
        SecureField("Повтор", text: $repeated)
        if !repeated.isEmpty {
            Label(password == repeated ? "Пароли совпадают" : "Пароли не совпадают",
                  systemImage: password == repeated ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(password == repeated ? .green : .red)
                .font(.callout)
        }
        Text("Требования домена: \(policy).").font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

/// AD's policy violation (19 / 0000052D) gets the domain's actual requirements instead of a bare code.
@MainActor private func policyAware(_ e: UIError?, _ model: AppModel) -> UIError? {
    guard let e, e.technical.contains("0000052D") || e.technical.hasPrefix("LDAP 19") else { return e }
    return UIError(title: "Пароль не соответствует политике домена", message: "Требования: \(model.info?.policyText ?? "").", technical: e.technical)
}

// MARK: - Reset password

struct ResetPasswordSheet: View {
    let obj: ADObject
    @EnvironmentObject var model: AppModel
    @State private var pw = ""
    @State private var pw2 = ""
    @State private var mustChange = true
    @State private var unlock = true
    @State private var error: UIError?

    var body: some View {
        SheetFrame(title: "Сбросить пароль", subtitle: "", primary: "Сбросить пароль", enabled: !pw.isEmpty && pw == pw2, error: $error, action: run) {
            HStack(spacing: 10) {
                Avatar(obj: obj, size: 36)
                VStack(alignment: .leading) {
                    Text(obj.name).fontWeight(.semibold)
                    Text([obj.sam, DN.path(DN.parent(obj.dn)).last].compactMap { $0 }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
                }
            }
            Form {
                PasswordFields(password: $pw, repeated: $pw2, policy: model.info?.policyText ?? "")
                Toggle("Потребовать смену пароля при следующем входе", isOn: $mustChange)
                if obj.isLocked {
                    Toggle("Разблокировать учётную запись · заблокирована \(Fmt.date(obj.lockoutTime).lowercased())", isOn: $unlock)
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: obj.isLocked ? 300 : 250)
        }
    }

    private func run() async -> UIError? {
        let dn = obj.dn, p = pw, m = mustChange, u = unlock && obj.isLocked
        let e = policyAware(await model.attempt { try await $0.resetPassword(dn, to: p, mustChange: m, unlock: u) }, model)
        if e == nil { model.showToast("Пароль сброшен" + (u ? ", учётная запись разблокирована" : "")) }
        return e
    }
}

// MARK: - Create

struct NewUserSheet: View {
    let parent: String
    @EnvironmentObject var model: AppModel
    @State private var given = ""
    @State private var surname = ""
    @State private var display = ""
    @State private var displayEdited = false
    @State private var sam = ""
    @State private var pw = ""
    @State private var pw2 = ""
    @State private var mustChange = true
    @State private var disabled = false
    @State private var error: UIError?

    private var autoDisplay: String { [surname, given].filter { !$0.isEmpty }.joined(separator: " ") }
    private var displayName: String { displayEdited ? display : autoDisplay }
    private var samValid: Bool {
        !sam.isEmpty && sam.count <= 20 && !sam.hasSuffix(".") && !sam.contains { "\"/\\[]:;|=,+*?<>@ ".contains($0) }
    }

    var body: some View {
        SheetFrame(title: "Новый пользователь", subtitle: "Создаётся в \(location(parent, model))", primary: "Создать",
                   enabled: !displayName.isEmpty && samValid && !pw.isEmpty && pw == pw2, width: 480, error: $error, action: run) {
            Form {
                Section("Имя") {
                    TextField("Имя", text: $given)
                    TextField("Фамилия", text: $surname)
                    TextField("Отображаемое имя", text: Binding(get: { displayName }, set: { display = $0; displayEdited = true }), prompt: Text("Фамилия Имя"))
                }
                Section("Вход") {
                    TextField("Логин", text: $sam, prompt: Text("p.ivanov"))
                    LabeledContent("UPN") { Text(sam.isEmpty ? "—" : "\(sam)@\(model.info?.dnsName ?? "")").font(.body.monospaced()) }
                    if !sam.isEmpty && !samValid {
                        Text(verbatim: "До 20 символов, без пробелов и символов \" / \\ [ ] : ; | = , + * ? < > @").font(.caption).foregroundStyle(.red)
                    }
                }
                Section("Пароль") {
                    PasswordFields(password: $pw, repeated: $pw2, policy: model.info?.policyText ?? "")
                    Toggle("Сменить пароль при следующем входе", isOn: $mustChange)
                    Toggle("Отключить учётную запись после создания", isOn: $disabled)
                }
            }
            .formStyle(.grouped)
            .frame(height: 580)
        }
    }

    private func run() async -> UIError? {
        let p = parent, g = given, s = surname, d = displayName, l = sam, w = pw, m = mustChange, x = disabled
        let e = policyAware(await model.attempt {
            try await $0.createUser(in: p, given: g, surname: s, display: d, sam: l, password: w, mustChange: m, disabled: x)
        }, model)
        if e == nil { model.showToast("Пользователь «\(d)» создан") }
        return e
    }
}

struct NewGroupSheet: View {
    let parent: String
    @EnvironmentObject var model: AppModel
    @State private var name = ""
    @State private var desc = ""
    @State private var security = true
    @State private var scope = GroupType.Scope.global
    @State private var error: UIError?

    var body: some View {
        SheetFrame(title: "Новая группа", subtitle: "Создаётся в \(location(parent, model))", primary: "Создать",
                   enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty, error: $error, action: run) {
            Form {
                TextField("Имя", text: $name, prompt: Text("VPN-Users"))
                TextField("Описание", text: $desc)
                Picker("Тип", selection: $security) {
                    Text("Безопасность").tag(true)
                    Text("Распространение").tag(false)
                }
                .pickerStyle(.segmented)
                Text(security ? "Группы безопасности можно использовать для прав доступа." : "Группы распространения — только для почтовых рассылок.")
                    .font(.caption).foregroundStyle(.secondary)
                Picker("Область", selection: $scope) {
                    Text("Локальная в домене").tag(GroupType.Scope.domainLocal)
                    Text("Глобальная").tag(GroupType.Scope.global)
                    Text("Универсальная").tag(GroupType.Scope.universal)
                }
                .pickerStyle(.segmented)
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: 250)
        }
    }

    private func run() async -> UIError? {
        let p = parent, n = name.trimmingCharacters(in: .whitespaces), d = desc, s = scope, sec = security
        let e = await model.attempt { try await $0.createGroup(in: p, name: n, description: d, scope: s, security: sec) }
        if e == nil { model.showToast("Группа «\(n)» создана") }
        return e
    }
}

struct NewComputerSheet: View {
    let parent: String
    @EnvironmentObject var model: AppModel
    @State private var name = ""
    @State private var desc = ""
    @State private var error: UIError?

    var body: some View {
        SheetFrame(title: "Новый компьютер", subtitle: "Создаётся в \(location(parent, model))", primary: "Создать",
                   enabled: ADNames.isValidComputerName(name), error: $error, action: run) {
            Form {
                TextField("Имя компьютера", text: $name, prompt: Text("IT-LT-044"))
                LabeledContent("Имя до Windows 2000") { Text(name.isEmpty ? "—" : name.uppercased() + "$").font(.body.monospaced()) }
                TextField("Описание", text: $desc)
                Text("Не длиннее 15 символов: латиница, цифры и дефис.").font(.caption)
                    .foregroundStyle(name.isEmpty || ADNames.isValidComputerName(name) ? Color.secondary : Color.red)
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: 190)
        }
    }

    private func run() async -> UIError? {
        let p = parent, n = name, d = desc
        let e = await model.attempt { try await $0.createComputer(in: p, name: n, description: d) }
        if e == nil { model.showToast("Компьютер \(n.uppercased()) создан") }
        return e
    }
}

struct NewOUSheet: View {
    let parent: String
    @EnvironmentObject var model: AppModel
    @State private var name = ""
    @State private var desc = ""
    @State private var error: UIError?

    var body: some View {
        SheetFrame(title: "Новое подразделение", subtitle: "Создаётся в \(location(parent, model))", primary: "Создать",
                   enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty, error: $error, action: run) {
            Form {
                TextField("Имя", text: $name, prompt: Text("Archive"))
                TextField("Описание", text: $desc)
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: 120)
        }
    }

    private func run() async -> UIError? {
        let p = parent, n = name.trimmingCharacters(in: .whitespaces), d = desc
        let e = await model.attempt { try await $0.createOU(in: p, name: n, description: d) }
        if e == nil { model.showToast("Подразделение «\(n)» создано"); model.resetTree() }
        return e
    }
}

// MARK: - Move

struct MoveSheet: View {
    let objs: [ADObject]
    @EnvironmentObject var model: AppModel
    @State private var target: String?
    @State private var error: UIError?

    private var invalid: Bool {
        guard let target else { return true }
        // Can't move into the current parent or into itself / its own subtree.
        return objs.allSatisfy { DN.parent($0.dn) == target } || objs.contains { target == $0.dn || target.hasSuffix("," + $0.dn) }
    }

    var body: some View {
        SheetFrame(title: objs.count == 1 ? "Переместить «\(objs[0].name)»" : "Переместить \(Fmt.objects(objs.count))",
                   subtitle: objs.count == 1 ? "Сейчас: \(location(DN.parent(objs[0].dn), model))" : objs.prefix(5).map(\.name).joined(separator: ", "),
                   primary: "Переместить", enabled: !invalid, width: 460, error: $error, action: run) {
            ContainerPicker(selection: $target)
                .frame(height: 300)
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
            Text("В: " + (target.map { location($0, model) } ?? "выберите подразделение"))
                .foregroundStyle(target == nil ? .secondary : .primary)
            Text("К объектам применятся групповые политики нового подразделения.").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func run() async -> UIError? {
        guard let target else { return nil }
        let dns = objs.map(\.dn)
        let e = await model.attempt { d in for dn in dns { try await d.move(dn, to: target) } }
        if e == nil {
            model.showToast(objs.count == 1 ? "Перемещено в «\(DN.path(target).last ?? "")»" : "Перемещено: \(objs.count)")
            if objs.contains(where: \.isContainer) { model.resetTree() }
        }
        return e
    }
}

struct ContainerPicker: View {
    @Binding var selection: String?
    @EnvironmentObject var model: AppModel

    var body: some View {
        List(selection: $selection) {
            if let info = model.info {
                Label(info.dnsName, systemImage: "building.2").tag(info.baseDN)
                OutlineGroup(items(info.baseDN), children: \.kids) { item in
                    Label(item.obj.rdnName, systemImage: item.obj.kind == .ou ? "folder.fill" : "folder")
                        .tag(item.obj.dn)
                        .onAppear { model.loadTree(item.obj.dn) }
                }
            }
        }
        .listStyle(.inset)
    }

    private func items(_ dn: String) -> [TreeItem] {
        (model.tree[dn] ?? []).map { o in
            TreeItem(obj: o, kids: model.tree[o.dn].map { $0.isEmpty ? nil : items(o.dn) } ?? [])
        }
    }
}

// MARK: - Group / member picker

struct PickerSheet: View {
    enum Mode { case groups([ADObject]), members(ADObject) }
    let mode: Mode
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    @State private var results: [ADObject] = []
    @State private var existing = Set<String>()
    @State private var picked = Set<String>()
    @State private var searching = false
    @State private var error: UIError?

    private var title: String {
        switch mode {
        case .groups(let o): o.count == 1 ? "Добавить «\(o[0].name)» в группы" : "Добавить \(Fmt.objects(o.count)) в группы"
        case .members(let g): "Добавить участников в «\(g.name)»"
        }
    }

    var body: some View {
        SheetFrame(title: title, subtitle: "Поиск по имени, логину или email во всём домене", primary: "Добавить",
                   enabled: !picked.isEmpty, width: 500, error: $error, action: run) {
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField(isGroups ? "Поиск групп" : "Поиск пользователей, групп и компьютеров", text: $query).textFieldStyle(.plain)
                if searching { ProgressView().controlSize(.small) }
            }
            .padding(7)
            .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 7))

            List(results) { o in
                let already = existing.contains(o.dn)
                Toggle(isOn: Binding(get: { picked.contains(o.dn) || already }, set: { if $0 { picked.insert(o.dn) } else { picked.remove(o.dn) } })) {
                    HStack {
                        ObjectRow(obj: o)
                        if already { Text(isGroups ? "уже состоит" : "уже участник").font(.caption).foregroundStyle(.secondary) }
                    }
                }
                .toggleStyle(.checkbox)
                .disabled(already)
            }
            .listStyle(.inset)
            .frame(height: 300)
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
            .overlay {
                if results.isEmpty && !searching {
                    Text(query.count < 2 ? "Введите хотя бы 2 символа" : "Ничего не найдено").foregroundStyle(.secondary)
                }
            }
            Text("Выбрано: \(picked.count)").foregroundStyle(.secondary)
        }
        .task(id: query) { await search() }
        .task { await loadExisting() }
    }

    private var isGroups: Bool { if case .groups = mode { return true }; return false }

    private func search() async {
        try? await Task.sleep(nanoseconds: 250_000_000)
        guard !Task.isCancelled, let dir = model.dir else { return }
        guard query.trimmingCharacters(in: .whitespaces).count >= 2 else { results = []; return }
        searching = true
        defer { searching = false }
        do {
            let found = try await dir.search(query, kind: isGroups ? .groups : .all, limit: 100)
            guard !Task.isCancelled else { return }
            results = found.filter { [.user, .group, .computer, .contact].contains($0.kind) }
        } catch { self.error = UIError("Поиск не удался", error) }
    }

    private func loadExisting() async {
        guard let dir = model.dir else { return }
        switch mode {
        case .groups(let o) where o.count == 1:
            existing = Set(((try? await dir.groups(of: dir.object(o[0].dn))) ?? []).map(\.dn))
        case .members(let g):
            existing = Set(((try? await dir.members(of: g.dn)) ?? []).map(\.dn))
        default: break
        }
    }

    private func run() async -> UIError? {
        let p = picked
        var pairs: [(member: String, group: String)] = []
        switch mode {
        case .groups(let objs): for o in objs { for g in p { pairs.append((o.dn, g)) } }
        case .members(let g): for m in p { pairs.append((m, g.dn)) }
        }
        let e = await model.attempt { d in
            for (m, g) in pairs {
                do { try await d.addMember(m, to: g) } catch let e as LDAPError where e.code == 20 || e.code == 68 {} // already a member
            }
        }
        if e == nil { model.showToast("Добавлено: \(pairs.count)") }
        return e
    }
}

// MARK: - Attribute editor

struct EditAttributeSheet: View {
    let obj: ADObject
    @State var name: String
    @State var text: String
    @EnvironmentObject var model: AppModel
    @State private var error: UIError?
    private let isNew: Bool

    init(obj: ADObject, name: String, text: String) {
        self.obj = obj
        _name = State(initialValue: name)
        _text = State(initialValue: text)
        isNew = name.isEmpty
    }

    var body: some View {
        SheetFrame(title: isNew ? "Добавить атрибут" : "Изменить атрибут", subtitle: obj.name, primary: "Сохранить",
                   enabled: !name.trimmingCharacters(in: .whitespaces).isEmpty, width: 480, error: $error, action: run) {
            TextField("Имя атрибута (LDAP)", text: $name, prompt: Text("extensionAttribute1"))
                .font(.body.monospaced())
                .disabled(!isNew)
            TextEditor(text: $text)
                .font(.body.monospaced())
                .frame(height: 140)
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
            Text("Каждое значение — с новой строки. Пустое поле очищает атрибут.").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func run() async -> UIError? {
        let dn = obj.dn, n = name.trimmingCharacters(in: .whitespaces)
        let vals = text.split(separator: "\n", omittingEmptySubsequences: true).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let e = await model.attempt { try await $0.setAttribute(dn, n, vals) }
        if e == nil { model.showToast("Атрибут \(n) сохранён") }
        return e
    }
}
