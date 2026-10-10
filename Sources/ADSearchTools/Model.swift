import ADKit
import SwiftUI

struct UIError: Identifiable {
    let id = UUID()
    let title: String
    let message: String
    let technical: String

    init(title: String, message: String, technical: String) {
        self.title = title
        self.message = message
        self.technical = technical
    }

    init(_ title: String, _ error: Error) {
        self.title = title
        if let e = error as? LDAPError {
            message = e.errorDescription ?? ""
            technical = e.technical
        } else {
            message = error.localizedDescription
            technical = ""
        }
    }
}

enum Place: Hashable {
    case quick(QuickFilter)
    case container(String)
}

enum SheetKind: Identifiable {
    case reset(ADObject)
    case newUser(String), newGroup(String), newComputer(String), newOU(String)
    case move([ADObject])
    case addToGroups([ADObject])
    case addMembers(ADObject)
    case editAttribute(ADObject, name: String, values: [String])

    var id: String {
        switch self {
        case .reset(let o): "reset\(o.dn)"
        case .newUser(let p): "nu\(p)"
        case .newGroup(let p): "ng\(p)"
        case .newComputer(let p): "nc\(p)"
        case .newOU(let p): "no\(p)"
        case .move(let o): "mv\(o.map(\.dn))"
        case .addToGroups(let o): "ag\(o.map(\.dn))"
        case .addMembers(let o): "am\(o.dn)"
        case .editAttribute(let o, let n, _): "ea\(o.dn)\(n)"
        }
    }
}

enum Confirm: Identifiable {
    case delete([ADObject]), disable([ADObject])
    var id: String {
        switch self { case .delete(let o): "del\(o.map(\.dn))"; case .disable(let o): "dis\(o.map(\.dn))" }
    }
}

@MainActor
final class AppModel: ObservableObject {
    // Connection
    @Published var dir: ADDirectory?
    @Published var info: DomainInfo?
    @Published var reconnecting = false
    /// Set by "Отключиться": the connect window then waits for the user instead of auto-connecting.
    var suppressAutoConnect = false

    // Navigation and list
    @Published var place: Place? {
        didSet { if place != oldValue, place != nil { query = ""; selection = []; openOverride = nil; detail = nil; reload() } }
    }
    @Published var kind: KindFilter = .all { didSet { if kind != oldValue, !query.isEmpty { reload() } } }
    @Published var query = "" { didSet { if query != oldValue { scheduleSearch() } } }
    @Published private(set) var items: [ADObject] = []
    @Published private(set) var loading = false
    @Published var selection = Set<String>() { didSet { if selection != oldValue { openOverride = nil; loadDetail() } } }
    @Published var useTable = false
    @Published var showDetail = true
    @Published private(set) var counts: [QuickFilter: Int] = [:]
    @Published private(set) var tree: [String: [ADObject]] = [:]

    // Detail
    @Published private(set) var detail: ADObject?
    @Published private(set) var openOverride: String?

    // Feedback
    @Published var toast: String?
    @Published var error: UIError?
    @Published var sheet: SheetKind?
    @Published var confirm: Confirm?
    /// Bumped after every successful change so dependent views (group lists) reload.
    @Published private(set) var revision = 0

    private var searchTask: Task<Void, Never>?
    private var loadTask: Task<Void, Never>?
    private var toastTask: Task<Void, Never>?

    var isSearching: Bool { !query.trimmingCharacters(in: .whitespaces).isEmpty }

    /// Container listings are filtered client-side; search applies the kind on the server.
    var visibleItems: [ADObject] {
        if isSearching && query.trimmingCharacters(in: .whitespaces).count < 2 { return [] }
        guard !isSearching, case .container = place else { return items }
        switch kind {
        case .all: return items
        case .people: return items.filter { $0.kind == .user || $0.kind == .contact }
        case .groups: return items.filter { $0.kind == .group }
        case .computers: return items.filter { $0.kind == .computer }
        }
    }

    var selectedObjects: [ADObject] { items.filter { selection.contains($0.dn) } }

    /// Where "+" creates objects: the open container, else the default Users/Computers containers.
    func creationParent(computer: Bool = false) -> String {
        if case .container(let dn) = place { return dn }
        return "CN=\(computer ? "Computers" : "Users"),\(info?.baseDN ?? "")"
    }

    // MARK: - Connect

    func didConnect(_ d: ADDirectory, _ i: DomainInfo) {
        dir = d
        info = i
        Task { await d.setReconnectHandler { [weak self] on in Task { @MainActor in self?.reconnecting = on } } }
        loadTree(i.baseDN)
        place = .container("CN=Users,\(i.baseDN)")
        refreshCounts()
    }

    func disconnect() {
        suppressAutoConnect = true
        dir = nil
        info = nil
        items = []
        tree = [:]
        counts = [:]
        detail = nil
        place = nil
        selection = []
    }

    // MARK: - Loading

    func reload() {
        guard let dir else { return }
        loadTask?.cancel()
        let place = place, q = query.trimmingCharacters(in: .whitespaces), kind = kind
        loading = true
        loadTask = Task {
            do {
                let result: [ADObject]
                if !q.isEmpty {
                    result = try await dir.search(q, kind: kind)
                } else {
                    switch place {
                    case .quick(let f): result = try await dir.quick(f)
                    case .container(let dn): result = try await dir.children(of: dn)
                    case nil: result = []
                    }
                }
                guard !Task.isCancelled else { return }
                items = result.sorted { a, b in
                    if a.isContainer != b.isContainer { return a.isContainer }
                    return a.name.localizedStandardCompare(b.name) == .orderedAscending
                }
                selection = selection.filter { dn in items.contains { $0.dn == dn } }
                loadDetail()
            } catch {
                guard !Task.isCancelled else { return }
                items = []
                self.error = UIError("Не удалось загрузить список", error)
            }
            loading = false
        }
    }

    private func scheduleSearch() {
        searchTask?.cancel()
        searchTask = Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !Task.isCancelled else { return }
            let q = query.trimmingCharacters(in: .whitespaces)
            if q.isEmpty || q.count >= 2 { selection = []; reload() }
        }
    }

    private var treeLoading = Set<String>()

    func loadTree(_ dn: String) {
        guard let dir, tree[dn] == nil, !treeLoading.contains(dn) else { return }
        treeLoading.insert(dn)
        Task {
            let kids = (try? await dir.children(of: dn, containersOnly: true)) ?? []
            treeLoading.remove(dn)
            tree[dn] = kids.sorted { $0.rdnName.localizedStandardCompare($1.rdnName) == .orderedAscending }
        }
    }

    func resetTree() {
        tree = [:]
        loadTree(info?.baseDN ?? "")
    }

    func refreshCounts() {
        guard let dir else { return }
        Task {
            for f in QuickFilter.allCases {
                counts[f] = (try? await dir.quick(f).count) ?? counts[f]
            }
        }
    }

    func loadDetail() {
        guard let dir else { return }
        let dn = openOverride ?? (selection.count == 1 ? selection.first : nil)
        guard let dn else { detail = nil; return }
        Task {
            let o = try? await dir.object(dn)
            if (openOverride ?? (selection.count == 1 ? selection.first : nil)) == dn { detail = o }
        }
    }

    /// Show any object in the detail panel (e.g. a manager link) without changing the list.
    func open(_ dn: String) {
        openOverride = dn
        showDetail = true
        loadDetail()
    }

    func navigate(into obj: ADObject) {
        guard obj.isContainer else { return }
        place = .container(obj.dn)
    }

    // MARK: - Operations

    /// Runs a directory change, then refreshes what may have changed. Errors become an alert.
    func perform(_ title: String, success: String? = nil, refreshTree: Bool = false, _ op: @escaping (ADDirectory) async throws -> Void) {
        guard let dir else { return }
        Task {
            do {
                try await op(dir)
                revision += 1
                if let success { showToast(success) }
            } catch {
                self.error = UIError(title, error)
            }
            if refreshTree { resetTree() }
            reload()
            refreshCounts()
        }
    }

    /// Same as perform, but lets a sheet show the error inline and stay open.
    func attempt(_ op: (ADDirectory) async throws -> Void) async -> UIError? {
        guard let dir else { return nil }
        do {
            try await op(dir)
            revision += 1
            reload()
            refreshCounts()
            return nil
        } catch {
            return UIError("Не удалось", error)
        }
    }

    func showToast(_ s: String) {
        toast = s
        toastTask?.cancel()
        toastTask = Task {
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            if !Task.isCancelled { toast = nil }
        }
    }

    func unlock(_ objs: [ADObject]) {
        perform("Не удалось разблокировать", success: objs.count == 1 ? "Учётная запись разблокирована" : "Разблокировано: \(objs.count)") { d in
            for o in objs { try await d.unlock(o.dn) }
        }
    }

    func setEnabled(_ objs: [ADObject], _ on: Bool) {
        perform(on ? "Не удалось включить" : "Не удалось отключить",
                success: objs.count == 1 ? (on ? "Учётная запись включена" : "Учётная запись отключена") : (on ? "Включено: \(objs.count)" : "Отключено: \(objs.count)")) { d in
            for o in objs { try await d.setEnabled(o.dn, on) }
        }
    }

    func delete(_ objs: [ADObject]) {
        perform("Не удалось удалить", success: objs.count == 1 ? "«\(objs[0].name)» удалён" : "Удалено: \(objs.count)",
                refreshTree: objs.contains(where: \.isContainer)) { [weak self] d in
            for o in objs { try await d.delete(o.dn) }
            await MainActor.run { self?.selection = [] }
        }
    }

    func removeMember(_ member: String, from group: String) async -> UIError? {
        await attempt { try await $0.removeMember(member, from: group) }
    }
}
