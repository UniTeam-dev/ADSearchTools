import Foundation

public struct ADConfig: Codable, Hashable {
    public var host: String
    public var port: Int
    public var user: String
    public init(host: String, port: Int = 636, user: String) { self.host = host; self.port = port; self.user = user }
    public var url: String { "ldaps://\(host):\(port)" }
}

public struct DomainInfo {
    public let baseDN: String
    public let dnsName: String
    public let netbios: String
    public let dcHost: String
    public let domainSID: Data?
    public let maxPwdAge: TimeInterval?   // nil = passwords never expire
    public let minPwdLength: Int
    public let complexity: Bool

    public var policyText: String {
        var parts = ["минимум \(minPwdLength) символов"]
        if complexity { parts.append("три из четырёх групп: заглавные, строчные, цифры, символы; без частей логина и имени") }
        return parts.joined(separator: "; ")
    }
}

public enum ADKind: String, Hashable { case user, group, computer, ou, container, domain, contact, other }

public enum ADStatus: Hashable { case locked, disabled, passwordExpired, expiring(Date) }

public enum QuickFilter: String, CaseIterable, Hashable { case locked, disabled, expiring }

public enum KindFilter: String, CaseIterable, Hashable { case all, people, groups, computers }

public struct ADObject: Identifiable, Hashable {
    public let entry: LDAPEntry
    public init(_ entry: LDAPEntry) { self.entry = entry }

    public var id: String { entry.dn }
    public var dn: String { entry.dn }

    public var kind: ADKind {
        let oc = Set(entry.strings("objectClass").map { $0.lowercased() })
        if oc.contains("computer") { return .computer }
        if oc.contains("user") { return .user }
        if oc.contains("group") { return .group }
        if oc.contains("organizationalunit") { return .ou }
        if oc.contains("domaindns") { return .domain }
        if oc.contains("contact") { return .contact }
        if oc.contains("container") || oc.contains("builtindomain") { return .container }
        return .other
    }

    public var isContainer: Bool { [.ou, .container, .domain].contains(kind) }
    public var name: String { entry.string("displayName").flatMap { $0.isEmpty ? nil : $0 } ?? DN.name(dn) }
    public var rdnName: String { DN.name(dn) }
    public var sam: String? { entry.string("sAMAccountName") }
    public var upn: String? { entry.string("userPrincipalName") }
    public var title: String? { entry.string("title") }
    public var department: String? { entry.string("department") }
    public var mail: String? { entry.string("mail") }
    public var descriptionText: String? { entry.string("description") }
    public var photo: Data? { entry.data("thumbnailPhoto") }
    public var uac: UAC { UAC(rawValue: Int(entry.int("userAccountControl") ?? 0)) }
    public var computedUAC: UAC? { entry.int("msDS-User-Account-Control-Computed").map { UAC(rawValue: Int($0)) } }
    public var groupType: Int32? { entry.int("groupType").map { Int32(truncatingIfNeeded: $0) } }
    public var whenChanged: Date? { entry.string("whenChanged").flatMap(ADTime.date(generalized:)) }
    /// `lastLogonTimestamp` is replicated but lags up to ~14 days — show as approximate.
    public var lastActivity: Date? { entry.int("lastLogonTimestamp").flatMap(ADTime.date(fileTime:)) }
    public var lockoutTime: Date? { entry.int("lockoutTime").flatMap(ADTime.date(fileTime:)) }
    public var pwdLastSet: Int64? { entry.int("pwdLastSet") }
    public var passwordExpiry: Date? { entry.int("msDS-UserPasswordExpiryTimeComputed").flatMap(ADTime.date(fileTime:)) }
    public var accountExpires: Date? { entry.int("accountExpires").flatMap(ADTime.date(fileTime:)) }
    public var manager: String? { entry.string("manager") }

    public var isDisabled: Bool { uac.contains(.accountDisable) }
    public var isLocked: Bool {
        if let c = computedUAC { return c.contains(.lockout) }
        return lockoutTime != nil
    }
    public var mustChangePassword: Bool { pwdLastSet == 0 }
    public var passwordNeverExpires: Bool { uac.contains(.dontExpirePassword) }
    public var isPasswordExpired: Bool {
        if computedUAC?.contains(.passwordExpired) == true && !mustChangePassword { return true }
        if let e = passwordExpiry, !passwordNeverExpires, pwdLastSet != 0 { return e < Date() }
        return false
    }

    /// Most important status first; nil = nothing to flag.
    public var status: ADStatus? {
        guard kind == .user || kind == .computer else { return nil }
        if isDisabled { return .disabled }
        guard kind == .user else { return nil }
        if isLocked { return .locked }
        if isPasswordExpired { return .passwordExpired }
        if let e = passwordExpiry, !passwordNeverExpires, e > Date(), e < Date().addingTimeInterval(14 * 86400) { return .expiring(e) }
        return nil
    }

    public var subtitle: String {
        switch kind {
        case .user, .contact: return [sam, title].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
        case .group:
            guard let t = groupType else { return "Группа" }
            return [GroupType.isSecurity(t) ? "Группа безопасности" : "Группа распространения", GroupType.scope(t).map(Self.scopeName)].compactMap { $0 }.joined(separator: " · ")
        case .computer:
            return [entry.string("operatingSystem"), lastActivity.map { "активность ≈ " + $0.formatted(.dateTime.day().month()) }].compactMap { $0 }.joined(separator: " · ")
        case .ou: return descriptionText ?? "Подразделение"
        case .container, .domain: return descriptionText ?? "Контейнер"
        case .other: return entry.strings("objectClass").last ?? ""
        }
    }

    public var typeName: String {
        switch kind {
        case .user: return "Пользователь"
        case .group: return (groupType.map(GroupType.isSecurity) ?? true) ? "Группа безопасности" : "Группа распространения"
        case .computer: return "Компьютер"
        case .ou: return "Подразделение"
        case .container: return "Контейнер"
        case .domain: return "Домен"
        case .contact: return "Контакт"
        case .other: return entry.strings("objectClass").last ?? "Объект"
        }
    }

    public static func scopeName(_ s: GroupType.Scope) -> String {
        switch s { case .global: "Глобальная"; case .domainLocal: "Локальная в домене"; case .universal: "Универсальная" }
    }
}

/// One live LDAPS session to a DC. Serialises all LDAP calls; reconnects once if AD dropped the idle connection.
public actor ADDirectory {
    public let config: ADConfig
    public private(set) var info: DomainInfo!
    private let password: String
    private let verifyCertificate: Bool
    private var conn: LDAPConnection?
    private var onReconnect: (@Sendable (Bool) -> Void)?

    static let listAttrs = ["objectClass", "cn", "name", "displayName", "sAMAccountName", "userPrincipalName", "title", "department",
                            "mail", "description", "userAccountControl", "msDS-User-Account-Control-Computed",
                            "msDS-UserPasswordExpiryTimeComputed", "lockoutTime", "pwdLastSet", "lastLogonTimestamp",
                            "operatingSystem", "groupType", "whenChanged", "thumbnailPhoto"]
    static let detailAttrs = ["*", "msDS-User-Account-Control-Computed", "msDS-UserPasswordExpiryTimeComputed"]
    static let hidden = "(!(showInAdvancedViewOnly=TRUE))"

    public init(config: ADConfig, password: String, verifyCertificate: Bool = ProcessInfo.processInfo.environment["AD_INSECURE_TLS"] != "1") {
        self.config = config
        self.password = password
        self.verifyCertificate = verifyCertificate
    }

    public func setReconnectHandler(_ h: @escaping @Sendable (Bool) -> Void) { onReconnect = h }

    /// Binds and reads domain basics. Throws LDAPError with the bind result on bad credentials.
    public func connect() throws -> DomainInfo {
        try open()
        return info
    }

    private func open() throws {
        let c = try LDAPConnection(url: config.url, verifyCertificate: verifyCertificate)
        try c.bind(user: config.user, password: password)
        conn = c
        if info == nil { info = try loadInfo(c) }
    }

    private func loadInfo(_ c: LDAPConnection) throws -> DomainInfo {
        guard let root = try c.search(base: "", scope: .base, filter: "(objectClass=*)",
                                      attrs: ["defaultNamingContext", "configurationNamingContext", "dnsHostName"]).first,
              let base = root.string("defaultNamingContext") else {
            throw LDAPError(code: 32, name: "No such object", diagnostic: "rootDSE без defaultNamingContext")
        }
        let domain = try c.search(base: base, scope: .base, filter: "(objectClass=*)",
                                  attrs: ["objectSid", "maxPwdAge", "minPwdLength", "pwdProperties"]).first
        var netbios = DN.dnsName(ofDomain: base).split(separator: ".").first.map { String($0).uppercased() } ?? ""
        if let cfg = root.string("configurationNamingContext"),
           let x = try? c.search(base: "CN=Partitions,\(cfg)", scope: .oneLevel,
                                 filter: "(&(objectClass=crossRef)(nCName=\(LDAPFilter.escape(base))))", attrs: ["nETBIOSName"]).first,
           let n = x.string("nETBIOSName") {
            netbios = n
        }
        let maxAge = domain?.int("maxPwdAge").map(ADTime.interval)
        return DomainInfo(baseDN: base, dnsName: DN.dnsName(ofDomain: base), netbios: netbios,
                          dcHost: root.string("dnsHostName") ?? config.host, domainSID: domain?.data("objectSid"),
                          maxPwdAge: (maxAge ?? 0) > 0 ? maxAge : nil,
                          minPwdLength: Int(domain?.int("minPwdLength") ?? 0),
                          complexity: (domain?.int("pwdProperties") ?? 0) & 1 != 0)
    }

    private func run<T>(_ body: (LDAPConnection) throws -> T) throws -> T {
        if conn == nil { try open() }
        do { return try body(conn!) } catch let e as LDAPError where e.isServerDown {
            // AD closes idle connections after MaxConnIdleTime (15 min by default).
            onReconnect?(true)
            defer { onReconnect?(false) }
            conn = nil
            try open()
            return try body(conn!)
        }
    }

    private func objects(_ base: String, _ scope: LDAPScope, _ filter: String, limit: Int = 0) throws -> [ADObject] {
        try run { try $0.search(base: base, scope: scope, filter: filter, attrs: Self.listAttrs, limit: limit) }.map(ADObject.init)
    }

    // MARK: - Reading

    public func children(of dn: String, containersOnly: Bool = false) throws -> [ADObject] {
        let f = containersOnly
            ? "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))\(Self.hidden))"
            : Self.hidden
        return try objects(dn, .oneLevel, f)
    }

    public func count(in dn: String) throws -> Int {
        try run { try $0.search(base: dn, scope: .oneLevel, filter: Self.hidden, attrs: ["1.1"]) }.count
    }

    public static func kindFilter(_ k: KindFilter) -> String {
        switch k {
        case .all: "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=contact))"
        case .people: "(&(objectCategory=person)(|(objectClass=user)(objectClass=contact)))"
        case .groups: "(objectClass=group)"
        case .computers: "(objectClass=computer)"
        }
    }

    /// Domain-wide Ambiguous Name Resolution — the same matching ADUC's "Find" uses (name, login, mail, …).
    public func search(_ text: String, kind: KindFilter = .all, limit: Int = 500) throws -> [ADObject] {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return [] }
        let f = "(&\(Self.kindFilter(kind))(anr=\(LDAPFilter.escape(t))))"
        return try objects(info.baseDN, .subtree, f, limit: limit)
    }

    public func quick(_ q: QuickFilter) throws -> [ADObject] {
        let person = "(objectCategory=person)(objectClass=user)"
        switch q {
        case .locked:
            return try objects(info.baseDN, .subtree, "(&\(person)(lockoutTime>=1))").filter(\.isLocked)
        case .disabled:
            return try objects(info.baseDN, .subtree, "(&\(person)(userAccountControl:1.2.840.113556.1.4.803:=2))")
        case .expiring:
            // ponytail: candidates come from the domain-wide maxPwdAge; users under a stricter fine-grained policy (PSO) can be missed.
            guard let age = info.maxPwdAge else { return [] }
            let now = Date()
            let from = ADTime.fileTime(now.addingTimeInterval(-age)), to = ADTime.fileTime(now.addingTimeInterval(-age + 14 * 86400))
            let f = "(&\(person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=65536))(pwdLastSet>=\(from))(pwdLastSet<=\(to)))"
            return try objects(info.baseDN, .subtree, f).filter { if case .expiring = $0.status { return true }; return $0.passwordExpiry == nil }
        }
    }

    public func object(_ dn: String) throws -> ADObject {
        guard let e = try run({ try $0.search(base: dn, scope: .base, filter: "(objectClass=*)", attrs: Self.detailAttrs) }).first else {
            throw LDAPError(code: 32, name: "No such object", diagnostic: dn)
        }
        return ADObject(e)
    }

    /// Groups the object belongs to, primary group (not stored in memberOf) first.
    public func groups(of obj: ADObject) throws -> [ADObject] {
        var out: [ADObject] = []
        if let rid = obj.entry.int("primaryGroupID"), let sid = info.domainSID {
            let f = "(objectSid=\(ADBinary.filterValue(ADBinary.sid(domain: sid, rid: UInt32(rid)))))"
            out += try objects(info.baseDN, .subtree, f, limit: 1)
        }
        let f = "(&(objectClass=group)(member=\(LDAPFilter.escape(obj.dn))))"
        return out + (try objects(info.baseDN, .subtree, f)).sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
    }

    /// Direct members via `memberOf` — avoids ranged retrieval of `member` on groups with >1500 entries.
    /// ponytail: members whose primary group this is (e.g. everyone in Domain Users) aren't listed, same as ADUC's Members tab.
    public func members(of groupDN: String) throws -> [ADObject] {
        try objects(info.baseDN, .subtree, "(memberOf=\(LDAPFilter.escape(groupDN)))")
            .sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
    }

    // MARK: - Account operations

    public func resetPassword(_ dn: String, to pw: String, mustChange: Bool, unlock: Bool) throws {
        var mods = [LDAPChange(.replace, "unicodePwd", [ADBinary.password(pw)])]
        if unlock { mods.append(LDAPChange(.replace, "lockoutTime", "0")) }
        try run { try $0.modify(dn, mods) }
        if mustChange { try setMustChangePassword(dn, true) }
    }

    public func unlock(_ dn: String) throws { try run { try $0.modify(dn, [LDAPChange(.replace, "lockoutTime", "0")]) } }

    public func setEnabled(_ dn: String, _ enabled: Bool) throws { try setUAC(dn, .accountDisable, !enabled) }

    public func setPasswordNeverExpires(_ dn: String, _ on: Bool) throws { try setUAC(dn, .dontExpirePassword, on) }

    private func setUAC(_ dn: String, _ flag: UAC, _ on: Bool) throws {
        var uac = try object(dn).uac
        if on { uac.insert(flag) } else { uac.remove(flag) }
        try run { try $0.modify(dn, [LDAPChange(.replace, "userAccountControl", String(uac.rawValue))]) }
    }

    /// pwdLastSet accepts only 0 ("must change") and -1 ("set to now").
    public func setMustChangePassword(_ dn: String, _ on: Bool) throws {
        try run { try $0.modify(dn, [LDAPChange(.replace, "pwdLastSet", on ? "0" : "-1")]) }
    }

    public func setAccountExpires(_ dn: String, _ date: Date?) throws {
        let v = date.map { String(ADTime.fileTime($0)) } ?? "9223372036854775807"
        try run { try $0.modify(dn, [LDAPChange(.replace, "accountExpires", v)]) }
    }

    // MARK: - Membership, move, delete

    public func addMember(_ member: String, to group: String) throws {
        try run { try $0.modify(group, [LDAPChange(.add, "member", member)]) }
    }

    public func removeMember(_ member: String, from group: String) throws {
        try run { try $0.modify(group, [LDAPChange(.delete, "member", member)]) }
    }

    @discardableResult
    public func move(_ dn: String, to parent: String) throws -> String {
        let rdn = DN.firstRDN(dn)
        try run { try $0.rename(dn, newRDN: rdn, newParent: parent) }
        return "\(rdn),\(parent)"
    }

    public func delete(_ dn: String) throws { try run { try $0.delete(dn) } }

    // MARK: - Editing attributes

    /// Replace (non-empty) or clear (nil/empty) several single-valued attributes in one atomic modify.
    public func update(_ dn: String, _ values: [String: String?]) throws {
        let mods = values.sorted { $0.key < $1.key }.map { k, v -> LDAPChange in
            if let v, !v.isEmpty { return LDAPChange(.replace, k, v) }
            return LDAPChange(.replace, k, [])
        }
        guard !mods.isEmpty else { return }
        try run { try $0.modify(dn, mods) }
    }

    public func setAttribute(_ dn: String, _ name: String, _ values: [String]) throws {
        try run { try $0.modify(dn, [LDAPChange(.replace, name, values.map { Data($0.utf8) })]) }
    }

    public func setGroupSecurity(_ dn: String, security: Bool, current: Int32) throws {
        let v = security ? current | GroupType.security : current & ~GroupType.security
        try run { try $0.modify(dn, [LDAPChange(.replace, "groupType", String(v))]) }
    }

    // MARK: - Creating

    @discardableResult
    public func createUser(in parent: String, given: String, surname: String, display: String, sam: String,
                           password: String, mustChange: Bool, disabled: Bool) throws -> String {
        let dn = "CN=\(DN.escape(display)),\(parent)"
        var attrs: [(String, [Data])] = [
            ("objectClass", ["top", "person", "organizationalPerson", "user"].map { Data($0.utf8) }),
            ("cn", [Data(display.utf8)]),
            ("displayName", [Data(display.utf8)]),
            ("sAMAccountName", [Data(sam.utf8)]),
            ("userPrincipalName", [Data("\(sam)@\(info.dnsName)".utf8)]),
            ("unicodePwd", [ADBinary.password(password)]),
            ("userAccountControl", [Data(String(UAC.normalAccount.rawValue | (disabled ? UAC.accountDisable.rawValue : 0)).utf8)]),
        ]
        if !given.isEmpty { attrs.append(("givenName", [Data(given.utf8)])) }
        if !surname.isEmpty { attrs.append(("sn", [Data(surname.utf8)])) }
        try run { try $0.add(dn, attrs) }
        if mustChange { try setMustChangePassword(dn, true) }
        return dn
    }

    @discardableResult
    public func createGroup(in parent: String, name: String, description: String, scope: GroupType.Scope, security: Bool) throws -> String {
        let dn = "CN=\(DN.escape(name)),\(parent)"
        var attrs: [(String, [Data])] = [
            ("objectClass", [Data("group".utf8)]),
            ("sAMAccountName", [Data(name.utf8)]),
            ("groupType", [Data(String(GroupType.value(scope: scope, security: security)).utf8)]),
        ]
        if !description.isEmpty { attrs.append(("description", [Data(description.utf8)])) }
        try run { try $0.add(dn, attrs) }
        return dn
    }

    @discardableResult
    public func createComputer(in parent: String, name: String, description: String) throws -> String {
        let n = name.uppercased()
        let dn = "CN=\(DN.escape(n)),\(parent)"
        var attrs: [(String, [Data])] = [
            ("objectClass", ["top", "person", "organizationalPerson", "user", "computer"].map { Data($0.utf8) }),
            ("sAMAccountName", [Data("\(n)$".utf8)]),
            ("userAccountControl", [Data(String(UAC.workstationTrust.rawValue).utf8)]),
        ]
        if !description.isEmpty { attrs.append(("description", [Data(description.utf8)])) }
        try run { try $0.add(dn, attrs) }
        return dn
    }

    @discardableResult
    public func createOU(in parent: String, name: String, description: String) throws -> String {
        let dn = "OU=\(DN.escape(name)),\(parent)"
        var attrs: [(String, [Data])] = [("objectClass", ["top", "organizationalUnit"].map { Data($0.utf8) })]
        if !description.isEmpty { attrs.append(("description", [Data(description.utf8)])) }
        try run { try $0.add(dn, attrs) }
        return dn
    }
}
