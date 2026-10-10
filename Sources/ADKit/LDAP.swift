import Foundation
import ldap

public struct LDAPError: Error, LocalizedError {
    public let code: Int32
    public let name: String        // ldap_err2string
    public let diagnostic: String  // AD's own text, e.g. "0000052D: Constraint violation …"

    public var errorDescription: String? { ADErrorText.describe(code: code, diagnostic: diagnostic) }
    /// Technical line shown small under the friendly text.
    public var technical: String { "LDAP \(code) · \(name)" + (diagnostic.isEmpty ? "" : " · \(diagnostic)") }
    public var isServerDown: Bool { code == LDAP_SERVER_DOWN || code == LDAP_CONNECT_ERROR || code == LDAP_TIMEOUT }
}

public struct LDAPEntry: Hashable {
    public let dn: String
    /// Keys are lower-cased attribute names.
    public let attrs: [String: [Data]]

    public init(dn: String, attrs: [String: [Data]]) { self.dn = dn; self.attrs = attrs }

    public func values(_ name: String) -> [Data] { attrs[name.lowercased()] ?? [] }
    public func strings(_ name: String) -> [String] { values(name).map { String(decoding: $0, as: UTF8.self) } }
    public func string(_ name: String) -> String? { strings(name).first }
    public func int(_ name: String) -> Int64? { string(name).flatMap { Int64($0) } }
    public func data(_ name: String) -> Data? { values(name).first }
}

public enum LDAPScope { case base, oneLevel, subtree
    var raw: Int32 { switch self { case .base: LDAP_SCOPE_BASE; case .oneLevel: LDAP_SCOPE_ONELEVEL; case .subtree: LDAP_SCOPE_SUBTREE } }
}

public struct LDAPChange {
    public enum Op { case add, delete, replace }
    public let op: Op, attr: String, values: [Data]
    public init(_ op: Op, _ attr: String, _ values: [Data]) { self.op = op; self.attr = attr; self.values = values }
    public init(_ op: Op, _ attr: String, _ value: String) { self.init(op, attr, [Data(value.utf8)]) }
}

/// Thin synchronous wrapper over the system OpenLDAP. Not thread-safe: ADDirectory (an actor) owns it.
public final class LDAPConnection {
    private let ld: OpaquePointer

    /// `url` = `ldaps://host:636`. `verifyCertificate: false` is only for the local test DC (AD_INSECURE_TLS=1).
    public init(url: String, timeout: Int = 10, verifyCertificate: Bool = true) throws {
        if !verifyCertificate {
            // Apple's libldap reads TLS options from the global context when the handle connects.
            var never = LDAP_OPT_X_TLS_NEVER
            ldap_set_option(nil, LDAP_OPT_X_TLS_REQUIRE_CERT, &never)
        }
        var handle: OpaquePointer?
        let rc = ldap_initialize(&handle, url)
        guard rc == LDAP_SUCCESS, let handle else {
            throw LDAPError(code: rc, name: String(cString: ldap_err2string(rc)), diagnostic: "")
        }
        ld = handle
        var v3 = LDAP_VERSION3
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &v3)
        ldap_set_option(ld, LDAP_OPT_REFERRALS, nil) // LDAP_OPT_OFF: AD referrals to other partitions break simple binds
        var tv = timeval(tv_sec: timeout, tv_usec: 0)
        ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv)
        ldap_set_option(ld, LDAP_OPT_TIMEOUT, &tv)
    }

    deinit { ldap_unbind_ext_s(ld, nil, nil) }

    public func bind(user: String, password: String) throws {
        // An empty password is an *unauthenticated* bind that AD accepts — never let it through.
        guard !password.isEmpty else { throw LDAPError(code: 49, name: "Invalid credentials", diagnostic: "empty password") }
        var bytes = Array(password.utf8)
        defer { for i in bytes.indices { bytes[i] = 0 } }
        try bytes.withUnsafeMutableBufferPointer { buf in
            var cred = berval(bv_len: ber_len_t(buf.count), bv_val: UnsafeMutableRawPointer(buf.baseAddress!).assumingMemoryBound(to: CChar.self))
            try check(ldap_sasl_bind_s(ld, user, nil, &cred, nil, nil, nil))
        }
    }

    /// Paged search (AD caps a single page at 1000 entries). `limit` 0 = everything.
    public func search(base: String, scope: LDAPScope, filter: String, attrs: [String]? = nil, limit: Int = 0) throws -> [LDAPEntry] {
        var out: [LDAPEntry] = []
        var cookie: UnsafeMutablePointer<berval>? = nil
        defer { if let cookie { ber_bvfree(cookie) } }
        repeat {
            var pageCtrl: UnsafeMutablePointer<LDAPControl>?
            try check(ldap_create_page_control(ld, 500, cookie, 0, &pageCtrl))
            defer { ldap_control_free(pageCtrl) }
            var ctrls: [UnsafeMutablePointer<LDAPControl>?] = [pageCtrl, nil]
            var res: OpaquePointer?
            defer { if let res { ldap_msgfree(res) } }
            var tv = timeval(tv_sec: 60, tv_usec: 0)
            let rc = withCStrings(attrs) { cattrs in
                ldap_search_ext_s(ld, base, scope.raw, filter, cattrs, 0, &ctrls, nil, &tv, 0, &res)
            }
            if rc != LDAP_SUCCESS && !(rc == LDAP_SIZELIMIT_EXCEEDED && !out.isEmpty) { try check(rc) }
            guard let res else { break }
            out += entries(res)

            var serverCtrls: UnsafeMutablePointer<UnsafeMutablePointer<LDAPControl>?>?
            var err: Int32 = 0
            ldap_parse_result(ld, res, &err, nil, nil, nil, &serverCtrls, 0)
            defer { if let serverCtrls { ldap_controls_free(serverCtrls) } }
            if let cookie { ber_bvfree(cookie) }
            cookie = nil
            if let pr = ldap_control_find("1.2.840.113556.1.4.319", serverCtrls, nil) {
                var count: ber_int_t = 0
                var next = berval()
                if ldap_parse_pageresponse_control(ld, pr, &count, &next) == LDAP_SUCCESS {
                    if next.bv_len > 0 { cookie = ber_bvdup(&next) }
                    ber_memfree(next.bv_val)
                }
            }
        } while cookie != nil && (limit == 0 || out.count < limit)
        return limit > 0 ? Array(out.prefix(limit)) : out
    }

    public func modify(_ dn: String, _ mods: [LDAPChange]) throws {
        try withMods(mods) { try check(ldap_modify_ext_s(ld, dn, $0, nil, nil)) }
    }

    public func add(_ dn: String, _ attrs: [(String, [Data])]) throws {
        try withMods(attrs.map { LDAPChange(.add, $0.0, $0.1) }) { try check(ldap_add_ext_s(ld, dn, $0, nil, nil)) }
    }

    public func delete(_ dn: String) throws { try check(ldap_delete_ext_s(ld, dn, nil, nil)) }

    /// Move and/or rename. `newRDN` like `CN=Ivanov Petr` (escaped).
    public func rename(_ dn: String, newRDN: String, newParent: String?) throws {
        try check(ldap_rename_s(ld, dn, newRDN, newParent, 1, nil, nil))
    }

    // MARK: - C plumbing

    private func check(_ rc: Int32) throws {
        guard rc != LDAP_SUCCESS else { return }
        var msg: UnsafeMutablePointer<CChar>?
        ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg)
        let diag = msg.map { String(cString: $0) }?.trimmingCharacters(in: .whitespacesAndNewlines.union(.controlCharacters)) ?? ""
        if let msg { ldap_memfree(msg) }
        throw LDAPError(code: rc, name: String(cString: ldap_err2string(rc)), diagnostic: diag)
    }

    private func entries(_ res: OpaquePointer) -> [LDAPEntry] {
        var out: [LDAPEntry] = []
        var e = ldap_first_entry(ld, res)
        while let entry = e {
            let dnPtr = ldap_get_dn(ld, entry)
            let dn = dnPtr.map { String(cString: $0) } ?? ""
            if let dnPtr { ldap_memfree(dnPtr) }
            var attrs: [String: [Data]] = [:]
            var ber: OpaquePointer?
            var a = ldap_first_attribute(ld, entry, &ber)
            while let attr = a {
                if let vals = ldap_get_values_len(ld, entry, attr) {
                    var list: [Data] = [], i = 0
                    while let v = vals[i] {
                        list.append(v.pointee.bv_len == 0 ? Data() : Data(bytes: v.pointee.bv_val, count: Int(v.pointee.bv_len)))
                        i += 1
                    }
                    ldap_value_free_len(vals)
                    attrs[String(cString: attr).lowercased()] = list
                }
                ldap_memfree(attr)
                a = ldap_next_attribute(ld, entry, ber)
            }
            if let ber { ber_free(ber, 0) }
            out.append(LDAPEntry(dn: dn, attrs: attrs))
            e = ldap_next_entry(ld, entry)
        }
        return out
    }

    private func withCStrings<R>(_ strings: [String]?, _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> R) -> R {
        guard let strings else { return body(nil) }
        var ptrs: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) } + [nil]
        defer { ptrs.forEach { free($0) } }
        return ptrs.withUnsafeMutableBufferPointer { body($0.baseAddress) }
    }

    /// Builds a NULL-terminated `LDAPMod*[]` with berval values, frees everything afterwards.
    private func withMods(_ mods: [LDAPChange], _ body: (UnsafeMutablePointer<UnsafeMutablePointer<LDAPMod>?>) throws -> Void) throws {
        // Everything is zeroed before free: values may carry a unicodePwd.
        var allocations: [(UnsafeMutableRawPointer, Int)] = []
        defer { allocations.forEach { memset($0.0, 0, $0.1); free($0.0) } }
        func alloc<T>(_ type: T.Type, _ count: Int) -> UnsafeMutablePointer<T> {
            let p = calloc(count, MemoryLayout<T>.stride)!
            allocations.append((p, count * MemoryLayout<T>.stride))
            return p.bindMemory(to: T.self, capacity: count)
        }
        let list = alloc(UnsafeMutablePointer<LDAPMod>?.self, mods.count + 1)
        for (i, m) in mods.enumerated() {
            let vals = alloc(UnsafeMutablePointer<berval>?.self, m.values.count + 1)
            for (j, d) in m.values.enumerated() {
                let bv = alloc(berval.self, 1)
                let bytes = alloc(CChar.self, max(d.count, 1))
                d.withUnsafeBytes { if let base = $0.baseAddress { memcpy(bytes, base, d.count) } }
                bv.pointee = berval(bv_len: ber_len_t(d.count), bv_val: bytes)
                vals[j] = bv
            }
            let type = alloc(CChar.self, m.attr.utf8.count + 1)
            _ = m.attr.withCString { strcpy(type, $0) }
            let op: Int32 = switch m.op { case .add: LDAP_MOD_ADD; case .delete: LDAP_MOD_DELETE; case .replace: LDAP_MOD_REPLACE }
            let mod = alloc(LDAPMod.self, 1)
            mod.pointee.mod_op = op | LDAP_MOD_BVALUES
            mod.pointee.mod_type = type
            // An empty value list on delete/replace means "the whole attribute".
            mod.pointee.mod_vals.modv_bvals = m.values.isEmpty ? nil : vals
            list[i] = mod
        }
        try body(list)
    }
}
