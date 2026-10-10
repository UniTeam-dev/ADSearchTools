import ADKit
import Foundation

// `swift run ADKitChecks` — pure-logic checks.
// With a test DC (TestDC/README) also exercises every write path end to end:
//   AD_TEST_URL=127.0.0.1:1636 AD_TEST_USER=Administrator@corp.local AD_TEST_PASS='Passw0rd!Test' AD_INSECURE_TLS=1 swift run ADKitChecks

var failures = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if !ok { failures += 1; print("FAIL [\(line)] \(what)") }
}

// Filters and DNs
check(LDAPFilter.escape("a*(b)\\c") == "a\\2a\\28b\\29\\5cc", "filter escape")
check(LDAPFilter.escape("Иван") == "Иван", "filter keeps unicode")
check(DN.escape("Ivanov, Petr") == "Ivanov\\, Petr", "dn escape comma")
check(DN.escape(" #x ") == "\\ #x\\ " && DN.escape("#x") == "\\#x", "dn escape leading/trailing")
check(DN.rdns("CN=Ivanov\\, Petr,OU=IT,DC=corp,DC=local") == ["CN=Ivanov\\, Petr", "OU=IT", "DC=corp", "DC=local"], "rdns split")
check(DN.name("CN=Ivanov\\, Petr,OU=IT,DC=corp") == "Ivanov, Petr", "dn name unescape")
check(DN.name("CN=\\D0\\98\\D0\\B2,OU=IT") == "Ив", "dn hex unescape")
check(DN.parent("CN=x,OU=IT,DC=corp,DC=local") == "OU=IT,DC=corp,DC=local", "dn parent")
check(DN.dnsName(ofDomain: "DC=corp,DC=local") == "corp.local", "dns name")
check(DN.path("CN=x,OU=IT,OU=Company,DC=corp,DC=local") == ["Company", "IT", "x"], "dn path")

// Flags, times, binary
check(UAC(rawValue: 0x10202).contains(.accountDisable) && UAC(rawValue: 0x10202).contains(.dontExpirePassword), "uac flags")
check(UAC(rawValue: 0x202).description == "0x202 · ACCOUNTDISABLE, NORMAL_ACCOUNT", "uac description")
check(GroupType.value(scope: .global, security: true) == -2147483646, "group type global security")
check(GroupType.scope(-2147483644) == .domainLocal && GroupType.isSecurity(-2147483644), "group type decode")
check(!GroupType.isSecurity(8) && GroupType.scope(8) == .universal, "distribution universal")
check(ADTime.date(fileTime: 0) == nil && ADTime.date(fileTime: Int64.max) == nil, "filetime never")
check(ADTime.date(fileTime: 116_444_736_000_000_000) == Date(timeIntervalSince1970: 0), "filetime epoch")
let now = Date(timeIntervalSince1970: 1_791_600_000)
check(abs(ADTime.date(fileTime: ADTime.fileTime(now))!.timeIntervalSince(now)) < 0.001, "filetime roundtrip")
check(ADTime.date(generalized: "20261010123456.0Z") == ADTime.date(fileTime: ADTime.fileTime(DateComponents(calendar: .init(identifier: .gregorian), timeZone: TimeZone(identifier: "UTC"), year: 2026, month: 10, day: 10, hour: 12, minute: 34, second: 56).date!)), "generalized time")
check(ADTime.interval(-36_288_000_000_000) == 42 * 86400, "interval")
check(ADBinary.guid(Data([0x3F, 0x2A, 0x91, 0x0C, 0x7B, 0x44, 0x0E, 0x4D, 0x9A, 0x61, 0xC2, 0x08, 0x5E, 0x13, 0xB7, 0x70])) == "0c912a3f-447b-4d0e-9a61-c2085e13b770", "guid")
let domSid = Data([1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0])
check(ADBinary.sid(domSid) == "S-1-5-21-1-2-3", "sid")
check(ADBinary.sid(ADBinary.sid(domain: domSid, rid: 513)) == "S-1-5-21-1-2-3-513", "sid + rid")
check(ADBinary.password("ab") == Data([0x22, 0, 0x61, 0, 0x62, 0, 0x22, 0]), "unicodePwd encoding")
check(ADNames.isValidComputerName("IT-LT-042") && !ADNames.isValidComputerName("IT_LT") && !ADNames.isValidComputerName("ABCDEFGHIJKLMNOP"), "computer name rules")
check(ADNames.initials("Иванов Пётр") == "ИП" && ADNames.initials("svc-backup") == "SB", "initials")
check(ADErrorText.describe(code: 19, diagnostic: "0000052D: Constraint violation") == "Пароль не соответствует политике домена.", "error text policy")
check(ADErrorText.describe(code: 49, diagnostic: "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v2580").contains("заблокирована"), "error text locked")

// SRV parsing: priority 0, weight 100, port 389, target lon-dc-02.corp.com
let srvData = Data([0, 0, 0, 100, 1, 0x85, 9] + Array("lon-dc-02".utf8) + [4] + Array("corp".utf8) + [3] + Array("com".utf8) + [0])
let srv = DCLocator.parse(srvData)
check(srv?.priority == 0 && srv?.weight == 100 && srv?.port == 389 && srv?.target == "lon-dc-02.corp.com", "srv parse")
check(DCLocator.parse(Data([0, 0, 0])) == nil, "srv parse short")
if let domain = ProcessInfo.processInfo.environment["AD_TEST_DOMAIN"] {
    let dcs = DCLocator.controllers(for: domain)
    print("DCs for \(domain):", dcs)
    check(!dcs.isEmpty, "DC locator finds controllers")
}
check(DCLocator.controllers(for: "nonexistent.invalid", timeout: 2).isEmpty, "no SRV → empty")

// Live DC
if let host = ProcessInfo.processInfo.environment["AD_TEST_URL"] {
    let env = ProcessInfo.processInfo.environment
    let parts = host.split(separator: ":")
    let cfg = ADConfig(host: String(parts[0]), port: parts.count > 1 ? Int(parts[1])! : 636, user: env["AD_TEST_USER"] ?? "")
    let sem = DispatchSemaphore(value: 0)
    Task {
        defer { sem.signal() }
        do {
            let bad = ADDirectory(config: cfg, password: "wrong")
            do { _ = try await bad.connect(); check(false, "bad password must fail") } catch let e as LDAPError { check(e.code == 49, "bad password → 49, got \(e.code)") }
            do { _ = try await ADDirectory(config: cfg, password: "").connect(); check(false, "empty password must fail") } catch {}

            let dir = ADDirectory(config: cfg, password: env["AD_TEST_PASS"] ?? "")
            let info = try await dir.connect()
            check(info.baseDN == "DC=corp,DC=local", "baseDN \(info.baseDN)")
            check(info.netbios == "CORP", "netbios \(info.netbios)")
            check(info.domainSID != nil, "domain SID")
            print("domain:", info.dnsName, info.netbios, info.dcHost, "maxPwdAge", info.maxPwdAge ?? -1, "policy:", info.policyText)

            let tree = try await dir.children(of: info.baseDN, containersOnly: true)
            check(tree.contains { $0.rdnName == "Users" }, "tree has Users")
            check(!tree.contains { $0.rdnName == "System" }, "advanced-only containers hidden")

            // Clean slate
            let ouName = "ADKitChecks"
            let ouDN = "OU=\(ouName),\(info.baseDN)"
            if let old = try? await dir.children(of: ouDN) {
                for o in old where o.kind == .ou { for c in (try? await dir.children(of: o.dn)) ?? [] { try? await dir.delete(c.dn) } }
                for o in old { try? await dir.delete(o.dn) }
                try? await dir.delete(ouDN)
            }

            try await dir.createOU(in: info.baseDN, name: ouName, description: "test")
            let archive = try await dir.createOU(in: ouDN, name: "Archive", description: "")
            let user = try await dir.createUser(in: ouDN, given: "Пётр", surname: "Иванов, тест", display: "Иванов, тест Пётр", sam: "t.ivanov",
                                                 password: "Init!Passw0rd-1", mustChange: true, disabled: false)
            var u = try await dir.object(user)
            check(u.kind == .user && u.sam == "t.ivanov", "user created")
            check(u.mustChangePassword, "must change at next logon")
            check(u.upn == "t.ivanov@corp.local", "upn")
            check(!u.isDisabled, "enabled")

            do { try await dir.resetPassword(user, to: "123", mustChange: false, unlock: false); check(false, "weak password must fail") }
            catch let e as LDAPError { check(e.code == 19 || e.code == 53, "weak password → constraint, got \(e.technical)") }

            try await dir.resetPassword(user, to: "Next!Passw0rd-2", mustChange: false, unlock: true)
            u = try await dir.object(user)
            check(!u.mustChangePassword, "pwdLastSet set after reset")

            // Lockout: threshold is 3 on the test DC
            for _ in 0..<4 { _ = try? await ADDirectory(config: ADConfig(host: cfg.host, port: cfg.port, user: "t.ivanov@corp.local"), password: "nope").connect() }
            u = try await dir.object(user)
            check(u.isLocked, "locked after bad passwords (computed=\(String(describing: u.computedUAC)), lockoutTime=\(String(describing: u.lockoutTime)))")
            check(try await dir.quick(.locked).contains { $0.dn == user }, "quick filter locked")
            try await dir.unlock(user)
            check(!(try await dir.object(user)).isLocked, "unlocked")
            _ = try await ADDirectory(config: ADConfig(host: cfg.host, port: cfg.port, user: "t.ivanov@corp.local"), password: "Next!Passw0rd-2").connect()

            try await dir.setEnabled(user, false)
            check((try await dir.object(user)).isDisabled, "disabled")
            check(try await dir.quick(.disabled).contains { $0.dn == user }, "quick filter disabled")
            try await dir.setEnabled(user, true)
            check(!(try await dir.object(user)).isDisabled, "re-enabled")

            try await dir.setPasswordNeverExpires(user, true)
            check((try await dir.object(user)).passwordNeverExpires, "never expires")
            try await dir.setPasswordNeverExpires(user, false)

            let exp = Date().addingTimeInterval(30 * 86400)
            try await dir.setAccountExpires(user, exp)
            check(abs(((try await dir.object(user)).accountExpires ?? .distantPast).timeIntervalSince(exp)) < 1, "account expires")
            try await dir.setAccountExpires(user, nil)
            check((try await dir.object(user)).accountExpires == nil, "account never expires")

            try await dir.update(user, ["title": "DevOps-инженер", "telephoneNumber": "+7 495 123-45-67", "mobile": nil])
            u = try await dir.object(user)
            check(u.title == "DevOps-инженер", "profile update")
            try await dir.update(user, ["title": ""])
            check((try await dir.object(user)).title == nil, "attribute cleared")
            try await dir.setAttribute(user, "info", ["line1"])
            check((try await dir.object(user)).entry.string("info") == "line1", "set attribute")

            let found = try await dir.search("t.ivan", kind: .people)
            check(found.contains { $0.dn == user }, "anr search by login")
            check(try await dir.search("Иванов, тест", kind: .groups).isEmpty, "kind filter")
            check(try await dir.search("*)(objectClass=*", kind: .all).isEmpty, "filter injection inert")

            let group = try await dir.createGroup(in: ouDN, name: "T-VPN-Users", description: "VPN", scope: .global, security: true)
            try await dir.addMember(user, to: group)
            check(try await dir.members(of: group).map(\.dn) == [user], "members")
            let groups = try await dir.groups(of: try await dir.object(user))
            check(groups.first?.rdnName == "Domain Users", "primary group first: \(groups.map(\.rdnName))")
            check(groups.contains { $0.dn == group }, "memberOf")
            do { try await dir.addMember(user, to: group); check(false, "duplicate member must fail") } catch let e as LDAPError { check(e.code == 20 || e.code == 68, "dup member code \(e.code)") }
            let g = try await dir.object(group)
            try await dir.setGroupSecurity(group, security: false, current: g.groupType!)
            check((try await dir.object(group)).groupType == 2, "group → distribution")
            try await dir.removeMember(user, from: group)
            check(try await dir.members(of: group).isEmpty, "member removed")

            let pc = try await dir.createComputer(in: ouDN, name: "it-lt-099", description: "test")
            let pco = try await dir.object(pc)
            check(pco.kind == .computer && pco.sam == "IT-LT-099$", "computer")

            let moved = try await dir.move(user, to: archive)
            check((try? await dir.object(moved))?.sam == "t.ivanov", "moved")
            check(try await dir.count(in: archive) == 1, "count")

            do { try await dir.delete(ouDN); check(false, "non-leaf delete must fail") } catch let e as LDAPError { check(e.code == 66, "non-leaf → 66, got \(e.code)") }
            for dn in [moved, group, pc, archive, ouDN] { try await dir.delete(dn) }
            do { _ = try await dir.object(ouDN); check(false, "deleted") } catch let e as LDAPError { check(e.code == 32, "gone") }
            print("live DC checks done")
        } catch {
            check(false, "live DC: \(error) \((error as? LDAPError)?.technical ?? "")")
        }
    }
    sem.wait()
}

print(failures == 0 ? "OK" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
