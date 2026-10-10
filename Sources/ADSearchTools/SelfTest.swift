#if DEBUG
import ADKit
import AppKit
import SwiftUI

/// `swift run ADSearchTools --selftest` against the seeded test DC (TestDC/seed.sh): drives AppModel the way the views do.
@MainActor
enum SelfTest {
    static func run() async {
        let env = ProcessInfo.processInfo.environment
        var fails = 0
        func check(_ ok: Bool, _ what: String) { print(ok ? "ok  " : "FAIL", what); if !ok { fails += 1 } }
        func settle(_ m: AppModel) async {
            try? await Task.sleep(nanoseconds: 700_000_000)
            while m.loading { try? await Task.sleep(nanoseconds: 100_000_000) }
            try? await Task.sleep(nanoseconds: 300_000_000)
        }

        let cfg = ADConfig(host: env["AD_TEST_HOST"] ?? "127.0.0.1", port: Int(env["AD_TEST_PORT"] ?? "1636")!, user: env["AD_TEST_USER"] ?? "Administrator@corp.local")
        let d = ADDirectory(config: cfg, password: env["AD_TEST_PASS"] ?? "")
        let m = AppModel()
        guard let info = try? await d.connect() else { print("FAIL connect"); exit(1) }
        m.didConnect(d, info)
        await settle(m)
        check(m.items.contains { $0.rdnName == "Administrator" }, "opens CN=Users after connect")
        check(m.tree[info.baseDN]?.contains { $0.rdnName == "Company" } == true, "domain tree loaded")
        check(m.counts[.locked] ?? 0 >= 1 && m.counts[.disabled] ?? 0 >= 1, "quick filter counts \(m.counts)")

        let it = "OU=IT,OU=Company,\(info.baseDN)"
        m.place = .container(it)
        await settle(m)
        check(m.items.count >= 8, "IT listing: \(m.items.map(\.name))")
        check(m.items.first?.isContainer == false && m.items.contains { $0.kind == .group }, "groups listed")
        let ivanov = m.items.first { $0.sam == "p.ivanov" }
        check(ivanov?.status == .locked && ivanov?.name == "Иванов Пётр", "Ivanov shown locked with displayName")
        check(m.items.first { $0.sam == "o.petrov" }?.status == .disabled, "Petrov disabled")
        check(m.items.first { $0.sam == "a.smirnova" }?.photo != nil, "Smirnova has photo")
        m.kind = .groups
        check(!m.visibleItems.isEmpty && m.visibleItems.allSatisfy { $0.kind == .group }, "kind filter in container")
        m.kind = .all

        m.query = "иван"
        await settle(m)
        let names = Set(m.items.compactMap(\.sam))
        check(m.isSearching && names.isSuperset(of: ["p.ivanov", "o.ivanova", "d.ivanchenko"]), "domain-wide search: \(names)")
        m.query = ""
        await settle(m)

        m.place = .quick(.locked)
        await settle(m)
        check(m.items.contains { $0.sam == "p.ivanov" }, "quick filter: locked")

        guard let iv = ivanov else { exit(1) }
        m.selection = [iv.dn]
        await settle(m)
        check(m.detail?.dn == iv.dn && m.detail?.manager != nil, "detail loads full object")
        m.open(m.detail!.manager!)
        await settle(m)
        check(m.detail?.sam == "a.smirnova", "manager link opens detail")

        m.unlock([iv])
        await settle(m)
        check(m.toast == "Учётная запись разблокирована", "unlock toast: \(m.toast ?? "nil")")
        check(!m.items.contains { $0.sam == "p.ivanov" }, "unlocked user leaves the locked filter")

        m.place = .container(it)
        await settle(m)
        let created = await m.attempt { try await $0.createGroup(in: it, name: "SelfTest-Group", description: "", scope: .global, security: true) }
        await settle(m)
        let g = m.items.first { $0.rdnName == "SelfTest-Group" }
        check(created == nil && g != nil, "create group via sheet path")
        if let g { m.delete([g]); await settle(m) }
        check(!m.items.contains { $0.rdnName == "SelfTest-Group" }, "delete")

        let bad = await m.attempt { try await $0.resetPassword(iv.dn, to: "1", mustChange: false, unlock: false) }
        check(bad?.technical.hasPrefix("LDAP 19") == true || bad?.technical.hasPrefix("LDAP 53") == true, "policy error surfaces: \(bad?.technical ?? "nil")")

        if case .untrusted(let issuer, _) = await TLSProbe.run(host: cfg.host, port: cfg.port) { check(issuer == "CORP-ROOT-CA", "TLS probe names CA: \(issuer)") } else { check(false, "TLS probe: untrusted expected") }
        if case .unreachable = await TLSProbe.run(host: "127.0.0.1", port: 1) { check(true, "TLS probe: closed port") } else { check(false, "TLS probe: closed port") }

        // Leave the demo state as seeded: lock Ivanov again.
        for _ in 0..<4 { _ = try? await ADDirectory(config: ADConfig(host: cfg.host, port: cfg.port, user: "p.ivanov@corp.local"), password: "x").connect() }
        m.refreshCounts()

        // Offscreen renders of the real views for eyeballing layout (SELFTEST_SNAPSHOTS=<dir>).
        if let dir = env["SELFTEST_SNAPSHOTS"] {
            m.place = .container(it)
            await settle(m)
            m.selection = [m.items.first { $0.sam == "p.ivanov" }!.dn]
            await settle(m)
            await snap(MainView().environmentObject(m), "\(dir)/1-main-profile.png")
            m.selection = [m.items.first { $0.sam == "a.smirnova" }!.dn]
            await settle(m)
            await snap(MainView().environmentObject(m), "\(dir)/2-main-smirnova.png")
            m.useTable = true
            await snap(MainView().environmentObject(m), "\(dir)/3-table.png")
            m.useTable = false
            m.selection = Set(m.items.filter { $0.kind == .user }.prefix(4).map(\.dn))
            await settle(m)
            await snap(MainView().environmentObject(m), "\(dir)/4-multi.png")
            if let ivn = m.items.first(where: { $0.sam == "p.ivanov" }) {
                m.selection = [ivn.dn]
                await settle(m)
                for (tab, name) in [(ObjectDetail.Tab.account, "5-account"), (.groups, "6-groups"), (.attrs, "7-attrs")] {
                    await snap(ObjectDetail(obj: m.detail!, initialTab: tab).environmentObject(m), "\(dir)/\(name).png", size: CGSize(width: 460, height: 780))
                }
                await snap(ResetPasswordSheet(obj: m.detail!).environmentObject(m), "\(dir)/8-reset.png", size: CGSize(width: 440, height: 420))
            }
            await snap(NewUserSheet(parent: it).environmentObject(m), "\(dir)/9-newuser.png", size: CGSize(width: 480, height: 640))
            let gdn = m.items.first { $0.rdnName == "IT-Admins" }!.dn
            m.selection = [gdn]
            await settle(m)
            await snap(MainView().environmentObject(m), "\(dir)/10-group.png")
            await snap(ConnectView().environmentObject(AppModel()), "\(dir)/11-connect.png", size: CGSize(width: 520, height: 620))
        }

        print(fails == 0 ? "SELFTEST OK" : "SELFTEST \(fails) FAILED")
        exit(fails == 0 ? 0 : 1)
    }
}

@MainActor
func snap<V: View>(_ view: V, _ path: String, size: CGSize = CGSize(width: 1280, height: 780)) async {
    let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height).background(Color(nsColor: .windowBackgroundColor)))
    let win = NSWindow(contentRect: NSRect(origin: NSPoint(x: -20000, y: -20000), size: size), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
    win.contentView = host
    win.orderFrontRegardless()
    try? await Task.sleep(nanoseconds: 1_500_000_000)
    host.layoutSubtreeIfNeeded()
    guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
    host.cacheDisplay(in: host.bounds, to: rep)
    try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
    win.orderOut(nil)
}
#endif
