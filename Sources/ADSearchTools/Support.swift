import ADKit
import AppKit
import Network
import Security
import SwiftUI

// MARK: - Keychain

enum Keychain {
    static let service = "ADSearchTools"

    static func password(for account: String) -> String? {
        var out: CFTypeRef?
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecReturnData as String: true]
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    static func save(_ password: String, for account: String) {
        delete(account)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecValueData as String: Data(password.utf8),
                                kSecAttrLabel as String: "ADSearchTools — \(account)"]
        SecItemAdd(q as CFDictionary, nil)
    }

    static func delete(_ account: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account]
        SecItemDelete(q as CFDictionary)
    }
}

// MARK: - TLS diagnostics

/// libldap reports an untrusted certificate and a dead server with the same -1, so the connect
/// window probes the port itself to tell them apart and to name the issuing CA.
enum TLSProbe {
    enum Result { case unreachable, trusted, untrusted(issuer: String, root: SecCertificate?), nameMismatch(certName: String) }

    /// All callbacks below run on one serial queue, so this unsynchronised box is safe.
    private final class State: @unchecked Sendable {
        var outcome: Result = .unreachable
        var cont: CheckedContinuation<Result, Never>?
        func finish() { cont?.resume(returning: outcome); cont = nil }
    }

    static func run(host: String, port: Int) async -> Result {
        await withCheckedContinuation { cont in
            let q = DispatchQueue(label: "tls-probe")
            let st = State()
            st.cont = cont
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
                let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
                SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
                let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
                if SecTrustEvaluateWithError(trust, nil) {
                    st.outcome = .trusted
                } else if SecTrustSetPolicies(trust, SecPolicyCreateBasicX509()) == errSecSuccess, SecTrustEvaluateWithError(trust, nil) {
                    // Chain is fine, the name isn't: typically an IP or short name instead of the DC's FQDN.
                    st.outcome = .nameMismatch(certName: chain.first.map(subjectName) ?? "?")
                } else {
                    let top = chain.last
                    let selfSigned = top.map { issuerName($0) == subjectName($0) } ?? false
                    st.outcome = .untrusted(issuer: chain.first.map(issuerName) ?? "неизвестный CA", root: selfSigned ? top : nil)
                }
                complete(true) // the handshake itself doesn't matter, we only wanted the chain
            }, q)
            let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(integerLiteral: UInt16(clamping: port)),
                                    using: NWParameters(tls: tls))
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready, .failed, .waiting: conn.cancel(); st.finish()
                default: break
                }
            }
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + 8) { conn.cancel(); st.finish() }
        }
    }

    static func subjectName(_ c: SecCertificate) -> String { SecCertificateCopySubjectSummary(c) as String? ?? "?" }

    static func issuerName(_ c: SecCertificate) -> String {
        guard let vals = SecCertificateCopyValues(c, [kSecOIDX509V1IssuerName] as CFArray, nil) as? [CFString: Any],
              let issuer = vals[kSecOIDX509V1IssuerName] as? [String: Any],
              let parts = issuer[kSecPropertyKeyValue as String] as? [[String: Any]] else { return "?" }
        let cn = parts.first { ($0[kSecPropertyKeyLabel as String] as? String) == (kSecOIDCommonName as String) }
        return (cn?[kSecPropertyKeyValue as String] as? String) ?? "?"
    }

    static func certificate(fromFile url: URL) -> SecCertificate? {
        guard var data = try? Data(contentsOf: url) else { return nil }
        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN CERTIFICATE-----") {
            let body = text.components(separatedBy: "-----BEGIN CERTIFICATE-----")[1]
                .components(separatedBy: "-----END CERTIFICATE-----")[0]
                .components(separatedBy: .whitespacesAndNewlines).joined()
            guard let der = Data(base64Encoded: body) else { return nil }
            data = der
        }
        return SecCertificateCreateWithData(nil, data as CFData)
    }

    /// Adds the CA to the login keychain and marks it trusted for this user. macOS asks for the user's password.
    static func trust(_ cert: SecCertificate) throws {
        let add: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecValueRef as String: cert]
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess || st == errSecDuplicateItem else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(st)) }
        let rc = SecTrustSettingsSetTrustSettings(cert, .user, nil)
        guard rc == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(rc)) }
    }
}

// MARK: - Formatting

enum Fmt {
    static let ru = Locale(identifier: "ru_RU")

    static func date(_ d: Date?, time: Bool = true) -> String {
        guard let d else { return "—" }
        let f = DateFormatter()
        f.locale = ru
        f.doesRelativeDateFormatting = true
        f.dateStyle = .medium
        f.timeStyle = time ? .short : .none
        return f.string(from: d)
    }

    static func approx(_ d: Date?) -> String {
        guard let d else { return "нет данных" }
        return "≈ " + date(d, time: false)
    }

    static func objects(_ n: Int) -> String {
        let m10 = n % 10, m100 = n % 100
        let w = m10 == 1 && m100 != 11 ? "объект" : (2...4).contains(m10) && !(12...14).contains(m100) ? "объекта" : "объектов"
        return "\(n) \(w)"
    }
}

extension ADObject {
    var symbol: String {
        switch kind {
        case .user, .contact: "person.fill"
        case .group: "person.2.fill"
        case .computer: (entry.string("operatingSystem") ?? "").lowercased().contains("mac") ? "laptopcomputer" : "desktopcomputer"
        case .ou: "folder.fill"
        case .container: "folder"
        case .domain: "building.2"
        case .other: "doc"
        }
    }

    var statusText: String {
        switch status {
        case .locked: "Заблокирован"
        case .disabled: "Отключён"
        case .passwordExpired: "Пароль истёк"
        case .expiring(let d): "Истекает " + d.formatted(.dateTime.day().month().locale(Fmt.ru))
        case nil: kind == .user || kind == .computer ? "Активен" : ""
        }
    }

    var changedSort: Date { whenChanged ?? .distantPast }
    var descriptionSort: String { descriptionText ?? "" }
}

// MARK: - Small views

struct Avatar: View {
    let obj: ADObject
    var size: CGFloat = 28

    var body: some View {
        Group {
            if let d = obj.photo, let img = NSImage(data: d) {
                Image(nsImage: img).resizable().scaledToFill()
            } else if obj.kind == .user || obj.kind == .contact {
                Text(ADNames.initials(obj.name))
                    .font(.system(size: size * 0.38, weight: .semibold))
                    .foregroundStyle(obj.isDisabled ? Color.secondary : tint)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(obj.isDisabled ? Color.secondary.opacity(0.15) : tint.opacity(0.18))
            } else {
                Image(systemName: obj.symbol)
                    .font(.system(size: size * 0.45))
                    .foregroundStyle(obj.isContainer || obj.kind == .group ? Color.accentColor : .secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.secondary.opacity(0.12))
            }
        }
        .frame(width: size, height: size)
        .clipShape(obj.kind == .user || obj.kind == .contact ? AnyShape(Circle()) : AnyShape(RoundedRectangle(cornerRadius: size * 0.25)))
        .accessibilityHidden(true)
    }

    private var tint: Color {
        let palette: [Color] = [.blue, .teal, .purple, .pink, .orange, .green, .indigo]
        return palette[abs(obj.name.unicodeScalars.reduce(0) { $0 &+ Int($1.value) }) % palette.count]
    }
}

struct StatusBadge: View {
    let status: ADStatus?
    var text: String

    var body: some View {
        if let status {
            Label(text, systemImage: symbol(status))
                .font(.caption.weight(.medium))
                .labelStyle(.titleAndIcon)
                .padding(.horizontal, 7).padding(.vertical, 2)
                .foregroundStyle(color(status))
                .background(color(status).opacity(0.15), in: Capsule())
        }
    }

    func symbol(_ s: ADStatus) -> String {
        switch s { case .locked: "lock.fill"; case .disabled: "nosign"; case .passwordExpired: "exclamationmark.circle.fill"; case .expiring: "clock.fill" }
    }

    func color(_ s: ADStatus) -> Color {
        switch s { case .locked: .orange; case .disabled: .secondary; case .passwordExpired: .red; case .expiring: .yellow }
    }
}

/// Inline error card used in sheets and the connect window.
struct ErrorBox: View {
    let title: String
    let message: String
    var technical: String = ""
    var symbol = "exclamationmark.triangle.fill"
    var color: Color = .orange

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(color).font(.title3)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).fontWeight(.semibold)
                Text(message).fixedSize(horizontal: false, vertical: true)
                if !technical.isEmpty {
                    Text(technical).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }
}

func copyToPasteboard(_ s: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(s, forType: .string)
}
