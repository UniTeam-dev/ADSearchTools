import Foundation

// Pure AD/LDAP helpers: no network, covered by ADKitChecks.

public enum LDAPFilter {
    /// RFC 4515 value escaping — anything typed by a user goes through this before landing in a filter.
    public static func escape(_ s: String) -> String {
        var out = ""
        for ch in s.unicodeScalars {
            switch ch {
            case "\\": out += "\\5c"
            case "*": out += "\\2a"
            case "(": out += "\\28"
            case ")": out += "\\29"
            case "\0": out += "\\00"
            default: out.unicodeScalars.append(ch)
            }
        }
        return out
    }
}

public enum DN {
    /// RFC 4514 attribute-value escaping for building an RDN like `CN=<value>`.
    public static func escape(_ value: String) -> String {
        var out = ""
        let chars = Array(value)
        for (i, ch) in chars.enumerated() {
            if ",+\"\\<>;=".contains(ch) || (i == 0 && (ch == " " || ch == "#")) || (i == chars.count - 1 && ch == " ") {
                out.append("\\")
            }
            out.append(ch)
        }
        return out
    }

    /// Splits a DN into RDN strings on unescaped commas (values stay escaped).
    public static func rdns(_ dn: String) -> [String] {
        var parts: [String] = [], cur = "", esc = false
        for ch in dn {
            if esc { cur.append(ch); esc = false; continue }
            if ch == "\\" { cur.append(ch); esc = true; continue }
            if ch == "," { parts.append(cur.trimmingCharacters(in: .whitespaces)); cur = ""; continue }
            cur.append(ch)
        }
        if !cur.isEmpty { parts.append(cur.trimmingCharacters(in: .whitespaces)) }
        return parts
    }

    public static func firstRDN(_ dn: String) -> String { rdns(dn).first ?? dn }

    public static func parent(_ dn: String) -> String { rdns(dn).dropFirst().joined(separator: ",") }

    /// Unescaped value of the first RDN: `CN=Ivanov\, Petr,OU=IT,...` → `Ivanov, Petr`.
    public static func name(_ dn: String) -> String { value(of: firstRDN(dn)) }

    static func value(of rdn: String) -> String {
        guard let eq = rdn.firstIndex(of: "=") else { return rdn }
        var out = "", it = rdn[rdn.index(after: eq)...].makeIterator()
        var pendingHex: [UInt8] = []
        func flushHex() { if !pendingHex.isEmpty { out += String(decoding: pendingHex, as: UTF8.self); pendingHex = [] } }
        while let ch = it.next() {
            guard ch == "\\", let n = it.next() else { flushHex(); out.append(ch); continue }
            if n.isHexDigit, let n2 = it.next() {
                if let byte = UInt8(String([n, n2]), radix: 16) { pendingHex.append(byte) } else { flushHex(); out.append(n); out.append(n2) }
            } else {
                flushHex(); out.append(n)
            }
        }
        flushHex()
        return out
    }

    /// `DC=corp,DC=local` → `corp.local`
    public static func dnsName(ofDomain dn: String) -> String {
        rdns(dn).filter { $0.uppercased().hasPrefix("DC=") }.map { value(of: $0) }.joined(separator: ".")
    }

    /// Human path below the domain: `CN=x,OU=IT,OU=Company,DC=corp,DC=local` → ["Company", "IT", "x"]
    public static func path(_ dn: String) -> [String] {
        rdns(dn).filter { !$0.uppercased().hasPrefix("DC=") }.map { value(of: $0) }.reversed()
    }
}

public struct UAC: OptionSet, Hashable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }
    public static let accountDisable = UAC(rawValue: 0x2)
    public static let lockout = UAC(rawValue: 0x10)
    public static let passwordNotRequired = UAC(rawValue: 0x20)
    public static let normalAccount = UAC(rawValue: 0x200)
    public static let workstationTrust = UAC(rawValue: 0x1000)
    public static let serverTrust = UAC(rawValue: 0x2000)
    public static let dontExpirePassword = UAC(rawValue: 0x10000)
    public static let passwordExpired = UAC(rawValue: 0x800000)

    static let names: [(Int, String)] = [
        (0x1, "SCRIPT"), (0x2, "ACCOUNTDISABLE"), (0x8, "HOMEDIR_REQUIRED"), (0x10, "LOCKOUT"),
        (0x20, "PASSWD_NOTREQD"), (0x40, "PASSWD_CANT_CHANGE"), (0x80, "ENCRYPTED_TEXT_PWD_ALLOWED"),
        (0x100, "TEMP_DUPLICATE_ACCOUNT"), (0x200, "NORMAL_ACCOUNT"), (0x800, "INTERDOMAIN_TRUST_ACCOUNT"),
        (0x1000, "WORKSTATION_TRUST_ACCOUNT"), (0x2000, "SERVER_TRUST_ACCOUNT"), (0x10000, "DONT_EXPIRE_PASSWORD"),
        (0x20000, "MNS_LOGON_ACCOUNT"), (0x40000, "SMARTCARD_REQUIRED"), (0x80000, "TRUSTED_FOR_DELEGATION"),
        (0x100000, "NOT_DELEGATED"), (0x200000, "USE_DES_KEY_ONLY"), (0x400000, "DONT_REQ_PREAUTH"),
        (0x800000, "PASSWORD_EXPIRED"), (0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    ]

    public var description: String {
        let flags = Self.names.filter { rawValue & $0.0 != 0 }.map(\.1)
        return String(format: "0x%X", rawValue) + (flags.isEmpty ? "" : " · " + flags.joined(separator: ", "))
    }
}

public enum GroupType {
    public static let security = Int32(bitPattern: 0x8000_0000)
    public enum Scope: Int32, CaseIterable, Hashable { case global = 2, domainLocal = 4, universal = 8 }

    public static func value(scope: Scope, security: Bool) -> Int32 { scope.rawValue | (security ? Self.security : 0) }
    public static func isSecurity(_ v: Int32) -> Bool { v & Self.security != 0 }
    public static func scope(_ v: Int32) -> Scope? { Scope.allCases.first { v & $0.rawValue != 0 } }
}

public enum ADTime {
    /// Windows FILETIME (100 ns ticks since 1601). 0 and Int64.max mean "never".
    public static func date(fileTime: Int64) -> Date? {
        guard fileTime > 0, fileTime != Int64.max else { return nil }
        return Date(timeIntervalSince1970: Double(fileTime) / 10_000_000 - 11_644_473_600)
    }

    public static func fileTime(_ date: Date) -> Int64 {
        Int64((date.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
    }

    /// GeneralizedTime as AD returns it: `20261010123456.0Z`.
    public static func date(generalized s: String) -> Date? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMddHHmmss"
        return f.date(from: String(s.prefix(14)))
    }

    /// AD stores intervals (maxPwdAge, lockoutDuration) as negative 100 ns ticks.
    public static func interval(_ ticks: Int64) -> TimeInterval { Double(-ticks) / 10_000_000 }
}

public enum ADBinary {
    public static func guid(_ d: Data) -> String? {
        guard d.count == 16 else { return nil }
        let b = [UInt8](d)
        let order = [3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15]
        return order.map { $0 < 0 ? "-" : String(format: "%02x", b[$0]) }.joined()
    }

    public static func sid(_ d: Data) -> String? {
        let b = [UInt8](d)
        guard b.count >= 8, b.count == 8 + Int(b[1]) * 4 else { return nil }
        let auth = b[2..<8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        var s = "S-\(b[0])-\(auth)"
        for i in 0..<Int(b[1]) {
            let o = 8 + i * 4
            s += "-\(UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24)"
        }
        return s
    }

    /// Binary SID with the last sub-authority replaced — domain SID + RID → primary group SID.
    public static func sid(domain: Data, rid: UInt32) -> Data {
        var b = [UInt8](domain)
        b[1] += 1
        b += [UInt8(rid & 0xff), UInt8(rid >> 8 & 0xff), UInt8(rid >> 16 & 0xff), UInt8(rid >> 24 & 0xff)]
        return Data(b)
    }

    /// Filter-escaped binary value: every byte as `\xx`.
    public static func filterValue(_ d: Data) -> String { d.map { String(format: "\\%02x", $0) }.joined() }

    public static func hex(_ d: Data, limit: Int = 64) -> String {
        let s = d.prefix(limit).map { String(format: "%02X", $0) }.joined(separator: " ")
        return d.count > limit ? s + " … (\(d.count) байт)" : s
    }

    /// `unicodePwd` value: the password in double quotes, UTF-16LE.
    public static func password(_ pw: String) -> Data {
        var d = Data()
        for u in "\"\(pw)\"".utf16 { d.append(UInt8(u & 0xff)); d.append(UInt8(u >> 8)) }
        return d
    }
}

public enum ADNames {
    /// pre-Windows 2000 computer name: ≤15 chars of letters, digits and hyphen.
    public static func isValidComputerName(_ s: String) -> Bool {
        !s.isEmpty && s.count <= 15 && s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
    }

    public static func initials(_ name: String) -> String {
        let words = name.split(whereSeparator: { $0 == " " || $0 == "." || $0 == "-" || $0 == "_" })
        return words.prefix(2).compactMap(\.first).map { String($0).uppercased() }.joined()
    }
}

/// Maps LDAP result codes + AD diagnostic strings to Russian text an admin can act on.
public enum ADErrorText {
    public static func describe(code: Int32, diagnostic: String) -> String {
        let d = diagnostic.lowercased()
        switch code {
        case 49:
            if d.contains("data 775") { return "Учётная запись заблокирована." }
            if d.contains("data 533") { return "Учётная запись отключена." }
            if d.contains("data 532") || d.contains("data 773") { return "Срок действия пароля истёк — смените его на Windows-машине или попросите коллегу сбросить." }
            if d.contains("data 701") { return "Срок действия учётной записи истёк." }
            return "Неверный логин или пароль. Проверьте раскладку и формат логина: user@corp.local или CORP\\user."
        case 50: return "Недостаточно прав для этой операции. Если это подразделение, оно может быть защищено от случайного удаления."
        case 19:
            if d.contains("0000052d") { return "Пароль не соответствует политике домена." }
            return "Значение нарушает ограничения схемы или политики AD."
        case 68: return "Объект с таким именем уже существует."
        case 32: return "Объект не найден — возможно, его уже удалили или переместили."
        case 66: return "Нельзя удалить: внутри есть другие объекты. Сначала удалите или перенесите их."
        case 53: return d.contains("0000001f") ? "Сервер отказался: операция требует защищённого соединения." : "Сервер отказался выполнять операцию."
        case 21: return "Недопустимый синтаксис значения атрибута."
        case 16: return "У объекта нет такого атрибута или значения."
        case 20: return "Такое значение уже есть у атрибута (например, пользователь уже состоит в группе)."
        case 17: return "Неизвестный атрибут — проверьте имя."
        case 65: return "Нарушение схемы: атрибут не допустим для этого типа объекта."
        case 4: return "Слишком много результатов — уточните запрос."
        case -1, 81: return "Сервер недоступен. Проверьте VPN, имя сервера и порт."
        case -5, 85: return "Сервер не ответил вовремя."
        case -11: return "Не удалось установить соединение."
        default: return "Ошибка LDAP \(code)."
        }
    }
}
