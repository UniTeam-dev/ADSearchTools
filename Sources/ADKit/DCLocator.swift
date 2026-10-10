import Foundation
import dnssd

/// Finds domain controllers the way Windows does: SRV `_ldap._tcp.dc._msdcs.<domain>`.
/// DC certificates usually name only the DC itself (lon-dc-04.corp.com), never the domain or a balancer alias,
/// so connecting to the domain name fails hostname verification — connecting to a located DC doesn't.
public enum DCLocator {
    public struct SRV: Equatable { public let priority: UInt16, weight: UInt16, port: UInt16, target: String }

    /// DC host names in SRV preference order (priority asc, then weight desc); empty if `domain` has no DC records.
    public static func controllers(for domain: String, timeout: TimeInterval = 3) -> [String] {
        let name = "_ldap._tcp.dc._msdcs.\(domain.trimmingCharacters(in: CharacterSet(charactersIn: ". ")))"
        var seen = Set<String>()
        return query(name, timeout: timeout)
            .sorted { ($0.priority, -Int($0.weight)) < ($1.priority, -Int($1.weight)) }
            .map(\.target)
            .filter { seen.insert($0.lowercased()).inserted }
    }

    private final class Box { var records: [SRV] = []; var done = false }

    static func query(_ name: String, timeout: TimeInterval) -> [SRV] {
        let box = Box()
        let ctx = Unmanaged.passUnretained(box).toOpaque()
        var ref: DNSServiceRef?
        let reply: DNSServiceQueryRecordReply = { _, flags, _, err, _, _, _, len, rdata, _, ctx in
            let box = Unmanaged<Box>.fromOpaque(ctx!).takeUnretainedValue()
            if err == kDNSServiceErr_NoError, let rdata, let srv = DCLocator.parse(Data(bytes: rdata, count: Int(len))) { box.records.append(srv) }
            if err != kDNSServiceErr_NoError || flags & kDNSServiceFlagsMoreComing == 0 { box.done = true }
        }
        guard DNSServiceQueryRecord(&ref, 0, 0, name, UInt16(kDNSServiceType_SRV), UInt16(kDNSServiceClass_IN), reply, ctx) == kDNSServiceErr_NoError,
              let ref else { return [] }
        defer { DNSServiceRefDeallocate(ref) }
        let deadline = Date().addingTimeInterval(timeout)
        var fds = pollfd(fd: DNSServiceRefSockFD(ref), events: Int16(POLLIN), revents: 0)
        while !box.done, Date() < deadline {
            let ms = Int32(max(1, deadline.timeIntervalSinceNow * 1000))
            guard poll(&fds, 1, ms) > 0, DNSServiceProcessResult(ref) == kDNSServiceErr_NoError else { break }
        }
        return box.records
    }

    /// SRV rdata: priority, weight, port (big-endian UInt16 each), then the target as uncompressed DNS labels.
    public static func parse(_ d: Data) -> SRV? {
        let b = [UInt8](d)
        guard b.count > 7 else { return nil }
        func u16(_ i: Int) -> UInt16 { UInt16(b[i]) << 8 | UInt16(b[i + 1]) }
        var labels: [String] = [], i = 6
        while i < b.count, b[i] != 0 {
            let n = Int(b[i])
            guard n < 64, i + 1 + n <= b.count else { return nil }
            labels.append(String(decoding: b[(i + 1)..<(i + 1 + n)], as: UTF8.self))
            i += 1 + n
        }
        guard !labels.isEmpty else { return nil }
        return SRV(priority: u16(0), weight: u16(2), port: u16(4), target: labels.joined(separator: "."))
    }
}
