import Foundation

public struct CIDR {
    public let network: UInt32
    public let prefix: Int
    public init?(string: String) {
        let parts = string.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              let ip = IPv4.parse(String(parts[0])) else { return nil }
        let mask: UInt32 = prefix == 0 ? 0 : (UInt32.max << (32 - prefix))
        self.network = ip & mask
        self.prefix = prefix
    }
    public func contains(_ ip: UInt32) -> Bool {
        let mask: UInt32 = prefix == 0 ? 0 : (UInt32.max << (32 - prefix))
        return (ip & mask) == network
    }
}

public enum IPv4 {
    public static func parse(_ s: String) -> UInt32? {
        let p = s.split(separator: ".")
        guard p.count == 4 else { return nil }
        var v: UInt32 = 0
        for x in p {
            guard let o = UInt32(x), o <= 255 else { return nil }
            v = (v << 8) | o
        }
        return v
    }
    public static func stringify(_ v: UInt32) -> String {
        "\((v >> 24) & 0xff).\((v >> 16) & 0xff).\((v >> 8) & 0xff).\(v & 0xff)"
    }
    public static let lanCIDRs: [CIDR] = [
        CIDR(string: "10.0.0.0/8"),
        CIDR(string: "172.16.0.0/12"),
        CIDR(string: "192.168.0.0/16"),
        CIDR(string: "127.0.0.0/8"),
        CIDR(string: "169.254.0.0/16"),
        CIDR(string: "224.0.0.0/4"),
        CIDR(string: "255.255.255.255/32")
    ].compactMap { $0 }

    public static func isLAN(_ ip: UInt32) -> Bool {
        lanCIDRs.contains { $0.contains(ip) }
    }
}

public struct RuleEngine {
    public let mode: ConnectMode
    public let bypassLAN: Bool
    public let rules: [ProxyRule]
    private let cidrs: [(CIDR, RulePolicy)]
    private let suffixes: [(String, RulePolicy)]
    private let keywords: [(String, RulePolicy)]
    private let domains: [(String, RulePolicy)]
    private let finalPolicy: RulePolicy

    public init(mode: ConnectMode, bypassLAN: Bool, rules: [ProxyRule]) {
        self.mode = mode
        self.bypassLAN = bypassLAN
        self.rules = rules.filter(\.enabled)
        var cidrs: [(CIDR, RulePolicy)] = []
        var suffixes: [(String, RulePolicy)] = []
        var keywords: [(String, RulePolicy)] = []
        var domains: [(String, RulePolicy)] = []
        var fin: RulePolicy = .proxy
        for r in self.rules {
            switch r.matchType {
            case .ipCIDR:
                if let c = CIDR(string: r.pattern) { cidrs.append((c, r.policy)) }
            case .domainSuffix:
                suffixes.append((r.pattern.lowercased().trimmingCharacters(in: .whitespaces), r.policy))
            case .domainKeyword:
                keywords.append((r.pattern.lowercased(), r.policy))
            case .domain:
                domains.append((r.pattern.lowercased(), r.policy))
            case .geoDummy:
                fin = r.policy
            }
        }
        self.cidrs = cidrs
        self.suffixes = suffixes
        self.keywords = keywords
        self.domains = domains
        self.finalPolicy = fin
    }

    public func policy(host: String?, ip: UInt32?) -> RulePolicy {
        switch mode {
        case .global:
            if bypassLAN, let ip, IPv4.isLAN(ip) { return .direct }
            return .proxy
        case .direct:
            return .direct
        case .rule:
            if bypassLAN, let ip, IPv4.isLAN(ip) { return .direct }
            if let ip {
                for (c, p) in cidrs where c.contains(ip) { return p }
            }
            if let host {
                let h = host.lowercased()
                for (d, p) in domains where h == d { return p }
                for (s, p) in suffixes {
                    if h == s || h.hasSuffix("." + s) { return p }
                }
                for (k, p) in keywords where h.contains(k) { return p }
            }
            return finalPolicy
        }
    }
}
