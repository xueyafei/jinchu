import Foundation

public enum ProxyType: String, Codable, CaseIterable, Identifiable {
    case ss, vmess, vless, trojan, hysteria2, socks, http
    public var id: String { rawValue }
    public var displayName: String {
        switch self {
        case .ss: return "Shadowsocks"
        case .vmess: return "VMess"
        case .vless: return "VLESS"
        case .trojan: return "Trojan"
        case .hysteria2: return "Hysteria2"
        case .socks: return "SOCKS5"
        case .http: return "HTTP"
        }
    }
    public var shortLabel: String {
        switch self {
        case .ss: return "SS"
        case .vmess: return "VM"
        case .vless: return "VL"
        case .trojan: return "TJ"
        case .hysteria2: return "HY2"
        case .socks: return "S5"
        case .http: return "HT"
        }
    }
}

public struct ProxyNode: Identifiable, Codable, Hashable, Equatable {
    public var id: UUID
    public var name: String
    public var type: ProxyType
    public var host: String
    public var port: Int
    public var password: String
    public var uuid: String
    public var method: String
    public var alterId: Int
    public var security: String
    public var network: String
    public var tls: Bool
    public var sni: String
    public var hostHeader: String
    public var path: String
    public var flow: String
    public var allowInsecure: Bool
    public var plugin: String
    public var pluginOpts: String
    public var username: String
    public var alpn: String
    public var obfs: String
    public var obfsPassword: String
    public var encryption: String
    public var serviceName: String
    public var fingerprint: String
    public var group: String
    public var subscriptionID: UUID?
    public var rawURI: String
    public var latencyMs: Int?
    public var extra: [String: String]

    public init(
        id: UUID = UUID(),
        name: String = "",
        type: ProxyType = .ss,
        host: String = "",
        port: Int = 443,
        password: String = "",
        uuid: String = "",
        method: String = "chacha20-ietf-poly1305",
        alterId: Int = 0,
        security: String = "",
        network: String = "tcp",
        tls: Bool = false,
        sni: String = "",
        hostHeader: String = "",
        path: String = "",
        flow: String = "",
        allowInsecure: Bool = false,
        plugin: String = "",
        pluginOpts: String = "",
        username: String = "",
        alpn: String = "",
        obfs: String = "",
        obfsPassword: String = "",
        encryption: String = "",
        serviceName: String = "",
        fingerprint: String = "",
        group: String = "默认",
        subscriptionID: UUID? = nil,
        rawURI: String = "",
        latencyMs: Int? = nil,
        extra: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.host = host
        self.port = port
        self.password = password
        self.uuid = uuid
        self.method = method
        self.alterId = alterId
        self.security = security
        self.network = network
        self.tls = tls
        self.sni = sni
        self.hostHeader = hostHeader
        self.path = path
        self.flow = flow
        self.allowInsecure = allowInsecure
        self.plugin = plugin
        self.pluginOpts = pluginOpts
        self.username = username
        self.alpn = alpn
        self.obfs = obfs
        self.obfsPassword = obfsPassword
        self.encryption = encryption
        self.serviceName = serviceName
        self.fingerprint = fingerprint
        self.group = group
        self.subscriptionID = subscriptionID
        self.rawURI = rawURI
        self.latencyMs = latencyMs
        self.extra = extra
    }

    public var displayTitle: String {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return n.isEmpty ? "\(host):\(port)" : n
    }

    public var endpoint: String { "\(host):\(port)" }

    public var supportsNativeOutbound: Bool {
        switch type {
        case .ss:
            return ["chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm"].contains(method)
                && plugin.isEmpty
        case .trojan:
            return network == "tcp" || network.isEmpty
        case .socks, .http:
            return true
        case .vmess, .vless, .hysteria2:
            return false
        }
    }
}

public struct Subscription: Identifiable, Codable, Hashable {
    public var id: UUID
    public var name: String
    public var url: String
    public var lastUpdate: Date?
    public var autoUpdate: Bool
    public var groupName: String

    public init(id: UUID = UUID(), name: String, url: String, lastUpdate: Date? = nil, autoUpdate: Bool = true, groupName: String? = nil) {
        self.id = id
        self.name = name
        self.url = url
        self.lastUpdate = lastUpdate
        self.autoUpdate = autoUpdate
        self.groupName = groupName ?? name
    }
}

public enum RulePolicy: String, Codable, CaseIterable, Identifiable {
    case proxy = "PROXY"
    case direct = "DIRECT"
    case reject = "REJECT"
    public var id: String { rawValue }
    public var zh: String {
        switch self {
        case .proxy: return "代理"
        case .direct: return "直连"
        case .reject: return "拒绝"
        }
    }
}

public enum RuleMatchType: String, Codable, CaseIterable, Identifiable {
    case domainSuffix = "DOMAIN-SUFFIX"
    case domainKeyword = "DOMAIN-KEYWORD"
    case domain = "DOMAIN"
    case ipCIDR = "IP-CIDR"
    case geoDummy = "FINAL"
    public var id: String { rawValue }
    public var zh: String {
        switch self {
        case .domainSuffix: return "域名后缀"
        case .domainKeyword: return "域名关键词"
        case .domain: return "完整域名"
        case .ipCIDR: return "IP CIDR"
        case .geoDummy: return "最终规则"
        }
    }
}

public struct ProxyRule: Identifiable, Codable, Hashable {
    public var id: UUID
    public var matchType: RuleMatchType
    public var pattern: String
    public var policy: RulePolicy
    public var enabled: Bool
    public var note: String

    public init(id: UUID = UUID(), matchType: RuleMatchType, pattern: String, policy: RulePolicy, enabled: Bool = true, note: String = "") {
        self.id = id
        self.matchType = matchType
        self.pattern = pattern
        self.policy = policy
        self.enabled = enabled
        self.note = note
    }
}

public enum ConnectMode: String, Codable, CaseIterable, Identifiable {
    case global, rule, direct
    public var id: String { rawValue }
    public var zh: String {
        switch self {
        case .global: return "全局"
        case .rule: return "规则"
        case .direct: return "直连"
        }
    }
    public var detail: String {
        switch self {
        case .global: return "全部流量走当前节点"
        case .rule: return "按规则分流（域名后缀 / 关键词 / CIDR）"
        case .direct: return "全部直连，不走节点"
        }
    }
}

public enum DNSMode: String, Codable, CaseIterable, Identifiable {
    case system, custom, doh
    public var id: String { rawValue }
    public var zh: String {
        switch self {
        case .system: return "系统 DNS"
        case .custom: return "自定义 DNS"
        case .doh: return "DoH（写入配置）"
        }
    }
}

public enum Appearance: String, Codable, CaseIterable, Identifiable {
    case dark, light, system
    public var id: String { rawValue }
    public var zh: String {
        switch self {
        case .dark: return "深色"
        case .light: return "浅色"
        case .system: return "跟随系统"
        }
    }
}

public struct AppSettings: Codable, Equatable {
    public var connectMode: ConnectMode
    public var bypassLAN: Bool
    public var dnsMode: DNSMode
    public var dnsServers: String
    public var dohURL: String
    public var appearance: Appearance
    public var selectedNodeID: UUID?

    public init(
        connectMode: ConnectMode = .rule,
        bypassLAN: Bool = true,
        dnsMode: DNSMode = .custom,
        dnsServers: String = "1.1.1.1,8.8.8.8",
        dohURL: String = "https://1.1.1.1/dns-query",
        appearance: Appearance = .dark,
        selectedNodeID: UUID? = nil
    ) {
        self.connectMode = connectMode
        self.bypassLAN = bypassLAN
        self.dnsMode = dnsMode
        self.dnsServers = dnsServers
        self.dohURL = dohURL
        self.appearance = appearance
        self.selectedNodeID = selectedNodeID
    }

    public var dnsServerList: [String] {
        dnsServers
            .split(whereSeparator: { $0 == "," || $0 == " " || $0 == ";" || $0 == "\n" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}

public struct TrafficSnapshot: Codable, Equatable {
    public var sessionUp: Int64
    public var sessionDown: Int64
    public var totalUp: Int64
    public var totalDown: Int64
    public var connectedAt: Date?
    public init(sessionUp: Int64 = 0, sessionDown: Int64 = 0, totalUp: Int64 = 0, totalDown: Int64 = 0, connectedAt: Date? = nil) {
        self.sessionUp = sessionUp
        self.sessionDown = sessionDown
        self.totalUp = totalUp
        self.totalDown = totalDown
        self.connectedAt = connectedAt
    }
}

public struct AppStoreFile: Codable {
    public var nodes: [ProxyNode]
    public var subscriptions: [Subscription]
    public var rules: [ProxyRule]
    public var settings: AppSettings
    public init(nodes: [ProxyNode] = [], subscriptions: [Subscription] = [], rules: [ProxyRule] = ProxyRule.starterChinaDirect, settings: AppSettings = AppSettings()) {
        self.nodes = nodes
        self.subscriptions = subscriptions
        self.rules = rules
        self.settings = settings
    }
}

public extension ProxyRule {
    static var starterChinaDirect: [ProxyRule] {
        let suffixes = [
            "cn", "com.cn", "gov.cn", "edu.cn", "net.cn", "org.cn",
            "qq.com", "baidu.com", "aliyun.com", "taobao.com", "tmall.com",
            "jd.com", "163.com", "126.com", "weixin.qq.com", "bilibili.com",
            "zhihu.com", "alipay.com", "aliyuncs.com", "tencent.com",
            "weibo.com", "iqiyi.com", "youku.com", "douban.com",
            "cctv.com", "12306.cn", "mi.com", "huawei.com", "xiaomi.com"
        ]
        var rules: [ProxyRule] = suffixes.map {
            ProxyRule(matchType: .domainSuffix, pattern: $0, policy: .direct, note: "国内直连（精简）")
        }
        rules.append(ProxyRule(matchType: .ipCIDR, pattern: "10.0.0.0/8", policy: .direct, note: "局域网"))
        rules.append(ProxyRule(matchType: .ipCIDR, pattern: "172.16.0.0/12", policy: .direct, note: "局域网"))
        rules.append(ProxyRule(matchType: .ipCIDR, pattern: "192.168.0.0/16", policy: .direct, note: "局域网"))
        rules.append(ProxyRule(matchType: .ipCIDR, pattern: "127.0.0.0/8", policy: .direct, note: "回环"))
        rules.append(ProxyRule(matchType: .ipCIDR, pattern: "169.254.0.0/16", policy: .direct, note: "链路本地"))
        rules.append(ProxyRule(matchType: .geoDummy, pattern: "*", policy: .proxy, note: "默认代理"))
        return rules
    }
}

public struct TunnelRuntimeConfig: Codable {
    public var node: ProxyNode?
    public var mode: ConnectMode
    public var bypassLAN: Bool
    public var rules: [ProxyRule]
    public var dnsMode: DNSMode
    public var dnsServers: [String]
    public var dohURL: String
    public var startedAt: Date
    public init(node: ProxyNode?, mode: ConnectMode, bypassLAN: Bool, rules: [ProxyRule], dnsMode: DNSMode, dnsServers: [String], dohURL: String, startedAt: Date = Date()) {
        self.node = node
        self.mode = mode
        self.bypassLAN = bypassLAN
        self.rules = rules
        self.dnsMode = dnsMode
        self.dnsServers = dnsServers
        self.dohURL = dohURL
        self.startedAt = startedAt
    }
}
