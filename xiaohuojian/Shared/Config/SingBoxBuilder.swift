import Foundation

/// Builds a sing-box 1.8+ JSON config from the selected node + rules.
/// VMess / VLESS / Hysteria2 are emitted here even when the v1 Swift data path
/// cannot originate those protocols yet — drop in libbox later and load this file.
public enum SingBoxBuilder {
    public static func build(config: TunnelRuntimeConfig) -> String {
        var root: [String: Any] = [
            "log": ["level": "warn", "timestamp": true],
            "inbounds": [tunInbound()],
            "outbounds": outbounds(config),
            "route": route(config)
        ]
        root["dns"] = dns(config)
        if JSONSerialization.isValidJSONObject(root),
           let data = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "{}"
    }

    static func tunInbound() -> [String: Any] {
        [
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "utun",
            "address": ["198.18.0.1/16"],
            "mtu": 9000,
            "auto_route": true,
            "strict_route": true,
            "stack": "system",
            "sniff": true
        ]
    }

    static func dns(_ cfg: TunnelRuntimeConfig) -> [String: Any] {
        var servers: [[String: Any]] = []
        if cfg.dnsMode == .doh, !cfg.dohURL.isEmpty {
            servers.append(["tag": "doh", "address": cfg.dohURL, "detour": "proxy"])
        }
        for (i, s) in cfg.dnsServers.enumerated() {
            servers.append(["tag": "dns-\(i)", "address": s])
        }
        if servers.isEmpty {
            servers.append(["tag": "dns-0", "address": "1.1.1.1"])
        }
        return [
            "servers": servers,
            "strategy": "ipv4_only"
        ]
    }

    static func outbounds(_ cfg: TunnelRuntimeConfig) -> [[String: Any]] {
        var list: [[String: Any]] = []
        if let n = cfg.node {
            list.append(outbound(n))
        } else {
            list.append(["type": "direct", "tag": "proxy"])
        }
        list.append(["type": "direct", "tag": "direct"])
        list.append(["type": "block", "tag": "block"])
        list.append(["type": "dns", "tag": "dns-out"])
        return list
    }

    public static func outbound(_ n: ProxyNode) -> [String: Any] {
        switch n.type {
        case .ss:
            var o: [String: Any] = [
                "type": "shadowsocks",
                "tag": "proxy",
                "server": n.host,
                "server_port": n.port,
                "method": n.method,
                "password": n.password
            ]
            if !n.plugin.isEmpty {
                o["plugin"] = n.plugin
                o["plugin_opts"] = n.pluginOpts
            }
            return o
        case .trojan:
            var o: [String: Any] = [
                "type": "trojan",
                "tag": "proxy",
                "server": n.host,
                "server_port": n.port,
                "password": n.password
            ]
            o["tls"] = tlsObject(n)
            if n.network == "ws" {
                o["transport"] = ["type": "ws", "path": n.path, "headers": ["Host": n.hostHeader]]
            }
            return o
        case .vmess:
            var o: [String: Any] = [
                "type": "vmess",
                "tag": "proxy",
                "server": n.host,
                "server_port": n.port,
                "uuid": n.uuid,
                "security": n.security.isEmpty ? "auto" : n.security,
                "alter_id": n.alterId
            ]
            if n.tls { o["tls"] = tlsObject(n) }
            o["transport"] = transport(n)
            return o
        case .vless:
            var o: [String: Any] = [
                "type": "vless",
                "tag": "proxy",
                "server": n.host,
                "server_port": n.port,
                "uuid": n.uuid
            ]
            if !n.flow.isEmpty { o["flow"] = n.flow }
            if n.tls || n.security == "reality" || n.security == "tls" {
                o["tls"] = tlsObject(n)
            }
            o["transport"] = transport(n)
            return o
        case .hysteria2:
            var o: [String: Any] = [
                "type": "hysteria2",
                "tag": "proxy",
                "server": n.host,
                "server_port": n.port,
                "password": n.password,
                "tls": tlsObject(n)
            ]
            if !n.obfs.isEmpty {
                o["obfs"] = ["type": n.obfs, "password": n.obfsPassword]
            }
            return o
        case .socks:
            var o: [String: Any] = [
                "type": "socks",
                "tag": "proxy",
                "server": n.host,
                "server_port": n.port,
                "version": "5"
            ]
            if !n.username.isEmpty {
                o["username"] = n.username
                o["password"] = n.password
            }
            return o
        case .http:
            var o: [String: Any] = [
                "type": "http",
                "tag": "proxy",
                "server": n.host,
                "server_port": n.port
            ]
            if !n.username.isEmpty {
                o["username"] = n.username
                o["password"] = n.password
            }
            if n.tls { o["tls"] = tlsObject(n) }
            return o
        }
    }

    static func tlsObject(_ n: ProxyNode) -> [String: Any] {
        var t: [String: Any] = [
            "enabled": true,
            "insecure": n.allowInsecure
        ]
        if !n.sni.isEmpty { t["server_name"] = n.sni }
        if !n.alpn.isEmpty { t["alpn"] = n.alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
        if n.security == "reality" {
            t["reality"] = ["enabled": true]
        }
        if !n.fingerprint.isEmpty { t["utls"] = ["enabled": true, "fingerprint": n.fingerprint] }
        return t
    }

    static func transport(_ n: ProxyNode) -> [String: Any] {
        switch n.network {
        case "ws":
            var headers: [String: String] = [:]
            if !n.hostHeader.isEmpty { headers["Host"] = n.hostHeader }
            return ["type": "ws", "path": n.path.isEmpty ? "/" : n.path, "headers": headers]
        case "grpc":
            return ["type": "grpc", "service_name": n.serviceName]
        case "h2", "http":
            return ["type": "http", "path": n.path, "host": [n.hostHeader]]
        default:
            return ["type": "tcp"]
        }
    }

    static func route(_ cfg: TunnelRuntimeConfig) -> [String: Any] {
        var rules: [[String: Any]] = [
            ["protocol": "dns", "outbound": "dns-out"]
        ]
        if cfg.bypassLAN {
            rules.append(["ip_is_private": true, "outbound": "direct"])
        }
        var domainSuffix: [String] = []
        var domainKeyword: [String] = []
        var domainFull: [String] = []
        var cidrDirect: [String] = []
        var domainSuffixProxy: [String] = []
        var rejectSuffix: [String] = []
        for r in cfg.rules where r.enabled {
            switch (r.matchType, r.policy) {
            case (.domainSuffix, .direct): domainSuffix.append(r.pattern)
            case (.domainKeyword, .direct): domainKeyword.append(r.pattern)
            case (.domain, .direct): domainFull.append(r.pattern)
            case (.ipCIDR, .direct): cidrDirect.append(r.pattern)
            case (.domainSuffix, .proxy): domainSuffixProxy.append(r.pattern)
            case (.domainSuffix, .reject): rejectSuffix.append(r.pattern)
            default: break
            }
        }
        if !domainSuffix.isEmpty { rules.append(["domain_suffix": domainSuffix, "outbound": "direct"]) }
        if !domainKeyword.isEmpty { rules.append(["domain_keyword": domainKeyword, "outbound": "direct"]) }
        if !domainFull.isEmpty { rules.append(["domain": domainFull, "outbound": "direct"]) }
        if !cidrDirect.isEmpty { rules.append(["ip_cidr": cidrDirect, "outbound": "direct"]) }
        if !domainSuffixProxy.isEmpty { rules.append(["domain_suffix": domainSuffixProxy, "outbound": "proxy"]) }
        if !rejectSuffix.isEmpty { rules.append(["domain_suffix": rejectSuffix, "outbound": "block"]) }

        let fallback: String
        switch cfg.mode {
        case .global: fallback = "proxy"
        case .direct: fallback = "direct"
        case .rule: fallback = "proxy"
        }
        return [
            "rules": rules,
            "final": fallback,
            "auto_detect_interface": true
        ]
    }
}
