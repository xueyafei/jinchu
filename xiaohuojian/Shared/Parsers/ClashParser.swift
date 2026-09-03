import Foundation

public enum ClashParser {
    public static func parse(_ text: String, group: String = "Clash") -> [ProxyNode] {
        let items = parseProxyMaps(text)
        return items.compactMap { clashMapToNode($0, group: group) }
    }

    static func parseProxyMaps(_ text: String) -> [[String: String]] {
        let lines = text.replacingOccurrences(of: "\t", with: "    ").components(separatedBy: .newlines)
        var inProxies = false
        var proxiesIndent: Int?
        var items: [[String: String]] = []
        var current: [String: String]?
        func flush() {
            if let c = current { items.append(c) }
            current = nil
        }
        for raw in lines {
            let stripped = raw.trimmingCharacters(in: .whitespaces)
            if stripped.isEmpty || stripped.hasPrefix("#") { continue }
            let indent = raw.prefix { $0 == " " }.count
            if !inProxies {
                if stripped == "proxies:" || stripped.hasPrefix("proxies:") {
                    inProxies = true
                    proxiesIndent = indent
                }
                continue
            }
            if let pi = proxiesIndent, indent <= pi, !stripped.hasPrefix("-") {
                flush()
                break
            }
            if stripped.hasPrefix("- ") || stripped == "-" {
                flush()
                current = [:]
                let after = stripped.dropFirst().trimmingCharacters(in: .whitespaces)
                if after.hasPrefix("{") {
                    for (k, v) in parseFlowMap(after) { current?[k] = v }
                } else if after.contains(":") {
                    let kv = splitKV(after)
                    current?[kv.0] = kv.1
                }
                continue
            }
            guard current != nil, stripped.contains(":") else { continue }
            let kv = splitKV(stripped)
            current?[kv.0] = kv.1
        }
        flush()
        return items
    }

    static func parseFlowMap(_ s0: String) -> [String: String] {
        var s = s0.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("{") && s.hasSuffix("}") {
            s = String(s.dropFirst().dropLast())
        }
        var out: [String: String] = [:]
        var cur = ""
        var quote: Character?
        for ch in s {
            if let q = quote {
                cur.append(ch)
                if ch == q { quote = nil }
                continue
            }
            if ch == "\"" || ch == "'" {
                quote = ch
                cur.append(ch)
                continue
            }
            if ch == "," {
                if cur.contains(":") {
                    let kv = splitKV(cur)
                    out[kv.0] = kv.1
                }
                cur = ""
            } else {
                cur.append(ch)
            }
        }
        let t = cur.trimmingCharacters(in: .whitespaces)
        if !t.isEmpty, t.contains(":") {
            let kv = splitKV(t)
            out[kv.0] = kv.1
        }
        return out
    }

    static func splitKV(_ s: String) -> (String, String) {
        guard let idx = s.firstIndex(of: ":") else { return (s.trimmingCharacters(in: .whitespaces), "") }
        let k = String(s[..<idx]).trimmingCharacters(in: .whitespaces)
        var v = String(s[s.index(after: idx)...]).trimmingCharacters(in: .whitespaces)
        if v == "|" || v == ">" { v = "" }
        v = unquote(v)
        return (k, v)
    }

    static func unquote(_ s0: String) -> String {
        var s = s0.trimmingCharacters(in: .whitespaces)
        if let r = s.range(of: " #") { s = String(s[..<r.lowerBound]).trimmingCharacters(in: .whitespaces) }
        if s.count >= 2 {
            if (s.hasPrefix("\"") && s.hasSuffix("\"")) || (s.hasPrefix("'") && s.hasSuffix("'")) {
                let inner = String(s.dropFirst().dropLast())
                if s.hasPrefix("\"") {
                    return inner.replacingOccurrences(of: "\\\"", with: "\"").replacingOccurrences(of: "\\n", with: "\n")
                }
                return inner
            }
        }
        return s
    }

    public static func clashMapToNode(_ p: [String: String], group: String) -> ProxyNode? {
        let t = (p["type"] ?? "").lowercased().trimmingCharacters(in: .whitespaces)
        let name = p["name"] ?? ""
        let host = p["server"] ?? p["host"] ?? ""
        let port = Int(p["port"] ?? "") ?? 0
        if t.isEmpty || host.isEmpty || port <= 0 { return nil }
        let tls = ["true", "1", "yes"].contains((p["tls"] ?? "").lowercased())
        let skip = ["true", "1", "yes"].contains((p["skip-cert-verify"] ?? p["skip_cert_verify"] ?? "").lowercased())
        let network = p["network"] ?? p["net"] ?? "tcp"
        let sni = p["sni"] ?? p["servername"] ?? p["server-name"] ?? ""
        let path = p["path"] ?? ""
        let hostHeader = p["ws-host"] ?? ""

        switch t {
        case "ss", "shadowsocks":
            return ProxyNode(name: name.isEmpty ? "\(host):\(port)" : name, type: .ss, host: host, port: port,
                             password: p["password"] ?? "", method: p["cipher"] ?? p["method"] ?? "",
                             plugin: p["plugin"] ?? "", pluginOpts: p["plugin-opts"] ?? p["plugin_opts"] ?? "",
                             group: group)
        case "vmess":
            let uuid = p["uuid"] ?? ""
            let aid = Int(p["alterId"] ?? p["alterid"] ?? "0") ?? 0
            return ProxyNode(name: name.isEmpty ? "\(host):\(port)" : name, type: .vmess, host: host, port: port,
                             password: uuid, uuid: uuid, method: p["cipher"] ?? p["security"] ?? "auto",
                             alterId: aid, security: p["cipher"] ?? p["security"] ?? "auto",
                             network: network, tls: tls, sni: sni, hostHeader: hostHeader, path: path,
                             allowInsecure: skip, group: group)
        case "vless":
            let uuid = p["uuid"] ?? ""
            return ProxyNode(name: name.isEmpty ? "\(host):\(port)" : name, type: .vless, host: host, port: port,
                             password: uuid, uuid: uuid, security: tls ? "tls" : "none",
                             network: network, tls: tls, sni: sni, hostHeader: hostHeader, path: path,
                             flow: p["flow"] ?? "", allowInsecure: skip, encryption: p["encryption"] ?? "none",
                             group: group)
        case "trojan":
            return ProxyNode(name: name.isEmpty ? "\(host):\(port)" : name, type: .trojan, host: host, port: port,
                             password: p["password"] ?? "", network: network, tls: true, sni: sni,
                             hostHeader: hostHeader, path: path, allowInsecure: skip, group: group)
        case "hysteria2", "hy2":
            return ProxyNode(name: name.isEmpty ? "\(host):\(port)" : name, type: .hysteria2, host: host, port: port,
                             password: p["password"] ?? p["auth"] ?? "", tls: true, sni: sni,
                             allowInsecure: skip, obfs: p["obfs"] ?? "", obfsPassword: p["obfs-password"] ?? "",
                             group: group)
        case "socks", "socks5":
            return ProxyNode(name: name.isEmpty ? "\(host):\(port)" : name, type: .socks, host: host, port: port,
                             password: p["password"] ?? "", username: p["username"] ?? p["user"] ?? "", group: group)
        case "http", "https":
            return ProxyNode(name: name.isEmpty ? "\(host):\(port)" : name, type: .http, host: host, port: port,
                             password: p["password"] ?? "", tls: t == "https" || tls,
                             username: p["username"] ?? "", group: group)
        default:
            return nil
        }
    }
}
