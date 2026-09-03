import Foundation

public enum URIParseError: Error, LocalizedError {
    case empty
    case unsupportedScheme(String)
    case malformed(String)
    case missingHostPort
    public var errorDescription: String? {
        switch self {
        case .empty: return "链接为空"
        case .unsupportedScheme(let s): return "不支持的协议：\(s)"
        case .malformed(let s): return "无法解析：\(s)"
        case .missingHostPort: return "缺少主机或端口"
        }
    }
}

public enum ProxyURIParser {
    public static func parse(_ uri: String) throws -> ProxyNode {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed.hasPrefix("#") { throw URIParseError.empty }
        guard let scheme = trimmed.split(separator: ":", maxSplits: 1).first.map(String.init)?.lowercased() else {
            throw URIParseError.empty
        }
        let node: ProxyNode
        switch scheme {
        case "ss": node = try parseSS(trimmed)
        case "vmess": node = try parseVMess(trimmed)
        case "vless": node = try parseVLESS(trimmed)
        case "trojan", "trojan-go": node = try parseTrojan(trimmed)
        case "hysteria2", "hy2": node = try parseHysteria2(trimmed)
        case "socks", "socks5", "socks5h": node = try parseSOCKS(trimmed)
        case "http", "https": node = try parseHTTP(trimmed)
        default: throw URIParseError.unsupportedScheme(scheme)
        }
        if node.host.isEmpty || node.port <= 0 { throw URIParseError.missingHostPort }
        return node
    }

    public static func parseMany(_ text: String) -> [ProxyNode] {
        var out: [ProxyNode] = []
        for rawLine in text.replacingOccurrences(of: "\r", with: "\n").components(separatedBy: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if let n = try? parse(line) { out.append(n) }
        }
        return out
    }

    public static func encode(_ node: ProxyNode) -> String {
        switch node.type {
        case .ss: return encodeSS(node)
        case .vmess: return encodeVMess(node)
        case .vless: return encodeVLESS(node)
        case .trojan: return encodeTrojan(node)
        case .hysteria2: return encodeHysteria2(node)
        case .socks: return encodeSOCKS(node)
        case .http: return encodeHTTP(node)
        }
    }

    // MARK: - helpers

    static func splitFragment(_ uri: String) -> (String, String) {
        guard let idx = uri.firstIndex(of: "#") else { return (uri, "") }
        let body = String(uri[..<idx])
        let frag = String(uri[uri.index(after: idx)...])
        return (body, frag.removingPercentEncoding ?? frag)
    }

    static func parseQuery(_ qs: String) -> [String: String] {
        var s = qs
        if s.hasPrefix("?") { s.removeFirst() }
        var out: [String: String] = [:]
        guard let items = URLComponents(string: "x://x?\(s)")?.queryItems else {
            for pair in s.split(separator: "&") {
                let p = pair.split(separator: "=", maxSplits: 1).map(String.init)
                if p.count == 2 {
                    out[p[0]] = p[1].removingPercentEncoding ?? p[1]
                } else if p.count == 1 {
                    out[p[0]] = ""
                }
            }
            return out
        }
        for it in items {
            out[it.name] = it.value ?? ""
        }
        return out
    }

    static func splitUserHost(_ rest: String) -> (userinfo: String?, hostport: String, query: String) {
        var r = rest
        var query = ""
        if let q = r.firstIndex(of: "?") {
            query = String(r[r.index(after: q)...])
            r = String(r[..<q])
        }
        if let at = r.lastIndex(of: "@") {
            return (String(r[..<at]), String(r[r.index(after: at)...]), query)
        }
        return (nil, r, query)
    }

    static func parseHostPort(_ hostport: String, defaultPort: Int? = nil) throws -> (String, Int) {
        var hp = hostport.trimmingCharacters(in: .whitespaces)
        if hp.hasPrefix("[") {
            guard let rb = hp.firstIndex(of: "]") else { throw URIParseError.malformed("ipv6") }
            let host = String(hp[hp.index(after: hp.startIndex)..<rb])
            let after = String(hp[hp.index(after: rb)...])
            if after.hasPrefix(":"), let p = Int(after.dropFirst()) { return (host, p) }
            if let d = defaultPort { return (host, d) }
            throw URIParseError.missingHostPort
        }
        if let colon = hp.lastIndex(of: ":") {
            let host = String(hp[..<colon])
            let ps = String(hp[hp.index(after: colon)...])
            if let p = Int(ps) { return (host, p) }
        }
        if let d = defaultPort { return (hp, d) }
        throw URIParseError.missingHostPort
    }

    static func looksLikeCipher(_ method: String) -> Bool {
        let m = method.lowercased()
        if m.contains("-") || m.contains("gcm") || m.contains("poly") || m.contains("chacha") || m.contains("aes") { return true }
        return ["rc4", "table", "none", "plain"].contains(m)
    }

    // MARK: SS

    static func parseSS(_ uri: String) throws -> ProxyNode {
        let (body, name0) = splitFragment(uri)
        guard body.lowercased().hasPrefix("ss://") else { throw URIParseError.malformed("ss") }
        var rest = String(body.dropFirst(5))
        var plugin = ""
        var pluginOpts = ""
        if let q = rest.firstIndex(of: "?") {
            let qs = String(rest[rest.index(after: q)...])
            rest = String(rest[..<q])
            let params = parseQuery(qs)
            if var p = params["plugin"], !p.isEmpty {
                if let semi = p.firstIndex(of: ";") {
                    plugin = String(p[..<semi])
                    pluginOpts = String(p[p.index(after: semi)...])
                } else {
                    plugin = p
                }
            }
        }
        var method = ""
        var password = ""
        var hostport: String
        if let at = rest.lastIndex(of: "@") {
            let userinfo = String(rest[..<at])
            hostport = String(rest[rest.index(after: at)...])
            let decoded = Data.xhjBase64(userinfo.removingPercentEncoding ?? userinfo).flatMap { String(data: $0, encoding: .utf8) }
            let unquoted = userinfo.removingPercentEncoding ?? userinfo
            if let decoded, decoded.contains(":"),
               (looksLikeCipher(decoded.split(separator: ":", maxSplits: 1).map(String.init).first ?? "")),
               (!unquoted.contains(":") || userinfo.range(of: "^[A-Za-z0-9_\\-+/=]+$", options: .regularExpression) != nil) {
                let parts = decoded.split(separator: ":", maxSplits: 1).map(String.init)
                method = parts[0]
                password = parts.count > 1 ? parts[1] : ""
            } else if unquoted.contains(":") {
                let parts = unquoted.split(separator: ":", maxSplits: 1).map(String.init)
                method = parts[0]
                password = parts.count > 1 ? parts[1] : ""
            } else if let decoded, decoded.contains(":") {
                let parts = decoded.split(separator: ":", maxSplits: 1).map(String.init)
                method = parts[0]
                password = parts.count > 1 ? parts[1] : ""
            } else {
                throw URIParseError.malformed("ss userinfo")
            }
        } else {
            guard let blobData = Data.xhjBase64(rest.removingPercentEncoding ?? rest),
                  let blob = String(data: blobData, encoding: .utf8),
                  let at = blob.lastIndex(of: "@") else {
                throw URIParseError.malformed("ss legacy")
            }
            let userinfo = String(blob[..<at])
            hostport = String(blob[blob.index(after: at)...])
            let parts = userinfo.split(separator: ":", maxSplits: 1).map(String.init)
            if parts.count < 2 { throw URIParseError.malformed("ss method") }
            method = parts[0]
            password = parts[1]
        }
        let (host, port) = try parseHostPort(hostport)
        var node = ProxyNode(name: name0.isEmpty ? "\(host):\(port)" : name0, type: .ss, host: host, port: port, password: password, method: method, plugin: plugin, pluginOpts: pluginOpts, rawURI: uri)
        return node
    }

    static func encodeSS(_ n: ProxyNode) -> String {
        let user = "\(n.method):\(n.password)"
        let b64 = Data(user.utf8).base64URLEncoded()
        let hp: String
        if n.host.contains(":"), !n.host.hasPrefix("[") {
            hp = "[\(n.host)]:\(n.port)"
        } else {
            hp = "\(n.host):\(n.port)"
        }
        var uri = "ss://\(b64)@\(hp)"
        if !n.plugin.isEmpty {
            var p = n.plugin
            if !n.pluginOpts.isEmpty { p += ";\(n.pluginOpts)" }
            uri += "?plugin=\(p.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? p)"
        }
        if !n.name.isEmpty {
            uri += "#\(n.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? n.name)"
        }
        return uri
    }

    // MARK: VMess

    static func parseVMess(_ uri: String) throws -> ProxyNode {
        let (body, frag) = splitFragment(uri)
        guard body.lowercased().hasPrefix("vmess://") else { throw URIParseError.malformed("vmess") }
        let payload = String(body.dropFirst(8))
        guard let data = Data.xhjBase64(payload),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URIParseError.malformed("vmess json")
        }
        func str(_ keys: String...) -> String {
            for k in keys {
                if let v = obj[k] { return String(describing: v) }
            }
            return ""
        }
        let tlsField = str("tls").lowercased()
        let tls = ["tls", "true", "1", "xtls", "reality"].contains(tlsField)
        let add = str("add", "server")
        let hostHeader = str("host")
        let host = add.isEmpty ? hostHeader : add
        let port = Int(str("port")) ?? 443
        let uuid = str("id", "uuid")
        let aid = Int(str("aid")) ?? 0
        let name = str("ps", "remarks").isEmpty ? (frag.isEmpty ? "\(host):\(port)" : frag) : str("ps", "remarks")
        var node = ProxyNode(
            name: name, type: .vmess, host: host, port: port, password: uuid, uuid: uuid,
            method: str("scy", "security").isEmpty ? "auto" : str("scy", "security"),
            alterId: aid, security: str("scy", "security").isEmpty ? "auto" : str("scy", "security"),
            network: str("net", "network").isEmpty ? "tcp" : str("net", "network"),
            tls: tls, sni: str("sni"), hostHeader: hostHeader, path: str("path"), alpn: str("alpn"),
            rawURI: uri
        )
        return node
    }

    static func encodeVMess(_ n: ProxyNode) -> String {
        let obj: [String: Any] = [
            "v": "2",
            "ps": n.name,
            "add": n.host,
            "port": String(n.port),
            "id": n.uuid.isEmpty ? n.password : n.uuid,
            "aid": String(n.alterId),
            "scy": n.security.isEmpty ? n.method : n.security,
            "net": n.network.isEmpty ? "tcp" : n.network,
            "type": "none",
            "host": n.hostHeader,
            "path": n.path,
            "tls": n.tls ? "tls" : "",
            "sni": n.sni,
            "alpn": n.alpn
        ]
        let data = try! JSONSerialization.data(withJSONObject: obj, options: [])
        return "vmess://" + data.base64EncodedString()
    }

    // MARK: VLESS

    static func parseVLESS(_ uri: String) throws -> ProxyNode {
        let (body, name0) = splitFragment(uri)
        guard body.lowercased().hasPrefix("vless://") else { throw URIParseError.malformed("vless") }
        let rest = String(body.dropFirst(8))
        let parts = splitUserHost(rest)
        guard let user = parts.userinfo else { throw URIParseError.malformed("vless @") }
        let uuid = user.removingPercentEncoding ?? user
        let (host, port) = try parseHostPort(parts.hostport)
        let params = parseQuery(parts.query)
        let security = params["security"] ?? "none"
        let tls = ["tls", "xtls", "reality"].contains(security.lowercased())
        let name = name0.isEmpty ? (params["remarks"] ?? "\(host):\(port)") : name0
        return ProxyNode(
            name: name, type: .vless, host: host, port: port, password: uuid, uuid: uuid,
            security: security, network: params["type"] ?? "tcp", tls: tls,
            sni: params["sni"] ?? params["peer"] ?? "",
            hostHeader: params["host"] ?? "", path: params["path"] ?? "",
            flow: params["flow"] ?? "",
            allowInsecure: ["1", "true", "True"].contains(params["allowInsecure"] ?? "0"),
            alpn: params["alpn"] ?? "", encryption: params["encryption"] ?? "none",
            serviceName: params["serviceName"] ?? "", fingerprint: params["fp"] ?? "",
            rawURI: uri
        )
    }

    static func encodeVLESS(_ n: ProxyNode) -> String {
        let hp = (n.host.contains(":") && !n.host.hasPrefix("[")) ? "[\(n.host)]:\(n.port)" : "\(n.host):\(n.port)"
        var q: [String: String] = [
            "type": n.network.isEmpty ? "tcp" : n.network,
            "security": n.security.isEmpty ? (n.tls ? "tls" : "none") : n.security,
            "encryption": n.encryption.isEmpty ? "none" : n.encryption
        ]
        if !n.sni.isEmpty { q["sni"] = n.sni }
        if !n.hostHeader.isEmpty { q["host"] = n.hostHeader }
        if !n.path.isEmpty { q["path"] = n.path }
        if !n.flow.isEmpty { q["flow"] = n.flow }
        if n.allowInsecure { q["allowInsecure"] = "1" }
        if !n.alpn.isEmpty { q["alpn"] = n.alpn }
        if !n.serviceName.isEmpty { q["serviceName"] = n.serviceName }
        if !n.fingerprint.isEmpty { q["fp"] = n.fingerprint }
        var comp = URLComponents()
        comp.queryItems = q.filter { !$0.value.isEmpty }.map { URLQueryItem(name: $0.key, value: $0.value) }
        let qs = comp.percentEncodedQuery.map { "?\($0)" } ?? ""
        var uri = "vless://\(n.uuid.isEmpty ? n.password : n.uuid)@\(hp)\(qs)"
        if !n.name.isEmpty {
            uri += "#\(n.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? n.name)"
        }
        return uri
    }

    // MARK: Trojan

    static func parseTrojan(_ uri: String) throws -> ProxyNode {
        let (body, name0) = splitFragment(uri)
        let rest: String
        if body.lowercased().hasPrefix("trojan-go://") {
            rest = String(body.dropFirst("trojan-go://".count))
        } else if body.lowercased().hasPrefix("trojan://") {
            rest = String(body.dropFirst("trojan://".count))
        } else {
            throw URIParseError.malformed("trojan")
        }
        let parts = splitUserHost(rest)
        guard let user = parts.userinfo else { throw URIParseError.malformed("trojan @") }
        let password = user.removingPercentEncoding ?? user
        let (host, port) = try parseHostPort(parts.hostport)
        let params = parseQuery(parts.query)
        let name = name0.isEmpty ? (params["remarks"] ?? "\(host):\(port)") : name0
        let insecure = ["1", "true", "True"].contains(params["allowInsecure"] ?? "0")
            || ["1", "true"].contains(params["skipVerify"] ?? "0")
        return ProxyNode(
            name: name, type: .trojan, host: host, port: port, password: password,
            security: params["security"] ?? "tls",
            network: params["type"] ?? params["network"] ?? "tcp",
            tls: true, sni: params["sni"] ?? params["peer"] ?? "",
            hostHeader: params["host"] ?? "", path: params["path"] ?? "",
            allowInsecure: insecure, alpn: params["alpn"] ?? "", rawURI: uri
        )
    }

    static func encodeTrojan(_ n: ProxyNode) -> String {
        let hp = (n.host.contains(":") && !n.host.hasPrefix("[")) ? "[\(n.host)]:\(n.port)" : "\(n.host):\(n.port)"
        var q: [String: String] = ["security": "tls", "type": n.network.isEmpty ? "tcp" : n.network]
        if !n.sni.isEmpty { q["sni"] = n.sni }
        if n.allowInsecure { q["allowInsecure"] = "1" }
        if !n.hostHeader.isEmpty { q["host"] = n.hostHeader }
        if !n.path.isEmpty { q["path"] = n.path }
        if !n.alpn.isEmpty { q["alpn"] = n.alpn }
        var comp = URLComponents()
        comp.queryItems = q.map { URLQueryItem(name: $0.key, value: $0.value) }
        let qs = comp.percentEncodedQuery.map { "?\($0)" } ?? ""
        let pw = n.password.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? n.password
        var uri = "trojan://\(pw)@\(hp)\(qs)"
        if !n.name.isEmpty {
            uri += "#\(n.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? n.name)"
        }
        return uri
    }

    // MARK: Hysteria2

    static func parseHysteria2(_ uri: String) throws -> ProxyNode {
        let (body, name0) = splitFragment(uri)
        let rest: String
        if body.lowercased().hasPrefix("hysteria2://") {
            rest = String(body.dropFirst("hysteria2://".count))
        } else if body.lowercased().hasPrefix("hy2://") {
            rest = String(body.dropFirst("hy2://".count))
        } else {
            throw URIParseError.malformed("hy2")
        }
        let parts = splitUserHost(rest)
        guard let user = parts.userinfo else { throw URIParseError.malformed("hy2 @") }
        let password = user.removingPercentEncoding ?? user
        let (host, port) = try parseHostPort(parts.hostport, defaultPort: 443)
        let params = parseQuery(parts.query)
        let name = name0.isEmpty ? "\(host):\(port)" : name0
        return ProxyNode(
            name: name, type: .hysteria2, host: host, port: port, password: password,
            tls: true, sni: params["sni"] ?? "",
            allowInsecure: ["1", "true", "True"].contains(params["insecure"] ?? "0"),
            alpn: params["alpn"] ?? "",
            obfs: params["obfs"] ?? "",
            obfsPassword: params["obfs-password"] ?? params["obfsPassword"] ?? "",
            rawURI: uri
        )
    }

    static func encodeHysteria2(_ n: ProxyNode) -> String {
        let hp = (n.host.contains(":") && !n.host.hasPrefix("[")) ? "[\(n.host)]:\(n.port)" : "\(n.host):\(n.port)"
        var q: [String: String] = [:]
        if !n.sni.isEmpty { q["sni"] = n.sni }
        if n.allowInsecure { q["insecure"] = "1" }
        if !n.obfs.isEmpty { q["obfs"] = n.obfs }
        if !n.obfsPassword.isEmpty { q["obfs-password"] = n.obfsPassword }
        if !n.alpn.isEmpty { q["alpn"] = n.alpn }
        var qs = ""
        if !q.isEmpty {
            var comp = URLComponents()
            comp.queryItems = q.map { URLQueryItem(name: $0.key, value: $0.value) }
            qs = comp.percentEncodedQuery.map { "?\($0)" } ?? ""
        }
        let pw = n.password.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? n.password
        var uri = "hysteria2://\(pw)@\(hp)\(qs)"
        if !n.name.isEmpty {
            uri += "#\(n.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? n.name)"
        }
        return uri
    }

    // MARK: SOCKS / HTTP

    static func parseSOCKS(_ uri: String) throws -> ProxyNode {
        let (body, name0) = splitFragment(uri)
        let rest: String
        if body.lowercased().hasPrefix("socks5h://") { rest = String(body.dropFirst(10)) }
        else if body.lowercased().hasPrefix("socks5://") { rest = String(body.dropFirst(9)) }
        else if body.lowercased().hasPrefix("socks://") { rest = String(body.dropFirst(8)) }
        else { throw URIParseError.malformed("socks") }
        let parts = splitUserHost(rest)
        var user = "", pass = ""
        if let u = parts.userinfo {
            let raw = u.removingPercentEncoding ?? u
            if let c = raw.firstIndex(of: ":") {
                user = String(raw[..<c])
                pass = String(raw[raw.index(after: c)...])
            } else { user = raw }
        }
        let (host, port) = try parseHostPort(parts.hostport)
        return ProxyNode(name: name0.isEmpty ? "\(host):\(port)" : name0, type: .socks, host: host, port: port, password: pass, username: user, rawURI: uri)
    }

    static func encodeSOCKS(_ n: ProxyNode) -> String {
        let hp = (n.host.contains(":") && !n.host.hasPrefix("[")) ? "[\(n.host)]:\(n.port)" : "\(n.host):\(n.port)"
        var auth = ""
        if !n.username.isEmpty {
            auth = n.username.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? n.username
            if !n.password.isEmpty {
                auth += ":" + (n.password.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? n.password)
            }
            auth += "@"
        }
        var uri = "socks5://\(auth)\(hp)"
        if !n.name.isEmpty { uri += "#\(n.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? n.name)" }
        return uri
    }

    static func parseHTTP(_ uri: String) throws -> ProxyNode {
        let (body, name0) = splitFragment(uri)
        let tls: Bool
        let rest: String
        if body.lowercased().hasPrefix("https://") {
            tls = true
            rest = String(body.dropFirst(8))
        } else if body.lowercased().hasPrefix("http://") {
            tls = false
            rest = String(body.dropFirst(7))
        } else { throw URIParseError.malformed("http") }
        let parts = splitUserHost(rest)
        var user = "", pass = ""
        if let u = parts.userinfo {
            let raw = u.removingPercentEncoding ?? u
            if let c = raw.firstIndex(of: ":") {
                user = String(raw[..<c])
                pass = String(raw[raw.index(after: c)...])
            } else { user = raw }
        }
        var hostport = parts.hostport
        if let slash = hostport.firstIndex(of: "/") { hostport = String(hostport[..<slash]) }
        let (host, port) = try parseHostPort(hostport)
        return ProxyNode(name: name0.isEmpty ? "\(host):\(port)" : name0, type: .http, host: host, port: port, password: pass, tls: tls, username: user, rawURI: uri)
    }

    static func encodeHTTP(_ n: ProxyNode) -> String {
        let scheme = n.tls ? "https" : "http"
        let hp = (n.host.contains(":") && !n.host.hasPrefix("[")) ? "[\(n.host)]:\(n.port)" : "\(n.host):\(n.port)"
        var auth = ""
        if !n.username.isEmpty {
            auth = n.username.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? n.username
            if !n.password.isEmpty {
                auth += ":" + (n.password.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? n.password)
            }
            auth += "@"
        }
        var uri = "\(scheme)://\(auth)\(hp)"
        if !n.name.isEmpty { uri += "#\(n.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? n.name)" }
        return uri
    }
}

extension Data {
    static func xhjBase64(_ s: String) -> Data? {
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - t.count % 4) % 4
        t += String(repeating: "=", count: pad)
        return Data(base64Encoded: t)
    }

    func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
