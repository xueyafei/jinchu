import Foundation

public enum SubscriptionParser {
    public static func parse(body: String, group: String = "订阅") -> [ProxyNode] {
        let text = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return [] }

        if text.hasPrefix("{") || text.hasPrefix("[") {
            if let data = text.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data),
               let nodes = parseSIP008(obj, group: group), !nodes.isEmpty {
                return nodes
            }
        }

        if text.contains("proxies:") || text.contains("proxy-groups:") || text.lstripHas("mixed-port:") {
            let nodes = ClashParser.parse(text, group: group)
            if !nodes.isEmpty { return nodes }
        }

        let compact = text.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
        if let decodedData = Data.xhjBase64(compact),
           let decoded = String(data: decodedData, encoding: .utf8),
           decoded.contains("://") {
            var nodes = ProxyURIParser.parseMany(decoded)
            for i in nodes.indices { nodes[i].group = group }
            if !nodes.isEmpty { return nodes }
        }

        var nodes = ProxyURIParser.parseMany(text)
        for i in nodes.indices { nodes[i].group = group }
        return nodes
    }

    public static func parseSIP008(_ obj: Any, group: String = "SIP008") -> [ProxyNode]? {
        var servers: [[String: Any]] = []
        if let dict = obj as? [String: Any] {
            if let arr = dict["servers"] as? [[String: Any]] { servers = arr }
            else if let arr = dict["proxies"] as? [[String: Any]] { servers = arr }
        } else if let arr = obj as? [[String: Any]] {
            servers = arr
        }
        var nodes: [ProxyNode] = []
        for s in servers {
            func str(_ k: String...) -> String {
                for key in k {
                    if let v = s[key] { return String(describing: v) }
                }
                return ""
            }
            let t = str("type").lowercased()
            if let server = optionalString(s["server"]) ?? optionalString(s["host"]), !server.isEmpty,
               (s["method"] != nil || s["cipher"] != nil), t.isEmpty || t == "ss" {
                let port = Int(str("server_port", "port")) ?? 8388
                let method = str("method", "cipher")
                let password = str("password")
                let name = str("remarks", "name").isEmpty ? "\(server):\(port)" : str("remarks", "name")
                nodes.append(ProxyNode(name: name, type: .ss, host: server, port: port, password: password, method: method,
                                       plugin: str("plugin"), pluginOpts: str("plugin_opts", "plugin-opts"), group: group))
                continue
            }
            if !t.isEmpty {
                var flat: [String: String] = [:]
                for (k, v) in s { flat[k] = String(describing: v) }
                if let n = ClashParser.clashMapToNode(flat, group: group) {
                    nodes.append(n)
                }
            }
        }
        return nodes
    }

    static func optionalString(_ v: Any?) -> String? {
        guard let v else { return nil }
        let s = String(describing: v)
        return s == "<null>" ? nil : s
    }
}

private extension String {
    func lstripHas(_ prefix: String) -> Bool {
        trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix(prefix)
    }
}
