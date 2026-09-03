import Foundation

enum OutboundFactory {
    static func make(node: ProxyNode?, policy: RulePolicy, destHost: String, destPort: UInt16) -> TunnelOutbound? {
        switch policy {
        case .reject:
            return nil
        case .direct:
            let c = DirectClient()
            c.start(host: destHost, port: destPort)
            return c
        case .proxy:
            guard let node else {
                let c = DirectClient()
                c.start(host: destHost, port: destPort)
                return c
            }
            return makeProxy(node: node, destHost: destHost, destPort: destPort)
        }
    }

    static func makeProxy(node: ProxyNode, destHost: String, destPort: UInt16) -> TunnelOutbound? {
        switch node.type {
        case .ss:
            guard let method = SSMethod(name: node.method) else { return nil }
            let master = SSCrypto.evpBytesToKey(password: node.password, keyLen: method.keyLen)
            let c = ShadowsocksClient(method: method, masterKey: master)
            c.start(node: node, destHost: destHost, destPort: destPort)
            return c
        case .trojan:
            let c = TrojanClient()
            c.start(node: node, destHost: destHost, destPort: destPort)
            return c
        case .socks:
            let c = SOCKS5Client()
            c.start(node: node, destHost: destHost, destPort: destPort)
            return c
        case .http:
            let c = HTTPProxyClient()
            c.start(node: node, destHost: destHost, destPort: destPort)
            return c
        case .vmess, .vless, .hysteria2:
            return nil
        }
    }
}
