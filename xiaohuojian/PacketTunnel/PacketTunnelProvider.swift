import Foundation
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var loop: PacketLoop?
    private var trafficTimer: DispatchSourceTimer?
    private var pendingUp: Int64 = 0
    private var pendingDown: Int64 = 0
    private let lock = NSLock()

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let store = AppGroupStore.shared
        guard let cfg = store.readTunnelConfig() else {
            completionHandler(NSError(domain: "XHJ", code: 1, userInfo: [NSLocalizedDescriptionKey: "找不到隧道配置，请在 App 内先选择节点再连接"]))
            return
        }
        let json = SingBoxBuilder.build(config: cfg)
        if let url = store.singBoxURL {
            try? json.write(to: url, atomically: true, encoding: .utf8)
        }

        let settings = Self.networkSettings(for: cfg)
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                completionHandler(error)
                return
            }
            guard let self else {
                completionHandler(NSError(domain: "XHJ", code: 2))
                return
            }
            if let node = cfg.node, [.vmess, .vless, .hysteria2].contains(node.type) {
                store.suite?.set("当前节点类型 \(node.type.displayName) 尚未在 v1 原生出站实现。已写入 sing-box.json。请换 SS AEAD / Trojan / SOCKS / HTTP，或稍后接入 libbox。", forKey: XHJ.DefaultsKey.lastError)
            } else {
                store.suite?.set("", forKey: XHJ.DefaultsKey.lastError)
            }
            let engine = RuleEngine(mode: cfg.mode, bypassLAN: cfg.bypassLAN, rules: cfg.rules)
            let dns = cfg.dnsServers.first ?? "1.1.1.1"
            let loop = PacketLoop(packetFlow: self.packetFlow, engine: engine, node: cfg.node, dns: dns)
            loop.onTraffic = { [weak self] u, d in
                self?.lock.lock()
                self?.pendingUp += u
                self?.pendingDown += d
                self?.lock.unlock()
            }
            self.loop = loop
            loop.start()
            store.resetSessionTraffic()
            self.startTrafficFlusher()
            store.suite?.set("connected", forKey: XHJ.DefaultsKey.tunnelState)
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        loop?.stop()
        loop = nil
        trafficTimer?.cancel()
        trafficTimer = nil
        flushTraffic()
        AppGroupStore.shared.suite?.set("stopped", forKey: XHJ.DefaultsKey.tunnelState)
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        flushTraffic()
        completionHandler?(messageData)
    }

    private func startTrafficFlusher() {
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.flushTraffic() }
        t.resume()
        trafficTimer = t
    }

    private func flushTraffic() {
        lock.lock()
        let u = pendingUp
        let d = pendingDown
        pendingUp = 0
        pendingDown = 0
        lock.unlock()
        if u != 0 || d != 0 {
            AppGroupStore.shared.addTraffic(up: u, down: d)
        }
    }

    static func networkSettings(for cfg: TunnelRuntimeConfig) -> NEPacketTunnelNetworkSettings {
        let remote = cfg.node?.host ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)
        settings.mtu = 1400
        let v4 = NEIPv4Settings(addresses: [XHJ.tunAddress], subnetMasks: [XHJ.tunSubnet])
        v4.includedRoutes = [NEIPv4Route.default()]
        var excluded: [NEIPv4Route] = []
        if cfg.bypassLAN || cfg.mode != .global {
            excluded.append(NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"))
            excluded.append(NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"))
            excluded.append(NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"))
            excluded.append(NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"))
        }
        if let host = cfg.node?.host, IPv4.parse(host) != nil {
            excluded.append(NEIPv4Route(destinationAddress: host, subnetMask: "255.255.255.255"))
        }
        v4.excludedRoutes = excluded
        settings.ipv4Settings = v4
        let servers = cfg.dnsServers.isEmpty ? XHJ.tunDNSFallback : cfg.dnsServers
        let dns = NEDNSSettings(servers: servers)
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        return settings
    }
}
