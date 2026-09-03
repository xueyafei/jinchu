import Foundation

public final class AppGroupStore {
    public static let shared = AppGroupStore()

    public let suite: UserDefaults?
    public let containerURL: URL?

    private let io = DispatchQueue(label: "app.xiaohuojian.store")
    private var cache: AppStoreFile

    public init() {
        suite = UserDefaults(suiteName: XHJ.appGroupID)
        containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: XHJ.appGroupID)
        cache = AppStoreFile()
        if let loaded = loadFromDisk() {
            cache = loaded
        } else {
            cache.rules = ProxyRule.starterChinaDirect
            persistLocked()
        }
    }

    public var storeFileURL: URL? {
        containerURL?.appendingPathComponent(XHJ.storeFileName)
    }

    public var tunnelConfigURL: URL? {
        containerURL?.appendingPathComponent(XHJ.tunnelConfigFileName)
    }

    public var singBoxURL: URL? {
        containerURL?.appendingPathComponent(XHJ.singBoxFileName)
    }

    public func snapshot() -> AppStoreFile {
        io.sync { cache }
    }

    public func update(_ mutate: (inout AppStoreFile) -> Void) {
        io.sync {
            mutate(&cache)
            persistLocked()
        }
    }

    public var nodes: [ProxyNode] { snapshot().nodes }
    public var subscriptions: [Subscription] { snapshot().subscriptions }
    public var rules: [ProxyRule] { snapshot().rules }
    public var settings: AppSettings { snapshot().settings }

    public func selectedNode() -> ProxyNode? {
        let s = snapshot()
        guard let id = s.settings.selectedNodeID else { return s.nodes.first }
        return s.nodes.first(where: { $0.id == id }) ?? s.nodes.first
    }

    public func selectNode(_ id: UUID?) {
        update { $0.settings.selectedNodeID = id }
        suite?.set(id?.uuidString, forKey: XHJ.DefaultsKey.selectedNodeID)
    }

    public func addNode(_ node: ProxyNode) {
        update { $0.nodes.append(node) }
    }

    public func upsertNode(_ node: ProxyNode) {
        update { store in
            if let i = store.nodes.firstIndex(where: { $0.id == node.id }) {
                store.nodes[i] = node
            } else {
                store.nodes.append(node)
            }
        }
    }

    public func deleteNodes(ids: [UUID]) {
        let set = Set(ids)
        update { store in
            store.nodes.removeAll { set.contains($0.id) }
            if let sel = store.settings.selectedNodeID, set.contains(sel) {
                store.settings.selectedNodeID = store.nodes.first?.id
            }
        }
    }

    public func replaceSubscriptionNodes(subscriptionID: UUID, group: String, nodes: [ProxyNode]) {
        update { store in
            store.nodes.removeAll { $0.subscriptionID == subscriptionID }
            var incoming = nodes
            for i in incoming.indices {
                incoming[i].subscriptionID = subscriptionID
                incoming[i].group = group
            }
            store.nodes.append(contentsOf: incoming)
            if let idx = store.subscriptions.firstIndex(where: { $0.id == subscriptionID }) {
                store.subscriptions[idx].lastUpdate = Date()
            }
        }
    }

    public func clearAll() {
        io.sync {
            cache = AppStoreFile(rules: ProxyRule.starterChinaDirect)
            persistLocked()
        }
        if let suite {
            for k in [XHJ.DefaultsKey.sessionUp, XHJ.DefaultsKey.sessionDown] {
                suite.set(Int64(0), forKey: k)
            }
        }
    }

    public func writeTunnelConfig() throws {
        let snap = snapshot()
        let cfg = TunnelRuntimeConfig(
            node: selectedNode(),
            mode: snap.settings.connectMode,
            bypassLAN: snap.settings.bypassLAN,
            rules: snap.rules.filter(\.enabled),
            dnsMode: snap.settings.dnsMode,
            dnsServers: snap.settings.dnsMode == .system ? XHJ.tunDNSFallback : (snap.settings.dnsServerList.isEmpty ? XHJ.tunDNSFallback : snap.settings.dnsServerList),
            dohURL: snap.settings.dohURL
        )
        let data = try JSONEncoder().encode(cfg)
        guard let url = tunnelConfigURL else { throw NSError(domain: "XHJ", code: 1, userInfo: [NSLocalizedDescriptionKey: "App Group 容器不可用"]) }
        try data.write(to: url, options: .atomic)
        let json = SingBoxBuilder.build(config: cfg)
        if let sdata = json.data(using: .utf8), let surl = singBoxURL {
            try sdata.write(to: surl, options: .atomic)
        }
        suite?.set(snap.settings.connectMode.rawValue, forKey: XHJ.DefaultsKey.connectMode)
    }

    public func readTunnelConfig() -> TunnelRuntimeConfig? {
        guard let url = tunnelConfigURL, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(TunnelRuntimeConfig.self, from: data)
    }

    public func readTraffic() -> TrafficSnapshot {
        let d = suite
        return TrafficSnapshot(
            sessionUp: d?.object(forKey: XHJ.DefaultsKey.sessionUp) as? Int64 ?? 0,
            sessionDown: d?.object(forKey: XHJ.DefaultsKey.sessionDown) as? Int64 ?? 0,
            totalUp: d?.object(forKey: XHJ.DefaultsKey.totalUp) as? Int64 ?? 0,
            totalDown: d?.object(forKey: XHJ.DefaultsKey.totalDown) as? Int64 ?? 0,
            connectedAt: d?.object(forKey: XHJ.DefaultsKey.connectedAt) as? Date
        )
    }

    public func writeTraffic(_ t: TrafficSnapshot) {
        suite?.set(t.sessionUp, forKey: XHJ.DefaultsKey.sessionUp)
        suite?.set(t.sessionDown, forKey: XHJ.DefaultsKey.sessionDown)
        suite?.set(t.totalUp, forKey: XHJ.DefaultsKey.totalUp)
        suite?.set(t.totalDown, forKey: XHJ.DefaultsKey.totalDown)
        if let c = t.connectedAt { suite?.set(c, forKey: XHJ.DefaultsKey.connectedAt) }
    }

    public func addTraffic(up: Int64, down: Int64) {
        let d = suite
        let su = (d?.object(forKey: XHJ.DefaultsKey.sessionUp) as? Int64 ?? 0) + up
        let sd = (d?.object(forKey: XHJ.DefaultsKey.sessionDown) as? Int64 ?? 0) + down
        let tu = (d?.object(forKey: XHJ.DefaultsKey.totalUp) as? Int64 ?? 0) + up
        let td = (d?.object(forKey: XHJ.DefaultsKey.totalDown) as? Int64 ?? 0) + down
        d?.set(su, forKey: XHJ.DefaultsKey.sessionUp)
        d?.set(sd, forKey: XHJ.DefaultsKey.sessionDown)
        d?.set(tu, forKey: XHJ.DefaultsKey.totalUp)
        d?.set(td, forKey: XHJ.DefaultsKey.totalDown)
    }

    public func resetSessionTraffic() {
        suite?.set(Int64(0), forKey: XHJ.DefaultsKey.sessionUp)
        suite?.set(Int64(0), forKey: XHJ.DefaultsKey.sessionDown)
        suite?.set(Date(), forKey: XHJ.DefaultsKey.connectedAt)
    }

    public func exportJSON() throws -> Data {
        try JSONEncoder().encode(snapshot())
    }

    public func importJSON(_ data: Data) throws {
        let decoded = try JSONDecoder().decode(AppStoreFile.self, from: data)
        io.sync {
            cache = decoded
            persistLocked()
        }
    }

    public func exportShareLinks() -> String {
        snapshot().nodes.map { ProxyURIParser.encode($0) }.joined(separator: "\n")
    }

    private func persistLocked() {
        guard let url = storeFileURL else { return }
        do {
            let data = try JSONEncoder().encode(cache)
            try data.write(to: url, options: .atomic)
        } catch {
            // keep cache
        }
        if let id = cache.settings.selectedNodeID {
            suite?.set(id.uuidString, forKey: XHJ.DefaultsKey.selectedNodeID)
        }
    }

    private func loadFromDisk() -> AppStoreFile? {
        guard let url = storeFileURL, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(AppStoreFile.self, from: data)
    }
}
