import Foundation
import Combine

@MainActor
final class StoreViewModel: ObservableObject {
    static let shared = StoreViewModel()
    private let backend = AppGroupStore.shared

    @Published var nodes: [ProxyNode] = []
    @Published var subscriptions: [Subscription] = []
    @Published var rules: [ProxyRule] = []
    @Published var settings: AppSettings = AppSettings()
    @Published var traffic: TrafficSnapshot = TrafficSnapshot()

    init() { reload() }

    func reload() {
        let s = backend.snapshot()
        nodes = s.nodes
        subscriptions = s.subscriptions
        rules = s.rules
        settings = s.settings
        traffic = backend.readTraffic()
    }

    var selectedNode: ProxyNode? {
        if let id = settings.selectedNodeID { return nodes.first(where: { $0.id == id }) }
        return nodes.first
    }

    func select(_ node: ProxyNode) {
        backend.selectNode(node.id)
        reload()
    }

    func upsert(_ node: ProxyNode) {
        backend.upsertNode(node)
        if settings.selectedNodeID == nil { backend.selectNode(node.id) }
        reload()
    }

    func deleteNodes(at offsets: IndexSet, in list: [ProxyNode]) {
        let ids = offsets.map { list[$0].id }
        backend.deleteNodes(ids: ids)
        reload()
    }

    func deleteNode(_ node: ProxyNode) {
        backend.deleteNodes(ids: [node.id])
        reload()
    }

    func updateSettings(_ mutate: (inout AppSettings) -> Void) {
        backend.update { mutate(&$0.settings) }
        reload()
    }

    func updateRules(_ mutate: (inout [ProxyRule]) -> Void) {
        backend.update { mutate(&$0.rules) }
        reload()
    }

    func addSubscription(_ sub: Subscription) {
        backend.update { $0.subscriptions.append(sub) }
        reload()
    }

    func deleteSubscription(_ sub: Subscription) {
        backend.update { store in
            store.subscriptions.removeAll { $0.id == sub.id }
            store.nodes.removeAll { $0.subscriptionID == sub.id }
        }
        reload()
    }

    func replaceSubscription(_ sub: Subscription, nodes newNodes: [ProxyNode]) {
        backend.replaceSubscriptionNodes(subscriptionID: sub.id, group: sub.groupName, nodes: newNodes)
        reload()
    }

    func importLinks(_ text: String, group: String = "手动") -> Int {
        let parsed = ProxyURIParser.parseMany(text)
        for var n in parsed {
            n.group = group
            backend.addNode(n)
        }
        reload()
        return parsed.count
    }

    func clearAll() {
        backend.clearAll()
        reload()
    }

    func refreshTraffic() {
        traffic = backend.readTraffic()
    }

    func prepareTunnel() throws {
        try backend.writeTunnelConfig()
    }
}
