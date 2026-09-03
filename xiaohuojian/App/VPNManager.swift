import Foundation
import Combine
import NetworkExtension

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?
    @Published var isBusy = false

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    private init() {
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            Task { @MainActor in
                self?.status = conn.status
            }
        }
        Task { await reload() }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    var isConnected: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    var statusText: String {
        switch status {
        case .connected: return "已连接"
        case .connecting: return "连接中"
        case .disconnecting: return "断开中"
        case .disconnected: return "未连接"
        case .reasserting: return "重连中"
        case .invalid: return "未安装配置"
        @unknown default: return "未知"
        }
    }

    func reload() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = all.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == XHJ.tunnelBundleID }) ?? all.first {
                manager = existing
                status = existing.connection.status
            } else {
                manager = nil
                status = .invalid
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    func toggle(store: StoreViewModel) async {
        if isConnected {
            await disconnect()
        } else {
            await connect(store: store)
        }
    }

    func connect(store: StoreViewModel) async {
        guard let node = store.selectedNode else {
            lastError = "请先添加并选择一个节点"
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            try store.prepareTunnel()
            let mgr = try await installedManager(displayServer: node.displayTitle)
            try mgr.connection.startVPNTunnel(options: [
                "node": node.displayTitle as NSString
            ])
            lastError = nil
            AppGroupStore.shared.resetSessionTraffic()
        } catch {
            lastError = explain(error)
        }
        await reload()
    }

    func disconnect() async {
        manager?.connection.stopVPNTunnel()
        status = .disconnecting
    }

    private func installedManager(displayServer: String) async throws -> NETunnelProviderManager {
        if let manager {
            try configure(manager, server: displayServer)
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            self.manager = manager
            return manager
        }
        let all = try await NETunnelProviderManager.loadAllFromPreferences()
        let mgr = all.first ?? NETunnelProviderManager()
        try configure(mgr, server: displayServer)
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        self.manager = mgr
        return mgr
    }

    private func configure(_ mgr: NETunnelProviderManager, server: String) throws {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = XHJ.tunnelBundleID
        proto.serverAddress = server
        proto.excludeLocalNetworks = true
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = XHJ.tunnelDescription
        mgr.isEnabled = true
        mgr.isOnDemandEnabled = false
    }

    private func explain(_ error: Error) -> String {
        let ns = error as NSError
        if ns.domain == NEVPNErrorDomain {
            switch NEVPNError.Code(rawValue: ns.code) {
            case .configurationDisabled: return "VPN 配置被禁用，请在系统设置中打开。"
            case .configurationInvalid: return "VPN 配置无效。免费个人团队通常无法使用 Network Extension，需要付费开发者账号。"
            case .configurationReadWriteFailed: return "无法写入 VPN 配置。"
            case .configurationStale: return "配置已过期，请重试。"
            case .configurationUnknown: return "未知配置错误。"
            default: break
            }
        }
        return error.localizedDescription
    }
}
