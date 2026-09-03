import SwiftUI

struct HomeView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: StoreViewModel
    @State private var showPicker = false
    @State private var pulse = false

    var node: ProxyNode? { store.selectedNode }

    var body: some View {
        NavigationStack {
            ZStack {
                XHJTheme.bg.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 22) {
                        connectButton
                        nodeCard
                        statsRow
                        if let err = vpn.lastError, !err.isEmpty {
                            Text(err)
                                .font(.footnote)
                                .foregroundStyle(XHJTheme.danger)
                                .padding(.horizontal)
                        }
                        hint
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 20)
                }
            }
            .navigationTitle("小火箭")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $showPicker) { NodePickerView() }
            .onAppear { store.refreshTraffic() }
            .onReceive(Timer.publish(every: 1.5, on: .main, in: .common).autoconnect()) { _ in
                if vpn.isConnected { store.refreshTraffic() }
            }
        }
    }

    var connectButton: some View {
        Button {
            Task { await vpn.toggle(store: store) }
        } label: {
            ZStack {
                Circle()
                    .fill(XHJTheme.card)
                    .frame(width: 168, height: 168)
                    .shadow(color: (vpn.isConnected ? XHJTheme.accent : Color.black).opacity(0.35), radius: 24)
                Circle()
                    .stroke(vpn.isConnected ? XHJTheme.accent : Color.white.opacity(0.12), lineWidth: 3)
                    .frame(width: 168, height: 168)
                    .scaleEffect(pulse && vpn.isConnected ? 1.04 : 1)
                VStack(spacing: 8) {
                    Image(systemName: vpn.isConnected ? "checkmark" : "power")
                        .font(.system(size: 44, weight: .semibold))
                        .foregroundStyle(vpn.isConnected ? XHJTheme.accent : Color.white.opacity(0.85))
                    Text(vpn.statusText)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(XHJTheme.secondary)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(vpn.isBusy)
        .padding(.top, 12)
        .onAppear {
            withAnimation(.easeInOut(duration: 1.6).repeatForever(autoreverses: true)) { pulse = true }
        }
    }

    var nodeCard: some View {
        Button { showPicker = true } label: {
            HStack(spacing: 12) {
                Text(node?.type.shortLabel ?? "—")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(XHJTheme.bg)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(XHJTheme.accent)
                    .clipShape(Capsule())
                VStack(alignment: .leading, spacing: 4) {
                    Text(node?.displayTitle ?? "未选择节点")
                        .font(.headline)
                        .foregroundStyle(XHJTheme.text)
                        .lineLimit(1)
                    Text(node.map { "\($0.endpoint) · \($0.type.displayName)" } ?? "点击选择或添加节点")
                        .font(.caption)
                        .foregroundStyle(XHJTheme.secondary)
                }
                Spacer()
                LatencyBadge(ms: node?.latencyMs)
                Image(systemName: "chevron.right")
                    .foregroundStyle(XHJTheme.secondary)
            }
            .padding(16)
            .background(XHJTheme.card)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        }
        .buttonStyle(.plain)
    }

    var statsRow: some View {
        HStack(spacing: 10) {
            stat("↑ 上传", TrafficFormat.bytes(store.traffic.sessionUp))
            stat("↓ 下载", TrafficFormat.bytes(store.traffic.sessionDown))
        }
    }

    func stat(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption).foregroundStyle(XHJTheme.secondary)
            Text(value).font(.title3.monospacedDigit().weight(.semibold))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(XHJTheme.card)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    var hint: some View {
        Text("首次连接会弹出系统 VPN 许可。免费个人团队通常无法加载 Packet Tunnel，请使用付费 Apple Developer 账号。")
            .font(.caption)
            .foregroundStyle(XHJTheme.secondary)
            .padding(.top, 8)
    }
}

enum TrafficFormat {
    static func bytes(_ v: Int64) -> String {
        let d = Double(v)
        if d < 1024 { return String(format: "%.0f B", d) }
        if d < 1024 * 1024 { return String(format: "%.1f KB", d / 1024) }
        if d < 1024 * 1024 * 1024 { return String(format: "%.2f MB", d / 1024 / 1024) }
        return String(format: "%.2f GB", d / 1024 / 1024 / 1024)
    }
}
