import SwiftUI

struct NodeEditView: View {
    @Environment(\.dismiss) var dismiss
    @State var node: ProxyNode
    var onSave: (ProxyNode) -> Void
    @State private var share = ""
    @State private var parseError: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("分享链接") {
                    TextField("粘贴 ss:// vmess:// …", text: $share, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("从链接填充") { applyShare() }
                    if let parseError { Text(parseError).foregroundStyle(XHJTheme.danger).font(.caption) }
                }
                Section("基本") {
                    Picker("类型", selection: $node.type) {
                        ForEach(ProxyType.allCases) { t in
                            Text(t.displayName).tag(t)
                        }
                    }
                    TextField("名称", text: $node.name)
                    TextField("服务器", text: $node.host)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("端口", value: $node.port, format: .number)
                        .keyboardType(.numberPad)
                    TextField("分组", text: $node.group)
                }
                credentialSection
                transportSection
            }
            .scrollContentBackground(.hidden)
            .background(XHJTheme.bg)
            .navigationTitle(node.name.isEmpty ? "添加节点" : "编辑节点")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        if node.rawURI.isEmpty { node.rawURI = ProxyURIParser.encode(node) }
                        onSave(node)
                        dismiss()
                    }
                    .disabled(node.host.isEmpty || node.port <= 0)
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    var credentialSection: some View {
        switch node.type {
        case .ss:
            Section("Shadowsocks") {
                TextField("加密", text: $node.method)
                    .textInputAutocapitalization(.never)
                Text("常用：chacha20-ietf-poly1305 / aes-256-gcm").font(.caption).foregroundStyle(.secondary)
                SecureField("密码", text: $node.password)
                TextField("插件（可选）", text: $node.plugin)
                TextField("插件参数", text: $node.pluginOpts)
            }
        case .vmess:
            Section("VMess") {
                TextField("UUID", text: $node.uuid)
                    .textInputAutocapitalization(.never)
                TextField("AlterID", value: $node.alterId, format: .number)
                TextField("加密 scy", text: $node.security)
            }
        case .vless:
            Section("VLESS") {
                TextField("UUID", text: $node.uuid)
                    .textInputAutocapitalization(.never)
                TextField("Flow", text: $node.flow)
                TextField("Encryption", text: $node.encryption)
            }
        case .trojan, .hysteria2:
            Section("认证") {
                SecureField("密码 / Auth", text: $node.password)
            }
        case .socks, .http:
            Section("认证（可选）") {
                TextField("用户名", text: $node.username)
                    .textInputAutocapitalization(.never)
                SecureField("密码", text: $node.password)
            }
        }
    }

    @ViewBuilder
    var transportSection: some View {
        if node.type != .ss && node.type != .socks {
            Section("传输") {
                TextField("network (tcp/ws/grpc)", text: $node.network)
                    .textInputAutocapitalization(.never)
                Toggle("TLS", isOn: $node.tls)
                TextField("SNI", text: $node.sni)
                    .textInputAutocapitalization(.never)
                TextField("Host", text: $node.hostHeader)
                    .textInputAutocapitalization(.never)
                TextField("Path", text: $node.path)
                    .textInputAutocapitalization(.never)
                Toggle("允许不安全证书", isOn: $node.allowInsecure)
                if node.type == .hysteria2 {
                    TextField("obfs", text: $node.obfs)
                    SecureField("obfs-password", text: $node.obfsPassword)
                }
            }
        }
        if node.type == .http {
            Section("HTTP") {
                Toggle("HTTPS 代理", isOn: $node.tls)
            }
        }
    }

    func applyShare() {
        do {
            var n = try ProxyURIParser.parse(share)
            n.id = node.id
            if n.group.isEmpty { n.group = node.group }
            node = n
            parseError = nil
        } catch {
            parseError = error.localizedDescription
        }
    }
}
