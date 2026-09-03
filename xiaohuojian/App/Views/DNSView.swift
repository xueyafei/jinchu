import SwiftUI

struct DNSView: View {
    @EnvironmentObject var store: StoreViewModel

    var body: some View {
        ZStack {
            XHJTheme.bg.ignoresSafeArea()
            Form {
                Picker("模式", selection: Binding(
                    get: { store.settings.dnsMode },
                    set: { v in store.updateSettings { $0.dnsMode = v } }
                )) {
                    ForEach(DNSMode.allCases) { m in Text(m.zh).tag(m) }
                }
                if store.settings.dnsMode == .custom {
                    TextField("服务器，逗号分隔", text: Binding(
                        get: { store.settings.dnsServers },
                        set: { v in store.updateSettings { $0.dnsServers = v } }
                    ))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                }
                if store.settings.dnsMode == .doh {
                    TextField("DoH URL", text: Binding(
                        get: { store.settings.dohURL },
                        set: { v in store.updateSettings { $0.dohURL = v } }
                    ))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    Text("v1 隧道使用自定义 UDP DNS；DoH URL 会写入 sing-box.json，供日后 libbox 使用。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("系统模式在隧道里仍会下发 1.1.1.1 作为 NEDNSSettings 占位，以便匹配全部域名查询。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .scrollContentBackground(.hidden)
        }
        .navigationTitle("DNS")
    }
}
