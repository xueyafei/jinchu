import SwiftUI

struct ConnectModeView: View {
    @EnvironmentObject var store: StoreViewModel

    var body: some View {
        ZStack {
            XHJTheme.bg.ignoresSafeArea()
            List {
                ForEach(ConnectMode.allCases) { mode in
                    Button {
                        store.updateSettings { $0.connectMode = mode }
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(mode.zh).foregroundStyle(XHJTheme.text)
                                Text(mode.detail).font(.caption).foregroundStyle(XHJTheme.secondary)
                            }
                            Spacer()
                            if store.settings.connectMode == mode {
                                Image(systemName: "checkmark").foregroundStyle(XHJTheme.accent)
                            }
                        }
                    }
                    .listRowBackground(XHJTheme.card)
                }
                Toggle(isOn: Binding(
                    get: { store.settings.bypassLAN },
                    set: { v in store.updateSettings { $0.bypassLAN = v } }
                )) {
                    VStack(alignment: .leading) {
                        Text("绕过局域网")
                        Text("10/8、172.16/12、192.168/16 等直连").font(.caption).foregroundStyle(XHJTheme.secondary)
                    }
                }
                .tint(XHJTheme.accent)
                .listRowBackground(XHJTheme.card)
            }
            .scrollContentBackground(.hidden)
        }
        .navigationTitle("连接模式")
    }
}
