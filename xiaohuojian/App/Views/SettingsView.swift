import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var store: StoreViewModel
    @State private var confirmClear = false

    var body: some View {
        NavigationStack {
            ZStack {
                XHJTheme.bg.ignoresSafeArea()
                List {
                    Section("外观") {
                        Picker("主题", selection: Binding(
                            get: { store.settings.appearance },
                            set: { v in store.updateSettings { $0.appearance = v } }
                        )) {
                            ForEach(Appearance.allCases) { a in Text(a.zh).tag(a) }
                        }
                        .listRowBackground(XHJTheme.card)
                    }
                    Section("数据") {
                        Button("清除全部数据", role: .destructive) { confirmClear = true }
                            .listRowBackground(XHJTheme.card)
                    }
                    Section("关于") {
                        HStack {
                            Text("应用")
                            Spacer()
                            Text("小火箭").foregroundStyle(XHJTheme.secondary)
                        }.listRowBackground(XHJTheme.card)
                        HStack {
                            Text("包名")
                            Spacer()
                            Text(XHJ.appBundleID).font(.caption).foregroundStyle(XHJTheme.secondary)
                        }.listRowBackground(XHJTheme.card)
                        HStack {
                            Text("版本")
                            Spacer()
                            Text("1.0.0 (个人侧载)").foregroundStyle(XHJTheme.secondary)
                        }.listRowBackground(XHJTheme.card)
                        Text("自用客户端。节点由你自行添加，不含任何内置服务器。界面为原创深色风格，未使用第三方商业客户端的图标或资源。")
                            .font(.caption)
                            .foregroundStyle(XHJTheme.secondary)
                            .listRowBackground(XHJTheme.card)
                    }
                }
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("设置")
            .alert("清除全部数据？", isPresented: $confirmClear) {
                Button("清除", role: .destructive) { store.clearAll() }
                Button("取消", role: .cancel) {}
            } message: {
                Text("将删除所有节点、订阅、规则并恢复默认国内直连精简列表。")
            }
        }
    }
}
