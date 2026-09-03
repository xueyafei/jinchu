import SwiftUI

struct ConfigView: View {
    @EnvironmentObject var store: StoreViewModel

    var body: some View {
        NavigationStack {
            ZStack {
                XHJTheme.bg.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 18) {
                        CardGroup {
                            NavigationLink { NodeListView() } label: {
                                ChevronLabel(title: "代理", value: "\(store.nodes.count)", systemImage: "globe")
                            }
                            RowDivider()
                            NavigationLink { SubscribeView() } label: {
                                ChevronLabel(title: "订阅", value: "\(store.subscriptions.count)", systemImage: "link")
                            }
                        }
                        CardGroup {
                            NavigationLink { ConnectModeView() } label: {
                                ChevronLabel(title: "连接模式", value: store.settings.connectMode.zh, systemImage: "arrow.triangle.branch")
                            }
                            RowDivider()
                            NavigationLink { RulesView() } label: {
                                ChevronLabel(title: "规则", value: "\(store.rules.filter(\.enabled).count)", systemImage: "list.bullet.rectangle")
                            }
                            RowDivider()
                            NavigationLink { DNSView() } label: {
                                ChevronLabel(title: "DNS", value: store.settings.dnsMode.zh, systemImage: "network")
                            }
                        }
                        CardGroup {
                            NavigationLink { BackupView() } label: {
                                ChevronLabel(title: "备份与导入", value: "", systemImage: "square.and.arrow.down")
                            }
                        }
                    }
                    .padding(16)
                }
            }
            .navigationTitle("配置")
        }
    }
}
