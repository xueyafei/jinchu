import SwiftUI

struct DataView: View {
    @EnvironmentObject var store: StoreViewModel
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        NavigationStack {
            ZStack {
                XHJTheme.bg.ignoresSafeArea()
                List {
                    Section("本次会话") {
                        row("上传", TrafficFormat.bytes(store.traffic.sessionUp))
                        row("下载", TrafficFormat.bytes(store.traffic.sessionDown))
                        if let t = store.traffic.connectedAt {
                            row("开始", t.formatted(date: .abbreviated, time: .standard))
                        }
                        row("状态", vpn.statusText)
                    }
                    Section("累计") {
                        row("上传", TrafficFormat.bytes(store.traffic.totalUp))
                        row("下载", TrafficFormat.bytes(store.traffic.totalDown))
                    }
                }
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("数据")
            .onAppear { store.refreshTraffic() }
            .onReceive(Timer.publish(every: 1.2, on: .main, in: .common).autoconnect()) { _ in
                store.refreshTraffic()
            }
        }
    }

    func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k)
            Spacer()
            Text(v).foregroundStyle(XHJTheme.secondary).monospacedDigit()
        }
        .listRowBackground(XHJTheme.card)
    }
}
