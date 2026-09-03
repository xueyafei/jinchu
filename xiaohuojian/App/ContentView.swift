import SwiftUI

struct ContentView: View {
    @EnvironmentObject var store: StoreViewModel
    @State private var tab = 0

    var body: some View {
        TabView(selection: $tab) {
            HomeView()
                .tabItem { Label("首页", systemImage: "paperplane.fill") }
                .tag(0)
            ConfigView()
                .tabItem { Label("配置", systemImage: "slider.horizontal.3") }
                .tag(1)
            DataView()
                .tabItem { Label("数据", systemImage: "chart.bar.fill") }
                .tag(2)
            SettingsView()
                .tabItem { Label("设置", systemImage: "gearshape.fill") }
                .tag(3)
        }
        .background(XHJTheme.bg.ignoresSafeArea())
        .onAppear { store.reload() }
    }
}
