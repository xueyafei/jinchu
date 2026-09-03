import SwiftUI

@main
struct XiaoHuoJianApp: App {
    @StateObject private var vpn = VPNManager.shared
    @StateObject private var store = StoreViewModel.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpn)
                .environmentObject(store)
                .preferredColorScheme(store.settings.appearance.colorScheme)
                .tint(XHJTheme.accent)
        }
    }
}

extension Appearance {
    var colorScheme: ColorScheme? {
        switch self {
        case .dark: return .dark
        case .light: return .light
        case .system: return nil
        }
    }
}
