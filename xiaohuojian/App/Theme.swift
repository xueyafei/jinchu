import SwiftUI
import UIKit

enum XHJTheme {
    static let accent = Color(red: 0.18, green: 0.90, blue: 0.65)
    static let accentDim = Color(red: 0.12, green: 0.55, blue: 0.42)
    static let bg = Color(red: 0.04, green: 0.04, blue: 0.05)
    static let grouped = Color(red: 0.07, green: 0.07, blue: 0.08)
    static let card = Color(red: 0.11, green: 0.11, blue: 0.12)
    static let cardElevated = Color(red: 0.16, green: 0.16, blue: 0.17)
    static let separator = Color.white.opacity(0.08)
    static let text = Color.white
    static let secondary = Color.white.opacity(0.55)
    static let danger = Color(red: 1.0, green: 0.35, blue: 0.35)
    static let warn = Color(red: 1.0, green: 0.75, blue: 0.28)

    static func latencyColor(_ ms: Int?) -> Color {
        guard let ms else { return secondary }
        if ms < 0 { return danger }
        if ms < 120 { return accent }
        if ms < 250 { return warn }
        return danger
    }
}

struct CardGroup<Content: View>: View {
    var content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        VStack(spacing: 0) { content }
            .background(XHJTheme.card)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct RowDivider: View {
    var body: some View {
        Rectangle().fill(XHJTheme.separator).frame(height: 1 / UIScreen.main.scale).padding(.leading, 16)
    }
}

struct ChevronLabel: View {
    var title: String
    var value: String = ""
    var systemImage: String
    var body: some View {
        HStack {
            Image(systemName: systemImage)
                .foregroundStyle(XHJTheme.accent)
                .frame(width: 28)
            Text(title)
            Spacer()
            if !value.isEmpty {
                Text(value).foregroundStyle(XHJTheme.secondary).lineLimit(1)
            }
            Image(systemName: "chevron.right").font(.footnote).foregroundStyle(XHJTheme.secondary)
        }
        .foregroundStyle(XHJTheme.text)
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
        .contentShape(Rectangle())
    }
}
