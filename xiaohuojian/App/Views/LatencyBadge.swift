import SwiftUI

struct LatencyBadge: View {
    var ms: Int?
    var body: some View {
        Text(label)
            .font(.caption.monospacedDigit().weight(.medium))
            .foregroundStyle(XHJTheme.latencyColor(ms))
    }
    var label: String {
        guard let ms else { return "—" }
        if ms < 0 { return "超时" }
        return "\(ms) ms"
    }
}
