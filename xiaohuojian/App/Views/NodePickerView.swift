import SwiftUI

struct NodePickerView: View {
    @EnvironmentObject var store: StoreViewModel
    @Environment(\.dismiss) var dismiss

    var grouped: [(String, [ProxyNode])] {
        let g = Dictionary(grouping: store.nodes, by: \.group)
        return g.keys.sorted().map { ($0, g[$0]!.sorted { $0.displayTitle < $1.displayTitle }) }
    }

    var body: some View {
        NavigationStack {
            ZStack {
                XHJTheme.bg.ignoresSafeArea()
                if store.nodes.isEmpty {
                    Text("还没有节点，去配置里添加吧").foregroundStyle(XHJTheme.secondary)
                } else {
                    List {
                        ForEach(grouped, id: \.0) { group, nodes in
                            Section(group) {
                                ForEach(nodes) { n in
                                    Button {
                                        store.select(n)
                                        dismiss()
                                    } label: {
                                        HStack {
                                            Text(n.type.shortLabel)
                                                .font(.caption2.weight(.bold))
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 2)
                                                .background(XHJTheme.accent.opacity(0.2))
                                                .foregroundStyle(XHJTheme.accent)
                                                .clipShape(Capsule())
                                            Text(n.displayTitle).foregroundStyle(XHJTheme.text)
                                            Spacer()
                                            LatencyBadge(ms: n.latencyMs)
                                            if store.selectedNode?.id == n.id {
                                                Image(systemName: "checkmark").foregroundStyle(XHJTheme.accent)
                                            }
                                        }
                                    }
                                    .listRowBackground(XHJTheme.card)
                                }
                            }
                        }
                    }
                    .scrollContentBackground(.hidden)
                }
            }
            .navigationTitle("选择节点")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } }
            }
        }
        .preferredColorScheme(.dark)
    }
}
