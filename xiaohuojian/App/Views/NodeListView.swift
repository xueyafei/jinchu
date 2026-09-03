import SwiftUI

struct NodeListView: View {
    @EnvironmentObject var store: StoreViewModel
    @State private var showAdd = false
    @State private var pasteText = ""
    @State private var showPaste = false
    @State private var testing = false
    @State private var editNode: ProxyNode?

    var grouped: [(String, [ProxyNode])] {
        let g = Dictionary(grouping: store.nodes, by: \.group)
        return g.keys.sorted().map { ($0, g[$0] ?? []) }
    }

    var body: some View {
        ZStack {
            XHJTheme.bg.ignoresSafeArea()
            List {
                ForEach(grouped, id: \.0) { group, nodes in
                    Section(group) {
                        ForEach(nodes) { n in
                            nodeRow(n)
                                .listRowBackground(XHJTheme.card)
                                .swipeActions {
                                    Button(role: .destructive) { store.deleteNode(n) } label: { Text("删除") }
                                    Button { editNode = n } label: { Text("编辑") }.tint(XHJTheme.accentDim)
                                }
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
        }
        .navigationTitle("代理")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("手动添加") { showAdd = true }
                    Button("粘贴分享链接") { showPaste = true }
                    Button(testing ? "测速中…" : "TCP 延迟测试") { Task { await testAll() } }
                        .disabled(testing)
                } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .sheet(isPresented: $showAdd) {
            NodeEditView(node: ProxyNode()) { store.upsert($0) }
        }
        .sheet(item: $editNode) { n in
            NodeEditView(node: n) { store.upsert($0) }
        }
        .alert("粘贴分享链接", isPresented: $showPaste) {
            TextField("ss://  vmess://  或整段订阅", text: $pasteText)
            Button("导入") {
                _ = store.importLinks(pasteText, group: "手动")
                pasteText = ""
            }
            Button("取消", role: .cancel) { pasteText = "" }
        } message: {
            Text("支持 ss / vmess / vless / trojan / hy2 / socks / http，一行一个。")
        }
    }

    func nodeRow(_ n: ProxyNode) -> some View {
        Button {
            store.select(n)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(n.type.shortLabel)
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(XHJTheme.accent)
                        Text(n.displayTitle).foregroundStyle(XHJTheme.text)
                    }
                    Text(n.endpoint).font(.caption).foregroundStyle(XHJTheme.secondary)
                }
                Spacer()
                LatencyBadge(ms: n.latencyMs)
                if store.selectedNode?.id == n.id {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(XHJTheme.accent)
                }
            }
        }
    }

    func testAll() async {
        testing = true
        defer { testing = false }
        var updated = store.nodes
        await withTaskGroup(of: (UUID, Int).self) { group in
            for n in updated {
                group.addTask { (n.id, await LatencyTester.ping(n)) }
            }
            for await (id, ms) in group {
                if let i = updated.firstIndex(where: { $0.id == id }) {
                    updated[i].latencyMs = ms
                }
            }
        }
        for n in updated { store.upsert(n) }
    }
}
