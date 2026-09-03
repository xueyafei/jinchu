import SwiftUI

struct SubscribeView: View {
    @EnvironmentObject var store: StoreViewModel
    @State private var showAdd = false
    @State private var name = ""
    @State private var url = ""
    @State private var busyID: UUID?
    @State private var message: String?

    var body: some View {
        ZStack {
            XHJTheme.bg.ignoresSafeArea()
            List {
                if let message {
                    Text(message).font(.caption).foregroundStyle(XHJTheme.accent)
                        .listRowBackground(XHJTheme.card)
                }
                ForEach(store.subscriptions) { sub in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(sub.name).foregroundStyle(XHJTheme.text)
                            Spacer()
                            if busyID == sub.id { ProgressView() }
                        }
                        Text(sub.url).font(.caption).foregroundStyle(XHJTheme.secondary).lineLimit(1)
                        if let d = sub.lastUpdate {
                            Text("更新于 \(d.formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption2).foregroundStyle(XHJTheme.secondary)
                        }
                    }
                    .listRowBackground(XHJTheme.card)
                    .swipeActions {
                        Button(role: .destructive) { store.deleteSubscription(sub) } label: { Text("删除") }
                        Button { Task { await refresh(sub) } } label: { Text("更新") }.tint(XHJTheme.accent)
                    }
                    .onTapGesture { Task { await refresh(sub) } }
                }
            }
            .scrollContentBackground(.hidden)
        }
        .navigationTitle("订阅")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showAdd = true } label: { Image(systemName: "plus") }
            }
        }
        .alert("添加订阅", isPresented: $showAdd) {
            TextField("名称", text: $name)
            TextField("https://…", text: $url)
            Button("添加") {
                let n = name.trimmingCharacters(in: .whitespaces)
                let u = url.trimmingCharacters(in: .whitespaces)
                guard !u.isEmpty else { return }
                let sub = Subscription(name: n.isEmpty ? "订阅" : n, url: u)
                store.addSubscription(sub)
                name = ""; url = ""
                Task { await refresh(sub) }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("拉取后会按 base64 URI 列表、Clash YAML 或 SIP008 JSON 解析，并替换该订阅分组下的节点。")
        }
    }

    func refresh(_ sub: Subscription) async {
        busyID = sub.id
        defer { busyID = nil }
        guard let u = URL(string: sub.url) else {
            message = "无效 URL"
            return
        }
        do {
            var req = URLRequest(url: u, timeoutInterval: 20)
            req.setValue("小火箭/1.0", forHTTPHeaderField: "User-Agent")
            let (data, resp) = try await URLSession.shared.data(for: req)
            if let http = resp as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                message = "HTTP \(http.statusCode)"
                return
            }
            let text = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
            let nodes = SubscriptionParser.parse(body: text, group: sub.groupName)
            store.replaceSubscription(sub, nodes: nodes)
            message = "已更新 \(nodes.count) 个节点"
        } catch {
            message = error.localizedDescription
        }
    }
}
