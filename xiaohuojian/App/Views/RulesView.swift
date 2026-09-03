import SwiftUI

struct RulesView: View {
    @EnvironmentObject var store: StoreViewModel
    @State private var showAdd = false
    @State private var draft = ProxyRule(matchType: .domainSuffix, pattern: "", policy: .direct)

    var body: some View {
        ZStack {
            XHJTheme.bg.ignoresSafeArea()
            List {
                ForEach(store.rules) { rule in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(rule.pattern.isEmpty ? rule.matchType.zh : rule.pattern)
                                .foregroundStyle(XHJTheme.text)
                            Text("\(rule.matchType.zh) · \(rule.policy.zh)")
                                .font(.caption).foregroundStyle(XHJTheme.secondary)
                        }
                        Spacer()
                        Toggle("", isOn: Binding(
                            get: { rule.enabled },
                            set: { v in
                                store.updateRules { arr in
                                    if let i = arr.firstIndex(where: { $0.id == rule.id }) {
                                        arr[i].enabled = v
                                    }
                                }
                            }
                        ))
                        .labelsHidden()
                        .tint(XHJTheme.accent)
                    }
                    .listRowBackground(XHJTheme.card)
                    .swipeActions {
                        Button(role: .destructive) {
                            store.updateRules { $0.removeAll { $0.id == rule.id } }
                        } label: { Text("删除") }
                    }
                }
                .onMove { src, dst in
                    store.updateRules { $0.move(fromOffsets: src, toOffset: dst) }
                }
            }
            .scrollContentBackground(.hidden)
            .environment(\.editMode, .constant(.active))
        }
        .navigationTitle("规则")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showAdd = true } label: { Image(systemName: "plus") }
            }
        }
        .sheet(isPresented: $showAdd) {
            NavigationStack {
                Form {
                    Picker("匹配", selection: $draft.matchType) {
                        ForEach(RuleMatchType.allCases) { t in Text(t.zh).tag(t) }
                    }
                    TextField("值（后缀 / 关键词 / CIDR）", text: $draft.pattern)
                        .textInputAutocapitalization(.never)
                    Picker("策略", selection: $draft.policy) {
                        ForEach(RulePolicy.allCases) { p in Text(p.zh).tag(p) }
                    }
                    TextField("备注", text: $draft.note)
                }
                .navigationTitle("添加规则")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("取消") { showAdd = false } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("添加") {
                            store.updateRules { $0.insert(draft, at: max(0, $0.count - 1)) }
                            draft = ProxyRule(matchType: .domainSuffix, pattern: "", policy: .direct)
                            showAdd = false
                        }
                        .disabled(draft.pattern.isEmpty && draft.matchType != .geoDummy)
                    }
                }
            }
            .preferredColorScheme(.dark)
        }
    }
}
