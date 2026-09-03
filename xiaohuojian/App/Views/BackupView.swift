import SwiftUI
import UIKit

struct BackupView: View {
    @EnvironmentObject var store: StoreViewModel
    @State private var exportText = ""
    @State private var importText = ""
    @State private var message: String?

    var body: some View {
        ZStack {
            XHJTheme.bg.ignoresSafeArea()
            Form {
                if let message { Text(message).foregroundStyle(XHJTheme.accent) }
                Section("导出分享链接") {
                    Button("生成 URI 列表") {
                        exportText = AppGroupStore.shared.exportShareLinks()
                        message = "已生成 \(store.nodes.count) 条"
                    }
                    TextEditor(text: $exportText)
                        .frame(minHeight: 120)
                        .font(.system(.footnote, design: .monospaced))
                }
                Section("导出 JSON") {
                    Button("复制完整备份 JSON") {
                        if let data = try? AppGroupStore.shared.exportJSON(),
                           let s = String(data: data, encoding: .utf8) {
                            exportText = s
                            UIPasteboard.general.string = s
                            message = "已复制到剪贴板"
                        }
                    }
                }
                Section("导入") {
                    TextEditor(text: $importText)
                        .frame(minHeight: 100)
                        .font(.system(.footnote, design: .monospaced))
                    Button("作为分享链接导入") {
                        let n = store.importLinks(importText, group: "导入")
                        message = "导入 \(n) 个节点"
                    }
                    Button("作为 JSON 备份导入") {
                        if let data = importText.data(using: .utf8) {
                            do {
                                try AppGroupStore.shared.importJSON(data)
                                store.reload()
                                message = "JSON 备份已恢复"
                            } catch {
                                message = error.localizedDescription
                            }
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
        }
        .navigationTitle("备份与导入")
    }
}
