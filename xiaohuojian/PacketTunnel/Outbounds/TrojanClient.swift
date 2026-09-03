import Foundation

/// Trojan-over-TLS TCP client.
final class TrojanClient: TunnelOutbound {
    var onReceive: ((Data) -> Void)?
    var onClose: (() -> Void)?
    private var stream: ByteStream?
    private var closed = false
    private var ready = false
    private var pending = Data()

    func start(node: ProxyNode, destHost: String, destPort: UInt16) {
        Task {
            do {
                let sni = node.sni.isEmpty ? node.host : node.sni
                let s = try await ByteStream.connect(host: node.host, port: UInt16(node.port), tls: true, sni: sni, insecure: node.allowInsecure)
                self.stream = s
                var hello = Data()
                hello.append(contentsOf: Array(TrojanAuth.hexSHA224(node.password).utf8))
                hello.append(contentsOf: [0x0d, 0x0a, 0x01])
                hello.append(SOCKSAddr.encode(host: destHost, port: destPort))
                hello.append(contentsOf: [0x0d, 0x0a])
                try await s.send(hello)
                ready = true
                if !pending.isEmpty {
                    try await s.send(pending)
                    pending = Data()
                }
                await pump(s)
            } catch {
                close()
            }
        }
    }

    func send(_ data: Data) {
        if ready, let stream { Task { try? await stream.send(data) } }
        else { pending.append(data) }
    }

    func close() {
        guard !closed else { return }
        closed = true
        stream?.cancel()
        onClose?()
    }

    private func pump(_ s: ByteStream) async {
        while !closed {
            do {
                let chunk = try await s.recv(min: 1, max: 32 * 1024)
                if chunk.isEmpty { break }
                onReceive?(chunk)
            } catch { break }
        }
        close()
    }
}
