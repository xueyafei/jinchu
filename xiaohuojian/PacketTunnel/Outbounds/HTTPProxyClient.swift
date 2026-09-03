import Foundation

final class HTTPProxyClient: TunnelOutbound {
    var onReceive: ((Data) -> Void)?
    var onClose: (() -> Void)?
    private var stream: ByteStream?
    private var closed = false
    private var ready = false
    private var pending = Data()

    func start(node: ProxyNode, destHost: String, destPort: UInt16) {
        Task {
            do {
                let s = try await ByteStream.connect(host: node.host, port: UInt16(node.port), tls: node.tls, sni: node.sni.isEmpty ? node.host : node.sni, insecure: node.allowInsecure)
                self.stream = s
                var req = "CONNECT \(destHost):\(destPort) HTTP/1.1\r\nHost: \(destHost):\(destPort)\r\n"
                if !node.username.isEmpty {
                    let raw = "\(node.username):\(node.password)"
                    let b64 = Data(raw.utf8).base64EncodedString()
                    req += "Proxy-Authorization: Basic \(b64)\r\n"
                }
                req += "Proxy-Connection: Keep-Alive\r\n\r\n"
                try await s.send(Data(req.utf8))
                var acc = Data()
                while acc.count < 4096 {
                    acc.append(try await s.recv(min: 1, max: 1024))
                    if let str = String(data: acc, encoding: .utf8), str.contains("\r\n\r\n") {
                        if !str.hasPrefix("HTTP/1.1 200") && !str.hasPrefix("HTTP/1.0 200") {
                            throw NSError(domain: "http", code: 1, userInfo: [NSLocalizedDescriptionKey: "CONNECT 失败"])
                        }
                        break
                    }
                }
                ready = true
                if !pending.isEmpty { try await s.send(pending); pending = Data() }
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
