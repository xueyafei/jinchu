import Foundation

final class SOCKS5Client: TunnelOutbound {
    var onReceive: ((Data) -> Void)?
    var onClose: (() -> Void)?
    private var stream: ByteStream?
    private var closed = false
    private var ready = false
    private var pending = Data()

    func start(node: ProxyNode, destHost: String, destPort: UInt16) {
        Task {
            do {
                let s = try await ByteStream.connect(host: node.host, port: UInt16(node.port), tls: false, sni: "", insecure: false)
                self.stream = s
                if node.username.isEmpty {
                    try await s.send(Data([0x05, 0x01, 0x00]))
                    let r = try await s.recvExact(2)
                    guard r.first == 0x05, r.count >= 2, r[1] == 0x00 else { throw NSError(domain: "socks", code: 1) }
                } else {
                    try await s.send(Data([0x05, 0x01, 0x02]))
                    let r = try await s.recvExact(2)
                    guard r.first == 0x05, r.count >= 2, r[1] == 0x02 else { throw NSError(domain: "socks", code: 1) }
                    var auth = Data([0x01, UInt8(min(node.username.utf8.count, 255))])
                    auth.append(contentsOf: Array(node.username.utf8).prefix(255))
                    auth.append(UInt8(min(node.password.utf8.count, 255)))
                    auth.append(contentsOf: Array(node.password.utf8).prefix(255))
                    try await s.send(auth)
                    let ar = try await s.recvExact(2)
                    guard ar.count >= 2, ar[1] == 0x00 else { throw NSError(domain: "socks", code: 2) }
                }
                var req = Data([0x05, 0x01, 0x00])
                req.append(SOCKSAddr.encode(host: destHost, port: destPort))
                try await s.send(req)
                let head = try await s.recvExact(4)
                guard head.count >= 4, head[1] == 0x00 else { throw NSError(domain: "socks", code: 3) }
                let atyp = head[3]
                var extra = 0
                if atyp == 1 { extra = 4 + 2 }
                else if atyp == 4 { extra = 16 + 2 }
                else if atyp == 3 {
                    let l = try await s.recvExact(1)
                    extra = Int(l[0]) + 2
                }
                _ = try await s.recvExact(extra)
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
        if ready, let stream {
            Task { try? await stream.send(data) }
        } else {
            pending.append(data)
        }
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
