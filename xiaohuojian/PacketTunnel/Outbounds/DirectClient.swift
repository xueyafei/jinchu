import Foundation

final class DirectClient: TunnelOutbound {
    var onReceive: ((Data) -> Void)?
    var onClose: (() -> Void)?
    private var stream: ByteStream?
    private var closed = false

    func start(host: String, port: UInt16) {
        Task {
            do {
                let s = try await ByteStream.connect(host: host, port: port, tls: false, sni: "", insecure: false)
                self.stream = s
                await pump(s)
            } catch {
                close()
            }
        }
    }

    func send(_ data: Data) {
        guard let stream else { return }
        Task { try? await stream.send(data) }
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
            } catch {
                break
            }
        }
        close()
    }
}
