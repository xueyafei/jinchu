import Foundation
import Network

final class ByteStream {
    private let conn: NWConnection
    private let queue = DispatchQueue(label: "app.xiaohuojian.stream")

    init(conn: NWConnection) {
        self.conn = conn
    }

    static func connect(host: String, port: UInt16, tls: Bool, sni: String, insecure: Bool, timeout: TimeInterval = 12) async throws -> ByteStream {
        let params: NWParameters
        if tls {
            let tlsOpts = NWProtocolTLS.Options()
            let sec = tlsOpts.securityProtocolOptions
            if !sni.isEmpty {
                sec_protocol_options_set_tls_server_name(sec, sni)
            }
            if insecure {
                sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, DispatchQueue.global())
            }
            let tcp = NWProtocolTCP.Options()
            tcp.noDelay = true
            params = NWParameters(tls: tlsOpts, tcp: tcp)
        } else {
            let tcp = NWProtocolTCP.Options()
            tcp.noDelay = true
            params = NWParameters(tls: nil, tcp: tcp)
        }
        params.prohibitExpensivePaths = false
        params.allowFastOpen = false
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: params)
        let stream = ByteStream(conn: conn)
        try await stream.start(timeout: timeout)
        return stream
    }

    private func start(timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            var settled = false
            let lock = NSLock()
            func done(_ err: Error?) {
                lock.lock(); defer { lock.unlock() }
                guard !settled else { return }
                settled = true
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: done(nil)
                case .failed(let e): done(e)
                case .cancelled: done(CancellationError())
                default: break
                }
            }
            conn.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                done(NSError(domain: "XHJ", code: -1, userInfo: [NSLocalizedDescriptionKey: "连接超时"]))
            }
        }
    }

    func send(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    func recv(min: Int, max: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            conn.receive(minimumIncompleteLength: min, maximumLength: max) { content, _, isComplete, err in
                if let err { cont.resume(throwing: err); return }
                if let content, !content.isEmpty {
                    cont.resume(returning: content)
                    return
                }
                if isComplete {
                    cont.resume(throwing: NSError(domain: "XHJ", code: -2, userInfo: [NSLocalizedDescriptionKey: "连接关闭"]))
                    return
                }
                cont.resume(returning: Data())
            }
        }
    }

    func recvExact(_ n: Int) async throws -> Data {
        var acc = Data()
        while acc.count < n {
            let chunk = try await recv(min: 1, max: n - acc.count)
            if chunk.isEmpty { throw NSError(domain: "XHJ", code: -2) }
            acc.append(chunk)
        }
        return acc
    }

    func cancel() { conn.cancel() }
}

protocol TunnelOutbound: AnyObject {
    func send(_ data: Data)
    func close()
    var onReceive: ((Data) -> Void)? { get set }
    var onClose: (() -> Void)? { get set }
}
