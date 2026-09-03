import Foundation
import Network

enum LatencyTester {
    static func ping(_ node: ProxyNode, timeout: TimeInterval = 3) async -> Int {
        await withCheckedContinuation { cont in
            let host = NWEndpoint.Host(node.host)
            guard let port = NWEndpoint.Port(rawValue: UInt16(node.port)) else {
                cont.resume(returning: -1)
                return
            }
            let conn = NWConnection(host: host, port: port, using: .tcp)
            let t0 = Date()
            let lock = NSLock()
            var resumed = false
            func finish(_ v: Int) {
                lock.lock()
                defer { lock.unlock() }
                guard !resumed else { return }
                resumed = true
                conn.cancel()
                cont.resume(returning: v)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let ms = Int(Date().timeIntervalSince(t0) * 1000)
                    finish(ms)
                case .failed, .cancelled:
                    finish(-1)
                default:
                    break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                finish(-1)
            }
        }
    }
}
