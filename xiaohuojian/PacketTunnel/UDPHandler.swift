import Foundation
import Network

/// v1: UDP/53 is forwarded to the configured DNS over a side UDP socket (not through SS/Trojan).
final class UDPHandler {
    private let dnsHost: String
    private let writePacket: (Data) -> Void
    private var ipID: UInt16 = 200
    private let queue = DispatchQueue(label: "app.xiaohuojian.udp")

    init(dnsHost: String, writePacket: @escaping (Data) -> Void) {
        self.dnsHost = dnsHost
        self.writePacket = writePacket
    }

    func handle(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16, payload: Data) {
        guard dstPort == 53, !payload.isEmpty else { return }
        let host = NWEndpoint.Host(dnsHost)
        guard let port = NWEndpoint.Port(rawValue: 53) else { return }
        let conn = NWConnection(host: host, port: port, using: .udp)
        conn.start(queue: queue)
        conn.send(content: payload, completion: .contentProcessed { _ in })
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, _, _ in
            guard let self, let data, !data.isEmpty else {
                conn.cancel()
                return
            }
            let udp = PacketCodec.buildUDP(srcPort: dstPort, dstPort: srcPort, payload: data, srcIP: dstIP, dstIP: srcIP)
            let ip = PacketCodec.buildIPv4(src: dstIP, dst: srcIP, proto: IPProto.udp, id: self.ipID, payload: udp)
            self.ipID &+= 1
            self.writePacket(ip)
            conn.cancel()
        }
    }
}
