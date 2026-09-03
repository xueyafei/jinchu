import Foundation
import NetworkExtension
import Darwin

final class PacketLoop {
    let packetFlow: NEPacketTunnelFlow
    let engine: RuleEngine
    let node: ProxyNode?
    let sessions = SessionTable()
    let udp: UDPHandler
    var onTraffic: (Int64, Int64) -> Void = { _, _ in }
    private var running = false

    init(packetFlow: NEPacketTunnelFlow, engine: RuleEngine, node: ProxyNode?, dns: String) {
        self.packetFlow = packetFlow
        self.engine = engine
        self.node = node
        self.udp = UDPHandler(dnsHost: dns) { [packetFlow] pkt in
            packetFlow.writePackets([pkt], withProtocols: [NSNumber(value: AF_INET)])
        }
    }

    func start() {
        running = true
        read()
    }

    func stop() {
        running = false
        sessions.clear()
    }

    private func read() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.running else { return }
            for p in packets { self.handle(p) }
            self.read()
        }
    }

    private func handle(_ packet: Data) {
        guard let ip = PacketCodec.parseIPv4(packet) else { return }
        if ip.header.proto == IPProto.tcp {
            handleTCP(ip)
        } else if ip.header.proto == IPProto.udp {
            if let u = PacketCodec.parseUDP(ip.payload) {
                udp.handle(srcIP: ip.header.src, dstIP: ip.header.dst, srcPort: u.src, dstPort: u.dst, payload: u.data)
            }
        }
    }

    private func handleTCP(_ ip: ParsedIPv4) {
        guard let t = PacketCodec.parseTCP(ip.payload) else { return }
        let key = TCPSession.key(ip.header.src, t.src, ip.header.dst, t.dst)
        if let existing = sessions.get(key) {
            existing.handleClient(seq: t.seq, flags: t.flags, payload: t.data)
            if !existing.alive { sessions.remove(key) }
            return
        }
        guard t.flags & TCPFlags.syn != 0, t.flags & TCPFlags.ack == 0 else { return }
        let dstHost = IPv4.stringify(ip.header.dst)
        let policy = engine.policy(host: nil, ip: ip.header.dst)
        let session = TCPSession(
            srcIP: ip.header.src, dstIP: ip.header.dst,
            srcPort: t.src, dstPort: t.dst,
            theirSeq: t.seq,
            writePacket: { [weak self] pkt in
                self?.packetFlow.writePackets([pkt], withProtocols: [NSNumber(value: AF_INET)])
            },
            onTraffic: { [weak self] u, d in self?.onTraffic(u, d) }
        )
        if policy == .reject {
            session.sendRST()
            return
        }
        guard let outbound = OutboundFactory.make(node: node, policy: policy, destHost: dstHost, destPort: t.dst) else {
            session.sendRST()
            return
        }
        session.attach(outbound)
        session.sendSYNACK()
        sessions.put(session)
    }
}
