import Foundation

final class TCPSession {
    let srcIP: UInt32
    let dstIP: UInt32
    let srcPort: UInt16
    let dstPort: UInt16
    var ourSeq: UInt32
    var theirSeq: UInt32
    var outbound: TunnelOutbound?
    var alive = true
    private let writePacket: (Data) -> Void
    private let onTraffic: (Int64, Int64) -> Void
    private var ipID: UInt16 = 1

    init(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16,
         theirSeq: UInt32, writePacket: @escaping (Data) -> Void,
         onTraffic: @escaping (Int64, Int64) -> Void) {
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.theirSeq = theirSeq &+ 1
        self.ourSeq = UInt32.random(in: 1_000_000..<2_000_000_000)
        self.writePacket = writePacket
        self.onTraffic = onTraffic
    }

    var key: String { TCPSession.key(srcIP, srcPort, dstIP, dstPort) }

    static func key(_ sIP: UInt32, _ sP: UInt16, _ dIP: UInt32, _ dP: UInt16) -> String {
        "\(sIP):\(sP)-\(dIP):\(dP)"
    }

    func sendSYNACK() {
        emit(flags: TCPFlags.syn | TCPFlags.ack, payload: Data())
        ourSeq &+= 1
    }

    func handleClient(seq: UInt32, flags: UInt8, payload: Data) {
        guard alive else { return }
        if flags & TCPFlags.rst != 0 {
            teardown()
            return
        }
        if !payload.isEmpty {
            theirSeq = seq &+ UInt32(payload.count)
            outbound?.send(payload)
            onTraffic(Int64(payload.count), 0)
            emit(flags: TCPFlags.ack, payload: Data())
        } else if flags & TCPFlags.ack != 0 {
            // keep-alive ack
        }
        if flags & TCPFlags.fin != 0 {
            theirSeq &+= 1
            emit(flags: TCPFlags.ack, payload: Data())
            emit(flags: TCPFlags.fin | TCPFlags.ack, payload: Data())
            ourSeq &+= 1
            teardown()
        }
    }

    func attach(_ outbound: TunnelOutbound) {
        self.outbound = outbound
        outbound.onReceive = { [weak self] data in
            self?.fromRemote(data)
        }
        outbound.onClose = { [weak self] in
            self?.remoteClosed()
        }
    }

    private func fromRemote(_ data: Data) {
        guard alive, !data.isEmpty else { return }
        onTraffic(0, Int64(data.count))
        var offset = 0
        let mss = 1360
        while offset < data.count {
            let end = min(offset + mss, data.count)
            let piece = data.subdata(in: offset..<end)
            emit(flags: TCPFlags.psh | TCPFlags.ack, payload: piece)
            ourSeq &+= UInt32(piece.count)
            offset = end
        }
    }

    private func remoteClosed() {
        guard alive else { return }
        emit(flags: TCPFlags.fin | TCPFlags.ack, payload: Data())
        ourSeq &+= 1
        teardown()
    }

    private func emit(flags: UInt8, payload: Data) {
        let tcp = PacketCodec.buildTCP(
            srcPort: dstPort, dstPort: srcPort,
            seq: ourSeq, ack: theirSeq,
            flags: flags, window: 65535,
            payload: payload,
            srcIP: dstIP, dstIP: srcIP
        )
        let ip = PacketCodec.buildIPv4(src: dstIP, dst: srcIP, proto: IPProto.tcp, id: ipID, payload: tcp)
        ipID &+= 1
        writePacket(ip)
    }

    func sendRST() {
        emit(flags: TCPFlags.rst | TCPFlags.ack, payload: Data())
        teardown()
    }

    func teardown() {
        alive = false
        outbound?.close()
        outbound = nil
    }
}

final class SessionTable {
    private var map: [String: TCPSession] = [:]
    private let lock = NSLock()

    func get(_ k: String) -> TCPSession? {
        lock.lock(); defer { lock.unlock() }
        return map[k]
    }
    func put(_ s: TCPSession) {
        lock.lock(); defer { lock.unlock() }
        map[s.key] = s
    }
    func remove(_ k: String) {
        lock.lock(); defer { lock.unlock() }
        map.removeValue(forKey: k)
    }
    func clear() {
        lock.lock(); defer { lock.unlock() }
        for s in map.values { s.teardown() }
        map.removeAll()
    }
}
