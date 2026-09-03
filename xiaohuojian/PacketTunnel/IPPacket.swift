import Foundation

enum IPProto {
    static let icmp: UInt8 = 1
    static let tcp: UInt8 = 6
    static let udp: UInt8 = 17
}

struct IPv4Header {
    var versionIHL: UInt8
    var tos: UInt8
    var totalLength: UInt16
    var id: UInt16
    var flagsFrag: UInt16
    var ttl: UInt8
    var proto: UInt8
    var checksum: UInt16
    var src: UInt32
    var dst: UInt32
    var headerLength: Int { Int(versionIHL & 0x0f) * 4 }
}

struct TCPFlags {
    static let fin: UInt8 = 0x01
    static let syn: UInt8 = 0x02
    static let rst: UInt8 = 0x04
    static let psh: UInt8 = 0x08
    static let ack: UInt8 = 0x10
}

struct ParsedIPv4 {
    var header: IPv4Header
    var payload: Data
    var raw: Data
}

enum PacketCodec {
    static func parseIPv4(_ data: Data) -> ParsedIPv4? {
        guard data.count >= 20 else { return nil }
        let ihl = Int(data[0] & 0x0f) * 4
        guard (data[0] >> 4) == 4, ihl >= 20, data.count >= ihl else { return nil }
        let total = u16(data, 2)
        let header = IPv4Header(
            versionIHL: data[0],
            tos: data[1],
            totalLength: total,
            id: u16(data, 4),
            flagsFrag: u16(data, 6),
            ttl: data[8],
            proto: data[9],
            checksum: u16(data, 10),
            src: u32(data, 12),
            dst: u32(data, 16)
        )
        let end = min(Int(total), data.count)
        guard end >= ihl else { return nil }
        return ParsedIPv4(header: header, payload: data.subdata(in: ihl..<end), raw: data)
    }

    static func parseTCP(_ payload: Data) -> (src: UInt16, dst: UInt16, seq: UInt32, ack: UInt32, flags: UInt8, window: UInt16, data: Data, hdrLen: Int)? {
        guard payload.count >= 20 else { return nil }
        let hdrLen = Int((payload[12] >> 4) * 4)
        guard hdrLen >= 20, payload.count >= hdrLen else { return nil }
        return (
            u16(payload, 0),
            u16(payload, 2),
            u32(payload, 4),
            u32(payload, 8),
            payload[13],
            u16(payload, 14),
            payload.subdata(in: hdrLen..<payload.count),
            hdrLen
        )
    }

    static func parseUDP(_ payload: Data) -> (src: UInt16, dst: UInt16, data: Data)? {
        guard payload.count >= 8 else { return nil }
        return (u16(payload, 0), u16(payload, 2), payload.subdata(in: 8..<payload.count))
    }

    static func buildIPv4(src: UInt32, dst: UInt32, proto: UInt8, id: UInt16, payload: Data, ttl: UInt8 = 64) -> Data {
        var ip = Data(count: 20)
        ip[0] = 0x45
        let total = UInt16(20 + payload.count)
        putU16(&ip, 2, total)
        putU16(&ip, 4, id)
        ip[8] = ttl
        ip[9] = proto
        putU32(&ip, 12, src)
        putU32(&ip, 16, dst)
        putU16(&ip, 10, checksum(ip))
        var out = ip
        out.append(payload)
        return out
    }

    static func buildTCP(
        srcPort: UInt16, dstPort: UInt16,
        seq: UInt32, ack: UInt32,
        flags: UInt8, window: UInt16,
        payload: Data,
        srcIP: UInt32, dstIP: UInt32
    ) -> Data {
        var tcp = Data(count: 20)
        putU16(&tcp, 0, srcPort)
        putU16(&tcp, 2, dstPort)
        putU32(&tcp, 4, seq)
        putU32(&tcp, 8, ack)
        tcp[12] = 5 << 4
        tcp[13] = flags
        putU16(&tcp, 14, window)
        var full = tcp
        full.append(payload)
        let csum = tcpChecksum(srcIP: srcIP, dstIP: dstIP, tcp: full)
        putU16(&full, 16, csum)
        return full
    }

    static func buildUDP(srcPort: UInt16, dstPort: UInt16, payload: Data, srcIP: UInt32, dstIP: UInt32) -> Data {
        var u = Data(count: 8)
        putU16(&u, 0, srcPort)
        putU16(&u, 2, dstPort)
        putU16(&u, 4, UInt16(8 + payload.count))
        var full = u
        full.append(payload)
        let csum = udpChecksum(srcIP: srcIP, dstIP: dstIP, udp: full)
        putU16(&full, 6, csum)
        return full
    }

    static func checksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        let bytes = [UInt8](data)
        while i + 1 < bytes.count {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum & 0xffff)
    }

    static func tcpChecksum(srcIP: UInt32, dstIP: UInt32, tcp: Data) -> UInt16 {
        var pseudo = Data()
        appendU32(&pseudo, srcIP)
        appendU32(&pseudo, dstIP)
        pseudo.append(0)
        pseudo.append(IPProto.tcp)
        appendU16(&pseudo, UInt16(tcp.count))
        pseudo.append(tcp)
        return checksum(pseudo)
    }

    static func udpChecksum(srcIP: UInt32, dstIP: UInt32, udp: Data) -> UInt16 {
        var pseudo = Data()
        appendU32(&pseudo, srcIP)
        appendU32(&pseudo, dstIP)
        pseudo.append(0)
        pseudo.append(IPProto.udp)
        appendU16(&pseudo, UInt16(udp.count))
        pseudo.append(udp)
        let c = checksum(pseudo)
        return c == 0 ? 0xffff : c
    }
}

func u16(_ d: Data, _ o: Int) -> UInt16 {
    UInt16(d[o]) << 8 | UInt16(d[o + 1])
}
func u32(_ d: Data, _ o: Int) -> UInt32 {
    UInt32(d[o]) << 24 | UInt32(d[o + 1]) << 16 | UInt32(d[o + 2]) << 8 | UInt32(d[o + 3])
}
func putU16(_ d: inout Data, _ o: Int, _ v: UInt16) {
    d[o] = UInt8(v >> 8)
    d[o + 1] = UInt8(v & 0xff)
}
func putU32(_ d: inout Data, _ o: Int, _ v: UInt32) {
    d[o] = UInt8(v >> 24)
    d[o + 1] = UInt8((v >> 16) & 0xff)
    d[o + 2] = UInt8((v >> 8) & 0xff)
    d[o + 3] = UInt8(v & 0xff)
}
func appendU16(_ d: inout Data, _ v: UInt16) {
    d.append(UInt8(v >> 8))
    d.append(UInt8(v & 0xff))
}
func appendU32(_ d: inout Data, _ v: UInt32) {
    d.append(UInt8(v >> 24))
    d.append(UInt8((v >> 16) & 0xff))
    d.append(UInt8((v >> 8) & 0xff))
    d.append(UInt8(v & 0xff))
}

enum SOCKSAddr {
    static func encode(host: String, port: UInt16) -> Data {
        var d = Data()
        if let ip = IPv4.parse(host) {
            d.append(0x01)
            appendU32(&d, ip)
        } else if host.contains(":") {
            d.append(0x04)
            var buf = [UInt8](repeating: 0, count: 16)
            // leave zeros if unparsable v6; host should be ipv4 in tun path
            d.append(contentsOf: buf)
        } else {
            d.append(0x03)
            let b = Array(host.utf8)
            d.append(UInt8(min(b.count, 255)))
            d.append(contentsOf: b.prefix(255))
        }
        appendU16(&d, port)
        return d
    }
}
