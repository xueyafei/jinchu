import Foundation
import Security

/// Shadowsocks AEAD TCP client (chacha20-ietf-poly1305 / aes-256-gcm / aes-128-gcm).
final class ShadowsocksClient: TunnelOutbound {
    var onReceive: ((Data) -> Void)?
    var onClose: (() -> Void)?

    private var stream: ByteStream?
    private var closed = false
    private var ready = false
    private var pending = Data()

    private var method: SSMethod
    private var key: Data
    private var encNonce: Data
    private var decNonce: Data
    private var decBuf = Data()

    init(method: SSMethod, masterKey: Data) {
        self.method = method
        self.key = Data()
        self.encNonce = Data(count: method.nonceLen)
        self.decNonce = Data(count: method.nonceLen)
        self.master = masterKey
    }

    private let master: Data

    func start(node: ProxyNode, destHost: String, destPort: UInt16) {
        Task {
            do {
                let s = try await ByteStream.connect(host: node.host, port: UInt16(node.port), tls: false, sni: "", insecure: false)
                self.stream = s
                var salt = Data(count: method.saltLen)
                let st = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, method.saltLen, $0.baseAddress!) }
                if st != errSecSuccess {
                    for i in 0..<salt.count { salt[i] = UInt8.random(in: 0...255) }
                }
                try await s.send(salt)
                key = SSCrypto.sessionKey(master: master, salt: salt, method: method)
                encNonce = Data(count: method.nonceLen)
                decNonce = Data(count: method.nonceLen)
                let header = SOCKSAddr.encode(host: destHost, port: destPort)
                try await s.send(try encryptChunk(header))
                ready = true
                if !pending.isEmpty {
                    try await sendEncrypted(pending)
                    pending = Data()
                }
                await pump(s)
            } catch {
                close()
            }
        }
    }

    func send(_ data: Data) {
        if ready {
            Task { try? await sendEncrypted(data) }
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

    private func sendEncrypted(_ data: Data) async throws {
        var offset = 0
        let maxChunk = 0x3fff
        while offset < data.count {
            let end = min(offset + maxChunk, data.count)
            let piece = data.subdata(in: offset..<end)
            try await stream?.send(try encryptChunk(piece))
            offset = end
        }
    }

    private func encryptChunk(_ payload: Data) throws -> Data {
        var len = Data(count: 2)
        let n = UInt16(payload.count)
        len[0] = UInt8(n >> 8)
        len[1] = UInt8(n & 0xff)
        let encLen = try SSCrypto.seal(method: method, key: key, nonce: encNonce, plaintext: len)
        SSCrypto.bumpNonce(&encNonce)
        let encPay = try SSCrypto.seal(method: method, key: key, nonce: encNonce, plaintext: payload)
        SSCrypto.bumpNonce(&encNonce)
        var out = Data()
        out.append(encLen)
        out.append(encPay)
        return out
    }

    private func pump(_ s: ByteStream) async {
        while !closed {
            do {
                let chunk = try await s.recv(min: 1, max: 32 * 1024)
                if chunk.isEmpty { break }
                decBuf.append(chunk)
                try drainDecrypt()
            } catch { break }
        }
        close()
    }

    private func drainDecrypt() throws {
        let tag = method.tagLen
        while true {
            let lenNeed = 2 + tag
            guard decBuf.count >= lenNeed else { return }
            let encLen = decBuf.prefix(lenNeed)
            let lenPlain = try SSCrypto.open(method: method, key: key, nonce: decNonce, ciphertextAndTag: Data(encLen))
            guard lenPlain.count == 2 else { throw SSError.short }
            let payloadLen = Int(lenPlain[0]) << 8 | Int(lenPlain[1])
            let payNeed = payloadLen + tag
            guard decBuf.count >= lenNeed + payNeed else { return }
            SSCrypto.bumpNonce(&decNonce)
            let encPay = decBuf.subdata(in: lenNeed..<(lenNeed + payNeed))
            let plain = try SSCrypto.open(method: method, key: key, nonce: decNonce, ciphertextAndTag: encPay)
            SSCrypto.bumpNonce(&decNonce)
            decBuf.removeSubrange(0..<(lenNeed + payNeed))
            if !plain.isEmpty { onReceive?(plain) }
        }
    }
}
