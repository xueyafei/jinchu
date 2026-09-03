import Foundation
import CryptoKit

enum SSMethod {
    case chacha20Poly1305
    case aes256gcm
    case aes128gcm

    init?(name: String) {
        switch name.lowercased() {
        case "chacha20-ietf-poly1305", "chacha20-poly1305":
            self = .chacha20Poly1305
        case "aes-256-gcm":
            self = .aes256gcm
        case "aes-128-gcm":
            self = .aes128gcm
        default:
            return nil
        }
    }

    var keyLen: Int {
        switch self {
        case .chacha20Poly1305, .aes256gcm: return 32
        case .aes128gcm: return 16
        }
    }
    var saltLen: Int { keyLen }
    var nonceLen: Int { 12 }
    var tagLen: Int { 16 }
}

enum SSCrypto {
    static func evpBytesToKey(password: String, keyLen: Int) -> Data {
        let pass = Data(password.utf8)
        var acc = Data()
        var last = Data()
        while acc.count < keyLen {
            var md = Data()
            md.append(last)
            md.append(pass)
            last = Data(Insecure.MD5.hash(data: md))
            acc.append(last)
        }
        return acc.prefix(keyLen)
    }

    static func hkdfSHA1(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        let prk = HMAC<Insecure.SHA1>.authenticationCode(for: ikm, using: SymmetricKey(data: salt))
        let prkKey = SymmetricKey(data: Data(prk))
        var t = Data()
        var okm = Data()
        var counter: UInt8 = 1
        while okm.count < length {
            var block = Data()
            block.append(t)
            block.append(info)
            block.append(counter)
            t = Data(HMAC<Insecure.SHA1>.authenticationCode(for: block, using: prkKey))
            okm.append(t)
            counter += 1
        }
        return okm.prefix(length)
    }

    static func sessionKey(master: Data, salt: Data, method: SSMethod) -> Data {
        hkdfSHA1(ikm: master, salt: salt, info: Data("ss-subkey".utf8), length: method.keyLen)
    }

    static func seal(method: SSMethod, key: Data, nonce: Data, plaintext: Data) throws -> Data {
        switch method {
        case .chacha20Poly1305:
            let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: try ChaChaPoly.Nonce(data: nonce))
            var out = Data(box.ciphertext)
            out.append(box.tag)
            return out
        case .aes256gcm, .aes128gcm:
            let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: try AES.GCM.Nonce(data: nonce))
            var out = Data(box.ciphertext)
            out.append(box.tag)
            return out
        }
    }

    static func open(method: SSMethod, key: Data, nonce: Data, ciphertextAndTag: Data) throws -> Data {
        guard ciphertextAndTag.count >= 16 else { throw SSError.short }
        let ct = ciphertextAndTag.dropLast(16)
        let tag = ciphertextAndTag.suffix(16)
        switch method {
        case .chacha20Poly1305:
            let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce), ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(box, using: SymmetricKey(data: key))
        case .aes256gcm, .aes128gcm:
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
            return try AES.GCM.open(box, using: SymmetricKey(data: key))
        }
    }

    static func bumpNonce(_ nonce: inout Data) {
        var i = 0
        while i < nonce.count {
            let v = nonce[i] &+ 1
            nonce[i] = v
            if v != 0 { break }
            i += 1
        }
    }
}

enum SSError: Error { case short, badMethod }
