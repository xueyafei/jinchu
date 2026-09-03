import Foundation
import CommonCrypto

enum TrojanAuth {
    /// 56-char hex of SHA224(password) as required by the Trojan protocol.
    static func hexSHA224(_ password: String) -> String {
        SHA224.hex(from: password)
    }
}

enum SHA224 {
    static func hex(from password: String) -> String {
        let data = Data(password.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA224(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
