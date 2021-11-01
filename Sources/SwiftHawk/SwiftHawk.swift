import Foundation
import CryptoKit

public struct HawkCredentials {
    public var id: String
    public var key: SymmetricKey

    public init(id: String, key: SymmetricKey) {
        self.id = id
        self.key = key
    }

    public init(id: String, key: String) {
        self.init(id: id, key: SymmetricKey(data: Data(key.utf8)))
    }
}

public extension URLRequest {
    mutating func sign<H: HashFunction>(credentials: HawkCredentials, hash: H.Type) {
        guard let url = url else { return }

        let nonce = makeNonce()
        let timestamp = Int(Date().timeIntervalSince1970)

        var path = url.path
        if let query = url.query {
            path += "?\(query)"
        }

        let string = "hawk.1.header\n\(timestamp)\n\(nonce)\n\(httpMethod?.uppercased() ?? "GET")\n\(path)\n\(url.host ?? "")\n\(port)\n\n\n"

        var hash = HMAC<H>(key: credentials.key)
        hash.update(data: Data(string.utf8))
        let signature = Data(hash.finalize()).base64EncodedString(options: [])

        let header = "Hawk id=\"\(credentials.id)\", ts=\"\(timestamp)\", nonce=\"\(nonce)\", mac=\"\(signature)\""

        addValue(header, forHTTPHeaderField: "Authorization")
    }

    mutating func sign(credentials: HawkCredentials) {
        self.sign(credentials: credentials, hash: SHA256.self)
    }

    var port: Int {
        if let port = url?.port {
            return port
        }

        switch url?.scheme {
        case "http": return 80
        case "https": return 443
        default: return 0
        }
    }

    func makeNonce() -> String {
        SymmetricKey(size: .init(bitCount: 48)).withUnsafeBytes { ptr in
            Data(ptr).base64EncodedString(options: [])
        }
    }
}
