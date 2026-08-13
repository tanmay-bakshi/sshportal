import Foundation

enum SSHPortalIdentifiers {
    static let application = "com.tanmaybakshi.sshportal.macos"
    static let appProxyExtension = "com.tanmaybakshi.sshportal.macos.AppProxyExtension"
    static let managerDescription = "SSHPortal Per-App VPN"
}

struct ProxyConfiguration {
    private enum Key {
        static let socksHost = "socksHost"
        static let socksPort = "socksPort"
        static let username = "username"
        static let password = "password"
    }

    let socksHost: String
    let socksPort: UInt16
    let username: String
    let password: String

    init(socksHost: String, socksPort: UInt16, username: String, password: String) throws {
        guard socksHost == "127.0.0.1" || socksHost == "::1" else {
            throw ProxyConfigurationError.nonLoopbackProxy
        }
        guard socksPort > 0 else {
            throw ProxyConfigurationError.invalidPort
        }
        guard Self.isValidCredential(username) else {
            throw ProxyConfigurationError.invalidUsername
        }
        guard Self.isValidCredential(password) else {
            throw ProxyConfigurationError.invalidPassword
        }

        self.socksHost = socksHost
        self.socksPort = socksPort
        self.username = username
        self.password = password
    }

    init(providerConfiguration: [String: Any]?) throws {
        guard
            let providerConfiguration,
            let socksHost = providerConfiguration[Key.socksHost] as? String,
            let portNumber = providerConfiguration[Key.socksPort] as? NSNumber,
            let username = providerConfiguration[Key.username] as? String,
            let password = providerConfiguration[Key.password] as? String,
            let socksPort = UInt16(exactly: portNumber)
        else {
            throw ProxyConfigurationError.missingValues
        }

        try self.init(
            socksHost: socksHost,
            socksPort: socksPort,
            username: username,
            password: password
        )
    }

    var providerConfiguration: [String: Any] {
        [
            Key.socksHost: socksHost,
            Key.socksPort: NSNumber(value: socksPort),
            Key.username: username,
            Key.password: password,
        ]
    }

    private static func isValidCredential(_ value: String) -> Bool {
        let byteCount = value.lengthOfBytes(using: .utf8)
        return byteCount > 0 && byteCount <= Int(UInt8.max)
    }
}

enum ProxyConfigurationError: LocalizedError {
    case missingValues
    case nonLoopbackProxy
    case invalidPort
    case invalidUsername
    case invalidPassword

    var errorDescription: String? {
        switch self {
        case .missingValues:
            return "The per-app VPN configuration is incomplete."
        case .nonLoopbackProxy:
            return "The per-app VPN proxy must use a loopback address."
        case .invalidPort:
            return "The per-app VPN proxy port is invalid."
        case .invalidUsername:
            return "The per-app VPN proxy username is invalid."
        case .invalidPassword:
            return "The per-app VPN proxy password is invalid."
        }
    }
}
