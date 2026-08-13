import Foundation
import struct Network.IPv4Address
import struct Network.IPv6Address
import NetworkExtension

struct SOCKSEndpoint: Equatable {
    let host: String
    let port: UInt16

    init(host: String, port: UInt16) throws {
        guard host.isEmpty == false else {
            throw SOCKSError.invalidEndpoint
        }
        self.host = host
        self.port = port
    }

    init(endpoint: NWEndpoint, preferredHostname: String? = nil) throws {
        guard let hostEndpoint = endpoint as? NWHostEndpoint, let port = UInt16(hostEndpoint.port) else {
            throw SOCKSError.unsupportedEndpoint
        }
        let preferredHostname = preferredHostname?.trimmingCharacters(in: .whitespacesAndNewlines)
        let host: String
        if let preferredHostname, preferredHostname.isEmpty == false {
            host = preferredHostname
        } else {
            host = hostEndpoint.hostname
        }
        try self.init(host: host, port: port)
    }

    var networkEndpoint: NWHostEndpoint {
        NWHostEndpoint(hostname: host, port: String(port))
    }
}

enum SOCKSProtocol {
    static let version: UInt8 = 5
    static let usernamePasswordMethod: UInt8 = 2

    static func greeting() -> Data {
        Data([version, 1, usernamePasswordMethod])
    }

    static func authentication(username: String, password: String) throws -> Data {
        let username = Data(username.utf8)
        let password = Data(password.utf8)
        guard
            username.isEmpty == false,
            username.count <= Int(UInt8.max),
            password.isEmpty == false,
            password.count <= Int(UInt8.max)
        else {
            throw SOCKSError.invalidCredentials
        }
        var request = Data([1, UInt8(username.count)])
        request.append(username)
        request.append(UInt8(password.count))
        request.append(password)
        return request
    }

    static func connectRequest(endpoint: SOCKSEndpoint) throws -> Data {
        try request(command: 1, endpoint: endpoint)
    }

    static func udpAssociateRequest() throws -> Data {
        try request(command: 3, endpoint: SOCKSEndpoint(host: "0.0.0.0", port: 0))
    }

    static func parseMethodSelection(_ data: Data) throws {
        guard data.count == 2, data[0] == version else {
            throw SOCKSError.invalidResponse
        }
        guard data[1] == usernamePasswordMethod else {
            throw SOCKSError.authenticationMethodRejected(data[1])
        }
    }

    static func parseAuthenticationResponse(_ data: Data) throws {
        guard data.count == 2, data[0] == 1 else {
            throw SOCKSError.invalidResponse
        }
        guard data[1] == 0 else {
            throw SOCKSError.authenticationRejected
        }
    }

    static func responseAddressByteCount(for header: Data) throws -> Int {
        guard header.count == 4, header[0] == version, header[2] == 0 else {
            throw SOCKSError.invalidResponse
        }
        guard header[1] == 0 else {
            throw SOCKSError.proxyRejected(header[1])
        }
        switch header[3] {
        case 1:
            return 4 + 2
        case 3:
            return -1
        case 4:
            return 16 + 2
        default:
            throw SOCKSError.unsupportedAddressType(header[3])
        }
    }

    static func parseResponseEndpoint(header: Data, address: Data) throws -> SOCKSEndpoint {
        guard header.count == 4 else {
            throw SOCKSError.invalidResponse
        }
        var cursor = DataCursor(address)
        let host: String
        switch header[3] {
        case 1:
            let bytes = try cursor.read(count: 4)
            host = bytes.map(String.init).joined(separator: ".")
        case 3:
            let length = Int(try cursor.readByte())
            let bytes = try cursor.read(count: length)
            guard let decoded = String(data: bytes, encoding: .utf8) else {
                throw SOCKSError.invalidEndpoint
            }
            host = decoded
        case 4:
            let bytes = try cursor.read(count: 16)
            guard let address = IPv6Address(bytes) else {
                throw SOCKSError.invalidEndpoint
            }
            host = address.debugDescription
        default:
            throw SOCKSError.unsupportedAddressType(header[3])
        }
        let portBytes = try cursor.read(count: 2)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
        guard cursor.isAtEnd else {
            throw SOCKSError.invalidResponse
        }
        return try SOCKSEndpoint(host: host, port: port)
    }

    static func encodeUDPDatagram(data: Data, endpoint: SOCKSEndpoint) throws -> Data {
        guard data.count <= 65_507 else {
            throw SOCKSError.datagramTooLarge
        }
        var packet = Data([0, 0, 0])
        try append(endpoint: endpoint, to: &packet)
        packet.append(data)
        guard packet.count <= 65_507 else {
            throw SOCKSError.datagramTooLarge
        }
        return packet
    }

    static func decodeUDPDatagram(_ packet: Data) throws -> (Data, SOCKSEndpoint) {
        var cursor = DataCursor(packet)
        guard
            try cursor.readByte() == 0,
            try cursor.readByte() == 0,
            try cursor.readByte() == 0
        else {
            throw SOCKSError.fragmentedDatagram
        }
        let endpoint = try readEndpoint(from: &cursor)
        return (cursor.remainingData, endpoint)
    }

    private static func request(command: UInt8, endpoint: SOCKSEndpoint) throws -> Data {
        var request = Data([version, command, 0])
        try append(endpoint: endpoint, to: &request)
        return request
    }

    private static func append(endpoint: SOCKSEndpoint, to data: inout Data) throws {
        if let address = IPv4Address(endpoint.host) {
            data.append(1)
            data.append(contentsOf: address.rawValue)
        } else if let address = IPv6Address(endpoint.host) {
            data.append(4)
            data.append(contentsOf: address.rawValue)
        } else {
            let hostname = Data(endpoint.host.utf8)
            guard hostname.isEmpty == false, hostname.count <= Int(UInt8.max) else {
                throw SOCKSError.invalidEndpoint
            }
            data.append(3)
            data.append(UInt8(hostname.count))
            data.append(hostname)
        }
        data.append(UInt8(endpoint.port >> 8))
        data.append(UInt8(endpoint.port & 0xff))
    }

    private static func readEndpoint(from cursor: inout DataCursor) throws -> SOCKSEndpoint {
        let addressType = try cursor.readByte()
        let host: String
        switch addressType {
        case 1:
            let bytes = try cursor.read(count: 4)
            host = bytes.map(String.init).joined(separator: ".")
        case 3:
            let length = Int(try cursor.readByte())
            let bytes = try cursor.read(count: length)
            guard let hostname = String(data: bytes, encoding: .utf8) else {
                throw SOCKSError.invalidEndpoint
            }
            host = hostname
        case 4:
            let bytes = try cursor.read(count: 16)
            guard let address = IPv6Address(bytes) else {
                throw SOCKSError.invalidEndpoint
            }
            host = address.debugDescription
        default:
            throw SOCKSError.unsupportedAddressType(addressType)
        }
        let portBytes = try cursor.read(count: 2)
        return try SOCKSEndpoint(
            host: host,
            port: UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
        )
    }
}

struct DataCursor {
    private let data: Data
    private var offset = 0

    init(_ data: Data) {
        self.data = data
    }

    var isAtEnd: Bool {
        offset == data.count
    }

    var remainingData: Data {
        data.subdata(in: offset..<data.count)
    }

    mutating func readByte() throws -> UInt8 {
        guard offset < data.count else {
            throw SOCKSError.truncatedPacket
        }
        defer { offset += 1 }
        return data[offset]
    }

    mutating func read(count: Int) throws -> Data {
        guard count >= 0, offset <= data.count - count else {
            throw SOCKSError.truncatedPacket
        }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }
}

enum SOCKSError: LocalizedError {
    case invalidCredentials
    case invalidEndpoint
    case unsupportedEndpoint
    case invalidResponse
    case truncatedPacket
    case authenticationMethodRejected(UInt8)
    case authenticationRejected
    case proxyRejected(UInt8)
    case unsupportedAddressType(UInt8)
    case fragmentedDatagram
    case datagramTooLarge
    case connectionClosed
    case unexpectedControlData

    var errorDescription: String? {
        switch self {
        case .invalidCredentials:
            return "The private SOCKS credentials are invalid."
        case .invalidEndpoint:
            return "A proxied network endpoint is invalid."
        case .unsupportedEndpoint:
            return "A proxied network endpoint type is not supported."
        case .invalidResponse:
            return "The private SOCKS proxy returned an invalid response."
        case .truncatedPacket:
            return "A SOCKS packet was truncated."
        case .authenticationMethodRejected(let method):
            return "The private SOCKS proxy selected unsupported authentication method \(method)."
        case .authenticationRejected:
            return "The private SOCKS proxy rejected the session credential."
        case .proxyRejected(let reply):
            return "The private SOCKS proxy rejected a connection with reply \(reply)."
        case .unsupportedAddressType(let addressType):
            return "SOCKS address type \(addressType) is not supported."
        case .fragmentedDatagram:
            return "Fragmented SOCKS UDP datagrams are not supported."
        case .datagramTooLarge:
            return "A proxied UDP datagram is too large."
        case .connectionClosed:
            return "The private SOCKS connection closed unexpectedly."
        case .unexpectedControlData:
            return "The private SOCKS UDP control connection returned unexpected data."
        }
    }
}
