import Foundation
import Network

actor SOCKSConnection {
    private let transport: any SOCKSConnectionTransport
    private let queue: DispatchQueue
    private var receiveBuffer = Data()
    private var receiveIsComplete = false

    init(host: String, port: UInt16, parameters: NWParameters, queue: DispatchQueue) throws {
        guard let networkPort = NWEndpoint.Port(rawValue: port) else {
            throw SOCKSError.invalidEndpoint
        }
        transport = NetworkSOCKSConnectionTransport(
            host: host,
            port: networkPort,
            parameters: parameters
        )
        self.queue = queue
    }

    init(transport: any SOCKSConnectionTransport, queue: DispatchQueue) {
        self.transport = transport
        self.queue = queue
    }

    func start() async throws {
        try await withTaskCancellationHandler {
            try await transport.start(queue: queue)
        } onCancel: {
            Task { [transport] in
                await transport.cancel()
            }
        }
    }

    func cancel() async {
        await transport.cancel()
    }

    func send(_ data: Data, isComplete: Bool = false) async throws {
        try await transport.send(data, isComplete: isComplete)
    }

    func receiveExactly(_ count: Int) async throws -> Data {
        guard count >= 0 else {
            throw SOCKSError.invalidReadBounds
        }
        if count == 0 {
            return Data()
        }

        try await fillReceiveBuffer(minimum: count, maximum: max(32_768, count))
        guard receiveBuffer.count >= count else {
            throw SOCKSError.connectionClosed
        }

        let result = receiveBuffer.prefix(count)
        receiveBuffer.removeFirst(count)
        return Data(result)
    }

    func receiveStream(minimum: Int = 1, maximum: Int = 32_768) async throws -> (Data, Bool) {
        guard minimum > 0, maximum >= minimum else {
            throw SOCKSError.invalidReadBounds
        }

        try await fillReceiveBuffer(minimum: minimum, maximum: maximum)
        let count = min(receiveBuffer.count, maximum)
        let data = Data(receiveBuffer.prefix(count))
        receiveBuffer.removeFirst(count)
        return (data, receiveIsComplete && receiveBuffer.isEmpty)
    }

    private func fillReceiveBuffer(minimum: Int, maximum: Int) async throws {
        while receiveBuffer.count < minimum && receiveIsComplete == false {
            let remainingCapacity = maximum - receiveBuffer.count
            let remainingMinimum = minimum - receiveBuffer.count
            let (data, isComplete) = try await receiveFromTransport(
                minimum: remainingMinimum,
                maximum: remainingCapacity
            )
            receiveBuffer.append(data)
            receiveIsComplete = isComplete
        }
    }

    private func receiveFromTransport(minimum: Int, maximum: Int) async throws -> (Data, Bool) {
        try await transport.receive(minimum: minimum, maximum: maximum)
    }

    func sendMessage(_ data: Data) async throws {
        try await send(data, isComplete: true)
    }

    func receiveMessage() async throws -> Data {
        try await transport.receiveMessage()
    }
}

extension SOCKSConnection {
    func authenticate(configuration: ProxyConfiguration) async throws {
        try await send(SOCKSProtocol.greeting())
        try SOCKSProtocol.parseMethodSelection(try await receiveExactly(2))
        try await send(
            SOCKSProtocol.authentication(
                username: configuration.username,
                password: configuration.password
            )
        )
        try SOCKSProtocol.parseAuthenticationResponse(try await receiveExactly(2))
    }

    func connect(to endpoint: SOCKSEndpoint) async throws {
        try await send(SOCKSProtocol.connectRequest(endpoint: endpoint))
        _ = try await readSuccessfulResponse()
    }

    func associateUDP() async throws -> SOCKSEndpoint {
        try await send(SOCKSProtocol.udpAssociateRequest())
        return try await readSuccessfulResponse()
    }

    private func readSuccessfulResponse() async throws -> SOCKSEndpoint {
        let header = try await receiveExactly(4)
        let addressByteCount = try SOCKSProtocol.responseAddressByteCount(for: header)
        if addressByteCount >= 0 {
            let address = try await receiveExactly(addressByteCount)
            return try SOCKSProtocol.parseResponseEndpoint(header: header, address: address)
        }

        let domainLength = Int(try await receiveExactly(1)[0])
        var address = Data([UInt8(domainLength)])
        address.append(try await receiveExactly(domainLength + 2))
        return try SOCKSProtocol.parseResponseEndpoint(header: header, address: address)
    }
}
