import Foundation
import Network

final class SOCKSConnection {
    let connection: NWConnection

    private let queue: DispatchQueue
    private let lock = NSLock()
    private var startContinuation: CheckedContinuation<Void, Error>?
    private var receiveBuffer = Data()

    init(host: String, port: UInt16, parameters: NWParameters, queue: DispatchQueue) throws {
        guard let networkPort = NWEndpoint.Port(rawValue: port) else {
            throw SOCKSError.invalidEndpoint
        }
        self.connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: networkPort,
            using: parameters
        )
        self.queue = queue
    }

    func start() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                startContinuation = continuation
                lock.unlock()
                connection.stateUpdateHandler = { [weak self] state in
                    self?.handle(state)
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func cancel() {
        connection.cancel()
    }

    func send(_ data: Data, isComplete: Bool = false) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            connection.send(
                content: data.isEmpty ? nil : data,
                contentContext: .defaultMessage,
                isComplete: isComplete,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: ())
                    }
                }
            )
        }
    }

    func receiveExactly(_ count: Int) async throws -> Data {
        while receiveBuffer.count < count {
            let (data, isComplete) = try await receive(minimum: 1, maximum: max(32_768, count))
            receiveBuffer.append(data)
            if isComplete && receiveBuffer.count < count {
                throw SOCKSError.connectionClosed
            }
        }
        let result = receiveBuffer.prefix(count)
        receiveBuffer.removeFirst(count)
        return Data(result)
    }

    func receive(minimum: Int = 1, maximum: Int = 32_768) async throws -> (Data, Bool) {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<(Data, Bool), Error>) in
            connection.receive(
                minimumIncompleteLength: minimum,
                maximumLength: maximum
            ) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: (data ?? Data(), isComplete))
            }
        }
    }

    func sendMessage(_ data: Data) async throws {
        try await send(data, isComplete: true)
    }

    func receiveMessage() async throws -> Data {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            connection.receiveMessage { data, _, _, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let data, data.isEmpty == false else {
                    continuation.resume(throwing: SOCKSError.connectionClosed)
                    return
                }
                continuation.resume(returning: data)
            }
        }
    }

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            finishStart(.success(()))
        case .failed(let error):
            finishStart(.failure(error))
        case .cancelled:
            finishStart(.failure(CancellationError()))
        case .setup, .preparing, .waiting:
            break
        @unknown default:
            break
        }
    }

    private func finishStart(_ result: Result<Void, Error>) {
        lock.lock()
        let continuation = startContinuation
        startContinuation = nil
        lock.unlock()
        continuation?.resume(with: result)
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
