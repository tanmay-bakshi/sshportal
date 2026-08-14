import Foundation
import Network
import Synchronization

protocol SOCKSConnectionTransport: Actor {
    func start(queue: DispatchQueue) async throws
    func cancel()
    func send(_ data: Data, isComplete: Bool) async throws
    func receive(minimum: Int, maximum: Int) async throws -> (Data, Bool)
    func receiveMessage() async throws -> Data
}

actor NetworkSOCKSConnectionTransport: SOCKSConnectionTransport {
    private let connection: NWConnection

    init(host: String, port: NWEndpoint.Port, parameters: NWParameters) {
        connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: port,
            using: parameters
        )
    }

    func start(queue: DispatchQueue) async throws {
        let continuation = Mutex<CheckedContinuation<Void, Error>?>(nil)
        try await withCheckedThrowingContinuation {
            (startContinuation: CheckedContinuation<Void, Error>) in
            continuation.withLock { $0 = startContinuation }
            connection.stateUpdateHandler = { state in
                let result: Result<Void, Error>?
                switch state {
                case .ready:
                    result = .success(())
                case .failed(let error):
                    result = .failure(error)
                case .cancelled:
                    result = .failure(CancellationError())
                case .setup, .preparing, .waiting:
                    result = nil
                @unknown default:
                    result = nil
                }
                guard let result else {
                    return
                }
                let activeContinuation = continuation.withLock {
                    let activeContinuation = $0
                    $0 = nil
                    return activeContinuation
                }
                activeContinuation?.resume(with: result)
            }
            connection.start(queue: queue)
        }
    }

    func cancel() {
        connection.cancel()
    }

    func send(_ data: Data, isComplete: Bool) async throws {
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

    func receive(minimum: Int, maximum: Int) async throws -> (Data, Bool) {
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
}
