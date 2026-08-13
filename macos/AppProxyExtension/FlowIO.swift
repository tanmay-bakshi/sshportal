import Foundation
import NetworkExtension

extension NEAppProxyFlow {
    func openAsync() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            open(withLocalEndpoint: nil) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

extension NEAppProxyTCPFlow {
    func readDataAsync() async throws -> Data {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            readData { data, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: data ?? Data())
                }
            }
        }
    }

    func writeDataAsync(_ data: Data) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            write(data) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

extension NEAppProxyUDPFlow {
    func readDatagramsAsync() async throws -> ([Data], [NWEndpoint]) {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<([Data], [NWEndpoint]), Error>) in
            readDatagrams { datagrams, endpoints, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let datagrams, let endpoints, datagrams.count == endpoints.count else {
                    continuation.resume(throwing: FlowIOError.invalidDatagramBatch)
                    return
                }
                continuation.resume(returning: (datagrams, endpoints))
            }
        }
    }

    func writeDatagramAsync(_ data: Data, from endpoint: NWEndpoint) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            writeDatagrams([data], sentBy: [endpoint]) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

enum FlowIOError: LocalizedError {
    case invalidDatagramBatch

    var errorDescription: String? {
        "macOS returned a malformed UDP flow batch."
    }
}

func appProxyFlowError(from error: Error?) -> NSError? {
    guard let error else {
        return nil
    }
    let underlyingError = error as NSError
    if underlyingError.domain == NEAppProxyErrorDomain {
        return underlyingError
    }
    let code: NEAppProxyFlowError.Code
    if error is CancellationError {
        code = .aborted
    } else if let socksError = error as? SOCKSError {
        switch socksError {
        case .proxyRejected(let reply):
            switch reply {
            case 2, 5:
                code = .refused
            case 3, 4:
                code = .hostUnreachable
            case 6:
                code = .timedOut
            case 8:
                code = .invalidArgument
            default:
                code = .internal
            }
        default:
            code = .internal
        }
    } else {
        code = .internal
    }
    return NSError(
        domain: NEAppProxyErrorDomain,
        code: code.rawValue,
        userInfo: [NSLocalizedDescriptionKey: error.localizedDescription]
    )
}
