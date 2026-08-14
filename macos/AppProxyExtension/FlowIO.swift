import Foundation
import NetworkExtension

/// NetworkExtension declares every `NEAppProxyFlow` instance thread-safe, but its Objective-C
/// interface does not carry that guarantee into Swift's concurrency type system.
struct ThreadSafeAppProxyFlow<Flow: NEAppProxyFlow>: @unchecked Sendable {
    let value: Flow

    init(_ value: Flow) {
        self.value = value
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

func validatedDatagramBatch<Element>(_ batch: [Element]?) throws -> [Element] {
    guard let batch, batch.isEmpty == false else {
        throw FlowIOError.invalidDatagramBatch
    }
    return batch
}
