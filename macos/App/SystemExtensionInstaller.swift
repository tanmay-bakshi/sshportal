import Foundation
import SystemExtensions

final class SystemExtensionInstaller: NSObject, OSSystemExtensionRequestDelegate {
    var approvalRequired: (() -> Void)?

    private var continuation: CheckedContinuation<Void, Error>?
    private var replacementError: Error?

    func install() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            precondition(self.continuation == nil)
            self.continuation = continuation
            self.replacementError = nil
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: SSHPortalIdentifiers.appProxyExtension,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension extension: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        let versionOrder = `extension`.bundleVersion.compare(
            existing.bundleVersion,
            options: .numeric
        )
        let shortVersionOrder = `extension`.bundleShortVersion.compare(
            existing.bundleShortVersion,
            options: .numeric
        )
        if versionOrder == .orderedAscending
            || (versionOrder == .orderedSame && shortVersionOrder == .orderedAscending)
        {
            replacementError = SystemExtensionInstallerError.newerVersionInstalled(
                existing.bundleShortVersion,
                existing.bundleVersion
            )
            return .cancel
        }
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        approvalRequired?()
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            finish(with: .success(()))
        case .willCompleteAfterReboot:
            finish(with: .failure(SystemExtensionInstallerError.rebootRequired))
        @unknown default:
            finish(with: .failure(SystemExtensionInstallerError.unknownResult))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish(with: .failure(replacementError ?? error))
    }

    private func finish(with result: Result<Void, Error>) {
        guard let continuation else {
            return
        }
        self.continuation = nil
        continuation.resume(with: result)
    }
}

enum SystemExtensionInstallerError: LocalizedError {
    case newerVersionInstalled(String, String)
    case rebootRequired
    case unknownResult

    var errorDescription: String? {
        switch self {
        case .newerVersionInstalled(let shortVersion, let version):
            return "A newer SSHPortal system extension is installed (version \(shortVersion), build \(version))."
        case .rebootRequired:
            return "macOS must restart before the SSHPortal system extension can be used."
        case .unknownResult:
            return "macOS returned an unknown result while activating the SSHPortal system extension."
        }
    }
}
