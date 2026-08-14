import Foundation
@preconcurrency import SystemExtensions

@MainActor
final class SystemExtensionInstaller: NSObject, @MainActor OSSystemExtensionRequestDelegate {
    var approvalRequired: (() -> Void)?

    private let submitRequest: @MainActor (OSSystemExtensionRequest) -> Void
    private var installation: Installation?

    override convenience init() {
        self.init { request in
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    init(submitRequest: @escaping @MainActor (OSSystemExtensionRequest) -> Void) {
        self.submitRequest = submitRequest
        super.init()
    }

    func install() async throws {
        guard installation == nil else {
            throw SystemExtensionInstallerError.alreadyInstalling
        }
        try Task.checkCancellation()

        let identifier = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, Error>) in
                guard Task.isCancelled == false else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                let request = OSSystemExtensionRequest.activationRequest(
                    forExtensionWithIdentifier: SSHPortalIdentifiers.appProxyExtension,
                    queue: .main
                )
                installation = Installation(
                    identifier: identifier,
                    request: request,
                    continuation: continuation
                )
                request.delegate = self
                submitRequest(request)
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.cancel(identifier: identifier)
            }
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension extension: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        guard installation?.request === request else {
            return .cancel
        }
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
            installation?.replacementError = SystemExtensionInstallerError.newerVersionInstalled(
                existing.bundleShortVersion,
                existing.bundleVersion
            )
            return .cancel
        }
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        guard installation?.request === request else {
            return
        }
        approvalRequired?()
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            finish(request: request, with: .success(()))
        case .willCompleteAfterReboot:
            finish(
                request: request,
                with: .failure(SystemExtensionInstallerError.rebootRequired)
            )
        @unknown default:
            finish(request: request, with: .failure(SystemExtensionInstallerError.unknownResult))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard let installation, installation.request === request else {
            return
        }
        finish(request: request, with: .failure(installation.replacementError ?? error))
    }

    private func cancel(identifier: UUID) {
        guard let installation, installation.identifier == identifier else {
            return
        }
        self.installation = nil
        installation.request.delegate = nil
        installation.continuation.resume(throwing: CancellationError())
    }

    private func finish(
        request: OSSystemExtensionRequest,
        with result: Result<Void, Error>
    ) {
        guard let installation, installation.request === request else {
            return
        }
        self.installation = nil
        request.delegate = nil
        installation.continuation.resume(with: result)
    }

    private struct Installation {
        let identifier: UUID
        let request: OSSystemExtensionRequest
        let continuation: CheckedContinuation<Void, Error>
        var replacementError: Error?
    }
}

enum SystemExtensionInstallerError: LocalizedError {
    case alreadyInstalling
    case newerVersionInstalled(String, String)
    case rebootRequired
    case unknownResult

    var errorDescription: String? {
        switch self {
        case .alreadyInstalling:
            return "The SSHPortal system extension is already being installed."
        case .newerVersionInstalled(let shortVersion, let version):
            return "A newer SSHPortal system extension is installed (version \(shortVersion), build \(version))."
        case .rebootRequired:
            return "macOS must restart before the SSHPortal system extension can be used."
        case .unknownResult:
            return "macOS returned an unknown result while activating the SSHPortal system extension."
        }
    }
}
