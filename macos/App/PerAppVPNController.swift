import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class PerAppVPNController {
    var unexpectedDisconnect: ((Error) -> Void)?

    private let managerStore: any PerAppVPNManagerStore
    private let ownershipProvider: any PerAppVPNOwnershipProvider
    private let notificationCenter: NotificationCenter
    private var manager: (any PerAppVPNManager)?
    private var ownershipLease: (any PerAppVPNOwnershipLease)?
    private var statusObserver: NSObjectProtocol?
    private var statusObservationIdentifier: UUID?
    private var startOperation: StartOperation?
    private var stopOperation: Task<Void, Error>?
    private var hasConnected = false
    private var isStopping = false

    init() {
        managerStore = NetworkExtensionPerAppVPNManagerStore()
        ownershipProvider = PerAppVPNFileOwnershipProvider()
        notificationCenter = .default
    }

    init(
        managerStore: any PerAppVPNManagerStore,
        ownershipProvider: any PerAppVPNOwnershipProvider,
        notificationCenter: NotificationCenter = .default
    ) {
        self.managerStore = managerStore
        self.ownershipProvider = ownershipProvider
        self.notificationCenter = notificationCenter
    }

    isolated deinit {
        if let statusObserver {
            notificationCenter.removeObserver(statusObserver)
        }
    }

    func start(for application: SignedApplication, proxy: ProxyConfiguration) async throws {
        guard
            manager == nil,
            ownershipLease == nil,
            startOperation == nil,
            stopOperation == nil
        else {
            throw PerAppVPNError.alreadyRunning
        }

        isStopping = false
        hasConnected = false
        let identifier = UUID()
        let task = Task { @MainActor in
            try await self.performStart(for: application, proxy: proxy)
        }
        startOperation = StartOperation(identifier: identifier, task: task)

        do {
            try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
            clearStartOperation(identifier: identifier)
        } catch {
            clearStartOperation(identifier: identifier)
            throw error
        }
    }

    func stop() async throws {
        if let stopOperation {
            try await stopOperation.value
            return
        }

        isStopping = true
        hasConnected = false
        removeStatusObserver()
        let startingOperation = startOperation
        startingOperation?.task.cancel()

        let task = Task { @MainActor in
            if let startingOperation {
                _ = await startingOperation.task.result
                self.clearStartOperation(identifier: startingOperation.identifier)
            }
            try await self.performStop()
        }
        stopOperation = task

        do {
            try await task.value
            stopOperation = nil
        } catch {
            stopOperation = nil
            throw error
        }
    }

    private func performStart(
        for application: SignedApplication,
        proxy: ProxyConfiguration
    ) async throws {
        try Task.checkCancellation()
        ownershipLease = try ownershipProvider.acquire()
        do {
            try await performOwnedStart(for: application, proxy: proxy)
        } catch {
            if manager == nil {
                releaseOwnership()
            }
            throw error
        }
    }

    private func performOwnedStart(
        for application: SignedApplication,
        proxy: ProxyConfiguration
    ) async throws {
        try await removeStaleConfigurations()
        try Task.checkCancellation()

        let candidate = managerStore.makeManager()
        candidate.configure(for: application, proxy: proxy)
        var persistenceWasAttempted = false

        do {
            try Task.checkCancellation()
            persistenceWasAttempted = true
            try await candidate.saveToPreferences()
            try Task.checkCancellation()

            manager = candidate
            try Task.checkCancellation()
            try await candidate.loadFromPreferences()
            try Task.checkCancellation()

            observeStatus(of: candidate)
            try candidate.startTunnel()
            try await waitForConnection(candidate)
            try Task.checkCancellation()
            hasConnected = true
        } catch {
            let startError = error
            hasConnected = false
            removeStatusObserver()

            guard persistenceWasAttempted else {
                throw startError
            }
            if manager == nil {
                manager = candidate
            }
            do {
                try await removePersistedManager(candidate)
                clearManager(ifIdenticalTo: candidate)
            } catch {
                throw PerAppVPNError.rollbackFailed(start: startError, rollback: error)
            }
            throw startError
        }
    }

    private func performStop() async throws {
        guard let manager else {
            releaseOwnership()
            return
        }
        try await removePersistedManager(manager)
        clearManager(ifIdenticalTo: manager)
        releaseOwnership()
    }

    private func removeStaleConfigurations() async throws {
        let managers = try await managerStore.loadAllManagers()
        for manager in managers where manager.belongsToSSHPortal {
            try Task.checkCancellation()
            try await removePersistedManager(manager)
        }
    }

    private func removePersistedManager(_ manager: any PerAppVPNManager) async throws {
        manager.stopTunnel()
        await waitForDisconnection(manager)
        do {
            try await manager.removeFromPreferences()
        } catch {
            let removalError = error
            manager.isEnabled = false
            do {
                try await manager.saveToPreferences()
            } catch {
                throw PerAppVPNError.disableAfterRemovalFailure(
                    removal: removalError,
                    disabling: error
                )
            }
            throw removalError
        }
    }

    private func observeStatus(of manager: any PerAppVPNManager) {
        removeStatusObserver()
        let observationIdentifier = UUID()
        statusObservationIdentifier = observationIdentifier
        statusObserver = notificationCenter.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.statusNotificationObject,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.statusDidChange(observationIdentifier: observationIdentifier)
            }
        }
    }

    private func statusDidChange(observationIdentifier: UUID) {
        guard
            statusObservationIdentifier == observationIdentifier,
            let manager,
            hasConnected,
            isStopping == false
        else {
            return
        }
        let status = manager.status
        switch status {
        case .connected, .reasserting:
            return
        case .invalid, .disconnected, .connecting, .disconnecting:
            removeStatusObserver()
            unexpectedDisconnect?(PerAppVPNError.disconnected(status))
        @unknown default:
            removeStatusObserver()
            unexpectedDisconnect?(PerAppVPNError.disconnected(status))
        }
    }

    private func removeStatusObserver() {
        statusObservationIdentifier = nil
        if let statusObserver {
            notificationCenter.removeObserver(statusObserver)
            self.statusObserver = nil
        }
    }

    private func waitForConnection(_ manager: any PerAppVPNManager) async throws {
        for _ in 0..<300 {
            switch manager.status {
            case .connected:
                return
            case .invalid:
                throw PerAppVPNError.invalidConfiguration
            case .disconnecting:
                throw PerAppVPNError.disconnected(.disconnecting)
            case .disconnected, .connecting, .reasserting:
                break
            @unknown default:
                break
            }
            try await Task.sleep(for: .milliseconds(200))
        }
        throw PerAppVPNError.connectionTimedOut
    }

    private func waitForDisconnection(_ manager: any PerAppVPNManager) async {
        for _ in 0..<50 {
            if manager.status == .disconnected || manager.status == .invalid {
                return
            }
            await sleepIgnoringCancellation(for: .milliseconds(100))
        }
    }

    private func sleepIgnoringCancellation(for duration: Duration) async {
        // Cancellation initiates rollback, so it must not collapse the disconnection grace period.
        await Task {
            try? await Task.sleep(for: duration)
        }.value
    }

    private func clearStartOperation(identifier: UUID) {
        guard startOperation?.identifier == identifier else {
            return
        }
        startOperation = nil
    }

    private func clearManager(ifIdenticalTo candidate: any PerAppVPNManager) {
        guard let manager, manager === candidate else {
            return
        }
        self.manager = nil
    }

    private func releaseOwnership() {
        ownershipLease?.release()
        ownershipLease = nil
    }

    private struct StartOperation {
        let identifier: UUID
        let task: Task<Void, Error>
    }
}

enum PerAppVPNError: LocalizedError {
    case alreadyRunning
    case invalidConfiguration
    case connectionTimedOut
    case disconnected(NEVPNStatus)
    case rollbackFailed(start: Error, rollback: Error)
    case disableAfterRemovalFailure(removal: Error, disabling: Error)

    var errorDescription: String? {
        switch self {
        case .alreadyRunning:
            return "The macOS per-app VPN is already starting, active, or stopping."
        case .invalidConfiguration:
            return "macOS rejected the per-app VPN configuration."
        case .connectionTimedOut:
            return "The per-app VPN did not connect within 60 seconds."
        case .disconnected(let status):
            return "The per-app VPN disconnected unexpectedly (status \(status.rawValue))."
        case .rollbackFailed(let start, let rollback):
            return "The per-app VPN failed to start (\(start.localizedDescription)) and its "
                + "configuration could not be removed (\(rollback.localizedDescription))."
        case .disableAfterRemovalFailure(let removal, let disabling):
            return "The per-app VPN configuration could not be removed "
                + "(\(removal.localizedDescription)) or disabled (\(disabling.localizedDescription))."
        }
    }
}
