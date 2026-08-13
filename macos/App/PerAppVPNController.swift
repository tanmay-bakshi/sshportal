import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class PerAppVPNController {
    var unexpectedDisconnect: ((Error) -> Void)?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var hasConnected = false
    private var isStopping = false

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    func start(for application: SignedApplication, proxy: ProxyConfiguration) async throws {
        try await removeStaleConfigurations()

        let manager = NETunnelProviderManager.forPerAppVPN()
        let appRule = NEAppRule(
            signingIdentifier: application.signingIdentifier,
            designatedRequirement: application.designatedRequirement
        )
        appRule.matchPath = application.executableURL.path

        let providerProtocol = NETunnelProviderProtocol()
        providerProtocol.providerBundleIdentifier = SSHPortalIdentifiers.appProxyExtension
        providerProtocol.serverAddress = proxy.socksHost
        providerProtocol.providerConfiguration = proxy.providerConfiguration
        providerProtocol.disconnectOnSleep = false

        manager.localizedDescription = SSHPortalIdentifiers.managerDescription
        manager.protocolConfiguration = providerProtocol
        manager.appRules = [appRule]
        manager.isOnDemandEnabled = false
        manager.isEnabled = true

        try await manager.saveToPreferencesAsync()
        self.manager = manager
        try await manager.loadFromPreferencesAsync()

        isStopping = false
        hasConnected = false
        observeStatus(of: manager)
        try manager.connection.startVPNTunnel()
        try await waitForConnection(manager)
        hasConnected = true
    }

    func stop() async throws {
        isStopping = true
        hasConnected = false
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
            self.statusObserver = nil
        }
        guard let manager else {
            return
        }

        manager.connection.stopVPNTunnel()
        await waitForDisconnection(manager)
        do {
            try await manager.removeFromPreferencesAsync()
        } catch {
            manager.isEnabled = false
            try? await manager.saveToPreferencesAsync()
            throw error
        }
        self.manager = nil
    }

    private func removeStaleConfigurations() async throws {
        let managers = try await NETunnelProviderManager.loadAllManagers()
        for manager in managers where Self.belongsToSSHPortal(manager) {
            manager.connection.stopVPNTunnel()
            await waitForDisconnection(manager)
            try await manager.removeFromPreferencesAsync()
        }
    }

    private static func belongsToSSHPortal(_ manager: NETunnelProviderManager) -> Bool {
        guard let providerProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            return false
        }
        return providerProtocol.providerBundleIdentifier == SSHPortalIdentifiers.appProxyExtension
    }

    private func observeStatus(of manager: NETunnelProviderManager) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        let connection = manager.connection
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self, weak connection] _ in
            guard let connection else {
                return
            }
            Task { @MainActor [weak self] in
                guard
                    let self,
                    self.hasConnected,
                    !self.isStopping,
                    connection.status != .connected && connection.status != .reasserting
                else {
                    return
                }
                self.unexpectedDisconnect?(PerAppVPNError.disconnected(connection.status))
            }
        }
    }

    private func waitForConnection(_ manager: NETunnelProviderManager) async throws {
        for _ in 0..<300 {
            switch manager.connection.status {
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

    private func waitForDisconnection(_ manager: NETunnelProviderManager) async {
        for _ in 0..<50 {
            if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                return
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }
}

enum PerAppVPNError: LocalizedError {
    case invalidConfiguration
    case connectionTimedOut
    case disconnected(NEVPNStatus)

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            return "macOS rejected the per-app VPN configuration."
        case .connectionTimedOut:
            return "The per-app VPN did not connect within 60 seconds."
        case .disconnected(let status):
            return "The per-app VPN disconnected unexpectedly (status \(status.rawValue))."
        }
    }
}

private extension NETunnelProviderManager {
    static func loadAllManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: managers ?? [])
            }
        }
    }

    func saveToPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    func loadFromPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    func removeFromPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            removeFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }
}
