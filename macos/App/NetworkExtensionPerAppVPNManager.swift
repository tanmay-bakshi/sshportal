import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class NetworkExtensionPerAppVPNManager: PerAppVPNManager {
    private let manager: NETunnelProviderManager

    init(manager: NETunnelProviderManager) {
        self.manager = manager
    }

    var belongsToSSHPortal: Bool {
        guard let providerProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            return false
        }
        return providerProtocol.providerBundleIdentifier == SSHPortalIdentifiers.appProxyExtension
    }

    var status: NEVPNStatus {
        manager.connection.status
    }

    var statusNotificationObject: AnyObject {
        manager.connection
    }

    var isEnabled: Bool {
        get { manager.isEnabled }
        set { manager.isEnabled = newValue }
    }

    func configure(for application: SignedApplication, proxy: ProxyConfiguration) {
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
    }

    func saveToPreferences() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    func loadFromPreferences() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    func removeFromPreferences() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.removeFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    func startTunnel() throws {
        try manager.connection.startVPNTunnel()
    }

    func stopTunnel() {
        manager.connection.stopVPNTunnel()
    }
}
