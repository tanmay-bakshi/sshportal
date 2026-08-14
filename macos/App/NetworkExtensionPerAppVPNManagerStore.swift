import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class NetworkExtensionPerAppVPNManagerStore: PerAppVPNManagerStore {
    func makeManager() -> any PerAppVPNManager {
        NetworkExtensionPerAppVPNManager(manager: .forPerAppVPN())
    }

    func loadAllManagers() async throws -> [any PerAppVPNManager] {
        let managers = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[ThreadSafeTunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(
                    returning: (managers ?? []).map(ThreadSafeTunnelProviderManager.init)
                )
            }
        }
        return managers.map { manager in
            NetworkExtensionPerAppVPNManager(manager: manager.value)
        }
    }
}

/// NetworkExtension documents `NETunnelProviderManager` as thread-safe, but its Objective-C
/// completion handler does not express that contract to Swift's concurrency checker.
private struct ThreadSafeTunnelProviderManager: @unchecked Sendable {
    let value: NETunnelProviderManager

    init(_ value: NETunnelProviderManager) {
        self.value = value
    }
}
