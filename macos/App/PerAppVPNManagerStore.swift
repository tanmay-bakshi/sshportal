import Foundation

@MainActor
protocol PerAppVPNManagerStore {
    func makeManager() -> any PerAppVPNManager
    func loadAllManagers() async throws -> [any PerAppVPNManager]
}
