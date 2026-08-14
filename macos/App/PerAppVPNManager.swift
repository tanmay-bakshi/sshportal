import Foundation
@preconcurrency import NetworkExtension

@MainActor
protocol PerAppVPNManager: AnyObject {
    var belongsToSSHPortal: Bool { get }
    var status: NEVPNStatus { get }
    var statusNotificationObject: AnyObject { get }
    var isEnabled: Bool { get set }

    func configure(for application: SignedApplication, proxy: ProxyConfiguration)
    func saveToPreferences() async throws
    func loadFromPreferences() async throws
    func removeFromPreferences() async throws
    func startTunnel() throws
    func stopTunnel()
}
