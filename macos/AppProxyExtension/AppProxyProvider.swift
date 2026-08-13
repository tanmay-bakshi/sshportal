import Foundation
import NetworkExtension
import OSLog

final class AppProxyProvider: NEAppProxyProvider {
    private let logger = Logger(
        subsystem: SSHPortalIdentifiers.appProxyExtension,
        category: "AppProxy"
    )
    private let networkQueue = DispatchQueue(label: "com.tanmaybakshi.sshportal.app-proxy")
    private let stateLock = NSLock()
    private var configuration: ProxyConfiguration?
    private var bridges: [UUID: FlowBridge] = [:]

    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            guard let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw AppProxyProviderError.missingProtocolConfiguration
            }
            let configuration = try ProxyConfiguration(
                providerConfiguration: providerProtocol.providerConfiguration
            )
            stateLock.lock()
            self.configuration = configuration
            stateLock.unlock()
            logger.log("SSHPortal per-app proxy started")
            completionHandler(nil)
        } catch {
            logger.error("Failed to start SSHPortal per-app proxy: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
        }
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stateLock.lock()
        configuration = nil
        let activeBridges = Array(bridges.values)
        bridges.removeAll()
        stateLock.unlock()
        for bridge in activeBridges {
            bridge.cancel()
        }
        logger.log("SSHPortal per-app proxy stopped with reason \(reason.rawValue)")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        stateLock.lock()
        guard let configuration else {
            stateLock.unlock()
            return false
        }
        let identifier = UUID()
        let completion: () -> Void = { [weak self] in
            _ = self?.removeBridge(identifier)
        }
        let bridge: FlowBridge
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            bridge = TCPFlowBridge(
                flow: tcpFlow,
                configuration: configuration,
                queue: networkQueue,
                completion: completion
            )
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            bridge = UDPFlowBridge(
                flow: udpFlow,
                configuration: configuration,
                queue: networkQueue,
                completion: completion
            )
        } else {
            stateLock.unlock()
            return false
        }
        bridges[identifier] = bridge
        stateLock.unlock()
        bridge.start()
        return true
    }

    private func removeBridge(_ identifier: UUID) {
        stateLock.lock()
        bridges.removeValue(forKey: identifier)
        stateLock.unlock()
    }
}

enum AppProxyProviderError: LocalizedError {
    case missingProtocolConfiguration

    var errorDescription: String? {
        "The SSHPortal app proxy has no tunnel provider configuration."
    }
}
