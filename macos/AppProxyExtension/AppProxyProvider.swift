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
    private let bridgeRegistry = FlowBridgeRegistry()
    private var activeSession: Session?
    private var nextGeneration: UInt64 = 1

    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping @Sendable (Error?) -> Void
    ) {
        do {
            guard let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw AppProxyProviderError.missingProtocolConfiguration
            }
            let configuration = try ProxyConfiguration(
                providerConfiguration: providerProtocol.providerConfiguration
            )
            stateLock.lock()
            guard activeSession == nil else {
                stateLock.unlock()
                throw AppProxyProviderError.alreadyRunning
            }
            let generation = nextGeneration
            nextGeneration += 1
            activeSession = Session(generation: generation, configuration: configuration)
            stateLock.unlock()
            Task { [bridgeRegistry, logger] in
                if await bridgeRegistry.start(generation: generation) {
                    logger.log("SSHPortal per-app proxy started")
                    completionHandler(nil)
                } else {
                    completionHandler(CancellationError())
                }
            }
        } catch {
            logger.error("Failed to start SSHPortal per-app proxy: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
        }
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping @Sendable () -> Void
    ) {
        stateLock.lock()
        let generation = activeSession?.generation
        activeSession = nil
        stateLock.unlock()
        guard let generation else {
            completionHandler()
            return
        }
        Task { [bridgeRegistry, logger] in
            await bridgeRegistry.stop(generation: generation)
            logger.log("SSHPortal per-app proxy stopped with reason \(reason.rawValue)")
            completionHandler()
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        stateLock.lock()
        guard let activeSession else {
            stateLock.unlock()
            return false
        }
        stateLock.unlock()
        let bridge: any FlowBridge
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            bridge = TCPFlowBridge(
                flow: ThreadSafeAppProxyFlow(tcpFlow),
                configuration: activeSession.configuration,
                queue: networkQueue
            )
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            bridge = UDPFlowBridge(
                flow: ThreadSafeAppProxyFlow(udpFlow),
                configuration: activeSession.configuration,
                queue: networkQueue
            )
        } else {
            return false
        }
        Task { [bridgeRegistry] in
            await bridgeRegistry.accept(bridge, generation: activeSession.generation)
        }
        return true
    }

    private struct Session {
        let generation: UInt64
        let configuration: ProxyConfiguration
    }
}

enum AppProxyProviderError: LocalizedError {
    case missingProtocolConfiguration
    case alreadyRunning

    var errorDescription: String? {
        switch self {
        case .missingProtocolConfiguration:
            return "The SSHPortal app proxy has no tunnel provider configuration."
        case .alreadyRunning:
            return "The SSHPortal app proxy is already running."
        }
    }
}
