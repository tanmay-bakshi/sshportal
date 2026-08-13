import Foundation
import NetworkExtension

protocol FlowBridge: AnyObject {
    func start()
    func cancel()
}

final class TCPFlowBridge: FlowBridge {
    private let flow: NEAppProxyTCPFlow
    private let configuration: ProxyConfiguration
    private let queue: DispatchQueue
    private let completion: () -> Void
    private let lock = NSLock()
    private var task: Task<Void, Never>?
    private var socksConnection: SOCKSConnection?
    private var isFinished = false

    init(
        flow: NEAppProxyTCPFlow,
        configuration: ProxyConfiguration,
        queue: DispatchQueue,
        completion: @escaping () -> Void
    ) {
        self.flow = flow
        self.configuration = configuration
        self.queue = queue
        self.completion = completion
    }

    func start() {
        lock.lock()
        guard isFinished == false, task == nil else {
            lock.unlock()
            return
        }
        let task = Task { [weak self] in
            guard let self else {
                return
            }
            do {
                try await run()
                finish(error: nil, cancelTask: false)
            } catch {
                finish(error: error, cancelTask: false)
            }
        }
        self.task = task
        lock.unlock()
    }

    func cancel() {
        finish(error: CancellationError(), cancelTask: true)
    }

    private func run() async throws {
        let target = try SOCKSEndpoint(
            endpoint: flow.remoteEndpoint,
            preferredHostname: flow.remoteHostname
        )
        let socksConnection = try SOCKSConnection(
            host: configuration.socksHost,
            port: configuration.socksPort,
            parameters: .tcp,
            queue: queue
        )
        try retain(socksConnection)
        try await socksConnection.start()
        try await socksConnection.authenticate(configuration: configuration)
        try await socksConnection.connect(to: target)
        try await flow.openAsync()

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [flow] in
                while true {
                    try Task.checkCancellation()
                    let data = try await flow.readDataAsync()
                    if data.isEmpty {
                        try await socksConnection.send(Data(), isComplete: true)
                        return
                    }
                    try await socksConnection.send(data)
                }
            }
            group.addTask { [flow] in
                while true {
                    try Task.checkCancellation()
                    let (data, isComplete) = try await socksConnection.receive()
                    if data.isEmpty == false {
                        try await flow.writeDataAsync(data)
                    }
                    if isComplete {
                        flow.closeWriteWithError(nil)
                        return
                    }
                }
            }
            do {
                try await group.waitForAll()
            } catch {
                group.cancelAll()
                socksConnection.cancel()
                let flowError = appProxyFlowError(from: error)
                flow.closeReadWithError(flowError)
                flow.closeWriteWithError(flowError)
                throw error
            }
        }
    }

    private func retain(_ connection: SOCKSConnection) throws {
        lock.lock()
        guard isFinished == false else {
            lock.unlock()
            connection.cancel()
            throw CancellationError()
        }
        socksConnection = connection
        lock.unlock()
    }

    private func finish(error: Error?, cancelTask: Bool) {
        lock.lock()
        guard isFinished == false else {
            lock.unlock()
            return
        }
        isFinished = true
        let activeTask = task
        let activeConnection = socksConnection
        task = nil
        socksConnection = nil
        lock.unlock()

        if cancelTask {
            activeTask?.cancel()
        }
        activeConnection?.cancel()
        let flowError = appProxyFlowError(from: error)
        flow.closeReadWithError(flowError)
        flow.closeWriteWithError(flowError)
        completion()
    }
}

final class UDPFlowBridge: FlowBridge {
    private let flow: NEAppProxyUDPFlow
    private let configuration: ProxyConfiguration
    private let queue: DispatchQueue
    private let completion: () -> Void
    private let lock = NSLock()
    private var task: Task<Void, Never>?
    private var controlConnection: SOCKSConnection?
    private var datagramConnection: SOCKSConnection?
    private var isFinished = false

    init(
        flow: NEAppProxyUDPFlow,
        configuration: ProxyConfiguration,
        queue: DispatchQueue,
        completion: @escaping () -> Void
    ) {
        self.flow = flow
        self.configuration = configuration
        self.queue = queue
        self.completion = completion
    }

    func start() {
        lock.lock()
        guard isFinished == false, task == nil else {
            lock.unlock()
            return
        }
        let task = Task { [weak self] in
            guard let self else {
                return
            }
            do {
                try await run()
                finish(error: nil, cancelTask: false)
            } catch {
                finish(error: error, cancelTask: false)
            }
        }
        self.task = task
        lock.unlock()
    }

    func cancel() {
        finish(error: CancellationError(), cancelTask: true)
    }

    private func run() async throws {
        let controlConnection = try SOCKSConnection(
            host: configuration.socksHost,
            port: configuration.socksPort,
            parameters: .tcp,
            queue: queue
        )
        try retainControlConnection(controlConnection)
        try await controlConnection.start()
        try await controlConnection.authenticate(configuration: configuration)
        var relay = try await controlConnection.associateUDP()
        if relay.host == "0.0.0.0" || relay.host == "::" {
            relay = try SOCKSEndpoint(host: configuration.socksHost, port: relay.port)
        }

        let datagramConnection = try SOCKSConnection(
            host: relay.host,
            port: relay.port,
            parameters: .udp,
            queue: queue
        )
        try retainDatagramConnection(datagramConnection)
        try await datagramConnection.start()
        try await flow.openAsync()

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [flow] in
                while true {
                    try Task.checkCancellation()
                    let (datagrams, endpoints) = try await flow.readDatagramsAsync()
                    for (datagram, endpoint) in zip(datagrams, endpoints) {
                        let target = try SOCKSEndpoint(endpoint: endpoint)
                        let packet = try SOCKSProtocol.encodeUDPDatagram(
                            data: datagram,
                            endpoint: target
                        )
                        try await datagramConnection.sendMessage(packet)
                    }
                }
            }
            group.addTask { [flow] in
                while true {
                    try Task.checkCancellation()
                    let packet = try await datagramConnection.receiveMessage()
                    let (datagram, source) = try SOCKSProtocol.decodeUDPDatagram(packet)
                    try await flow.writeDatagramAsync(datagram, from: source.networkEndpoint)
                }
            }
            group.addTask {
                let (data, _) = try await controlConnection.receive()
                if data.isEmpty == false {
                    throw SOCKSError.unexpectedControlData
                }
                throw SOCKSError.connectionClosed
            }
            do {
                try await group.waitForAll()
            } catch {
                group.cancelAll()
                controlConnection.cancel()
                datagramConnection.cancel()
                let flowError = appProxyFlowError(from: error)
                flow.closeReadWithError(flowError)
                flow.closeWriteWithError(flowError)
                throw error
            }
        }
    }

    private func retainControlConnection(_ connection: SOCKSConnection) throws {
        lock.lock()
        guard isFinished == false else {
            lock.unlock()
            connection.cancel()
            throw CancellationError()
        }
        controlConnection = connection
        lock.unlock()
    }

    private func retainDatagramConnection(_ connection: SOCKSConnection) throws {
        lock.lock()
        guard isFinished == false else {
            lock.unlock()
            connection.cancel()
            throw CancellationError()
        }
        datagramConnection = connection
        lock.unlock()
    }

    private func finish(error: Error?, cancelTask: Bool) {
        lock.lock()
        guard isFinished == false else {
            lock.unlock()
            return
        }
        isFinished = true
        let activeTask = task
        let activeControlConnection = controlConnection
        let activeDatagramConnection = datagramConnection
        task = nil
        controlConnection = nil
        datagramConnection = nil
        lock.unlock()

        if cancelTask {
            activeTask?.cancel()
        }
        activeControlConnection?.cancel()
        activeDatagramConnection?.cancel()
        let flowError = appProxyFlowError(from: error)
        flow.closeReadWithError(flowError)
        flow.closeWriteWithError(flowError)
        completion()
    }
}
