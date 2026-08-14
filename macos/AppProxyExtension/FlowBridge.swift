import Foundation
import NetworkExtension

actor TCPFlowBridge: FlowBridge {
    private let flow: ThreadSafeAppProxyFlow<NEAppProxyTCPFlow>
    private let configuration: ProxyConfiguration
    private let queue: DispatchQueue
    private var socksConnection: SOCKSConnection?
    private var isRunning = false
    private var isFinished = false

    init(
        flow: ThreadSafeAppProxyFlow<NEAppProxyTCPFlow>,
        configuration: ProxyConfiguration,
        queue: DispatchQueue
    ) {
        self.flow = flow
        self.configuration = configuration
        self.queue = queue
    }

    func run() async {
        guard isRunning == false, isFinished == false else {
            return
        }
        isRunning = true

        do {
            try await relay()
            await finish(error: nil)
        } catch {
            await finish(error: error)
        }
    }

    func cancel() async {
        await finish(error: CancellationError())
    }

    private func relay() async throws {
        let target = try SOCKSEndpoint(
            endpoint: flow.value.remoteFlowEndpoint,
            preferredHostname: flow.value.remoteHostname
        )
        let socksConnection = try SOCKSConnection(
            host: configuration.socksHost,
            port: configuration.socksPort,
            parameters: .tcp,
            queue: queue
        )
        self.socksConnection = socksConnection
        try Task.checkCancellation()
        try await socksConnection.start()
        try await socksConnection.authenticate(configuration: configuration)
        try await socksConnection.connect(to: target)
        try await openFlow()

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [self, socksConnection] in
                try await relayApplicationToProxy(socksConnection)
            }
            group.addTask { [self, socksConnection] in
                try await relayProxyToApplication(socksConnection)
            }
            do {
                try await group.waitForAll()
            } catch {
                group.cancelAll()
                await socksConnection.cancel()
                closeFlow(error: error)
                throw error
            }
        }
    }

    private func relayApplicationToProxy(_ socksConnection: SOCKSConnection) async throws {
        while true {
            try Task.checkCancellation()
            let data = try await readFlowData()
            if data.isEmpty {
                try await socksConnection.send(Data(), isComplete: true)
                return
            }
            try await socksConnection.send(data)
        }
    }

    private func relayProxyToApplication(_ socksConnection: SOCKSConnection) async throws {
        while true {
            try Task.checkCancellation()
            let (data, isComplete) = try await socksConnection.receiveStream()
            if data.isEmpty == false {
                try await writeFlowData(data)
            }
            if isComplete {
                flow.value.closeWriteWithError(nil)
                return
            }
        }
    }

    private func finish(error: Error?) async {
        guard isFinished == false else {
            return
        }
        isFinished = true
        let activeConnection = socksConnection
        socksConnection = nil
        if let activeConnection {
            await activeConnection.cancel()
        }
        closeFlow(error: error)
    }

    private func closeFlow(error: Error?) {
        let flowError = appProxyFlowError(from: error)
        flow.value.closeReadWithError(flowError)
        flow.value.closeWriteWithError(flowError)
    }

    private func openFlow() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            flow.value.open(withLocalFlowEndpoint: nil) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func readFlowData() async throws -> Data {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            flow.value.readData { data, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: data ?? Data())
                }
            }
        }
    }

    private func writeFlowData(_ data: Data) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            flow.value.write(data) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

actor UDPFlowBridge: FlowBridge {
    private let flow: ThreadSafeAppProxyFlow<NEAppProxyUDPFlow>
    private let configuration: ProxyConfiguration
    private let queue: DispatchQueue
    private var controlConnection: SOCKSConnection?
    private var datagramConnection: SOCKSConnection?
    private var isRunning = false
    private var isFinished = false

    init(
        flow: ThreadSafeAppProxyFlow<NEAppProxyUDPFlow>,
        configuration: ProxyConfiguration,
        queue: DispatchQueue
    ) {
        self.flow = flow
        self.configuration = configuration
        self.queue = queue
    }

    func run() async {
        guard isRunning == false, isFinished == false else {
            return
        }
        isRunning = true

        do {
            try await relay()
            await finish(error: nil)
        } catch {
            await finish(error: error)
        }
    }

    func cancel() async {
        await finish(error: CancellationError())
    }

    private func relay() async throws {
        let controlConnection = try SOCKSConnection(
            host: configuration.socksHost,
            port: configuration.socksPort,
            parameters: .tcp,
            queue: queue
        )
        self.controlConnection = controlConnection
        try Task.checkCancellation()
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
        self.datagramConnection = datagramConnection
        try Task.checkCancellation()
        try await datagramConnection.start()
        try await openFlow()

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [self, datagramConnection] in
                try await relayApplicationToProxy(datagramConnection)
            }
            group.addTask { [self, datagramConnection] in
                try await relayProxyToApplication(datagramConnection)
            }
            group.addTask { [controlConnection] in
                let (data, _) = try await controlConnection.receiveStream()
                if data.isEmpty == false {
                    throw SOCKSError.unexpectedControlData
                }
                throw SOCKSError.connectionClosed
            }
            do {
                try await group.waitForAll()
            } catch {
                group.cancelAll()
                await controlConnection.cancel()
                await datagramConnection.cancel()
                closeFlow(error: error)
                throw error
            }
        }
    }

    private func relayApplicationToProxy(_ datagramConnection: SOCKSConnection) async throws {
        while true {
            try Task.checkCancellation()
            let datagrams = try await readFlowDatagrams()
            for (datagram, target) in datagrams {
                let packet = try SOCKSProtocol.encodeUDPDatagram(
                    data: datagram,
                    endpoint: target
                )
                try await datagramConnection.sendMessage(packet)
            }
        }
    }

    private func relayProxyToApplication(_ datagramConnection: SOCKSConnection) async throws {
        while true {
            try Task.checkCancellation()
            let packet = try await datagramConnection.receiveMessage()
            let (datagram, source) = try SOCKSProtocol.decodeUDPDatagram(packet)
            try await writeFlowDatagram(datagram, from: source)
        }
    }

    private func finish(error: Error?) async {
        guard isFinished == false else {
            return
        }
        isFinished = true
        let activeControlConnection = controlConnection
        let activeDatagramConnection = datagramConnection
        controlConnection = nil
        datagramConnection = nil
        if let activeControlConnection {
            await activeControlConnection.cancel()
        }
        if let activeDatagramConnection {
            await activeDatagramConnection.cancel()
        }
        closeFlow(error: error)
    }

    private func closeFlow(error: Error?) {
        let flowError = appProxyFlowError(from: error)
        flow.value.closeReadWithError(flowError)
        flow.value.closeWriteWithError(flowError)
    }

    private func openFlow() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            flow.value.open(withLocalFlowEndpoint: nil) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func readFlowDatagrams() async throws -> [(Data, SOCKSEndpoint)] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[(Data, SOCKSEndpoint)], Error>) in
            flow.value.readDatagrams { datagrams, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                do {
                    let decoded = try validatedDatagramBatch(datagrams).map { datagram, endpoint in
                        (datagram, try SOCKSEndpoint(endpoint: endpoint))
                    }
                    continuation.resume(returning: decoded)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func writeFlowDatagram(_ data: Data, from source: SOCKSEndpoint) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            flow.value.writeDatagrams([(data, source.networkEndpoint)]) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}
