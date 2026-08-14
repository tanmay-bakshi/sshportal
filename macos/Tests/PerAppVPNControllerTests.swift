import Foundation
@preconcurrency import NetworkExtension
import XCTest

@MainActor
final class PerAppVPNControllerTests: XCTestCase {
    func testCancellationAfterPreferenceSaveRollsBackUnassignedManager() async throws {
        let saveGate = CancellationGate()
        let manager = FakeManager(saveGate: saveGate)
        let controller = PerAppVPNController(
            managerStore: FakeManagerStore(manager: manager),
            ownershipProvider: NoOpOwnershipProvider()
        )
        let (application, proxy) = try configuration()
        let startTask = Task { @MainActor in
            try await controller.start(for: application, proxy: proxy)
        }

        await saveGate.waitUntilEntered()
        startTask.cancel()
        await saveGate.waitUntilCancellationObserved()
        await saveGate.resume()

        await assertCancelled(startTask)
        XCTAssertEqual(manager.saveCount, 1)
        XCTAssertEqual(manager.loadCount, 0)
        XCTAssertEqual(manager.removeCount, 1)
        XCTAssertEqual(manager.startTunnelCount, 0)
        XCTAssertFalse(manager.isPersisted)
    }

    func testStopWaitsForAssignedStartingManagerToFinishRollback() async throws {
        let loadGate = CancellationGate()
        let manager = FakeManager(loadGate: loadGate)
        let controller = PerAppVPNController(
            managerStore: FakeManagerStore(manager: manager),
            ownershipProvider: NoOpOwnershipProvider()
        )
        let (application, proxy) = try configuration()
        let startTask = Task { @MainActor in
            try await controller.start(for: application, proxy: proxy)
        }

        await loadGate.waitUntilEntered()
        let stopTask = Task { @MainActor in
            try await controller.stop()
        }
        await loadGate.waitUntilCancellationObserved()
        XCTAssertEqual(manager.removeCount, 0)

        await loadGate.resume()
        try await stopTask.value
        await assertCancelled(startTask)

        XCTAssertEqual(manager.saveCount, 1)
        XCTAssertEqual(manager.loadCount, 1)
        XCTAssertEqual(manager.removeCount, 1)
        XCTAssertEqual(manager.startTunnelCount, 0)
        XCTAssertFalse(manager.isPersisted)
    }

    func testCancelledTunnelStartWaitsForDisconnectionBeforeRemovingPreferences() async throws {
        let manager = FakeManager()
        let controller = PerAppVPNController(
            managerStore: FakeManagerStore(manager: manager),
            ownershipProvider: NoOpOwnershipProvider()
        )
        let (application, proxy) = try configuration()
        let tunnelStarted = expectation(description: "tunnel start attempted")
        manager.startTunnelHook = {
            manager.status = .connecting
            tunnelStarted.fulfill()
        }
        manager.stopTunnelHook = {
            manager.status = .disconnecting
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(20))
                manager.status = .disconnected
            }
        }
        let startTask = Task { @MainActor in
            try await controller.start(for: application, proxy: proxy)
        }

        await fulfillment(of: [tunnelStarted], timeout: 1)
        startTask.cancel()
        await assertCancelled(startTask)

        XCTAssertEqual(manager.statusAtRemoval, .disconnected)
        XCTAssertFalse(manager.isPersisted)
    }

    func testExclusiveOwnershipPreventsAnotherControllerFromEnumeratingManagers() async throws {
        let directoryURL = FileManager.default.temporaryDirectory
            .appending(path: "sshportal-ownership-tests-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: directoryURL) }

        let firstManager = FakeManager()
        let firstStore = FakeManagerStore(manager: firstManager)
        let firstController = PerAppVPNController(
            managerStore: firstStore,
            ownershipProvider: PerAppVPNFileOwnershipProvider(directoryURL: directoryURL)
        )
        let secondManager = FakeManager()
        let secondStore = FakeManagerStore(manager: secondManager)
        let secondController = PerAppVPNController(
            managerStore: secondStore,
            ownershipProvider: PerAppVPNFileOwnershipProvider(directoryURL: directoryURL)
        )
        let (application, proxy) = try configuration()

        try await firstController.start(for: application, proxy: proxy)
        do {
            try await secondController.start(for: application, proxy: proxy)
            XCTFail("Expected the second controller to be rejected while the first owns the manager.")
        } catch PerAppVPNOwnershipError.alreadyOwned {
        } catch {
            XCTFail("Unexpected ownership error: \(error)")
        }

        XCTAssertEqual(secondStore.loadAllCount, 0)
        XCTAssertEqual(secondManager.saveCount, 0)
        XCTAssertEqual(secondManager.removeCount, 0)

        try await firstController.stop()
        try await secondController.start(for: application, proxy: proxy)
        try await secondController.stop()
    }

    func testUnrelatedVPNNotificationDoesNotEndDisconnectObservation() async throws {
        let notificationCenter = NotificationCenter()
        let manager = FakeManager()
        let controller = PerAppVPNController(
            managerStore: FakeManagerStore(manager: manager),
            ownershipProvider: NoOpOwnershipProvider(),
            notificationCenter: notificationCenter
        )
        let (application, proxy) = try configuration()
        let disconnectReported = expectation(description: "unexpected disconnect reported")
        controller.unexpectedDisconnect = { _ in
            disconnectReported.fulfill()
        }

        try await controller.start(for: application, proxy: proxy)
        notificationCenter.post(name: .NEVPNStatusDidChange, object: NSObject())
        manager.status = .disconnected
        notificationCenter.post(
            name: .NEVPNStatusDidChange,
            object: manager.statusNotificationObject
        )

        await fulfillment(of: [disconnectReported], timeout: 1)
        try await controller.stop()
    }

    func testStartupStatusNotificationDoesNotEndDisconnectObservation() async throws {
        let notificationCenter = NotificationCenter()
        let manager = FakeManager()
        let controller = PerAppVPNController(
            managerStore: FakeManagerStore(manager: manager),
            ownershipProvider: NoOpOwnershipProvider(),
            notificationCenter: notificationCenter
        )
        let (application, proxy) = try configuration()
        let disconnectReported = expectation(description: "unexpected disconnect reported")
        controller.unexpectedDisconnect = { _ in
            disconnectReported.fulfill()
        }
        manager.startTunnelHook = {
            manager.status = .connecting
            notificationCenter.post(
                name: .NEVPNStatusDidChange,
                object: manager.statusNotificationObject
            )
            manager.status = .connected
        }

        try await controller.start(for: application, proxy: proxy)
        manager.status = .disconnected
        notificationCenter.post(
            name: .NEVPNStatusDidChange,
            object: manager.statusNotificationObject
        )

        await fulfillment(of: [disconnectReported], timeout: 1)
        try await controller.stop()
    }

    private func configuration() throws -> (SignedApplication, ProxyConfiguration) {
        let bundleURL = URL(fileURLWithPath: "/Applications/Browser.app", isDirectory: true)
        let application = SignedApplication(
            testName: "Browser",
            bundleURL: bundleURL,
            executableURL: bundleURL.appending(path: "Contents/MacOS/Browser"),
            signingIdentifier: "com.example.browser",
            designatedRequirement: "identifier com.example.browser"
        )
        let proxy = try ProxyConfiguration(
            socksHost: "127.0.0.1",
            socksPort: 49_152,
            username: "sshportal",
            password: "session-secret"
        )
        return (application, proxy)
    }

    private func assertCancelled(_ task: Task<Void, Error>) async {
        do {
            try await task.value
            XCTFail("Expected cancellation.")
        } catch is CancellationError {
        } catch {
            XCTFail("Unexpected start error: \(error)")
        }
    }

    private final class FakeManagerStore: PerAppVPNManagerStore {
        private let manager: FakeManager
        private(set) var loadAllCount = 0

        init(manager: FakeManager) {
            self.manager = manager
        }

        func makeManager() -> any PerAppVPNManager {
            manager
        }

        func loadAllManagers() async throws -> [any PerAppVPNManager] {
            loadAllCount += 1
            return []
        }
    }

    private final class FakeManager: PerAppVPNManager {
        let belongsToSSHPortal = true
        let statusNotificationObject: AnyObject = NSObject()
        var status: NEVPNStatus = .disconnected
        var isEnabled = false
        private(set) var isPersisted = false
        private(set) var saveCount = 0
        private(set) var loadCount = 0
        private(set) var removeCount = 0
        private(set) var startTunnelCount = 0
        private(set) var statusAtRemoval: NEVPNStatus?
        var startTunnelHook: (() -> Void)?
        var stopTunnelHook: (() -> Void)?

        private let saveGate: CancellationGate?
        private let loadGate: CancellationGate?

        init(saveGate: CancellationGate? = nil, loadGate: CancellationGate? = nil) {
            self.saveGate = saveGate
            self.loadGate = loadGate
        }

        func configure(for application: SignedApplication, proxy: ProxyConfiguration) {
            isEnabled = true
        }

        func saveToPreferences() async throws {
            saveCount += 1
            if let saveGate {
                await saveGate.suspendIgnoringCancellation()
            }
            isPersisted = true
        }

        func loadFromPreferences() async throws {
            loadCount += 1
            if let loadGate {
                await loadGate.suspendIgnoringCancellation()
            }
        }

        func removeFromPreferences() async throws {
            removeCount += 1
            statusAtRemoval = status
            isPersisted = false
        }

        func startTunnel() throws {
            startTunnelCount += 1
            if let startTunnelHook {
                startTunnelHook()
                return
            }
            status = .connected
        }

        func stopTunnel() {
            if let stopTunnelHook {
                stopTunnelHook()
                return
            }
            status = .disconnected
        }
    }

    private final class NoOpOwnershipProvider: PerAppVPNOwnershipProvider {
        func acquire() throws -> any PerAppVPNOwnershipLease {
            NoOpOwnershipLease()
        }
    }

    private final class NoOpOwnershipLease: PerAppVPNOwnershipLease {
        func release() {}
    }

    private actor CancellationGate {
        private var entered = false
        private var cancellationWasObserved = false
        private var entryWaiters: [CheckedContinuation<Void, Never>] = []
        private var cancellationWaiters: [CheckedContinuation<Void, Never>] = []
        private var releaseContinuation: CheckedContinuation<Void, Never>?

        func suspendIgnoringCancellation() async {
            entered = true
            let entryWaiters = self.entryWaiters
            self.entryWaiters.removeAll()
            for waiter in entryWaiters {
                waiter.resume()
            }

            await withTaskCancellationHandler {
                await withCheckedContinuation {
                    (continuation: CheckedContinuation<Void, Never>) in
                    releaseContinuation = continuation
                }
            } onCancel: {
                Task {
                    await self.observeCancellation()
                }
            }
        }

        func waitUntilEntered() async {
            if entered {
                return
            }
            await withCheckedContinuation {
                (continuation: CheckedContinuation<Void, Never>) in
                entryWaiters.append(continuation)
            }
        }

        func waitUntilCancellationObserved() async {
            if cancellationWasObserved {
                return
            }
            await withCheckedContinuation {
                (continuation: CheckedContinuation<Void, Never>) in
                cancellationWaiters.append(continuation)
            }
        }

        func resume() {
            guard let releaseContinuation else {
                preconditionFailure("The cancellation gate was resumed before it suspended.")
            }
            self.releaseContinuation = nil
            releaseContinuation.resume()
        }

        private func observeCancellation() {
            cancellationWasObserved = true
            let cancellationWaiters = self.cancellationWaiters
            self.cancellationWaiters.removeAll()
            for waiter in cancellationWaiters {
                waiter.resume()
            }
        }
    }
}

private extension SignedApplication {
    init(
        testName: String,
        bundleURL: URL,
        executableURL: URL,
        signingIdentifier: String,
        designatedRequirement: String
    ) {
        name = testName
        self.bundleURL = bundleURL
        self.executableURL = executableURL
        self.signingIdentifier = signingIdentifier
        self.designatedRequirement = designatedRequirement
    }
}
