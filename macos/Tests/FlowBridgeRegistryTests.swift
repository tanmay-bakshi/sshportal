import XCTest

final class FlowBridgeRegistryTests: XCTestCase {
    func testStopBeforeStartRejectsTheStoppedGeneration() async {
        let registry = FlowBridgeRegistry()

        await registry.stop(generation: 1)
        let didStart = await registry.start(generation: 1)

        XCTAssertFalse(didStart)
    }

    func testAcceptAfterStopCancelsTheFlow() async {
        let registry = FlowBridgeRegistry()
        let bridge = FakeFlowBridge()
        let didStart = await registry.start(generation: 1)
        XCTAssertTrue(didStart)

        await registry.stop(generation: 1)
        await registry.accept(bridge, generation: 1)

        let cancellationCount = await bridge.cancellationCount
        XCTAssertEqual(cancellationCount, 1)
    }

    func testStopCancelsAndAwaitsActiveFlows() async {
        let registry = FlowBridgeRegistry()
        let bridge = FakeFlowBridge()
        let didStart = await registry.start(generation: 1)
        XCTAssertTrue(didStart)
        await registry.accept(bridge, generation: 1)
        await bridge.waitUntilRunning()

        await registry.stop(generation: 1)

        let cancellationCount = await bridge.cancellationCount
        let didFinish = await bridge.didFinish
        XCTAssertEqual(cancellationCount, 1)
        XCTAssertTrue(didFinish)
    }

    private actor FakeFlowBridge: FlowBridge {
        private(set) var cancellationCount = 0
        private(set) var didFinish = false
        private var isCancelled = false
        private var runningWaiters: [CheckedContinuation<Void, Never>] = []
        private var finishContinuation: CheckedContinuation<Void, Never>?

        func run() async {
            let runningWaiters = self.runningWaiters
            self.runningWaiters.removeAll()
            for waiter in runningWaiters {
                waiter.resume()
            }
            if isCancelled == false {
                await withCheckedContinuation {
                    (continuation: CheckedContinuation<Void, Never>) in
                    finishContinuation = continuation
                }
            }
            didFinish = true
        }

        func cancel() {
            cancellationCount += 1
            isCancelled = true
            let finishContinuation = self.finishContinuation
            self.finishContinuation = nil
            finishContinuation?.resume()
        }

        func waitUntilRunning() async {
            if finishContinuation != nil || didFinish {
                return
            }
            await withCheckedContinuation {
                (continuation: CheckedContinuation<Void, Never>) in
                runningWaiters.append(continuation)
            }
        }
    }
}
