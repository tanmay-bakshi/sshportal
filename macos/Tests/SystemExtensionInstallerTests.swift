import SystemExtensions
import XCTest

@MainActor
final class SystemExtensionInstallerTests: XCTestCase {
    func testCancellationFinishesPromptlyAndLateCallbackCannotCompleteNextInstall() async throws {
        var submittedRequests: [OSSystemExtensionRequest] = []
        let installer = SystemExtensionInstaller { request in
            submittedRequests.append(request)
        }

        let firstTask = Task { @MainActor in
            try await installer.install()
        }
        await waitForRequestCount(1, in: submittedRequests)
        let firstRequest = try XCTUnwrap(submittedRequests.first)
        firstTask.cancel()
        await assertCancelled(firstTask)

        var secondInstallationCompleted = false
        let secondTask = Task { @MainActor in
            try await installer.install()
            secondInstallationCompleted = true
        }
        await waitForRequestCount(2, in: submittedRequests)
        let secondRequest = submittedRequests[1]

        installer.request(firstRequest, didFinishWithResult: .completed)
        await Task.yield()
        XCTAssertFalse(secondInstallationCompleted)

        installer.request(secondRequest, didFinishWithResult: .completed)
        try await secondTask.value
        XCTAssertTrue(secondInstallationCompleted)
    }

    private func waitForRequestCount(
        _ expectedCount: Int,
        in requests: @autoclosure () -> [OSSystemExtensionRequest]
    ) async {
        for _ in 0..<100 where requests().count < expectedCount {
            await Task.yield()
        }
        XCTAssertEqual(requests().count, expectedCount)
    }

    private func assertCancelled(_ task: Task<Void, Error>) async {
        do {
            try await task.value
            XCTFail("Expected cancellation.")
        } catch is CancellationError {
        } catch {
            XCTFail("Unexpected installation error: \(error)")
        }
    }
}
