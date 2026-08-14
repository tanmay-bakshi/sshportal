import Foundation
import Network
import XCTest

final class SOCKSConnectionTests: XCTestCase {
    func testConnectPreservesCoalescedFirstPayloadForStreamReader() async throws {
        let payload = Data("first proxied bytes".utf8)
        let response = Data([5, 0, 0, 1, 127, 0, 0, 1, 0x13, 0x88]) + payload
        let transport = FakeTransport(streamResponse: response, isComplete: true)
        let connection = SOCKSConnection(
            transport: transport,
            queue: DispatchQueue(label: "SOCKSConnectionTests")
        )

        try await connection.start()
        try await connection.connect(to: SOCKSEndpoint(host: "example.test", port: 443))
        let (receivedPayload, isComplete) = try await connection.receiveStream()

        XCTAssertEqual(receivedPayload, payload)
        XCTAssertTrue(isComplete)
        let streamReceiveCount = await transport.streamReceiveCount
        XCTAssertEqual(streamReceiveCount, 1)
    }

    private actor FakeTransport: SOCKSConnectionTransport {
        private var streamResponse: Data?
        private let responseIsComplete: Bool
        private(set) var streamReceiveCount = 0

        init(streamResponse: Data, isComplete: Bool) {
            self.streamResponse = streamResponse
            responseIsComplete = isComplete
        }

        func start(queue: DispatchQueue) async throws {}

        func cancel() {}

        func send(_ data: Data, isComplete: Bool) async throws {}

        func receive(minimum: Int, maximum: Int) async throws -> (Data, Bool) {
            streamReceiveCount += 1
            guard let streamResponse else {
                return (Data(), true)
            }
            precondition(streamResponse.count >= minimum)
            precondition(streamResponse.count <= maximum)
            self.streamResponse = nil
            return (streamResponse, responseIsComplete)
        }

        func receiveMessage() async throws -> Data {
            throw SOCKSError.connectionClosed
        }
    }
}
