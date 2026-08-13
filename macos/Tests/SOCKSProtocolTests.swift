import Network
import XCTest

final class SOCKSProtocolTests: XCTestCase {
    func testIPv4UDPRoundTrip() throws {
        let endpoint = try SOCKSEndpoint(host: "192.0.2.40", port: 53)
        let payload = Data("query".utf8)

        let encoded = try SOCKSProtocol.encodeUDPDatagram(data: payload, endpoint: endpoint)
        let (decodedPayload, decodedEndpoint) = try SOCKSProtocol.decodeUDPDatagram(encoded)

        XCTAssertEqual(decodedPayload, payload)
        XCTAssertEqual(decodedEndpoint, endpoint)
    }

    func testDomainUDPRoundTrip() throws {
        let endpoint = try SOCKSEndpoint(host: "resolver.client.internal", port: 5353)
        let payload = Data([0, 1, 2, 3])

        let encoded = try SOCKSProtocol.encodeUDPDatagram(data: payload, endpoint: endpoint)
        let (decodedPayload, decodedEndpoint) = try SOCKSProtocol.decodeUDPDatagram(encoded)

        XCTAssertEqual(decodedPayload, payload)
        XCTAssertEqual(decodedEndpoint, endpoint)
    }

    func testFragmentedUDPDatagramIsRejected() throws {
        let packet = Data([0, 0, 1, 1, 127, 0, 0, 1, 0, 53])

        XCTAssertThrowsError(try SOCKSProtocol.decodeUDPDatagram(packet))
    }

    func testOversizedUDPDatagramIsRejectedAfterEncapsulation() throws {
        let endpoint = try SOCKSEndpoint(host: "192.0.2.40", port: 53)
        let payload = Data(repeating: 0, count: 65_498)

        XCTAssertThrowsError(
            try SOCKSProtocol.encodeUDPDatagram(data: payload, endpoint: endpoint)
        )
    }

    func testUsernamePasswordRequestUsesRFC1929Framing() throws {
        let request = try SOCKSProtocol.authentication(
            username: "sshportal",
            password: "secret"
        )

        XCTAssertEqual(request, Data([1, 9]) + Data("sshportal".utf8) + Data([6]) + Data("secret".utf8))
    }
}
