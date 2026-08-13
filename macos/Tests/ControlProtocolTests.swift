import XCTest

final class ControlProtocolTests: XCTestCase {
    func testStartCommandDecodesPrivateLoopbackProxy() throws {
        let data = Data(
            """
            {
              "command": "start",
              "application_path": "/Applications/Firefox.app",
              "socks_host": "127.0.0.1",
              "socks_port": 49152,
              "username": "sshportal",
              "password": "session-secret"
            }
            """.utf8
        )

        guard case .start(let configuration) = try ControlCommand(data: data) else {
            return XCTFail("Expected a start command.")
        }

        XCTAssertEqual(configuration.applicationPath, "/Applications/Firefox.app")
        XCTAssertEqual(configuration.proxy.socksHost, "127.0.0.1")
        XCTAssertEqual(configuration.proxy.socksPort, 49152)
        XCTAssertEqual(configuration.proxy.username, "sshportal")
        XCTAssertEqual(configuration.proxy.password, "session-secret")
    }

    func testStartCommandRejectsNonLoopbackProxy() throws {
        let data = Data(
            """
            {
              "command": "start",
              "application_path": "/Applications/Firefox.app",
              "socks_host": "192.0.2.10",
              "socks_port": 49152,
              "username": "sshportal",
              "password": "session-secret"
            }
            """.utf8
        )

        XCTAssertThrowsError(try ControlCommand(data: data)) { error in
            XCTAssertEqual(
                error.localizedDescription,
                ProxyConfigurationError.nonLoopbackProxy.localizedDescription
            )
        }
    }

    func testStopCommandDecodes() throws {
        let command = try ControlCommand(data: Data(#"{"command":"stop"}"#.utf8))

        guard case .stop = command else {
            return XCTFail("Expected a stop command.")
        }
    }
}
