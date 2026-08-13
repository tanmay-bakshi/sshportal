import XCTest

final class SignedApplicationTests: XCTestCase {
    func testReadsIdentityFromSignedSystemApplication() throws {
        let path = "/Applications/Safari.app"
        let application = try SignedApplication(bundlePath: path)

        XCTAssertEqual(application.name, "Safari")
        XCTAssertEqual(application.signingIdentifier, "com.apple.Safari")
        XCTAssertEqual(
            application.bundleURL.path,
            URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        )
        XCTAssertFalse(application.designatedRequirement.isEmpty)
        XCTAssertTrue(application.executableURL.isFileURL)
    }

    func testRejectsNonApplicationPath() throws {
        XCTAssertThrowsError(try SignedApplication(bundlePath: "/System/Applications"))
    }
}
