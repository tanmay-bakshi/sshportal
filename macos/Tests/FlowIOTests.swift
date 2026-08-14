import Foundation
import XCTest

final class FlowIOTests: XCTestCase {
    func testNilDatagramBatchIsRejected() {
        XCTAssertThrowsError(try validatedDatagramBatch(nil as [Data]?))
    }

    func testEmptyDatagramBatchIsRejected() {
        XCTAssertThrowsError(try validatedDatagramBatch([Data]()))
    }

    func testZeroLengthDatagramIsPreserved() throws {
        let batch = try validatedDatagramBatch([Data()])

        XCTAssertEqual(batch.count, 1)
        XCTAssertTrue(batch[0].isEmpty)
    }
}
