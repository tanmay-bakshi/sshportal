import Darwin
import Foundation

final class PerAppVPNFileOwnershipProvider: PerAppVPNOwnershipProvider {
    private let directoryURL: URL

    init(
        directoryURL: URL = URL.applicationSupportDirectory
            .appending(path: "SSHPortal", directoryHint: .isDirectory)
    ) {
        self.directoryURL = directoryURL
    }

    func acquire() throws -> any PerAppVPNOwnershipLease {
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true
        )
        let lockURL = directoryURL.appending(path: "per-app-vpn.lock")
        let descriptor = Darwin.open(
            lockURL.path,
            O_CREAT | O_RDWR | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else {
            throw posixError()
        }

        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let lockError = errno
            _ = Darwin.close(descriptor)
            if lockError == EWOULDBLOCK || lockError == EAGAIN {
                throw PerAppVPNOwnershipError.alreadyOwned
            }
            throw posixError(code: lockError)
        }
        return Lease(descriptor: descriptor)
    }

    private func posixError(code: Int32 = errno) -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
    }

    private final class Lease: PerAppVPNOwnershipLease {
        private let lock = NSLock()
        private var descriptor: Int32?

        init(descriptor: Int32) {
            self.descriptor = descriptor
        }

        deinit {
            release()
        }

        func release() {
            lock.lock()
            guard let descriptor else {
                lock.unlock()
                return
            }
            self.descriptor = nil
            lock.unlock()

            _ = flock(descriptor, LOCK_UN)
            _ = Darwin.close(descriptor)
        }
    }
}
