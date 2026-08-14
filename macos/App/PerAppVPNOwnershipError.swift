import Foundation

enum PerAppVPNOwnershipError: LocalizedError {
    case alreadyOwned

    var errorDescription: String? {
        switch self {
        case .alreadyOwned:
            return "Another SSHPortal per-app VPN session is already active for this user."
        }
    }
}
