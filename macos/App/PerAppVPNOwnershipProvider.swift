import Foundation

protocol PerAppVPNOwnershipProvider {
    func acquire() throws -> any PerAppVPNOwnershipLease
}
