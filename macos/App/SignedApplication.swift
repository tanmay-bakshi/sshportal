import Foundation
import Security

struct SignedApplication {
    let name: String
    let bundleURL: URL
    let executableURL: URL
    let signingIdentifier: String
    let designatedRequirement: String

    init(bundlePath: String) throws {
        let bundleURL = URL(fileURLWithPath: bundlePath, isDirectory: true).resolvingSymlinksInPath()
        guard bundleURL.pathExtension == "app", let bundle = Bundle(url: bundleURL) else {
            throw SignedApplicationError.invalidBundle(bundlePath)
        }
        guard let executableURL = bundle.executableURL else {
            throw SignedApplicationError.missingExecutable(bundlePath)
        }

        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(executableURL as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let staticCode else {
            throw SignedApplicationError.securityFailure("create static code", createStatus)
        }
        let validationStatus = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
            nil
        )
        guard validationStatus == errSecSuccess else {
            throw SignedApplicationError.invalidSignature(executableURL.path, validationStatus)
        }

        var rawSigningInformation: CFDictionary?
        let informationStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawSigningInformation
        )
        guard
            informationStatus == errSecSuccess,
            let signingInformation = rawSigningInformation as? [CFString: Any],
            let signingIdentifier = signingInformation[kSecCodeInfoIdentifier] as? String
        else {
            throw SignedApplicationError.securityFailure("read signing information", informationStatus)
        }

        var requirement: SecRequirement?
        let requirementStatus = SecCodeCopyDesignatedRequirement(staticCode, [], &requirement)
        guard requirementStatus == errSecSuccess, let requirement else {
            throw SignedApplicationError.securityFailure(
                "read designated requirement",
                requirementStatus
            )
        }
        var rawRequirement: CFString?
        let requirementStringStatus = SecRequirementCopyString(requirement, [], &rawRequirement)
        guard
            requirementStringStatus == errSecSuccess,
            let designatedRequirement = rawRequirement as String?
        else {
            throw SignedApplicationError.securityFailure(
                "format designated requirement",
                requirementStringStatus
            )
        }

        self.name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? bundle.object(forInfoDictionaryKey: kCFBundleNameKey as String) as? String
            ?? bundleURL.deletingPathExtension().lastPathComponent
        self.bundleURL = bundleURL
        self.executableURL = executableURL
        self.signingIdentifier = signingIdentifier
        self.designatedRequirement = designatedRequirement
    }
}

enum SignedApplicationError: LocalizedError {
    case invalidBundle(String)
    case missingExecutable(String)
    case invalidSignature(String, OSStatus)
    case securityFailure(String, OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidBundle(let path):
            return "The selected VPN application is not a valid .app bundle: \(path)"
        case .missingExecutable(let path):
            return "The selected VPN application has no executable: \(path)"
        case .invalidSignature(let path, let status):
            return "The selected VPN application has an invalid code signature (\(status)): \(path)"
        case .securityFailure(let operation, let status):
            return "Failed to \(operation) for the selected VPN application (\(status))."
        }
    }
}
