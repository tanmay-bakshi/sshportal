import Foundation

enum ControlCommand {
    case start(StartConfiguration)
    case stop

    init(data: Data) throws {
        let payload = try JSONDecoder().decode(Payload.self, from: data)
        switch payload.command {
        case "start":
            guard
                let applicationPath = payload.applicationPath,
                let socksHost = payload.socksHost,
                let socksPort = payload.socksPort,
                let username = payload.username,
                let password = payload.password
            else {
                throw ControlProtocolError.incompleteStartCommand
            }
            self = .start(
                StartConfiguration(
                    applicationPath: applicationPath,
                    proxy: try ProxyConfiguration(
                        socksHost: socksHost,
                        socksPort: socksPort,
                        username: username,
                        password: password
                    )
                )
            )
        case "stop":
            self = .stop
        default:
            throw ControlProtocolError.unknownCommand(payload.command)
        }
    }

    private struct Payload: Decodable {
        let command: String
        let applicationPath: String?
        let socksHost: String?
        let socksPort: UInt16?
        let username: String?
        let password: String?

        enum CodingKeys: String, CodingKey {
            case command
            case applicationPath = "application_path"
            case socksHost = "socks_host"
            case socksPort = "socks_port"
            case username
            case password
        }
    }
}

struct StartConfiguration {
    let applicationPath: String
    let proxy: ProxyConfiguration
}

struct CompanionEvent: Encodable {
    let event: String
    let application: String?
    let signingIdentifier: String?
    let message: String?

    static let installing = CompanionEvent(event: "installing")
    static let approvalRequired = CompanionEvent(event: "approval_required")
    static let active = CompanionEvent(event: "active")
    static let stopped = CompanionEvent(event: "stopped")

    static func configuring(application: String, signingIdentifier: String) -> CompanionEvent {
        CompanionEvent(
            event: "configuring",
            application: application,
            signingIdentifier: signingIdentifier,
            message: nil
        )
    }

    static func error(_ message: String) -> CompanionEvent {
        CompanionEvent(event: "error", application: nil, signingIdentifier: nil, message: message)
    }

    private init(
        event: String,
        application: String? = nil,
        signingIdentifier: String? = nil,
        message: String? = nil
    ) {
        self.event = event
        self.application = application
        self.signingIdentifier = signingIdentifier
        self.message = message
    }

    enum CodingKeys: String, CodingKey {
        case event
        case application
        case signingIdentifier = "signing_identifier"
        case message
    }
}

enum ControlProtocolError: LocalizedError {
    case incompleteStartCommand
    case unknownCommand(String)

    var errorDescription: String? {
        switch self {
        case .incompleteStartCommand:
            return "The start command is incomplete."
        case .unknownCommand(let command):
            return "The control command \(command) is not supported."
        }
    }
}
