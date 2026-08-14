import AppKit
import Foundation

@MainActor
final class ApplicationCoordinator: NSObject, NSApplicationDelegate {
    private let installer = SystemExtensionInstaller()
    private let vpnController = PerAppVPNController()
    private let eventWriter = EventWriter()
    private var commandTask: Task<Void, Never>?
    private var startTask: Task<Void, Never>?
    private var stopTask: Task<Void, Never>?
    private var hasStarted = false
    private var isStopping = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        guard CommandLine.arguments.contains("--stdio-control") else {
            let alert = NSAlert()
            alert.messageText = "SSHPortal Per-App VPN"
            alert.informativeText = "This companion is started automatically by sshportal-server --vpn-app."
            alert.runModal()
            NSApp.terminate(nil)
            return
        }

        installer.approvalRequired = { [weak self] in
            self?.eventWriter.send(.approvalRequired)
        }
        vpnController.unexpectedDisconnect = { [weak self] error in
            self?.fail(error)
        }
        startReadingCommands()
    }

    private func startReadingCommands() {
        commandTask = Task { [weak self] in
            do {
                for try await line in FileHandle.standardInput.bytes.lines {
                    try Task.checkCancellation()
                    let command = try ControlCommand(data: Data(line.utf8))
                    self?.handle(command)
                }
                self?.stop()
            } catch is CancellationError {
                return
            } catch {
                self?.fail(error)
            }
        }
    }

    private func handle(_ command: ControlCommand) {
        switch command {
        case .start(let configuration):
            start(configuration)
        case .stop:
            stop()
        }
    }

    private func start(_ configuration: StartConfiguration) {
        guard !hasStarted && !isStopping else {
            fail(ApplicationCoordinatorError.duplicateStart)
            return
        }
        hasStarted = true
        startTask = Task { [weak self] in
            guard let self else {
                return
            }
            do {
                let application = try SignedApplication(bundlePath: configuration.applicationPath)
                eventWriter.send(
                    .configuring(
                        application: application.name,
                        signingIdentifier: application.signingIdentifier
                    )
                )
                eventWriter.send(.installing)
                try await installer.install()
                try Task.checkCancellation()
                try await vpnController.start(for: application, proxy: configuration.proxy)
                try Task.checkCancellation()
                eventWriter.send(.active)
            } catch is CancellationError {
                return
            } catch {
                fail(error)
            }
        }
    }

    private func stop() {
        guard isStopping == false, stopTask == nil else {
            return
        }
        isStopping = true
        commandTask?.cancel()
        commandTask = nil
        let activeStartTask = startTask
        activeStartTask?.cancel()
        stopTask = Task { [weak self] in
            guard let self else {
                return
            }
            await activeStartTask?.value
            startTask = nil
            do {
                try await vpnController.stop()
                eventWriter.send(.stopped)
                NSApp.terminate(nil)
            } catch {
                eventWriter.send(.error(error.localizedDescription))
                NSApp.terminate(nil)
            }
        }
    }

    private func fail(_ error: Error) {
        guard !isStopping else {
            return
        }
        eventWriter.send(.error(error.localizedDescription))
        stop()
    }
}

private final class EventWriter {
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()

    func send(_ event: CompanionEvent) {
        do {
            var data = try encoder.encode(event)
            data.append(0x0a)
            try FileHandle.standardOutput.write(contentsOf: data)
        } catch {
            FileHandle.standardError.write(
                Data("failed to write companion event: \(error.localizedDescription)\n".utf8)
            )
        }
    }
}

enum ApplicationCoordinatorError: LocalizedError {
    case duplicateStart

    var errorDescription: String? {
        "The macOS per-app VPN companion received more than one start command."
    }
}
