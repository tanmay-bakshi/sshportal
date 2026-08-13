import AppKit

MainActor.assumeIsolated {
    let application = NSApplication.shared
    let coordinator = ApplicationCoordinator()
    application.delegate = coordinator
    application.run()
}
