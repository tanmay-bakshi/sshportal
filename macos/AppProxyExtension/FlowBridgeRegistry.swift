import Foundation

protocol FlowBridge: Actor {
    func run() async
    func cancel() async
}

actor FlowBridgeRegistry {
    private struct Entry {
        let bridge: any FlowBridge
        let task: Task<Void, Never>
    }

    private var entries: [UUID: Entry] = [:]
    private var activeGeneration: UInt64?
    private var latestStoppedGeneration: UInt64 = 0

    func start(generation: UInt64) -> Bool {
        guard
            generation > latestStoppedGeneration,
            activeGeneration == nil,
            entries.isEmpty
        else {
            return false
        }
        activeGeneration = generation
        return true
    }

    func accept(_ bridge: any FlowBridge, generation: UInt64) async {
        guard activeGeneration == generation else {
            await bridge.cancel()
            return
        }

        let identifier = UUID()
        let task = Task { [weak self] in
            await bridge.run()
            await self?.remove(identifier)
        }
        entries[identifier] = Entry(bridge: bridge, task: task)
    }

    func stop(generation: UInt64) async {
        latestStoppedGeneration = max(latestStoppedGeneration, generation)
        guard activeGeneration == generation else {
            return
        }
        activeGeneration = nil
        let activeEntries = Array(entries.values)
        entries.removeAll()
        for entry in activeEntries {
            entry.task.cancel()
        }
        await withTaskGroup(of: Void.self) { group in
            for entry in activeEntries {
                group.addTask {
                    await entry.bridge.cancel()
                    await entry.task.value
                }
            }
        }
    }

    private func remove(_ identifier: UUID) {
        entries.removeValue(forKey: identifier)
    }
}
