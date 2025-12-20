import Foundation
import UserNotifications

/// AI-powered monitoring loop that periodically checks for changes
@MainActor
final class AIMonitoringLoop: ObservableObject {
    static let shared = AIMonitoringLoop()

    // MARK: - Published State

    @Published private(set) var isRunning = false
    @Published private(set) var lastCheckTime: Date?
    @Published private(set) var lastAnalysis: AnalysisResult?
    @Published private(set) var checkCount = 0
    @Published private(set) var errorMessage: String?

    // MARK: - Private

    private let configuration = AIConfiguration.shared
    private let apiClient = ClaudeAPIClient()
    private var timer: Timer?
    private var baseline: [PersistenceItem] = []
    private var lastScanDate: Date?

    private init() {}

    // MARK: - Analysis Result

    struct AnalysisResult: Identifiable {
        let id = UUID()
        let timestamp: Date
        let severity: AISeverity
        let summary: String
        let findings: [Finding]
        let recommendations: [String]
        let diffSummary: String

        struct Finding: Identifiable {
            let id = UUID()
            let severity: AISeverity
            let title: String
            let description: String
            let affectedItems: [String]
            let mitreTechniques: [String]
        }
    }

    // MARK: - Control

    /// Start the monitoring loop
    func start() async {
        guard configuration.isAIActive else {
            errorMessage = "AI analysis is not enabled"
            return
        }

        guard !isRunning else { return }

        isRunning = true
        errorMessage = nil
        checkCount = 0

        // Capture initial baseline
        await captureBaseline()

        // Start timer
        startTimer()

        print("[AIMonitoringLoop] Started with interval: \(configuration.aiCheckInterval)s")
    }

    /// Stop the monitoring loop
    func stop() {
        timer?.invalidate()
        timer = nil
        isRunning = false
        print("[AIMonitoringLoop] Stopped")
    }

    /// Toggle monitoring state
    func toggle() async {
        if isRunning {
            stop()
        } else {
            await start()
        }
    }

    /// Manually trigger a check
    func checkNow() async {
        await performCheck()
    }

    // MARK: - Private Methods

    private func captureBaseline() async {
        // Get current items from AppState
        if let appState = getAppState() {
            baseline = appState.items
            lastScanDate = Date()
        }
    }

    private func startTimer() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: configuration.aiCheckInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.performCheck()
            }
        }
    }

    private func performCheck() async {
        lastCheckTime = Date()
        checkCount += 1

        print("[AIMonitoringLoop] Performing check #\(checkCount)")

        // Get current state
        guard let appState = getAppState() else {
            errorMessage = "Cannot access AppState"
            return
        }

        let currentItems = appState.items
        let diff = computeDiff(from: baseline, to: currentItems)

        // If no changes, skip API call
        guard diff.hasChanges else {
            print("[AIMonitoringLoop] No changes detected")
            return
        }

        print("[AIMonitoringLoop] Changes detected: \(diff.summary)")

        // Build request
        let request = ClaudeAPIClient.AnalysisRequest(
            diffSummary: diff.summary,
            addedItems: diff.added.map { itemToSummary($0) },
            removedItems: diff.removed.map { itemToSummary($0) },
            modifiedItems: diff.modified.map { mod in
                ClaudeAPIClient.ModifiedItemSummary(
                    identifier: mod.identifier,
                    name: mod.name,
                    changes: mod.changes
                )
            },
            currentStats: ClaudeAPIClient.SystemStats(
                totalItems: currentItems.count,
                unsignedCount: currentItems.filter { $0.trustLevel == .unsigned }.count,
                criticalRiskCount: currentItems.filter { ($0.riskScore ?? 0) >= 75 }.count,
                highRiskCount: currentItems.filter { ($0.riskScore ?? 0) >= 50 && ($0.riskScore ?? 0) < 75 }.count,
                lolbinItemCount: currentItems.filter { !($0.lolbinsDetections?.isEmpty ?? true) }.count
            ),
            systemInfo: ClaudeAPIClient.SystemInfo(
                hostname: Host.current().localizedName ?? "Unknown",
                macosVersion: ProcessInfo.processInfo.operatingSystemVersionString
            )
        )

        // Call Claude API
        do {
            let response = try await apiClient.analyzeDiff(request)

            // Convert to our result type
            let analysis = AnalysisResult(
                timestamp: Date(),
                severity: AISeverity(rawValue: response.severity) ?? .info,
                summary: response.summary,
                findings: response.findings.map { finding in
                    AnalysisResult.Finding(
                        severity: AISeverity(rawValue: finding.severity) ?? .info,
                        title: finding.title,
                        description: finding.description,
                        affectedItems: finding.affectedItems,
                        mitreTechniques: finding.mitreTechniques ?? []
                    )
                },
                recommendations: response.recommendations,
                diffSummary: diff.summary
            )

            lastAnalysis = analysis
            errorMessage = nil

            // Update baseline
            baseline = currentItems
            lastScanDate = Date()

            // Send notification if severity meets threshold
            if analysis.severity >= configuration.notificationThreshold {
                await sendNotification(analysis)
            }

            print("[AIMonitoringLoop] Analysis complete - Severity: \(analysis.severity.rawValue)")

        } catch {
            errorMessage = error.localizedDescription
            print("[AIMonitoringLoop] Error: \(error.localizedDescription)")
        }
    }

    private func itemToSummary(_ item: PersistenceItem) -> ClaudeAPIClient.ItemSummary {
        ClaudeAPIClient.ItemSummary(
            identifier: item.identifier,
            name: item.name,
            category: item.category.rawValue,
            trustLevel: item.trustLevel.rawValue,
            riskScore: item.riskScore ?? 0,
            executablePath: item.executablePath?.path,
            isAppleSigned: item.signatureInfo?.isAppleSigned ?? false,
            hasLolbins: !(item.lolbinsDetections?.isEmpty ?? true)
        )
    }

    // MARK: - Diff Computation

    private struct DiffResult {
        let added: [PersistenceItem]
        let removed: [PersistenceItem]
        let modified: [ModifiedItem]
        let hasChanges: Bool
        let summary: String

        struct ModifiedItem {
            let identifier: String
            let name: String
            let changes: [String]
        }
    }

    private func computeDiff(from oldItems: [PersistenceItem], to newItems: [PersistenceItem]) -> DiffResult {
        let oldById = Dictionary(uniqueKeysWithValues: oldItems.map { ($0.identifier, $0) })
        let newById = Dictionary(uniqueKeysWithValues: newItems.map { ($0.identifier, $0) })

        let oldIds = Set(oldById.keys)
        let newIds = Set(newById.keys)

        let addedIds = newIds.subtracting(oldIds)
        let removedIds = oldIds.subtracting(newIds)
        let commonIds = oldIds.intersection(newIds)

        let added = addedIds.compactMap { newById[$0] }
        let removed = removedIds.compactMap { oldById[$0] }

        var modified: [DiffResult.ModifiedItem] = []
        for id in commonIds {
            guard let oldItem = oldById[id], let newItem = newById[id] else { continue }
            let changes = detectChanges(old: oldItem, new: newItem)
            if !changes.isEmpty {
                modified.append(DiffResult.ModifiedItem(
                    identifier: id,
                    name: newItem.name,
                    changes: changes
                ))
            }
        }

        let hasChanges = !added.isEmpty || !removed.isEmpty || !modified.isEmpty

        var summaryParts: [String] = []
        if !added.isEmpty { summaryParts.append("+\(added.count) added") }
        if !removed.isEmpty { summaryParts.append("-\(removed.count) removed") }
        if !modified.isEmpty { summaryParts.append("~\(modified.count) modified") }

        return DiffResult(
            added: added,
            removed: removed,
            modified: modified,
            hasChanges: hasChanges,
            summary: summaryParts.isEmpty ? "No changes" : summaryParts.joined(separator: ", ")
        )
    }

    private func detectChanges(old: PersistenceItem, new: PersistenceItem) -> [String] {
        var changes: [String] = []

        if old.trustLevel != new.trustLevel {
            changes.append("Trust level: \(old.trustLevel.rawValue) → \(new.trustLevel.rawValue)")
        }
        if old.isEnabled != new.isEnabled {
            changes.append("Enabled: \(old.isEnabled) → \(new.isEnabled)")
        }
        if old.riskScore != new.riskScore {
            changes.append("Risk score: \(old.riskScore ?? 0) → \(new.riskScore ?? 0)")
        }
        if old.executablePath?.path != new.executablePath?.path {
            changes.append("Executable path changed")
        }

        return changes
    }

    // MARK: - Notifications

    private func sendNotification(_ analysis: AnalysisResult) async {
        let content = UNMutableNotificationContent()
        content.title = "Persistence Changes Detected"
        content.subtitle = "Severity: \(analysis.severity.displayName)"
        content.body = analysis.summary
        content.sound = analysis.severity >= .high ? .defaultCritical : .default

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )

        do {
            try await UNUserNotificationCenter.current().add(request)
        } catch {
            print("[AIMonitoringLoop] Failed to send notification: \(error)")
        }
    }

    // MARK: - AppState Access

    private func getAppState() -> AppState? {
        // Access shared AppState instance
        // This assumes AppState.shared exists
        return AppState.shared
    }
}
