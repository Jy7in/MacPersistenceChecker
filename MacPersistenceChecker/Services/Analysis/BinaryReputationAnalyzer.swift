import Foundation

/// Binary Reputation & Behavioral Analysis
/// Detects suspicious behavioral patterns in persistence items
final class BinaryReputationAnalyzer {

    static let shared = BinaryReputationAnalyzer()

    // MARK: - Behavioral Anomaly Types

    struct BehavioralAnomaly {
        let type: AnomalyType
        let title: String
        let description: String
        let severity: Severity
        let riskPoints: Int
        let tags: [String]
    }

    enum AnomalyType: String {
        case hiddenPersistenceGuard = "Hidden Persistence Guard"
        case aggressivePersistence = "Aggressive Persistence"
        case stealthyAutoStart = "Stealthy Auto-Start"
        case orphanedPersistence = "Orphaned Persistence"
        case suspiciousLocation = "Suspicious Location"
        case privilegeEscalation = "Privilege Escalation Risk"
        case networkPersistence = "Network-Enabled Persistence"
        case scriptBasedPersistence = "Script-Based Persistence"
        case hiddenFromUser = "Hidden From User"
        case frequentRestart = "Frequent Restart Pattern"
    }

    enum Severity: String {
        case low = "Low"
        case medium = "Medium"
        case high = "High"
        case critical = "Critical"

        var color: String {
            switch self {
            case .low: return "gray"
            case .medium: return "yellow"
            case .high: return "orange"
            case .critical: return "red"
            }
        }
    }

    // MARK: - Analysis

    struct ReputationResult {
        let hasAnomalies: Bool
        let anomalies: [BehavioralAnomaly]
        let overallSeverity: Severity
        let totalRiskPoints: Int
        let summary: String
    }

    /// Analyze a persistence item for behavioral anomalies
    func analyze(_ item: PersistenceItem) -> ReputationResult {
        var anomalies: [BehavioralAnomaly] = []

        // Check each behavioral pattern
        if let anomaly = checkHiddenPersistenceGuard(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkAggressivePersistence(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkStealthyAutoStart(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkOrphanedPersistence(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkSuspiciousLocation(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkPrivilegeEscalation(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkNetworkPersistence(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkScriptBasedPersistence(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkHiddenFromUser(item) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkFrequentRestart(item) {
            anomalies.append(anomaly)
        }

        // Calculate overall severity
        let overallSeverity = calculateOverallSeverity(anomalies)
        let totalRiskPoints = anomalies.reduce(0) { $0 + $1.riskPoints }

        let summary: String
        if anomalies.isEmpty {
            summary = "No behavioral anomalies detected"
        } else {
            summary = "Behavioral anomalies detected - \(anomalies.count) suspicious pattern\(anomalies.count > 1 ? "s" : "") found"
        }

        return ReputationResult(
            hasAnomalies: !anomalies.isEmpty,
            anomalies: anomalies,
            overallSeverity: overallSeverity,
            totalRiskPoints: totalRiskPoints,
            summary: summary
        )
    }

    // MARK: - Individual Checks

    /// Hidden Persistence Guard - KeepAlive agent without obvious watchdog purpose
    private func checkHiddenPersistenceGuard(_ item: PersistenceItem) -> BehavioralAnomaly? {
        // KeepAlive on a LaunchAgent (not daemon) without being a known service
        guard item.keepAlive == true else { return nil }
        guard item.category == .launchAgents else { return nil }

        // Check if it's a known legitimate watchdog
        let knownWatchdogs = ["updater", "helper", "agent", "service", "daemon", "sync", "backup", "monitor"]
        let nameLower = item.name.lowercased()
        let isLikelyWatchdog = knownWatchdogs.contains { nameLower.contains($0) }

        // If it doesn't look like a typical watchdog but has KeepAlive, flag it
        if !isLikelyWatchdog {
            return BehavioralAnomaly(
                type: .hiddenPersistenceGuard,
                title: "Hidden Persistence Guard",
                description: "KeepAlive agent without obvious watchdog purpose. KeepAlive ensures auto-restart on crash/kill. Legitimate for services, suspicious for hidden agents. Malware uses this to survive termination attempts.",
                severity: .medium,
                riskPoints: 10,
                tags: ["Launch Behavior", "Persistence"]
            )
        }

        return nil
    }

    /// Aggressive Persistence - RunAtLoad + KeepAlive on non-service
    private func checkAggressivePersistence(_ item: PersistenceItem) -> BehavioralAnomaly? {
        guard item.runAtLoad == true && item.keepAlive == true else { return nil }

        // This is aggressive if it's not obviously a service/daemon
        let nameLower = item.name.lowercased()
        let isLikelyService = nameLower.contains("service") || nameLower.contains("daemon") ||
                             nameLower.contains(".d.") || item.category == .launchDaemons

        if !isLikelyService {
            return BehavioralAnomaly(
                type: .aggressivePersistence,
                title: "Aggressive Persistence",
                description: "RunAtLoad + KeepAlive on non-service. This agent starts at boot and auto-restarts if killed. For services this is normal, for other agents it indicates aggressive persistence.",
                severity: .medium,
                riskPoints: 15,
                tags: ["Launch Behavior", "Auto-Start"]
            )
        }

        return nil
    }

    /// Stealthy Auto-Start - RunAtLoad without visible UI
    private func checkStealthyAutoStart(_ item: PersistenceItem) -> BehavioralAnomaly? {
        guard item.runAtLoad == true else { return nil }

        // Check if it's a background-only item (no UI)
        let nameLower = item.name.lowercased()
        let hasUIIndicator = nameLower.contains("app") || nameLower.contains("ui") ||
                            nameLower.contains("gui") || nameLower.contains("menu")

        // Background processes that auto-start silently
        if !hasUIIndicator && item.category == .launchAgents {
            // Only flag if it's not from a known vendor
            if item.signatureInfo?.isAppleSigned != true &&
               item.trustLevel != .knownVendor {
                return BehavioralAnomaly(
                    type: .stealthyAutoStart,
                    title: "Stealthy Auto-Start",
                    description: "Background process with RunAtLoad from unknown vendor. Starts silently at login with no visible UI.",
                    severity: .low,
                    riskPoints: 5,
                    tags: ["Auto-Start", "Background"]
                )
            }
        }

        return nil
    }

    /// Orphaned Persistence - plist exists but executable missing
    private func checkOrphanedPersistence(_ item: PersistenceItem) -> BehavioralAnomaly? {
        // Check if executable exists
        if let execPath = item.executablePath {
            if !FileManager.default.fileExists(atPath: execPath.path) {
                return BehavioralAnomaly(
                    type: .orphanedPersistence,
                    title: "Orphaned Persistence",
                    description: "Persistence plist points to non-existent executable. Could be leftover from uninstalled software or malware that deleted itself.",
                    severity: .medium,
                    riskPoints: 10,
                    tags: ["Broken", "Suspicious"]
                )
            }
        }

        return nil
    }

    /// Suspicious Location - executable in unusual path
    private func checkSuspiciousLocation(_ item: PersistenceItem) -> BehavioralAnomaly? {
        guard let execPath = item.executablePath?.path else { return nil }

        let suspiciousPaths = [
            "/tmp/",
            "/var/tmp/",
            "/private/tmp/",
            "/Users/Shared/",
            "/.hidden",
            "/.",  // hidden directories
        ]

        for suspPath in suspiciousPaths {
            if execPath.contains(suspPath) {
                return BehavioralAnomaly(
                    type: .suspiciousLocation,
                    title: "Suspicious Executable Location",
                    description: "Executable located in suspicious path: \(suspPath). Legitimate software rarely uses temporary or hidden directories.",
                    severity: .high,
                    riskPoints: 15,
                    tags: ["Location", "Suspicious Path"]
                )
            }
        }

        // Check for hidden files (starting with .)
        let filename = (execPath as NSString).lastPathComponent
        if filename.hasPrefix(".") {
            return BehavioralAnomaly(
                type: .suspiciousLocation,
                title: "Hidden Executable",
                description: "Executable is a hidden file (starts with dot). Common malware evasion technique.",
                severity: .high,
                riskPoints: 15,
                tags: ["Hidden", "Evasion"]
            )
        }

        return nil
    }

    /// Privilege Escalation Risk - user agent calling privileged operations
    private func checkPrivilegeEscalation(_ item: PersistenceItem) -> BehavioralAnomaly? {
        guard item.category == .launchAgents else { return nil }

        // Check if arguments contain sudo or privilege escalation
        if let args = item.programArguments {
            let argsJoined = args.joined(separator: " ").lowercased()

            if argsJoined.contains("sudo") || argsJoined.contains("as root") ||
               argsJoined.contains("admin") || argsJoined.contains("privilege") {
                return BehavioralAnomaly(
                    type: .privilegeEscalation,
                    title: "Privilege Escalation Attempt",
                    description: "User-level agent attempting privileged operations. May prompt for admin credentials or exploit vulnerabilities.",
                    severity: .high,
                    riskPoints: 15,
                    tags: ["Privilege", "Escalation"]
                )
            }
        }

        return nil
    }

    /// Network Persistence - persistence item with network capabilities
    private func checkNetworkPersistence(_ item: PersistenceItem) -> BehavioralAnomaly? {
        guard let args = item.programArguments else { return nil }

        let argsJoined = args.joined(separator: " ").lowercased()
        let networkIndicators = ["http://", "https://", "curl", "wget", "nc ", "netcat",
                                 "socket", "connect", "listen", ":443", ":80", ":8080"]

        for indicator in networkIndicators {
            if argsJoined.contains(indicator) {
                return BehavioralAnomaly(
                    type: .networkPersistence,
                    title: "Network-Enabled Persistence",
                    description: "Persistence item with network capabilities. May download payloads, exfiltrate data, or establish C2 channel.",
                    severity: .medium,
                    riskPoints: 10,
                    tags: ["Network", "C2"]
                )
            }
        }

        return nil
    }

    /// Script-Based Persistence - persistence using script interpreters
    private func checkScriptBasedPersistence(_ item: PersistenceItem) -> BehavioralAnomaly? {
        guard let args = item.programArguments, !args.isEmpty else { return nil }

        let scriptInterpreters = ["python", "python3", "perl", "ruby", "osascript", "bash", "sh", "zsh"]
        let firstArg = (args[0] as NSString).lastPathComponent.lowercased()

        // Check if it's running through a script interpreter
        for interpreter in scriptInterpreters {
            if firstArg.contains(interpreter) {
                // Check if it's running an inline script or external script
                let hasInlineScript = args.contains { $0.contains("-c") || $0.contains("-e") }

                if hasInlineScript {
                    return BehavioralAnomaly(
                        type: .scriptBasedPersistence,
                        title: "Inline Script Persistence",
                        description: "Persistence runs inline script via \(interpreter). Harder to audit than standalone executables. Common malware technique.",
                        severity: .high,
                        riskPoints: 15,
                        tags: ["Script", "Obfuscation"]
                    )
                } else {
                    return BehavioralAnomaly(
                        type: .scriptBasedPersistence,
                        title: "Script-Based Persistence",
                        description: "Persistence uses \(interpreter) interpreter. Script-based persistence is easier to modify without detection.",
                        severity: .low,
                        riskPoints: 5,
                        tags: ["Script", "Interpreter"]
                    )
                }
            }
        }

        return nil
    }

    /// Hidden From User - processes designed to avoid user detection
    private func checkHiddenFromUser(_ item: PersistenceItem) -> BehavioralAnomaly? {
        let nameLower = item.name.lowercased()

        // Check for names that try to look like system processes
        let systemImpersonation = ["system", "apple", "com.apple", "macos", "darwin", "kernel", "core"]

        for sysName in systemImpersonation {
            if nameLower.contains(sysName) && item.signatureInfo?.isAppleSigned != true {
                return BehavioralAnomaly(
                    type: .hiddenFromUser,
                    title: "System Process Impersonation",
                    description: "Non-Apple item using system-like naming. May be attempting to blend in with legitimate system processes.",
                    severity: .high,
                    riskPoints: 15,
                    tags: ["Impersonation", "Evasion"]
                )
            }
        }

        return nil
    }

    /// Frequent Restart Pattern - very low StartInterval
    private func checkFrequentRestart(_ item: PersistenceItem) -> BehavioralAnomaly? {
        if let interval = item.startInterval, interval < 60 {
            return BehavioralAnomaly(
                type: .frequentRestart,
                title: "Frequent Restart Pattern",
                description: "StartInterval of \(interval) seconds. Very frequent execution may indicate watchdog behavior or polling for C2 commands.",
                severity: .medium,
                riskPoints: 10,
                tags: ["Frequency", "Watchdog"]
            )
        }

        return nil
    }

    // MARK: - Helpers

    private func calculateOverallSeverity(_ anomalies: [BehavioralAnomaly]) -> Severity {
        if anomalies.isEmpty { return .low }

        if anomalies.contains(where: { $0.severity == .critical }) {
            return .critical
        } else if anomalies.contains(where: { $0.severity == .high }) {
            return .high
        } else if anomalies.contains(where: { $0.severity == .medium }) {
            return .medium
        }
        return .low
    }
}
