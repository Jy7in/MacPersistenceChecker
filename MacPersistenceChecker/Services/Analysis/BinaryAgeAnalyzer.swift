import Foundation

/// Binary Age vs Persistence Age Analyzer
/// Detects suspicious timestamp patterns that indicate post-install malicious updates
/// Pattern: old plist + newly created binary = classic "malicious update post-install"
final class BinaryAgeAnalyzer {

    static let shared = BinaryAgeAnalyzer()

    // MARK: - Age Anomaly Types

    struct AgeAnomaly: Identifiable {
        let id = UUID()
        let type: AnomalyType
        let title: String
        let description: String
        let severity: Severity
        let riskPoints: Int
        let plistAge: String
        let binaryAge: String
        let timeDifference: String
    }

    enum AnomalyType: String {
        case oldPlistNewBinary = "Old Plist, New Binary"
        case binaryNewerThanNotarization = "Binary Newer Than Notarization"
        case silentBinarySwap = "Silent Binary Swap"
        case recentBinaryOldPlist = "Recent Binary, Old Plist"
        case mismatchedTimestamps = "Mismatched Timestamps"
        case suspiciousModificationTime = "Suspicious Modification Time"
        case binaryModifiedAfterInstall = "Binary Modified After Install"
    }

    enum Severity: String {
        case low = "Low"
        case medium = "Medium"
        case high = "High"
        case critical = "Critical"

        var points: Int {
            switch self {
            case .low: return 5
            case .medium: return 10
            case .high: return 15
            case .critical: return 20
            }
        }
    }

    // MARK: - Thresholds

    /// Days threshold for considering something "old" vs "new"
    private let oldThresholdDays: Double = 30
    /// Days threshold for recent modifications
    private let recentThresholdDays: Double = 7
    /// Hours threshold for very recent (suspicious) modifications
    private let veryRecentThresholdHours: Double = 24
    /// Notarization typically happens close to build time
    private let notarizationWindowDays: Double = 7

    // MARK: - Analysis

    struct AgeAnalysisResult {
        let hasAnomalies: Bool
        let anomalies: [AgeAnomaly]
        let overallSeverity: Severity
        let totalRiskPoints: Int
        let summary: String
    }

    /// Analyze a persistence item for age-related anomalies
    func analyze(_ item: PersistenceItem) -> AgeAnalysisResult {
        var anomalies: [AgeAnomaly] = []

        let now = Date()

        // Get timestamps
        let plistCreated = item.plistCreatedAt
        let plistModified = item.plistModifiedAt
        let binaryCreated = item.binaryCreatedAt
        let binaryModified = item.binaryModifiedAt

        // Check various anomaly patterns
        if let anomaly = checkOldPlistNewBinary(plistCreated: plistCreated, binaryCreated: binaryCreated, now: now) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkSilentBinarySwap(plistModified: plistModified, binaryModified: binaryModified, now: now) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkRecentBinaryOldPlist(plistCreated: plistCreated, binaryCreated: binaryCreated, now: now) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkMismatchedTimestamps(plistCreated: plistCreated, plistModified: plistModified, binaryCreated: binaryCreated, binaryModified: binaryModified) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkSuspiciousModificationTime(binaryModified: binaryModified, now: now) {
            anomalies.append(anomaly)
        }

        if let anomaly = checkBinaryModifiedAfterInstall(plistCreated: plistCreated, binaryModified: binaryModified, item: item) {
            anomalies.append(anomaly)
        }

        // Calculate overall severity
        let overallSeverity = calculateOverallSeverity(anomalies)
        let totalRiskPoints = anomalies.reduce(0) { $0 + $1.riskPoints }

        let summary: String
        if anomalies.isEmpty {
            summary = "No age-related anomalies detected"
        } else {
            summary = "Suspicious timestamp pattern detected - possible binary swap or post-install modification"
        }

        return AgeAnalysisResult(
            hasAnomalies: !anomalies.isEmpty,
            anomalies: anomalies,
            overallSeverity: overallSeverity,
            totalRiskPoints: totalRiskPoints,
            summary: summary
        )
    }

    // MARK: - Anomaly Checks

    /// Old plist + newly created binary = classic malicious update pattern
    private func checkOldPlistNewBinary(plistCreated: Date?, binaryCreated: Date?, now: Date) -> AgeAnomaly? {
        guard let plistDate = plistCreated, let binaryDate = binaryCreated else { return nil }

        let plistAgeDays = now.timeIntervalSince(plistDate) / 86400
        let binaryAgeDays = now.timeIntervalSince(binaryDate) / 86400

        // Plist is old (> 30 days) but binary is new (< 7 days)
        if plistAgeDays > oldThresholdDays && binaryAgeDays < recentThresholdDays {
            let daysDiff = Int(plistAgeDays - binaryAgeDays)

            return AgeAnomaly(
                type: .oldPlistNewBinary,
                title: "Old Plist, New Binary",
                description: "The persistence plist was created \(Int(plistAgeDays)) days ago, but the binary is only \(Int(binaryAgeDays)) days old. This is a classic 'malicious update post-install' pattern where malware replaces a legitimate binary with a malicious one.",
                severity: .critical,
                riskPoints: 25,
                plistAge: formatAge(plistDate),
                binaryAge: formatAge(binaryDate),
                timeDifference: "\(daysDiff) days difference"
            )
        }

        return nil
    }

    /// Binary was modified recently while plist wasn't = silent swap
    private func checkSilentBinarySwap(plistModified: Date?, binaryModified: Date?, now: Date) -> AgeAnomaly? {
        guard let binaryMod = binaryModified else { return nil }

        let binaryModAgeDays = now.timeIntervalSince(binaryMod) / 86400

        // Binary modified very recently
        if binaryModAgeDays < recentThresholdDays {
            // If plist wasn't modified or was modified much earlier
            if let plistMod = plistModified {
                let plistModAgeDays = now.timeIntervalSince(plistMod) / 86400

                // Plist modified > 30 days ago but binary modified < 7 days ago
                if plistModAgeDays > oldThresholdDays {
                    return AgeAnomaly(
                        type: .silentBinarySwap,
                        title: "Silent Binary Swap",
                        description: "Binary was modified recently (\(Int(binaryModAgeDays)) days ago) but plist hasn't changed in \(Int(plistModAgeDays)) days. This suggests the binary was silently replaced without updating the configuration - a common malware tactic.",
                        severity: .critical,
                        riskPoints: 25,
                        plistAge: "Modified \(Int(plistModAgeDays)) days ago",
                        binaryAge: "Modified \(Int(binaryModAgeDays)) days ago",
                        timeDifference: "Binary updated without plist change"
                    )
                }
            }
        }

        return nil
    }

    /// Recent binary with very old plist (general pattern)
    private func checkRecentBinaryOldPlist(plistCreated: Date?, binaryCreated: Date?, now: Date) -> AgeAnomaly? {
        guard let plistDate = plistCreated, let binaryDate = binaryCreated else { return nil }

        let plistAgeDays = now.timeIntervalSince(plistDate) / 86400
        let binaryAgeDays = now.timeIntervalSince(binaryDate) / 86400

        // Very large age difference (> 90 days) is suspicious
        let ageDifference = plistAgeDays - binaryAgeDays

        if ageDifference > 90 {
            return AgeAnomaly(
                type: .recentBinaryOldPlist,
                title: "Significant Age Mismatch",
                description: "There's a \(Int(ageDifference)) day gap between plist creation and binary creation. While legitimate updates can cause this, such large gaps warrant investigation.",
                severity: .medium,
                riskPoints: 10,
                plistAge: formatAge(plistDate),
                binaryAge: formatAge(binaryDate),
                timeDifference: "\(Int(ageDifference)) days gap"
            )
        }

        return nil
    }

    /// Check for mismatched creation/modification timestamps
    private func checkMismatchedTimestamps(plistCreated: Date?, plistModified: Date?, binaryCreated: Date?, binaryModified: Date?) -> AgeAnomaly? {
        // Binary modified before it was created (timestamp manipulation)
        if let created = binaryCreated, let modified = binaryModified {
            if modified < created {
                return AgeAnomaly(
                    type: .mismatchedTimestamps,
                    title: "Timestamp Manipulation Detected",
                    description: "Binary's modification date is before its creation date. This indicates timestamp manipulation, a technique used by malware to appear legitimate or hide recent changes.",
                    severity: .critical,
                    riskPoints: 30,
                    plistAge: "N/A",
                    binaryAge: "Created: \(formatDate(created)), Modified: \(formatDate(modified))",
                    timeDifference: "Impossible timestamp (modified before created)"
                )
            }
        }

        return nil
    }

    /// Check for modifications during suspicious hours (late night)
    private func checkSuspiciousModificationTime(binaryModified: Date?, now: Date) -> AgeAnomaly? {
        guard let modDate = binaryModified else { return nil }

        let calendar = Calendar.current
        let hour = calendar.component(.hour, from: modDate)
        let daysSinceModification = now.timeIntervalSince(modDate) / 86400

        // Modified very recently AND during suspicious hours (2 AM - 5 AM)
        if daysSinceModification < recentThresholdDays && (hour >= 2 && hour <= 5) {
            return AgeAnomaly(
                type: .suspiciousModificationTime,
                title: "Suspicious Modification Time",
                description: "Binary was modified at \(hour):00 (late night/early morning). Malware often performs modifications during hours when users are unlikely to notice. This is especially suspicious for recently modified binaries.",
                severity: .medium,
                riskPoints: 10,
                plistAge: "N/A",
                binaryAge: formatAge(modDate),
                timeDifference: "Modified at \(hour):00"
            )
        }

        return nil
    }

    /// Binary modified significantly after initial install
    private func checkBinaryModifiedAfterInstall(plistCreated: Date?, binaryModified: Date?, item: PersistenceItem) -> AgeAnomaly? {
        guard let plistDate = plistCreated, let binaryMod = binaryModified else { return nil }

        // Binary modified more than 7 days after plist was created
        let daysSincePlist = binaryMod.timeIntervalSince(plistDate) / 86400

        if daysSincePlist > notarizationWindowDays {
            // Only flag if this isn't obviously an updater
            let nameLower = item.name.lowercased()
            if !nameLower.contains("update") && !nameLower.contains("upgrade") {
                return AgeAnomaly(
                    type: .binaryModifiedAfterInstall,
                    title: "Binary Modified Post-Install",
                    description: "Binary was modified \(Int(daysSincePlist)) days after initial installation (plist creation). For non-updater services, this could indicate a malicious binary replacement.",
                    severity: .high,
                    riskPoints: 15,
                    plistAge: formatAge(plistDate),
                    binaryAge: "Modified \(formatAge(binaryMod))",
                    timeDifference: "\(Int(daysSincePlist)) days after install"
                )
            }
        }

        return nil
    }

    // MARK: - Helpers

    private func formatAge(_ date: Date) -> String {
        let days = Date().timeIntervalSince(date) / 86400

        if days < 1 {
            let hours = Date().timeIntervalSince(date) / 3600
            return "\(Int(hours)) hours ago"
        } else if days < 7 {
            return "\(Int(days)) days ago"
        } else if days < 30 {
            let weeks = Int(days / 7)
            return "\(weeks) week\(weeks > 1 ? "s" : "") ago"
        } else if days < 365 {
            let months = Int(days / 30)
            return "\(months) month\(months > 1 ? "s" : "") ago"
        } else {
            let years = Int(days / 365)
            return "\(years) year\(years > 1 ? "s" : "") ago"
        }
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    private func calculateOverallSeverity(_ anomalies: [AgeAnomaly]) -> Severity {
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
