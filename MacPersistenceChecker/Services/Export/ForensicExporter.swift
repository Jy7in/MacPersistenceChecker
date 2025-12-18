import Foundation

/// Forensic JSON Exporter
/// Generates machine-readable JSON for SIEM, SOAR, LLM, and IR pipelines
final class ForensicExporter {

    static let shared = ForensicExporter()

    // MARK: - Export Structure

    struct ForensicReport: Codable {
        let metadata: ReportMetadata
        let summary: ScanSummary
        let items: [ForensicItem]
        let riskAnalysis: RiskAnalysis
        let timeline: [TimelineEvent]
    }

    struct ReportMetadata: Codable {
        let exportVersion: String
        let exportTimestamp: String
        let exportTimestampUnix: Int64
        let hostname: String
        let macosVersion: String
        let hardwareModel: String
        let serialNumber: String?
        let toolName: String
        let toolVersion: String
    }

    struct ScanSummary: Codable {
        let totalItems: Int
        let itemsByCategory: [String: Int]
        let itemsByTrustLevel: [String: Int]
        let itemsByRiskSeverity: [String: Int]
        let criticalItems: Int
        let highRiskItems: Int
        let unsignedItems: Int
        let suspiciousItems: Int
    }

    struct ForensicItem: Codable {
        // Identity
        let id: String
        let identifier: String
        let name: String
        let category: String
        let categoryDescription: String

        // Paths
        let plistPath: String?
        let executablePath: String?
        let parentAppPath: String?

        // State
        let isEnabled: Bool
        let isLoaded: Bool
        let executableExists: Bool
        let configFileExists: Bool

        // Trust & Signature
        let trustLevel: String
        let trustLevelDescription: String
        let signature: SignatureDetails?

        // Launch Configuration
        let launchConfig: LaunchConfiguration?

        // Risk Assessment
        let riskScore: Int
        let riskSeverity: String
        let riskFactors: [RiskFactor]

        // LOLBins
        let lolbinsDetections: [LOLBinDetail]?
        let lolbinsTotalRisk: Int?

        // Behavioral Analysis
        let behavioralAnomalies: [BehavioralAnomalyDetail]?
        let behavioralSeverity: String?
        let behavioralRiskPoints: Int?

        // Intent Mismatch
        let intentMismatches: [IntentMismatchDetail]?
        let intentMismatchSeverity: String?
        let intentMismatchRiskPoints: Int?

        // Age Analysis
        let ageAnomalies: [AgeAnomalyDetail]?
        let ageAnomalySeverity: String?
        let ageAnomalyRiskPoints: Int?

        // Signed-but-Dangerous
        let signedButDangerousFlags: [SignedDangerousDetail]?
        let signedButDangerousRisk: String?

        // Timestamps
        let timestamps: ItemTimestamps

        // MITRE ATT&CK
        let mitreTactics: [String]
        let mitreTechniques: [MITRETechniqueDetail]
    }

    struct SignatureDetails: Codable {
        let isSigned: Bool
        let isValid: Bool
        let isAppleSigned: Bool
        let isNotarized: Bool
        let hasHardenedRuntime: Bool
        let teamIdentifier: String?
        let bundleIdentifier: String?
        let commonName: String?
        let organizationName: String?
        let signingAuthority: String?
        let certificateExpiration: String?
        let isCertificateExpired: Bool
    }

    struct LaunchConfiguration: Codable {
        let runAtLoad: Bool?
        let keepAlive: Bool?
        let startInterval: Int?
        let throttleInterval: Int?
        let programArguments: [String]?
        let workingDirectory: String?
        let environmentVariables: [String: String]?
        let standardOutPath: String?
        let standardErrorPath: String?
    }

    struct RiskFactor: Codable {
        let factor: String
        let description: String
        let points: Int
    }

    struct LOLBinDetail: Codable {
        let binary: String
        let category: String
        let severity: String
        let description: String
        let reason: String
        let mitreTechnique: String?
        let riskPoints: Int
    }

    struct BehavioralAnomalyDetail: Codable {
        let type: String
        let title: String
        let description: String
        let severity: String
        let riskPoints: Int
        let tags: [String]
    }

    struct IntentMismatchDetail: Codable {
        let type: String
        let title: String
        let description: String
        let severity: String
        let riskPoints: Int
        let plistIntent: String
        let binaryReality: String
    }

    struct AgeAnomalyDetail: Codable {
        let type: String
        let title: String
        let description: String
        let severity: String
        let riskPoints: Int
        let plistAge: String
        let binaryAge: String
        let timeDifference: String
    }

    struct SignedDangerousDetail: Codable {
        let type: String
        let title: String
        let description: String
        let severity: String
        let points: Int
    }

    struct ItemTimestamps: Codable {
        let plistCreated: String?
        let plistModified: String?
        let binaryCreated: String?
        let binaryModified: String?
        let binaryLastExecuted: String?
        let discoveredAt: String
    }

    struct MITRETechniqueDetail: Codable {
        let id: String
        let name: String
        let description: String
        let url: String
    }

    struct RiskAnalysis: Codable {
        let overallRiskScore: Double
        let riskDistribution: [String: Int]
        let topRiskFactors: [TopRiskFactor]
        let criticalFindings: [CriticalFinding]
    }

    struct TopRiskFactor: Codable {
        let factor: String
        let occurrences: Int
        let totalPoints: Int
    }

    struct CriticalFinding: Codable {
        let itemIdentifier: String
        let itemName: String
        let finding: String
        let severity: String
        let recommendation: String
    }

    struct TimelineEvent: Codable {
        let timestamp: String
        let timestampUnix: Int64
        let eventType: String
        let itemIdentifier: String
        let itemName: String
        let description: String
    }

    // MARK: - Export Methods

    /// Generate forensic JSON report from persistence items
    func generateReport(items: [PersistenceItem]) -> ForensicReport {
        let metadata = generateMetadata()
        let summary = generateSummary(items: items)
        let forensicItems = items.map { convertToForensicItem($0) }
        let riskAnalysis = generateRiskAnalysis(items: items)
        let timeline = generateTimeline(items: items)

        return ForensicReport(
            metadata: metadata,
            summary: summary,
            items: forensicItems,
            riskAnalysis: riskAnalysis,
            timeline: timeline
        )
    }

    /// Export to JSON string
    func exportToJSON(items: [PersistenceItem], prettyPrint: Bool = true) -> String? {
        let report = generateReport(items: items)

        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrint ? [.prettyPrinted, .sortedKeys] : .sortedKeys
        encoder.dateEncodingStrategy = .iso8601

        do {
            let data = try encoder.encode(report)
            return String(data: data, encoding: .utf8)
        } catch {
            print("Failed to encode forensic report: \(error)")
            return nil
        }
    }

    /// Export to file
    func exportToFile(items: [PersistenceItem], url: URL) throws {
        guard let json = exportToJSON(items: items) else {
            throw ExportError.encodingFailed
        }

        try json.write(to: url, atomically: true, encoding: .utf8)
    }

    // MARK: - Private Methods

    private func generateMetadata() -> ReportMetadata {
        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        let hostname = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString

        // Get hardware model
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        let hardwareModel = String(cString: model)

        // Get serial number (may fail without proper entitlements)
        let serialNumber = getSerialNumber()

        return ReportMetadata(
            exportVersion: "1.0",
            exportTimestamp: dateFormatter.string(from: Date()),
            exportTimestampUnix: Int64(Date().timeIntervalSince1970),
            hostname: hostname,
            macosVersion: osVersion,
            hardwareModel: hardwareModel,
            serialNumber: serialNumber,
            toolName: "MacPersistenceChecker",
            toolVersion: "1.8"
        )
    }

    private func getSerialNumber() -> String? {
        let platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard platformExpert > 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }

        guard let serialNumberAsCFString = IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0)?.takeUnretainedValue() as? String else {
            return nil
        }
        return serialNumberAsCFString
    }

    private func generateSummary(items: [PersistenceItem]) -> ScanSummary {
        var categoryCount: [String: Int] = [:]
        var trustCount: [String: Int] = [:]
        var riskCount: [String: Int] = [:]
        var criticalCount = 0
        var highRiskCount = 0
        var unsignedCount = 0
        var suspiciousCount = 0

        for item in items {
            // Category
            categoryCount[item.category.rawValue, default: 0] += 1

            // Trust level
            trustCount[item.trustLevel.rawValue, default: 0] += 1

            // Risk severity
            let severity = RiskScorer.RiskSeverity.from(score: item.riskScore ?? 0)
            riskCount[severity.rawValue, default: 0] += 1

            if severity == .critical { criticalCount += 1 }
            if severity == .high || severity == .critical { highRiskCount += 1 }
            if item.trustLevel == .unsigned { unsignedCount += 1 }
            if item.trustLevel == .suspicious { suspiciousCount += 1 }
        }

        return ScanSummary(
            totalItems: items.count,
            itemsByCategory: categoryCount,
            itemsByTrustLevel: trustCount,
            itemsByRiskSeverity: riskCount,
            criticalItems: criticalCount,
            highRiskItems: highRiskCount,
            unsignedItems: unsignedCount,
            suspiciousItems: suspiciousCount
        )
    }

    private func convertToForensicItem(_ item: PersistenceItem) -> ForensicItem {
        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        // Signature details
        var signatureDetails: SignatureDetails? = nil
        if let sig = item.signatureInfo {
            signatureDetails = SignatureDetails(
                isSigned: sig.isSigned,
                isValid: sig.isValid,
                isAppleSigned: sig.isAppleSigned,
                isNotarized: sig.isNotarized,
                hasHardenedRuntime: sig.hasHardenedRuntime,
                teamIdentifier: sig.teamIdentifier,
                bundleIdentifier: sig.bundleIdentifier,
                commonName: sig.commonName,
                organizationName: sig.organizationName,
                signingAuthority: sig.signingAuthority,
                certificateExpiration: sig.certificateExpirationDate.map { dateFormatter.string(from: $0) },
                isCertificateExpired: sig.isCertificateExpired
            )
        }

        // Launch config
        var launchConfig: LaunchConfiguration? = nil
        if item.category == .launchDaemons || item.category == .launchAgents {
            launchConfig = LaunchConfiguration(
                runAtLoad: item.runAtLoad,
                keepAlive: item.keepAlive,
                startInterval: item.startInterval,
                throttleInterval: item.throttleInterval,
                programArguments: item.programArguments,
                workingDirectory: item.workingDirectory,
                environmentVariables: item.environmentVariables,
                standardOutPath: item.standardOutPath,
                standardErrorPath: item.standardErrorPath
            )
        }

        // Risk factors
        let riskFactors = (item.riskDetails ?? []).map { detail in
            RiskFactor(factor: detail.factor, description: detail.description, points: detail.points)
        }

        // LOLBins
        let lolbins = item.lolbinsDetections?.map { detection in
            LOLBinDetail(
                binary: detection.binary,
                category: detection.category,
                severity: detection.severity,
                description: detection.description,
                reason: detection.reason,
                mitreTechnique: detection.mitreTechnique,
                riskPoints: detection.riskPoints
            )
        }

        // Behavioral anomalies
        let behavioral = item.behavioralAnomalies?.map { anomaly in
            BehavioralAnomalyDetail(
                type: anomaly.type,
                title: anomaly.title,
                description: anomaly.description,
                severity: anomaly.severity,
                riskPoints: anomaly.riskPoints,
                tags: anomaly.tags
            )
        }

        // Intent mismatches
        let intentMismatches = item.intentMismatches?.map { mismatch in
            IntentMismatchDetail(
                type: mismatch.type,
                title: mismatch.title,
                description: mismatch.description,
                severity: mismatch.severity,
                riskPoints: mismatch.riskPoints,
                plistIntent: mismatch.plistIntent,
                binaryReality: mismatch.binaryReality
            )
        }

        // Age anomalies
        let ageAnomalies = item.ageAnomalies?.map { anomaly in
            AgeAnomalyDetail(
                type: anomaly.type,
                title: anomaly.title,
                description: anomaly.description,
                severity: anomaly.severity,
                riskPoints: anomaly.riskPoints,
                plistAge: anomaly.plistAge,
                binaryAge: anomaly.binaryAge,
                timeDifference: anomaly.timeDifference
            )
        }

        // Signed-but-dangerous
        let signedDangerous = item.signedButDangerousFlags?.map { flag in
            SignedDangerousDetail(
                type: flag.type,
                title: flag.title,
                description: flag.description,
                severity: flag.severity,
                points: flag.points
            )
        }

        // Timestamps
        let timestamps = ItemTimestamps(
            plistCreated: item.plistCreatedAt.map { dateFormatter.string(from: $0) },
            plistModified: item.plistModifiedAt.map { dateFormatter.string(from: $0) },
            binaryCreated: item.binaryCreatedAt.map { dateFormatter.string(from: $0) },
            binaryModified: item.binaryModifiedAt.map { dateFormatter.string(from: $0) },
            binaryLastExecuted: item.binaryLastExecutedAt.map { dateFormatter.string(from: $0) },
            discoveredAt: dateFormatter.string(from: item.discoveredAt)
        )

        // MITRE
        let mitreTechniques = item.category.mitreTechniques.map { technique in
            MITRETechniqueDetail(
                id: technique.id,
                name: technique.name,
                description: technique.description,
                url: technique.url.absoluteString
            )
        }

        return ForensicItem(
            id: item.id.uuidString,
            identifier: item.identifier,
            name: item.name,
            category: item.category.rawValue,
            categoryDescription: item.category.displayName,
            plistPath: item.plistPath?.path,
            executablePath: item.executablePath?.path,
            parentAppPath: item.parentAppPath?.path,
            isEnabled: item.isEnabled,
            isLoaded: item.isLoaded,
            executableExists: item.executableExists,
            configFileExists: item.configFileExists,
            trustLevel: item.trustLevel.rawValue,
            trustLevelDescription: item.trustLevel.description,
            signature: signatureDetails,
            launchConfig: launchConfig,
            riskScore: item.riskScore ?? 0,
            riskSeverity: RiskScorer.RiskSeverity.from(score: item.riskScore ?? 0).rawValue,
            riskFactors: riskFactors,
            lolbinsDetections: lolbins,
            lolbinsTotalRisk: item.lolbinsRisk,
            behavioralAnomalies: behavioral,
            behavioralSeverity: item.behavioralSeverity,
            behavioralRiskPoints: item.behavioralRiskPoints,
            intentMismatches: intentMismatches,
            intentMismatchSeverity: item.intentMismatchSeverity,
            intentMismatchRiskPoints: item.intentMismatchRiskPoints,
            ageAnomalies: ageAnomalies,
            ageAnomalySeverity: item.ageAnomalySeverity,
            ageAnomalyRiskPoints: item.ageAnomalyRiskPoints,
            signedButDangerousFlags: signedDangerous,
            signedButDangerousRisk: item.signedButDangerousRisk,
            timestamps: timestamps,
            mitreTactics: item.category.mitreTactics.map { $0.rawValue },
            mitreTechniques: mitreTechniques
        )
    }

    private func generateRiskAnalysis(items: [PersistenceItem]) -> RiskAnalysis {
        // Calculate overall risk
        let scores = items.compactMap { $0.riskScore }
        let overallScore = scores.isEmpty ? 0 : Double(scores.reduce(0, +)) / Double(scores.count)

        // Risk distribution
        var distribution: [String: Int] = ["Low": 0, "Medium": 0, "High": 0, "Critical": 0]
        for item in items {
            let severity = RiskScorer.RiskSeverity.from(score: item.riskScore ?? 0)
            distribution[severity.rawValue, default: 0] += 1
        }

        // Top risk factors
        var factorCounts: [String: (count: Int, points: Int)] = [:]
        for item in items {
            for detail in item.riskDetails ?? [] {
                let existing = factorCounts[detail.factor] ?? (0, 0)
                factorCounts[detail.factor] = (existing.count + 1, existing.points + detail.points)
            }
        }
        let topFactors = factorCounts.map { TopRiskFactor(factor: $0.key, occurrences: $0.value.count, totalPoints: $0.value.points) }
            .sorted { $0.totalPoints > $1.totalPoints }
            .prefix(10)
            .map { $0 }

        // Critical findings
        var criticalFindings: [CriticalFinding] = []
        for item in items {
            let severity = RiskScorer.RiskSeverity.from(score: item.riskScore ?? 0)
            if severity == .critical || severity == .high {
                var finding = "High risk persistence item"
                var recommendation = "Investigate this item and consider removal if not needed"

                if item.trustLevel == .unsigned {
                    finding = "Unsigned persistence item with high risk score"
                    recommendation = "This item lacks code signature - verify its legitimacy or remove"
                } else if item.lolbinsDetections?.isEmpty == false {
                    finding = "LOLBin usage detected in persistence context"
                    recommendation = "Review why legitimate system binaries are being used for persistence"
                } else if item.intentMismatches?.isEmpty == false {
                    finding = "Plist/binary intent mismatch detected"
                    recommendation = "Binary capabilities don't match declared purpose - possible dropper"
                } else if item.ageAnomalies?.isEmpty == false {
                    finding = "Suspicious timestamp pattern detected"
                    recommendation = "Binary may have been swapped after installation - verify integrity"
                }

                criticalFindings.append(CriticalFinding(
                    itemIdentifier: item.identifier,
                    itemName: item.name,
                    finding: finding,
                    severity: severity.rawValue,
                    recommendation: recommendation
                ))
            }
        }

        return RiskAnalysis(
            overallRiskScore: overallScore,
            riskDistribution: distribution,
            topRiskFactors: Array(topFactors),
            criticalFindings: criticalFindings
        )
    }

    private func generateTimeline(items: [PersistenceItem]) -> [TimelineEvent] {
        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        var events: [TimelineEvent] = []

        for item in items {
            // Plist created
            if let date = item.plistCreatedAt {
                events.append(TimelineEvent(
                    timestamp: dateFormatter.string(from: date),
                    timestampUnix: Int64(date.timeIntervalSince1970),
                    eventType: "plist_created",
                    itemIdentifier: item.identifier,
                    itemName: item.name,
                    description: "Persistence configuration created"
                ))
            }

            // Binary created
            if let date = item.binaryCreatedAt {
                events.append(TimelineEvent(
                    timestamp: dateFormatter.string(from: date),
                    timestampUnix: Int64(date.timeIntervalSince1970),
                    eventType: "binary_created",
                    itemIdentifier: item.identifier,
                    itemName: item.name,
                    description: "Executable binary created"
                ))
            }

            // Binary modified
            if let date = item.binaryModifiedAt {
                events.append(TimelineEvent(
                    timestamp: dateFormatter.string(from: date),
                    timestampUnix: Int64(date.timeIntervalSince1970),
                    eventType: "binary_modified",
                    itemIdentifier: item.identifier,
                    itemName: item.name,
                    description: "Executable binary modified"
                ))
            }

            // Binary executed
            if let date = item.binaryLastExecutedAt {
                events.append(TimelineEvent(
                    timestamp: dateFormatter.string(from: date),
                    timestampUnix: Int64(date.timeIntervalSince1970),
                    eventType: "binary_executed",
                    itemIdentifier: item.identifier,
                    itemName: item.name,
                    description: "Executable was run"
                ))
            }

            // Discovered
            events.append(TimelineEvent(
                timestamp: dateFormatter.string(from: item.discoveredAt),
                timestampUnix: Int64(item.discoveredAt.timeIntervalSince1970),
                eventType: "discovered",
                itemIdentifier: item.identifier,
                itemName: item.name,
                description: "Item discovered by scan"
            ))
        }

        // Sort by timestamp
        return events.sorted { $0.timestampUnix < $1.timestampUnix }
    }

    // MARK: - Errors

    enum ExportError: Error, LocalizedError {
        case encodingFailed
        case writeFailed
        case noData

        var errorDescription: String? {
            switch self {
            case .encodingFailed: return "Failed to encode report to JSON"
            case .writeFailed: return "Failed to write file"
            case .noData: return "No scan data available"
            }
        }
    }
}
