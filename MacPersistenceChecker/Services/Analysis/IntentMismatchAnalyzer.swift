import Foundation

/// Executable vs Plist Intent Mismatch Analyzer
/// Detects when what the plist declares doesn't match what the binary actually does
/// This is exactly what modern droppers do: innocent-looking plist → heavy binary
final class IntentMismatchAnalyzer {

    static let shared = IntentMismatchAnalyzer()

    // MARK: - Mismatch Types

    struct IntentMismatch: Identifiable {
        let id = UUID()
        let type: MismatchType
        let title: String
        let description: String
        let severity: Severity
        let riskPoints: Int
        let plistIntent: String
        let binaryReality: String
    }

    enum MismatchType: String {
        case innocentPlistHeavyBinary = "Innocent Plist, Heavy Binary"
        case passiveHelperWithNetwork = "Passive Helper with Network"
        case passiveHelperWithDylib = "Passive Helper with Dylib Loading"
        case minimalPlistFullEntitlements = "Minimal Plist, Full Entitlements"
        case backgroundAgentWithGUI = "Background Agent with GUI Access"
        case simpleTaskWithKeychain = "Simple Task with Keychain Access"
        case helperWithShellExecution = "Helper with Shell Execution"
        case watchdogWithDataAccess = "Watchdog with Data Access"
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

    // MARK: - Heavy Entitlements (suspicious when plist looks innocent)

    private let heavyEntitlements: [String: (description: String, severity: Severity)] = [
        // Network
        "com.apple.security.network.client": ("Network client access", .medium),
        "com.apple.security.network.server": ("Network server access", .high),

        // File system
        "com.apple.security.files.all": ("Full file system access", .critical),
        "com.apple.security.files.user-selected.read-write": ("User file access", .medium),
        "com.apple.security.temporary-exception.files.absolute-path.read-write": ("Absolute path file access", .high),

        // Keychain
        "keychain-access-groups": ("Keychain access", .high),
        "com.apple.security.keychain": ("Keychain access", .high),

        // Automation
        "com.apple.security.automation.apple-events": ("Apple Events automation", .high),
        "com.apple.security.scripting-targets": ("Scripting targets", .high),

        // System
        "com.apple.security.cs.allow-unsigned-executable-memory": ("Unsigned executable memory", .critical),
        "com.apple.security.cs.disable-library-validation": ("Disabled library validation", .critical),
        "com.apple.security.cs.allow-dyld-environment-variables": ("DYLD environment variables", .critical),
        "com.apple.security.get-task-allow": ("Task port access (debugging)", .high),

        // Privacy
        "com.apple.security.personal-information.location": ("Location access", .medium),
        "com.apple.security.personal-information.addressbook": ("Contacts access", .medium),
        "com.apple.security.personal-information.calendars": ("Calendar access", .medium),
        "com.apple.security.personal-information.photos-library": ("Photos access", .medium),

        // Device
        "com.apple.security.device.camera": ("Camera access", .medium),
        "com.apple.security.device.microphone": ("Microphone access", .high),
        "com.apple.security.device.usb": ("USB access", .medium),

        // TCC
        "com.apple.private.tcc.allow": ("TCC bypass", .critical),
        "com.apple.private.tcc.manager": ("TCC management", .critical),

        // Mach
        "com.apple.security.temporary-exception.mach-lookup.global-name": ("Mach service lookup", .medium),
        "com.apple.security.temporary-exception.mach-register.global-name": ("Mach service registration", .high),
    ]

    // MARK: - Analysis

    struct MismatchResult {
        let hasMismatches: Bool
        let mismatches: [IntentMismatch]
        let overallSeverity: Severity
        let totalRiskPoints: Int
        let summary: String
    }

    /// Analyze a persistence item for intent mismatches
    func analyze(_ item: PersistenceItem, entitlements: [String: Any]?) -> MismatchResult {
        var mismatches: [IntentMismatch] = []

        // Get plist "intent" profile
        let plistProfile = analyzePlistIntent(item)

        // Get binary "reality" profile
        let binaryProfile = analyzeBinaryReality(item, entitlements: entitlements)

        // Check for mismatches
        mismatches.append(contentsOf: checkInnocentPlistHeavyBinary(plistProfile: plistProfile, binaryProfile: binaryProfile, item: item))
        mismatches.append(contentsOf: checkPassiveHelperWithNetwork(plistProfile: plistProfile, binaryProfile: binaryProfile, item: item))
        mismatches.append(contentsOf: checkPassiveHelperWithDylib(plistProfile: plistProfile, binaryProfile: binaryProfile, item: item))
        mismatches.append(contentsOf: checkMinimalPlistFullEntitlements(plistProfile: plistProfile, binaryProfile: binaryProfile, item: item, entitlements: entitlements))

        // Calculate overall severity
        let overallSeverity = calculateOverallSeverity(mismatches)
        let totalRiskPoints = mismatches.reduce(0) { $0 + $1.riskPoints }

        let summary: String
        if mismatches.isEmpty {
            summary = "No intent mismatches detected"
        } else {
            summary = "Intent mismatch detected - plist declares one thing, binary does another"
        }

        return MismatchResult(
            hasMismatches: !mismatches.isEmpty,
            mismatches: mismatches,
            overallSeverity: overallSeverity,
            totalRiskPoints: totalRiskPoints,
            summary: summary
        )
    }

    // MARK: - Plist Intent Analysis

    struct PlistProfile {
        let isSimple: Bool           // No complex arguments, just runs a binary
        let isPassive: Bool          // No RunAtLoad, no KeepAlive
        let isWatchdog: Bool         // KeepAlive or frequent StartInterval
        let isBackgroundOnly: Bool   // Looks like background service
        let hasNetworkArgs: Bool     // Arguments contain network indicators
        let hasScriptArgs: Bool      // Arguments contain script interpreters
        let complexity: Int          // 0-10, how complex the plist looks
    }

    private func analyzePlistIntent(_ item: PersistenceItem) -> PlistProfile {
        var complexity = 0

        // Check if simple (just runs a binary with minimal args)
        let argCount = item.programArguments?.count ?? 0
        let isSimple = argCount <= 2
        if argCount > 3 { complexity += 2 }

        // Check if passive (doesn't auto-start aggressively)
        let isPassive = item.runAtLoad != true && item.keepAlive != true
        if item.runAtLoad == true { complexity += 1 }
        if item.keepAlive == true { complexity += 2 }

        // Check if watchdog
        let isWatchdog = item.keepAlive == true || (item.startInterval ?? 999999) < 300

        // Check if background only (name suggests background service)
        let nameLower = item.name.lowercased()
        let isBackgroundOnly = nameLower.contains("helper") || nameLower.contains("agent") ||
                               nameLower.contains("service") || nameLower.contains("daemon") ||
                               nameLower.contains("updater") || nameLower.contains("sync")

        // Check arguments for network indicators
        let argsJoined = (item.programArguments ?? []).joined(separator: " ").lowercased()
        let hasNetworkArgs = argsJoined.contains("http") || argsJoined.contains("url") ||
                            argsJoined.contains("curl") || argsJoined.contains("download") ||
                            argsJoined.contains("upload") || argsJoined.contains("server")
        if hasNetworkArgs { complexity += 2 }

        // Check for script interpreters in args
        let hasScriptArgs = argsJoined.contains("python") || argsJoined.contains("ruby") ||
                           argsJoined.contains("perl") || argsJoined.contains("osascript") ||
                           argsJoined.contains("bash") || argsJoined.contains("-c ")
        if hasScriptArgs { complexity += 2 }

        // Environment variables add complexity
        if let env = item.environmentVariables, !env.isEmpty {
            complexity += env.count
        }

        return PlistProfile(
            isSimple: isSimple,
            isPassive: isPassive,
            isWatchdog: isWatchdog,
            isBackgroundOnly: isBackgroundOnly,
            hasNetworkArgs: hasNetworkArgs,
            hasScriptArgs: hasScriptArgs,
            complexity: min(complexity, 10)
        )
    }

    // MARK: - Binary Reality Analysis

    struct BinaryProfile {
        let hasNetworkEntitlements: Bool
        let hasKeychainEntitlements: Bool
        let hasAutomationEntitlements: Bool
        let hasDangerousEntitlements: Bool  // disable-library-validation, etc.
        let hasPrivacyEntitlements: Bool
        let hasTCCEntitlements: Bool
        let entitlementCount: Int
        let heavyEntitlements: [(key: String, description: String, severity: Severity)]
    }

    private func analyzeBinaryReality(_ item: PersistenceItem, entitlements: [String: Any]?) -> BinaryProfile {
        guard let entitlements = entitlements else {
            return BinaryProfile(
                hasNetworkEntitlements: false,
                hasKeychainEntitlements: false,
                hasAutomationEntitlements: false,
                hasDangerousEntitlements: false,
                hasPrivacyEntitlements: false,
                hasTCCEntitlements: false,
                entitlementCount: 0,
                heavyEntitlements: []
            )
        }

        var hasNetwork = false
        var hasKeychain = false
        var hasAutomation = false
        var hasDangerous = false
        var hasPrivacy = false
        var hasTCC = false
        var heavy: [(key: String, description: String, severity: Severity)] = []

        for key in entitlements.keys {
            guard let keyStr = key as? String else { continue }

            // Check against known heavy entitlements
            if let info = heavyEntitlements[keyStr] {
                heavy.append((key: keyStr, description: info.description, severity: info.severity))
            }

            // Categorize
            if keyStr.contains("network") {
                hasNetwork = true
            }
            if keyStr.contains("keychain") {
                hasKeychain = true
            }
            if keyStr.contains("automation") || keyStr.contains("apple-events") || keyStr.contains("scripting") {
                hasAutomation = true
            }
            if keyStr.contains("disable-library-validation") || keyStr.contains("allow-unsigned") ||
               keyStr.contains("dyld-environment") || keyStr.contains("get-task-allow") {
                hasDangerous = true
            }
            if keyStr.contains("personal-information") || keyStr.contains("camera") ||
               keyStr.contains("microphone") || keyStr.contains("photos") {
                hasPrivacy = true
            }
            if keyStr.contains("tcc") {
                hasTCC = true
            }
        }

        return BinaryProfile(
            hasNetworkEntitlements: hasNetwork,
            hasKeychainEntitlements: hasKeychain,
            hasAutomationEntitlements: hasAutomation,
            hasDangerousEntitlements: hasDangerous,
            hasPrivacyEntitlements: hasPrivacy,
            hasTCCEntitlements: hasTCC,
            entitlementCount: entitlements.count,
            heavyEntitlements: heavy
        )
    }

    // MARK: - Mismatch Checks

    /// Check for innocent plist with heavy binary entitlements
    private func checkInnocentPlistHeavyBinary(plistProfile: PlistProfile, binaryProfile: BinaryProfile, item: PersistenceItem) -> [IntentMismatch] {
        var mismatches: [IntentMismatch] = []

        // Innocent plist = simple, passive, low complexity
        let innocentPlist = plistProfile.isSimple && plistProfile.complexity <= 3

        // Heavy binary = dangerous entitlements or many heavy entitlements
        let heavyBinary = binaryProfile.hasDangerousEntitlements ||
                         binaryProfile.hasTCCEntitlements ||
                         binaryProfile.heavyEntitlements.count >= 3

        if innocentPlist && heavyBinary {
            let heavyList = binaryProfile.heavyEntitlements.map { $0.description }.joined(separator: ", ")

            mismatches.append(IntentMismatch(
                type: .innocentPlistHeavyBinary,
                title: "Innocent Plist, Heavy Binary",
                description: "The plist appears simple and benign, but the binary has powerful entitlements. This is a classic dropper pattern - hide malicious capabilities behind innocent-looking configuration.",
                severity: .critical,
                riskPoints: 25,
                plistIntent: "Simple launch configuration with \(item.programArguments?.count ?? 0) arguments",
                binaryReality: "Binary has: \(heavyList.isEmpty ? "multiple heavy entitlements" : heavyList)"
            ))
        }

        return mismatches
    }

    /// Check for passive helper that opens network connections
    private func checkPassiveHelperWithNetwork(plistProfile: PlistProfile, binaryProfile: BinaryProfile, item: PersistenceItem) -> [IntentMismatch] {
        var mismatches: [IntentMismatch] = []

        // Passive helper = isPassive && isBackgroundOnly && !hasNetworkArgs
        let passiveHelper = plistProfile.isPassive && plistProfile.isBackgroundOnly && !plistProfile.hasNetworkArgs

        // But has network entitlements
        if passiveHelper && binaryProfile.hasNetworkEntitlements {
            mismatches.append(IntentMismatch(
                type: .passiveHelperWithNetwork,
                title: "Passive Helper with Network Access",
                description: "Helper declared as passive background service but has network entitlements. Legitimate helpers rarely need network access unless explicitly for sync/update purposes.",
                severity: .high,
                riskPoints: 15,
                plistIntent: "Passive background helper with no network arguments",
                binaryReality: "Binary has network client/server entitlements"
            ))
        }

        return mismatches
    }

    /// Check for passive helper that loads dynamic libraries
    private func checkPassiveHelperWithDylib(plistProfile: PlistProfile, binaryProfile: BinaryProfile, item: PersistenceItem) -> [IntentMismatch] {
        var mismatches: [IntentMismatch] = []

        let passiveHelper = plistProfile.isBackgroundOnly && plistProfile.complexity <= 4

        // Has entitlements that allow dylib manipulation
        if passiveHelper && binaryProfile.hasDangerousEntitlements {
            mismatches.append(IntentMismatch(
                type: .passiveHelperWithDylib,
                title: "Helper with Dynamic Library Loading",
                description: "Helper has entitlements to load unsigned code or manipulate libraries. This allows code injection and is commonly abused by malware to load malicious dylibs.",
                severity: .critical,
                riskPoints: 20,
                plistIntent: "Simple helper service",
                binaryReality: "Can load unsigned code or manipulate DYLD environment"
            ))
        }

        return mismatches
    }

    /// Check for minimal plist with full entitlements
    private func checkMinimalPlistFullEntitlements(plistProfile: PlistProfile, binaryProfile: BinaryProfile, item: PersistenceItem, entitlements: [String: Any]?) -> [IntentMismatch] {
        var mismatches: [IntentMismatch] = []

        let minimalPlist = plistProfile.isSimple && plistProfile.isPassive
        let fullEntitlements = binaryProfile.entitlementCount >= 5 ||
                              (binaryProfile.hasKeychainEntitlements && binaryProfile.hasAutomationEntitlements) ||
                              (binaryProfile.hasNetworkEntitlements && binaryProfile.hasPrivacyEntitlements)

        if minimalPlist && fullEntitlements {
            mismatches.append(IntentMismatch(
                type: .minimalPlistFullEntitlements,
                title: "Minimal Config, Maximum Capabilities",
                description: "The plist is minimal but the binary has extensive entitlements across multiple categories. Legitimate software usually has entitlements that match its declared purpose.",
                severity: .high,
                riskPoints: 15,
                plistIntent: "Minimal configuration, appears to be simple background task",
                binaryReality: "Binary has \(binaryProfile.entitlementCount) entitlements spanning multiple capability areas"
            ))
        }

        // Special case: simple task with keychain access
        if plistProfile.isSimple && binaryProfile.hasKeychainEntitlements && !item.name.lowercased().contains("keychain") {
            mismatches.append(IntentMismatch(
                type: .simpleTaskWithKeychain,
                title: "Simple Task with Keychain Access",
                description: "A simple-looking task has keychain access entitlements. This could be used for credential harvesting.",
                severity: .high,
                riskPoints: 15,
                plistIntent: "Simple task with no keychain-related arguments",
                binaryReality: "Binary can access keychain data"
            ))
        }

        return mismatches
    }

    // MARK: - Helpers

    private func calculateOverallSeverity(_ mismatches: [IntentMismatch]) -> Severity {
        if mismatches.isEmpty { return .low }

        if mismatches.contains(where: { $0.severity == .critical }) {
            return .critical
        } else if mismatches.contains(where: { $0.severity == .high }) {
            return .high
        } else if mismatches.contains(where: { $0.severity == .medium }) {
            return .medium
        }
        return .low
    }
}
