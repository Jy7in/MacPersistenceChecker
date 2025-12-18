import Foundation

/// Living-off-the-Land Binaries Detector
/// Detects suspicious use of legitimate macOS binaries in persistence contexts
final class LOLBinsDetector {

    static let shared = LOLBinsDetector()

    // MARK: - LOLBin Definitions

    struct LOLBinMatch {
        let binary: String
        let category: LOLBinCategory
        let severity: Severity
        let description: String
        let mitreTechnique: String?
    }

    enum LOLBinCategory: String {
        case scripting = "Scripting"
        case networkDownloader = "Network/Downloader"
        case execution = "Execution"
        case discovery = "Discovery"
        case persistence = "Persistence"
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

    // Known LOLBins on macOS with their risk context
    private let lolbins: [String: (category: LOLBinCategory, baseSeverity: Severity, description: String, mitre: String?)] = [
        // Scripting - high risk in persistence
        "osascript": (.scripting, .high, "AppleScript execution - can control GUI, access keychain, execute arbitrary commands", "T1059.002"),
        "python": (.scripting, .medium, "Python interpreter - arbitrary code execution", "T1059.006"),
        "python3": (.scripting, .medium, "Python3 interpreter - arbitrary code execution", "T1059.006"),
        "perl": (.scripting, .medium, "Perl interpreter - arbitrary code execution", "T1059"),
        "ruby": (.scripting, .medium, "Ruby interpreter - arbitrary code execution", "T1059"),
        "bash": (.scripting, .medium, "Bash shell - command execution", "T1059.004"),
        "sh": (.scripting, .low, "Shell - command execution", "T1059.004"),
        "zsh": (.scripting, .low, "Zsh shell - command execution", "T1059.004"),

        // Network/Downloader - critical in auto-start context
        "curl": (.networkDownloader, .high, "HTTP client - can download and execute payloads", "T1105"),
        "wget": (.networkDownloader, .high, "HTTP client - can download payloads", "T1105"),
        "nc": (.networkDownloader, .critical, "Netcat - reverse shells, data exfiltration", "T1095"),
        "netcat": (.networkDownloader, .critical, "Netcat - reverse shells, data exfiltration", "T1095"),
        "nscurl": (.networkDownloader, .medium, "macOS native curl - network requests", "T1105"),
        "sftp": (.networkDownloader, .medium, "SFTP client - file transfer", "T1105"),
        "scp": (.networkDownloader, .medium, "Secure copy - file transfer", "T1105"),

        // Execution helpers
        "open": (.execution, .low, "Open command - can launch apps/URLs", "T1204"),
        "xattr": (.execution, .medium, "Extended attributes - can remove quarantine flag", "T1553.001"),
        "launchctl": (.persistence, .high, "Launchd control - persistence manipulation", "T1569.001"),
        "defaults": (.execution, .low, "Defaults command - plist manipulation", "T1647"),
        "plutil": (.execution, .low, "Plist utility - plist manipulation", "T1647"),
        "sqlite3": (.discovery, .medium, "SQLite - can access TCC.db, browser data", "T1005"),

        // Discovery/Recon
        "security": (.discovery, .high, "Security command - keychain access, certificate manipulation", "T1555.001"),
        "dscl": (.discovery, .medium, "Directory Services - user enumeration", "T1087.001"),
        "systemsetup": (.discovery, .low, "System configuration", "T1082"),
        "sw_vers": (.discovery, .low, "System version info", "T1082"),
        "ioreg": (.discovery, .low, "I/O Registry - hardware enumeration", "T1082"),
        "diskutil": (.discovery, .low, "Disk utility - volume enumeration", "T1082"),

        // Potentially dangerous
        "dd": (.execution, .medium, "Data duplicator - disk operations", "T1561"),
        "tar": (.execution, .low, "Archive utility - can extract payloads", "T1560"),
        "unzip": (.execution, .low, "Unzip - can extract payloads", "T1560"),
        "base64": (.execution, .medium, "Base64 - encode/decode payloads (obfuscation)", "T1027"),
        "xxd": (.execution, .medium, "Hex dump - payload manipulation", "T1027"),
        "openssl": (.execution, .high, "OpenSSL - encryption, C2 communication", "T1573"),
        "ssh": (.networkDownloader, .medium, "SSH client - remote access, tunneling", "T1021.004"),
        "screen": (.execution, .low, "Terminal multiplexer - session persistence", "T1505"),
        "tmux": (.execution, .low, "Terminal multiplexer - session persistence", "T1505"),
        "caffeinate": (.execution, .low, "Prevent sleep - keep malware running", "T1497"),
        "pmset": (.execution, .medium, "Power management - prevent sleep/shutdown", "T1497"),
    ]

    // MARK: - Detection

    struct LOLBinDetection {
        let binary: String
        let category: LOLBinCategory
        let severity: Severity
        let description: String
        let reason: String
        let mitreTechnique: String?
        let riskPoints: Int
    }

    /// Analyze a persistence item for LOLBin usage
    func analyze(_ item: PersistenceItem) -> [LOLBinDetection] {
        var detections: [LOLBinDetection] = []

        // Get the executable path and arguments
        guard let executablePath = item.executablePath?.path ?? item.plistPath?.path else {
            return detections
        }

        // Check main executable
        let executableName = (executablePath as NSString).lastPathComponent.lowercased()
        if let detection = checkBinary(executableName, in: item) {
            detections.append(detection)
        }

        // Check program arguments for LOLBins
        if let args = item.programArguments {
            for arg in args {
                let argLower = arg.lowercased()
                // Extract binary name from path
                let binaryName = (argLower as NSString).lastPathComponent

                // Skip if it's the same as executable or not a known LOLBin
                if binaryName != executableName, let detection = checkBinary(binaryName, in: item) {
                    // Avoid duplicates
                    if !detections.contains(where: { $0.binary == detection.binary }) {
                        detections.append(detection)
                    }
                }

                // Also check for inline scripts containing LOLBins
                for (lolbin, _) in lolbins {
                    if argLower.contains(lolbin) && !detections.contains(where: { $0.binary == lolbin }) {
                        if let detection = checkBinary(lolbin, in: item) {
                            detections.append(detection)
                        }
                    }
                }
            }
        }

        return detections
    }

    private func checkBinary(_ binaryName: String, in item: PersistenceItem) -> LOLBinDetection? {
        guard let lolbinInfo = lolbins[binaryName] else {
            return nil
        }

        // Calculate context-aware severity
        let (finalSeverity, reason) = calculateContextualSeverity(
            binary: binaryName,
            baseSeverity: lolbinInfo.baseSeverity,
            category: lolbinInfo.category,
            item: item
        )

        return LOLBinDetection(
            binary: binaryName,
            category: lolbinInfo.category,
            severity: finalSeverity,
            description: lolbinInfo.description,
            reason: reason,
            mitreTechnique: lolbinInfo.mitre,
            riskPoints: finalSeverity.points
        )
    }

    /// Calculate severity based on context (the combo that matters)
    private func calculateContextualSeverity(
        binary: String,
        baseSeverity: Severity,
        category: LOLBinCategory,
        item: PersistenceItem
    ) -> (Severity, String) {

        var severity = baseSeverity
        var reasons: [String] = []

        // CRITICAL COMBOS

        // osascript + persistence = very suspicious
        if binary == "osascript" {
            if item.keepAlive == true || item.runAtLoad == true {
                severity = .critical
                reasons.append("AppleScript with persistence - can automate malicious GUI actions")
            }
        }

        // curl/wget + auto-start = download & execute pattern
        if ["curl", "wget", "nc", "netcat"].contains(binary) {
            if item.runAtLoad == true {
                severity = .critical
                reasons.append("Network tool with auto-start - classic download & execute pattern")
            }
            if item.keepAlive == true {
                severity = .critical
                reasons.append("Network tool with KeepAlive - persistent C2 channel")
            }
        }

        // python/scripting + privileged helper = code execution with elevated privs
        if ["python", "python3", "perl", "ruby"].contains(binary) {
            if item.category == .privilegedHelpers {
                severity = .critical
                reasons.append("Script interpreter as privileged helper - elevated code execution")
            }
            if item.category == .launchDaemons {
                severity = .high
                reasons.append("Script interpreter in LaunchDaemon - runs as root")
            }
        }

        // security command in persistence = keychain theft
        if binary == "security" && (item.runAtLoad == true || item.keepAlive == true) {
            severity = .critical
            reasons.append("Keychain tool with persistence - credential harvesting risk")
        }

        // launchctl in persistence = meta-persistence
        if binary == "launchctl" && item.runAtLoad == true {
            severity = .high
            reasons.append("Launchctl with auto-start - can install additional persistence")
        }

        // xattr in persistence = quarantine bypass
        if binary == "xattr" && item.runAtLoad == true {
            severity = .high
            reasons.append("Xattr with auto-start - may remove quarantine from downloads")
        }

        // sqlite3 in persistence = data theft
        if binary == "sqlite3" && (item.runAtLoad == true || item.keepAlive == true) {
            severity = .high
            reasons.append("SQLite with persistence - can access TCC.db, browser data, cookies")
        }

        // openssl in persistence = encrypted C2
        if binary == "openssl" && (item.runAtLoad == true || item.keepAlive == true) {
            severity = .high
            reasons.append("OpenSSL with persistence - encrypted command & control")
        }

        // base64 in persistence = obfuscation
        if binary == "base64" && item.runAtLoad == true {
            severity = .medium
            reasons.append("Base64 with auto-start - payload obfuscation technique")
        }

        // Default reason if no specific combo detected
        if reasons.isEmpty {
            reasons.append("LOLBin detected in persistence context")
        }

        return (severity, reasons.joined(separator: "; "))
    }

    /// Get total risk points from detections
    func totalRiskPoints(_ detections: [LOLBinDetection]) -> Int {
        return detections.reduce(0) { $0 + $1.riskPoints }
    }
}
