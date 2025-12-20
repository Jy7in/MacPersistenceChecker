import Foundation
import Combine

/// User-configurable settings for the monitoring system
final class MonitorConfiguration: ObservableObject {
    static let shared = MonitorConfiguration()

    // MARK: - UserDefaults Keys

    private enum Keys {
        static let monitoringEnabled = "MonitoringEnabled"
        static let autoStartMonitoring = "MonitorAutoStart"
        static let cooldownInterval = "MonitorCooldownInterval"
        static let minimumRelevance = "MonitorMinimumRelevance"
        static let enabledCategories = "MonitorEnabledCategories"
        static let notifyOnAdd = "MonitorNotifyOnAdd"
        static let notifyOnRemove = "MonitorNotifyOnRemove"
        static let notifyOnModify = "MonitorNotifyOnModify"
        static let playSoundOnHighRelevance = "MonitorPlaySoundHighRelevance"
        static let showBadge = "MonitorShowBadge"
        static let notificationCooldownHours = "MonitorNotificationCooldownHours"
    }

    // MARK: - Published Properties

    /// Global monitoring enabled state
    @Published var monitoringEnabled: Bool {
        didSet { save(monitoringEnabled, for: Keys.monitoringEnabled) }
    }

    /// Auto-start monitoring when app launches
    @Published var autoStartMonitoring: Bool {
        didSet { save(autoStartMonitoring, for: Keys.autoStartMonitoring) }
    }

    /// Cooldown interval for debouncing (in seconds)
    @Published var cooldownInterval: TimeInterval {
        didSet { save(cooldownInterval, for: Keys.cooldownInterval) }
    }

    /// Minimum relevance score to trigger notification (0-100)
    @Published var minimumRelevanceScore: Int {
        didSet { save(minimumRelevanceScore, for: Keys.minimumRelevance) }
    }

    /// Categories to monitor
    @Published var enabledCategories: Set<PersistenceCategory> {
        didSet {
            let rawValues = enabledCategories.map { $0.rawValue }
            UserDefaults.standard.set(rawValues, forKey: Keys.enabledCategories)
        }
    }

    /// Notify on item addition
    @Published var notifyOnAdd: Bool {
        didSet { save(notifyOnAdd, for: Keys.notifyOnAdd) }
    }

    /// Notify on item removal
    @Published var notifyOnRemove: Bool {
        didSet { save(notifyOnRemove, for: Keys.notifyOnRemove) }
    }

    /// Notify on item modification
    @Published var notifyOnModify: Bool {
        didSet { save(notifyOnModify, for: Keys.notifyOnModify) }
    }

    /// Play sound for high relevance changes (>= 60)
    @Published var playSoundOnHighRelevance: Bool {
        didSet { save(playSoundOnHighRelevance, for: Keys.playSoundOnHighRelevance) }
    }

    /// Show badge on app icon for unacknowledged changes
    @Published var showBadge: Bool {
        didSet { save(showBadge, for: Keys.showBadge) }
    }

    /// Notification cooldown in hours (don't repeat same item notification)
    @Published var notificationCooldownHours: Int {
        didSet { save(notificationCooldownHours, for: Keys.notificationCooldownHours) }
    }

    /// Track when we last notified for each item (identifier -> timestamp)
    private var lastNotificationTimes: [String: Date] = [:]
    private let lastNotificationTimesLock = NSLock()

    // MARK: - Computed Properties

    /// All categories that are enabled for monitoring (considering both scanner config and monitor config)
    var allEnabledCategories: Set<PersistenceCategory> {
        let scannerConfig = ScannerConfiguration.shared

        // Start with core categories
        var enabled = Set(PersistenceCategory.coreCategories)

        // Add extended categories if scanner has them enabled
        if scannerConfig.extendedScannersEnabled {
            for category in PersistenceCategory.extendedCategories {
                if scannerConfig.enabledCategories.contains(category) {
                    enabled.insert(category)
                }
            }
        }

        // Intersect with monitor-specific enabled categories
        return enabled.intersection(enabledCategories)
    }

    /// Categories that can be monitored (have file paths)
    var monitorableCategories: [PersistenceCategory] {
        PersistenceCategory.allCases.filter { !$0.monitoredPaths.isEmpty }
    }

    // MARK: - Initialization

    private init() {
        let defaults = UserDefaults.standard

        // Load boolean settings
        self.monitoringEnabled = defaults.bool(forKey: Keys.monitoringEnabled)
        self.autoStartMonitoring = defaults.bool(forKey: Keys.autoStartMonitoring)
        self.notifyOnAdd = defaults.object(forKey: Keys.notifyOnAdd) as? Bool ?? true
        self.notifyOnRemove = defaults.object(forKey: Keys.notifyOnRemove) as? Bool ?? true
        self.notifyOnModify = defaults.object(forKey: Keys.notifyOnModify) as? Bool ?? true
        self.playSoundOnHighRelevance = defaults.object(forKey: Keys.playSoundOnHighRelevance) as? Bool ?? true
        self.showBadge = defaults.object(forKey: Keys.showBadge) as? Bool ?? true

        // Load cooldown interval
        let savedCooldown = defaults.double(forKey: Keys.cooldownInterval)
        self.cooldownInterval = savedCooldown > 0 ? savedCooldown : 5.0  // Default 5 seconds

        // Load minimum relevance (default 50 = medium)
        let savedRelevance = defaults.integer(forKey: Keys.minimumRelevance)
        self.minimumRelevanceScore = savedRelevance > 0 ? savedRelevance : 50

        // Load notification cooldown (default 2 hours)
        let savedNotifCooldown = defaults.integer(forKey: Keys.notificationCooldownHours)
        self.notificationCooldownHours = savedNotifCooldown > 0 ? savedNotifCooldown : 2

        // Load enabled categories
        if let savedCategories = defaults.array(forKey: Keys.enabledCategories) as? [String] {
            self.enabledCategories = Set(savedCategories.compactMap { PersistenceCategory(rawValue: $0) })
        } else {
            // Default: all monitorable categories
            self.enabledCategories = Set(PersistenceCategory.allCases.filter { !$0.monitoredPaths.isEmpty })
        }
    }

    // MARK: - Methods

    /// Reset all settings to defaults
    func resetToDefaults() {
        monitoringEnabled = false
        autoStartMonitoring = false
        cooldownInterval = 5.0
        minimumRelevanceScore = 30
        enabledCategories = Set(PersistenceCategory.allCases.filter { !$0.monitoredPaths.isEmpty })
        notifyOnAdd = true
        notifyOnRemove = true
        notifyOnModify = true
        playSoundOnHighRelevance = true
        showBadge = true
    }

    /// Enable all categories for monitoring
    func enableAllCategories() {
        enabledCategories = Set(monitorableCategories)
    }

    /// Enable only core categories
    func enableCoreOnly() {
        enabledCategories = Set(PersistenceCategory.coreCategories.filter { !$0.monitoredPaths.isEmpty })
    }

    /// Check if a specific change type should trigger notification
    func shouldNotify(for changeType: MonitorChangeType) -> Bool {
        switch changeType {
        case .added:
            return notifyOnAdd
        case .removed:
            return notifyOnRemove
        case .modified, .enabled, .disabled:
            return notifyOnModify
        }
    }

    /// Check if we can send notification for this item (respects cooldown)
    func canNotify(forIdentifier identifier: String) -> Bool {
        lastNotificationTimesLock.lock()
        defer { lastNotificationTimesLock.unlock() }

        guard let lastTime = lastNotificationTimes[identifier] else {
            return true // Never notified before
        }

        let hoursSinceLastNotification = Date().timeIntervalSince(lastTime) / 3600
        return hoursSinceLastNotification >= Double(notificationCooldownHours)
    }

    /// Record that we sent a notification for this item
    func recordNotification(forIdentifier identifier: String) {
        lastNotificationTimesLock.lock()
        defer { lastNotificationTimesLock.unlock() }
        lastNotificationTimes[identifier] = Date()
    }

    /// Clear old notification records (call periodically)
    func cleanupOldNotificationRecords() {
        lastNotificationTimesLock.lock()
        defer { lastNotificationTimesLock.unlock() }

        let cutoff = Date().addingTimeInterval(-Double(notificationCooldownHours) * 3600)
        lastNotificationTimes = lastNotificationTimes.filter { $0.value > cutoff }
    }

    // MARK: - Private Helpers

    private func save(_ value: Bool, for key: String) {
        UserDefaults.standard.set(value, forKey: key)
    }

    private func save(_ value: Int, for key: String) {
        UserDefaults.standard.set(value, forKey: key)
    }

    private func save(_ value: Double, for key: String) {
        UserDefaults.standard.set(value, forKey: key)
    }
}

// MARK: - Presets

extension MonitorConfiguration {
    /// Preset configurations for quick setup
    enum Preset: String, CaseIterable {
        case minimal = "Minimal"
        case balanced = "Balanced"
        case paranoid = "Paranoid"

        var description: String {
            switch self {
            case .minimal:
                return "Only critical categories, high threshold"
            case .balanced:
                return "Core categories, moderate threshold"
            case .paranoid:
                return "All categories, low threshold"
            }
        }
    }

    func apply(preset: Preset) {
        switch preset {
        case .minimal:
            enabledCategories = Set([.launchDaemons, .launchAgents, .privilegedHelpers])
            minimumRelevanceScore = 60
            cooldownInterval = 10.0
            notifyOnRemove = false

        case .balanced:
            enableCoreOnly()
            minimumRelevanceScore = 30
            cooldownInterval = 5.0
            notifyOnAdd = true
            notifyOnRemove = true
            notifyOnModify = true

        case .paranoid:
            enableAllCategories()
            minimumRelevanceScore = 10
            cooldownInterval = 2.0
            notifyOnAdd = true
            notifyOnRemove = true
            notifyOnModify = true
        }
    }
}
