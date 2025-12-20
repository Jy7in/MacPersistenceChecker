import AppKit
import SwiftUI

/// Helper to open the Settings window from anywhere in the app
func openSettingsWindow() {
    // Activate the app first
    NSApplication.shared.activate(ignoringOtherApps: true)

    // Find and click the Settings menu item in the app menu
    if let mainMenu = NSApp.mainMenu,
       let appMenu = mainMenu.items.first?.submenu {
        for item in appMenu.items {
            if item.title.contains("Settings") || item.title.contains("Preferences") {
                // Perform the menu item action
                if let action = item.action {
                    NSApp.sendAction(action, to: item.target, from: nil)
                    return
                }
            }
        }
    }
}
