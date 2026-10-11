import QtQuick
import Quickshell
import Quickshell.Io
import "BatteryModel.js" as BatteryModel

// Passive local telemetry only.
Item {
  id: root

  property var shell: null
  property string telemetryScript: Quickshell.env("HOME")
    + "/.config/omarchy/plugins/r8q.battery/r8q-battery-telemetry.py"
  property var sample: ({})
  property string currentBand: "normal"
  property string pendingBand: ""
  property int pendingLevel: -1
  property double retryAfterMs: 0

  PersistentProperties {
    id: persisted
    reloadableId: "r8q-battery"
    property string alertBand: "normal"
  }

  function acceptTelemetryLine(line) {
    try {
      var parsed = JSON.parse(String(line || ""))
      if (!parsed || parsed.schema !== "r8q-battery-telemetry/v1") return
      telemetryProcess.pendingSample = parsed
      telemetryProcess.validOutput = true
    } catch (error) {
      // A malformed helper line is not telemetry and cannot trigger a warning.
    }
  }

  function applyTelemetry(parsed) {
    root.sample = parsed
    var result = BatteryModel.evaluateAlert(persisted.alertBand, parsed)
    root.currentBand = result.band
    if (!result.notify) {
      // The model preserves a delivered band through missing readings and
      // clears it only when credible capacity crosses its hysteresis threshold.
      persisted.alertBand = result.band
      return
    }
    if (warningProcess.running || Date.now() < root.retryAfterMs) return

    root.pendingBand = result.band
    root.pendingLevel = result.level
    warningProcess.command = [
      "gdbus", "call", "--session",
      "--dest", "org.freedesktop.Notifications",
      "--object-path", "/org/freedesktop/Notifications",
      "--method", "org.freedesktop.Notifications.Notify",
      "r8q-battery", "0", "battery-caution",
      result.band === "critical" ? "Recharge soon" : "Low battery",
      "Battery is down to " + String(result.level) + "%",
      "[]",
      result.band === "critical" ? "{'urgency': <byte 2>}" : "{'urgency': <byte 1>}",
      "30000"
    ]
    warningProcess.running = true
  }

  function telemetryFailed() {
    // Keep the last delivered band. A helper failure must not count as a
    // successful warning or silently re-arm the next low-battery transition.
    root.sample = ({})
    // Unknown helper state holds the last delivered band and cannot re-arm it.
  }

  Process {
    id: telemetryProcess
    property var pendingSample: null
    property bool validOutput: false
    command: ["python3", root.telemetryScript]
    stdout: SplitParser { onRead: function(line) { root.acceptTelemetryLine(String(line)) } }
    onStarted: {
      pendingSample = null
      validOutput = false
    }
    onExited: function(exitCode) {
      var parsed = pendingSample
      pendingSample = null
      if (exitCode === 0 && validOutput && parsed) root.applyTelemetry(parsed)
      else root.telemetryFailed()
    }
  }

  Process {
    id: warningProcess
    onExited: function(exitCode) {
      var sentBand = root.pendingBand
      root.pendingBand = ""
      root.pendingLevel = -1
      if (exitCode === 0 && sentBand !== "" && root.currentBand === sentBand) {
        persisted.alertBand = sentBand
        root.retryAfterMs = 0
      } else if (exitCode !== 0) {
        // Retry later without treating a failed sender as delivered.
        root.retryAfterMs = Date.now() + 120000
      }
    }
  }

  Timer {
    interval: 30000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: if (!telemetryProcess.running) telemetryProcess.running = true
  }
}
