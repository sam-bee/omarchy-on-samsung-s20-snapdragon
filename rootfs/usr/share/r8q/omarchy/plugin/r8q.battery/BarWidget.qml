import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui
import "BatteryModel.js" as BatteryModel

BarWidget {
  id: root
  moduleName: "r8q.battery"

  property string telemetryScript: Quickshell.env("HOME")
    + "/.config/omarchy/plugins/r8q.battery/r8q-battery-telemetry.py"
  property var sample: ({})
  readonly property string label: BatteryModel.barText(sample)

  implicitWidth: 82
  implicitHeight: 48

  function acceptTelemetryLine(line) {
    try {
      var parsed = JSON.parse(String(line || ""))
      if (parsed && parsed.schema === "r8q-battery-telemetry/v1")
        telemetryProcess.pendingSample = parsed
    } catch (error) {
      // Keep the safe unavailable label on malformed output.
    }
  }

  WidgetButton {
    anchors.fill: parent
    bar: root.bar
    text: root.label
    fixedWidth: 82
    fixedHeight: 48
    horizontalMargin: 8
    verticalPadding: 8
  }

  Process {
    id: telemetryProcess
    property var pendingSample: null
    command: ["python3", root.telemetryScript]
    stdout: SplitParser { onRead: function(line) { root.acceptTelemetryLine(String(line)) } }
    onStarted: pendingSample = null
    onExited: function(exitCode) {
      if (exitCode === 0 && pendingSample) root.sample = pendingSample
      else root.sample = ({})
      pendingSample = null
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
