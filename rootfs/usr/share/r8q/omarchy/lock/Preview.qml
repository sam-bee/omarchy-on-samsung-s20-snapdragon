import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Wayland

// Offline visual/touch preview.  This file intentionally contains no
// WlSessionLock, PamContext, IPC handler, Process, or filesystem writes.
// Submitted text is discarded immediately and is never logged or persisted.
PanelWindow {
    id: root

    visible: true
    color: "#0b0e14"
    anchors {
        top: true
        bottom: true
        left: true
        right: true
    }

    WlrLayershell.namespace: "r8q-phone-lock-preview"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    property string previewPassword: ""
    property string previewMessage: ""
    property int previewSubmissions: 0

    LockView {
        anchors.fill: parent
        previewMode: true
        inputEnabled: true
        loadBackground: false
        passwordText: root.previewPassword
        failureMessage: root.previewMessage

        onPasswordTextEdited: function (value) {
            // This is intentionally in-memory only.  It is cleared on submit and
            // disappears when the preview process exits.
            root.previewPassword = value;
        }

        onSubmitPassword: function (value) {
            // Do not retain or print `value`; the preview never authenticates.
            root.previewPassword = "";
            root.previewSubmissions += 1;
            // Keep the fake submission neutral rather than presenting it as an
            // authentication failure.  The persistent preview banner already
            // explains that this surface does not authenticate.
            root.previewMessage = "";
        }

        onClearFailureRequested: root.previewMessage = ""
        onWakeRequested: {}
    }

    Button {
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.margins: 16
        height: 48
        leftPadding: 18
        rightPadding: 18
        text: "Close preview"
        onClicked: Qt.quit()
    }

    // A demo must return to the ordinary desktop even without an operator.
    Timer {
        interval: 90000
        running: true
        onTriggered: Qt.quit()
    }
}
