import QtQuick
import QtQuick.Controls

// Phone-oriented lock surface for the pinned Omarchy lock Service.qml.
//
// The four signals and the properties consumed by Service.qml intentionally
// retain the upstream LockView contract.  This file owns presentation and
// touch input only; PAM and WlSessionLock remain in Service.qml.
Item {
    id: root

    property string backgroundPath: ""
    property int backgroundVersion: 0
    property bool fingerprintConfigured: false
    property bool authenticatingPassword: false
    property string failureMessage: ""
    property int failedAttempts: 0
    property bool inputEnabled: true
    property bool loadBackground: true
    property string passwordText: ""

    // Preview.qml sets this only for the offline fake-state preview.  The
    // production lock surface never displays a preview marker.
    property bool previewMode: false
    property string previewLabel: "PREVIEW — no authentication is performed"

    property bool syncingPasswordText: false

    signal submitPassword(string password)
    signal passwordTextEdited(string password)
    signal clearFailureRequested
    signal wakeRequested

    readonly property bool canInteract: inputEnabled && !authenticatingPassword
    readonly property bool portrait: width > 0 && height > width
    readonly property real contentWidth: Math.min(portrait ? 420 : 680, Math.max(0, width - (portrait ? 28 : 48)))
    readonly property real keyGap: Math.max(7, Math.min(14, contentWidth * 0.025))
    readonly property real keyHeight: Math.max(58, Math.min(88, portrait ? width * 0.14 : height * 0.09))
    readonly property real fieldHeight: portrait ? 76 : 68
    readonly property real actionHeight: portrait ? 66 : 60
    readonly property real passwordDotFontSize: portrait ? 31 : 29
    readonly property real passwordDotLetterSpacing: 3
    readonly property real passwordDotScale: dotMetrics.advanceWidth > 0 ? Math.min(1, (passwordInput.width - 4) / dotMetrics.advanceWidth) : 1

    function fileUrl(path) {
        if (!path)
            return "";
        var encoded = String(path).split("/").map(encodeURIComponent).join("/");
        return "file://" + encoded + "?v=" + backgroundVersion;
    }

    function forcePasswordFocus() {
        if (canInteract)
            passwordInput.forceActiveFocus();
    }

    function hideInputMethod() {
        Qt.inputMethod.hide();
    }

    function syncPasswordText() {
        if (passwordInput.text === passwordText)
            return;
        syncingPasswordText = true;
        passwordInput.text = passwordText;
        syncingPasswordText = false;
    }

    function currentPassword() {
        var inputValue = String(passwordInput.text || "");
        return inputValue.length > 0 ? inputValue : String(passwordText || "");
    }

    function publishPassword(value) {
        if (!canInteract)
            return;
        wakeRequested();
        passwordTextEdited(String(value));
        if (String(value).length > 0 && failureMessage.length > 0)
            clearFailureRequested();
    }

    function clearPassword() {
        hideInputMethod();
        publishPassword("");
        if (failureMessage.length > 0)
            clearFailureRequested();
    }

    function submitCurrentPassword() {
        if (!canInteract)
            return;
        hideInputMethod();

        var submitted = currentPassword();
        // Clear the displayed and service-bound value before handing the secret
        // to the PAM bridge.  The function parameter is never logged or stored.
        passwordTextEdited("");
        if (submitted.length > 0)
            submitPassword(submitted);
    }

    function handleKey(key) {
        if (!canInteract)
            return;
        var value = currentPassword();
        hideInputMethod();
        wakeRequested();

        if (key === "Clear") {
            clearPassword();
        } else if (key === "⌫") {
            publishPassword(value.slice(0, -1));
        } else {
            publishPassword(value + key);
        }
    }

    onPasswordTextChanged: syncPasswordText()
    Component.onCompleted: syncPasswordText()

    // Keep long passwords visibly represented instead of clipping the dots.
    // This changes only the display scale; the underlying TextInput text is
    // never shortened or otherwise altered.
    TextMetrics {
        id: dotMetrics
        font.family: passwordInput.font.family
        font.pixelSize: root.passwordDotFontSize
        font.letterSpacing: root.passwordDotLetterSpacing
        text: "●".repeat(passwordInput.text.length)
    }

    Rectangle {
        anchors.fill: parent
        color: "#0b0e14"

        Image {
            anchors.fill: parent
            source: root.loadBackground && root.backgroundPath.length > 0 ? root.fileUrl(root.backgroundPath) : ""
            fillMode: Image.PreserveAspectCrop
            asynchronous: true
            cache: false
            sourceSize.width: width
            sourceSize.height: height
            opacity: 0.32
        }

        Rectangle {
            anchors.fill: parent
            color: "#9a0b0e15"
        }

        // Waking is deliberately separate from the controls, so a tap in an
        // empty area can wake the display without granting any unlock capability.
        MouseArea {
            anchors.fill: parent
            z: 0
            hoverEnabled: true
            onClicked: {
                root.wakeRequested();
            }
            onPositionChanged: root.wakeRequested()
        }

        Flickable {
            id: contentScroller
            anchors.fill: parent
            z: 1
            clip: true
            contentWidth: width
            contentHeight: Math.max(height, content.height + 32)
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            interactive: content.height + 32 > height
            onMovementStarted: root.wakeRequested()

            Column {
                id: content
                x: Math.max(0, (contentScroller.width - width) / 2)
                y: Math.max(16, (contentScroller.height - height) / 2)
                width: root.contentWidth
                height: implicitHeight
                spacing: root.portrait ? 14 : 12

                Text {
                    visible: root.previewMode
                    width: parent.width
                    height: Math.max(32, implicitHeight)
                    text: root.previewLabel
                    color: "#ffcc66"
                    font.pixelSize: 16
                    font.bold: true
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    wrapMode: Text.WordWrap
                }

                Text {
                    width: parent.width
                    height: 34
                    text: root.previewMode ? "Keypad preview" : root.failureMessage.length > 0 ? "Unlock required" : "Phone locked"
                    color: "#f1f4fb"
                    font.pixelSize: root.portrait ? 26 : 24
                    font.bold: true
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }

                Rectangle {
                    id: inputCard
                    width: parent.width
                    height: root.fieldHeight
                    radius: 17
                    color: "#161b26"
                    border.width: root.failureMessage.length > 0 ? 3 : 2
                    border.color: root.failureMessage.length > 0 ? "#f07474" : "#6e7d9a"

                    MouseArea {
                        anchors.fill: parent
                        z: 0
                        enabled: root.canInteract
                        onClicked: root.forcePasswordFocus()
                    }

                    TextInput {
                        id: passwordInput
                        objectName: "lock-password-input"
                        Accessible.role: Accessible.EditableText
                        Accessible.name: "PIN"
                        Accessible.description: "Enter the PIN for the locked session"
                        anchors.fill: parent
                        anchors.leftMargin: 18
                        anchors.rightMargin: 18
                        anchors.topMargin: 2
                        anchors.bottomMargin: 2
                        z: 1
                        activeFocusOnPress: true
                        enabled: root.canInteract
                        readOnly: root.authenticatingPassword
                        clip: true
                        echoMode: TextInput.Password
                        passwordCharacter: "●"
                        passwordMaskDelay: 0
                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
                        color: "#f1f4fb"
                        selectionColor: "#405170"
                        selectedTextColor: "#f1f4fb"
                        font.pixelSize: text.length > 0 ? Math.max(1, Math.floor(root.passwordDotFontSize * root.passwordDotScale)) : root.passwordDotFontSize
                        font.letterSpacing: text.length > 0 ? root.passwordDotLetterSpacing * root.passwordDotScale : 0
                        horizontalAlignment: TextInput.AlignHCenter
                        verticalAlignment: TextInput.AlignVCenter
                        cursorVisible: activeFocus && root.canInteract && text.length > 0

                        onTextChanged: {
                            if (!root.syncingPasswordText)
                                root.passwordTextEdited(text);
                            if (text.length > 0) {
                                root.wakeRequested();
                                if (root.failureMessage.length > 0)
                                    root.clearFailureRequested();
                            }
                        }

                        onAccepted: root.submitCurrentPassword()

                        Keys.onPressed: function (event) {
                            root.wakeRequested();
                            if (event.key === Qt.Key_Escape || (event.modifiers & Qt.ControlModifier && event.key === Qt.Key_U)) {
                                root.clearPassword();
                                event.accepted = true;
                            }
                        }
                    }

                    Text {
                        anchors.fill: passwordInput
                        z: 2
                        enabled: false
                        text: root.authenticatingPassword ? "Checking…" : root.failureMessage.length > 0 ? root.failureMessage : "Enter PIN or use keypad"
                        color: root.authenticatingPassword ? "#b9c5da" : root.failureMessage.length > 0 ? "#f6a0a0" : "#9caac2"
                        font.pixelSize: root.portrait ? 18 : 17
                        font.italic: root.failureMessage.length > 0
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        elide: Text.ElideRight
                        visible: passwordInput.text.length === 0
                    }
                }

                Keypad {
                    id: keypad
                    width: parent.width
                    height: implicitHeight
                    gap: root.keyGap
                    buttonHeight: root.keyHeight
                    enabled: root.canInteract
                    onKeyPressed: function (key) {
                        root.handleKey(key);
                    }
                }

                Row {
                    id: actionRow
                    width: parent.width
                    height: root.actionHeight
                    spacing: root.keyGap

                    Button {
                        id: clearButton
                        objectName: "lock-clear"
                        width: (parent.width - parent.spacing) * 0.34
                        height: parent.height
                        padding: 0
                        focusPolicy: Qt.TabFocus
                        enabled: root.canInteract
                        Accessible.role: Accessible.Button
                        Accessible.name: "Clear"
                        Accessible.description: "Clear entered password"

                        contentItem: Text {
                            text: "Clear"
                            color: "#e1e7f3"
                            font.pixelSize: 18
                            font.bold: true
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }

                        background: Rectangle {
                            radius: 16
                            color: clearButton.pressed ? "#405170" : clearButton.hovered ? "#2d3a53" : "#20293a"
                            border.width: clearButton.activeFocus || clearButton.hovered ? 2 : 1
                            border.color: clearButton.activeFocus || clearButton.hovered ? "#8da2c7" : "#4b5c7a"
                            opacity: clearButton.enabled ? 1.0 : 0.52
                        }

                        onPressed: root.hideInputMethod()
                        onClicked: root.clearPassword()
                    }

                    Button {
                        id: submitButton
                        objectName: "lock-submit"
                        width: parent.width - clearButton.width - parent.spacing
                        height: parent.height
                        padding: 0
                        focusPolicy: Qt.TabFocus
                        enabled: root.canInteract
                        Accessible.role: Accessible.Button
                        Accessible.name: "Unlock"
                        Accessible.description: "Submit the entered password"

                        contentItem: Text {
                            text: root.authenticatingPassword ? "Checking…" : "Unlock"
                            color: "#ffffff"
                            font.pixelSize: 19
                            font.bold: true
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }

                        background: Rectangle {
                            radius: 16
                            color: submitButton.pressed ? "#6d8bc2" : submitButton.hovered ? "#5b7fbd" : "#4d6fa9"
                            border.width: submitButton.activeFocus || submitButton.hovered ? 2 : 1
                            border.color: "#94add8"
                            opacity: submitButton.enabled ? 1.0 : 0.52
                        }

                        onPressed: root.hideInputMethod()
                        onClicked: root.submitCurrentPassword()
                    }
                }

                Text {
                    width: parent.width
                    height: Math.max(28, implicitHeight)
                    text: root.fingerprintConfigured ? "Touch fingerprint or enter password" : "Use the touch keypad or a physical keyboard"
                    color: "#9caac2"
                    font.pixelSize: 14
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
