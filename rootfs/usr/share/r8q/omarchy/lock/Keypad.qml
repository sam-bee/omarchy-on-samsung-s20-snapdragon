import QtQuick
import QtQuick.Controls

// A small, touch-first numeric keypad for the phone lock surface.  It emits
// key labels and deliberately does not own password state or authentication.
// The lock view remains responsible for forwarding the resulting value to
// Service.qml, so this component is also safe to exercise with fake state.
Item {
    id: root

    property var labels: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "Clear", "0", "⌫"]
    property real gap: 10
    property real buttonHeight: 72

    signal keyPressed(string key)

    implicitHeight: buttonHeight * 4 + gap * 3

    Grid {
        id: keypadGrid
        anchors.fill: parent
        columns: 3
        rowSpacing: root.gap
        columnSpacing: root.gap

        Repeater {
            model: root.labels

            delegate: Button {
                id: keyButton
                property string label: modelData
                objectName: "key-" + label

                width: Math.max(0, (keypadGrid.width - root.gap * 2) / 3)
                height: root.buttonHeight
                padding: 0
                focusPolicy: Qt.TabFocus
                Accessible.role: Accessible.Button
                Accessible.name: label === "⌫" ? "Backspace" : label
                Accessible.description: label === "Clear" ? "Clear entered PIN" : label === "⌫" ? "Delete the last character" : "Enter digit " + label

                contentItem: Text {
                    text: keyButton.label
                    color: "#f1f4fb"
                    font.pixelSize: Math.max(22, Math.min(32, root.buttonHeight * 0.36))
                    font.bold: keyButton.label.length > 1
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }

                background: Rectangle {
                    radius: Math.min(18, keyButton.height * 0.22)
                    color: keyButton.pressed ? "#405170" : keyButton.hovered ? "#2d3a53" : "#20293a"
                    border.width: 1
                    border.color: keyButton.activeFocus || keyButton.hovered ? "#8da2c7" : "#4b5c7a"
                    opacity: keyButton.enabled ? 1.0 : 0.52
                }

                onPressed: Qt.inputMethod.hide()
                onClicked: root.keyPressed(label)
            }
        }
    }
}
