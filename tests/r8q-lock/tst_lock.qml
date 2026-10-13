import QtQuick
import QtTest
import "../../rootfs/usr/share/r8q/omarchy/lock"

// Synthetic credentials only. This test never invokes PAM or session locking.
Item {
  id: fixture
  width: 540
  height: 1200
  property string entered: ""
  property string submitted: ""
  property int submissions: 0
  property bool busy: false
  property bool acceptsInput: true

  LockView {
    id: view
    anchors.fill: parent
    loadBackground: false
    passwordText: fixture.entered
    authenticatingPassword: fixture.busy
    inputEnabled: fixture.acceptsInput
    onPasswordTextEdited: function(value) { fixture.entered = value }
    onSubmitPassword: function(value) {
      // Verify clearing precedes handing the secret to authentication.
      if (fixture.entered !== "") throw new Error("credential remained visible on submit")
      fixture.submitted = value
      fixture.submissions += 1
    }
    onClearFailureRequested: view.failureMessage = ""
  }

  TestCase {
    name: "PhoneLockInput"
    when: windowShown

    function init() {
      fixture.busy = false
      fixture.acceptsInput = true
      fixture.entered = ""
      fixture.submitted = ""
      fixture.submissions = 0
      view.failureMessage = ""
      wait(20)
    }

    function button(name) {
      var item = findChild(view, name)
      verify(item !== null, "missing " + name)
      return item
    }

    function click(name) {
      var item = button(name)
      mouseClick(item, item.width / 2, item.height / 2)
      wait(10)
    }

    function test_touch_digits_backspace_clear_and_submit() {
      click("key-1")
      compare(fixture.entered, "1")
      click("key-2")
      compare(fixture.entered, "12")
      click("key-⌫")
      compare(fixture.entered, "1")
      click("key-0")
      compare(fixture.entered, "10")
      click("lock-submit")
      compare(fixture.submitted, "10")
      compare(fixture.submissions, 1)
      compare(fixture.entered, "")
      compare(button("lock-password-input").text, "")
      click("key-3")
      click("key-Clear")
      compare(fixture.entered, "")
      click("key-4")
      click("lock-clear")
      compare(fixture.entered, "")
    }

    function test_empty_submit_does_not_authenticate() {
      click("lock-submit")
      compare(fixture.submissions, 0)
    }

    function test_clear_resets_failure() {
      view.failureMessage = "Synthetic authentication failure"
      click("lock-clear")
      compare(view.failureMessage, "")
    }

    function test_long_password_keeps_value_and_fits_dots() {
      fixture.entered = "synthetic-long-password-".repeat(4)
      wait(20)
      var input = button("lock-password-input")
      compare(input.text, fixture.entered)
      verify(view.passwordDotScale < 1)
      verify(input.font.pixelSize < view.passwordDotFontSize)
    }

    function test_busy_blocks_touch_and_keyboard() {
      fixture.entered = "1234"
      fixture.busy = true
      wait(20)
      click("key-5")
      click("key-⌫")
      click("lock-clear")
      click("lock-submit")
      keyClick(Qt.Key_6)
      compare(fixture.entered, "1234")
      compare(fixture.submissions, 0)
    }

    function test_input_disabled_blocks_changes() {
      fixture.acceptsInput = false
      wait(20)
      click("key-7")
      click("lock-submit")
      compare(fixture.entered, "")
      compare(fixture.submissions, 0)
    }

    function test_physical_keyboard_fallback_and_masking() {
      var input = button("lock-password-input")
      input.forceActiveFocus()
      var text = "test-passphrase"
      for (var i = 0; i < text.length; i++) keyClick(text[i])
      compare(fixture.entered, "test-passphrase")
      compare(input.echoMode, TextInput.Password)
      compare(input.passwordMaskDelay, 0)
      keyClick(Qt.Key_Return)
      compare(fixture.submitted, "test-passphrase")
      compare(fixture.entered, "")
      fixture.entered = "another-test"
      keyClick(Qt.Key_U, Qt.ControlModifier)
      compare(fixture.entered, "")
    }
  }
}
