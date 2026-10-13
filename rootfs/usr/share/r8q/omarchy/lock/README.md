# Phone lock surface

This directory contains a phone-oriented `LockView.qml`, its reusable
touch-first `Keypad.qml`, and an offline `Preview.qml`.  The view keeps the
signal/property contract expected by the pinned Omarchy lock service:

- `backgroundPath`, `backgroundVersion`, `fingerprintConfigured`,
  `authenticatingPassword`, `failureMessage`, `failedAttempts`,
  `inputEnabled`, `loadBackground`, and `passwordText` properties;
- `submitPassword`, `passwordTextEdited`, `clearFailureRequested`, and
  `wakeRequested` signals.

PAM authentication and the Wayland session lock remain in `Service.qml`.  The
phone view only collects input and never logs or persists a password.  The
touch keypad supports digits, backspace, clear, and an explicit Unlock action;
the `TextInput` remains available for arbitrary passwords and physical
keyboards.  The field is focused only when explicitly tapped (or focused by
the keyboard focus system), while keypad controls hide the input method so a
touch keyboard cannot cover the keypad.  The complete surface is a vertical
`Flickable` when the available height is too short for the controls.  Long
passwords scale their masked dots to remain visible without changing the
underlying value.

The keypad and actions use Qt Quick Controls `Button` focus behavior and
accessibility names.  Fingerprint handling remains in the upstream service;
the phone view only displays the service's configured-fingerprint hint.

`Preview.qml` uses a normal Quickshell `PanelWindow`, not `WlSessionLock`, and
contains no PAM or IPC code.  It visibly labels itself as a preview and
discards submitted text immediately.  Once Quickshell is available in a
graphical session, run it with:

```sh
quickshell -p /usr/share/r8q/omarchy/lock/Preview.qml
```

When testing from the source tree before deployment, pass the corresponding
absolute path to `Preview.qml`.  The parent integration still needs to place
this `LockView.qml` where the pinned `shell/plugins/lock/Service.qml` resolves
its local `LockView` type; this directory deliberately does not modify the
Omarchy source or deployment scripts.

No upstream source files were copied into this directory, so there is no
additional license notice to preserve here.
