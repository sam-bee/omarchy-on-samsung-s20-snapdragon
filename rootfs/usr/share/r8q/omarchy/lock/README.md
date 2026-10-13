# Phone lock surface

This directory contains a phone-oriented `LockView.qml`, its reusable
touch-first `Keypad.qml`, the production `Service.qml`, and an offline
`Preview.qml`. The view keeps the
signal/property contract expected by the pinned Omarchy lock service:

- `backgroundPath`, `backgroundVersion`, `fingerprintConfigured`,
  `authenticatingPassword`, `failureMessage`, `failedAttempts`,
  `inputEnabled`, `loadBackground`, and `passwordText` properties;
- `submitPassword`, `passwordTextEdited`, `clearFailureRequested`, and
  `wakeRequested` signals.

PAM authentication and the Wayland session lock are owned by `Service.qml`. The
phone view only collects input and never logs or persists a password.  The
touch keypad supports digits, backspace, clear, and an explicit Unlock action;
production service accepts 4–12 numeric digits through PAM for `alarm`.
The field also supports physical keyboards. It is focused only when explicitly tapped (or focused by
the keyboard focus system), while keypad controls hide the input method so a
touch keyboard cannot cover the keypad.  The complete surface is a vertical
`Flickable` when the available height is too short for the controls.  Long
passwords scale their masked dots to remain visible without changing the
underlying value.

The keypad and actions use Qt Quick Controls `Button` focus behavior and
accessibility names. Fingerprint authentication is disabled on this port.

`Preview.qml` uses a normal Quickshell `PanelWindow`, not `WlSessionLock`, and
contains no PAM or IPC code.  It visibly labels itself as a preview and
discards submitted text immediately.  Once Quickshell is available in a
graphical session, run it with:

```sh
quickshell -p /usr/share/r8q/omarchy/lock/Preview.qml
```

When testing from the source tree before deployment, pass the corresponding
absolute path to `Preview.qml`. The runtime preparer places Service, LockView
and Keypad at the canonical `shell/plugins/lock/` paths and retains the pinned
upstream implementation as provenance. It includes the lock PAM and DPMS
helper. Provision the private numeric account credential and key-only recovery
before starting this profile; no PIN is stored in QML, JSON or Git.

Service.qml derives from pinned Omarchy c668141e; the accompanying LICENSE
preserves its MIT copyright and permission notice.
