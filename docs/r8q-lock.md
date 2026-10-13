# Phone lock preparation

The phone-oriented [LockView](../rootfs/usr/share/r8q/omarchy/lock/LockView.qml)
and [Keypad](../rootfs/usr/share/r8q/omarchy/lock/Keypad.qml) are presentation
components compatible with the pinned Omarchy c668 lock service. That service
owns PAM authentication and the native Wayland session lock. These components
do not implement either security primitive themselves.

The current deliverable is a safe preview, not an activated screen lock. The
phone's existing five-minute DPMS policy, Side/Power toggle, desktop startup
and recovery access remain unchanged. Omarchy's lock plugin remains disabled,
and no lock PAM file or user credential is provisioned by this preparation.

## Preview

The [preview](../rootfs/usr/share/r8q/omarchy/lock/Preview.qml) displays the
same keypad in an ordinary overlay. It clearly labels itself, discards
submitted text, offers a Close button, and exits after 90 seconds. The
[helper](../rootfs/usr/local/bin/r8q-lock-preview) adds an independent process
timeout. Run `r8q-lock-preview` as `alarm` from the existing phone desktop
environment; a remote launch must inherit that session's Wayland and D-Bus
environment. Do not type an actual personal credential into the preview.

Numeric input is handled inside the surface, with large keys, clear,
backspace and explicit submit. An explicit field tap supports text entry;
physical keyboard input is also supported if a working keyboard path exists.
Keypad actions request hiding the input method instead of repeatedly focusing
the field. This request does not prove how Squeekboard behaves on a native
session-lock surface. Shorter displays can scroll the keypad; buttons expose
accessible names and keyboard activation. Long-password dot fitting preserves
the full input value.

The rootfs overlay includes these files as provenance/staged assets. The
runtime preparer does not replace the upstream `shell/plugins/lock/LockView`
or enable the lock. Future integration must explicitly stage both `LockView`
and `Keypad` beside the upstream lock service in a reviewed candidate.

## Checks completed on 2026-10-13

The source view's synthetic input tests passed on the phone's Qt 6.11.2
runtime. A separate Quickshell 0.3.1 overlay rendered successfully on DSI-1 at
1080x2400, scale 2. The main Hyprland and Omarchy processes were preserved,
and the prior DPMS state was restored after capture. These checks establish
input logic and rendering only; human touch acceptance is pending.

See [the test instructions](../tests/r8q-lock/README.md) and
[encryption preparation](r8q-encryption.md).

## Gates before enabling a real lock

1. Confirm finger taps, backspace, clear, submit and scrolling on the phone.
2. Choose and privately set the session credential. Provision a narrow PAM
   policy with a non-empty credential, retry limits and verified success/error
   behavior. No plaintext PIN belongs in QML or JSON.
3. Adapt upstream wake/blank helpers to the existing phone DPMS policy. Wait
   for the compositor-confirmed secure lock state before blanking. Preserve
   Side/Power wake without permitting it to unlock the session.
4. Start locked after every compositor/service restart, and prove there is no
   exposed desktop during startup, failed authentication or lock-client crash.
5. Audit root tty autologin, USB SSH passwords, VT shortcuts and debug recovery
   paths. Preserve only intentional authenticated administration/recovery.

The upstream service permits password entry while fingerprint authentication
is armed. Fingerprint support is unproven on this port; enabling it later needs
its own driver/authentication review. Do not change that upstream concurrency
policy by treating a continuously armed fingerprint listener as an input lock.
