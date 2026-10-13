# Phone screen locking

The phone uses Quickshell's native Wayland session lock. The phone-owned
Service, LockView and numeric Keypad replace the pinned Omarchy plugin's
canonical files; the runtime preparer retains upstream files as provenance.
Service.qml derives from Omarchy c668141e and carries the adjacent MIT LICENSE.

## Authentication

The operator selected a four-digit PIN and entered it privately on the phone.
The service accepts 4–12 digits and authenticates the alarm account through
/etc/pam.d/r8q-lock. The PIN is the account's local Unix password, separate from
any later LUKS passphrase. No credential is stored in QML, JSON, scripts, logs
or Git. Input is cleared before submission; the pending secret is cleared
when passed to a hidden PAM prompt. Unsupported prompts and a 15-second
check timeout fail without releasing the lock. Fingerprint is disabled.

The dedicated PAM stack has no nullok. Five failures within five minutes
impose a 30-second pause. Its tally is separate under /run/r8q-lock-faillock.
The tally is owned by alarm with group root. PAM can change mode 0600 to 0660;
group root restricts that extra access to administrators.

The built-in keypad supports digits, backspace, Clear and Unlock without
Squeekboard. Physical keyboard entry works after focusing the masked field.
The view scrolls on short displays and supplies accessible controls. The
90-second r8q-lock-preview remains a labelled, unauthenticated test overlay.

## Display policy

r8q-screen-lock is a credential-free alarm-session helper. It waits for
requested, sessionLocked and secure; secure is the compositor acknowledgement.
The blank action requests and confirms a lock before disabling DSI-1 DPMS.
blank-confirmed refuses an unconfirmed lock. power locks/blanks an awake
screen or wakes a protected one. wake never releases the session lock.
Idle uses blank at five minutes; the lock view blanks after one minute
without interaction. Input and authentication keep the lock view awake.

Startup disables DPMS before launching ordinary clients. The startup helper
starts the shell, waits for secure coverage, then lifts the curtain and starts
the keyboard/idle client. Failure retains the curtain for authenticated SSH
recovery. Fresh shell instances also lock once PAM loads, preserving upstream
orphan-lock recovery. No unlock IPC method exists; PAM success releases it.

## Administration and provisioning

Root console autologin is removed. The live root password is locked. SSH uses
public keys only, with password and keyboard-interactive login disabled. A
fresh pinned USB key connection passed after root password locking. Authorized
administrators can still manage the phone while the screen is locked.

Provision the private alarm PIN, key-only recovery and locked root password
before starting this profile on a fresh image. The preparer never creates or
copies a credential. Check sshd -T: OpenSSH's first obtained value wins; a
later drop-in cannot override an earlier unsafe explicit setting. The live
phone's first-position block was validated before reload.

Run r8q-screen-lock status as alarm with the running desktop's Wayland,
Hyprland and D-Bus environment. Use authenticated USB SSH for failures. Ending
the lock client is not an unlock method: the compositor retains its failsafe.

This protects the session. USERDATA remains plaintext until the separate
encryption migration. The unlocked bootloader/recovery path remains a
physical-access boundary, and session keys remain in memory.

## Validation

Actual ARM Qt 6.11.2/Quickshell 0.3.1 keypad tests report nine passes. The final
service passes Qt's formatter/parser. Three helper tests reject optimistic
lock requests and prevent blanking after failed confirmation. An isolated PAM
probe rejected empty and nonnumeric synthetic credentials, recorded exactly
two failures and cleaned its separate policy/tally. It never read or tried
the real PIN.

Initial native activation confirmed requested=true, sessionLocked=true and
secure=true. Human wrong/right PIN, side-button wake, idle and shell/compositor
restart acceptance are recorded in the project log and ignored
out/screen-lock-20261013 receipts as they complete.

References: [WlSessionLock](https://quickshell.org/docs/v0.3.1/types/Quickshell.Wayland/WlSessionLock/),
[PamContext](https://quickshell.org/docs/v0.3.1/types/Quickshell.Services.Pam/PamContext/),
and [Linux-PAM faillock](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_faillock/pam_faillock.8.xml).
