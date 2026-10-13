# Linux on the Samsung Galaxy S20 FE 5G (`r8q`)

This fork builds on [sitsirK/r8q-arch](https://github.com/sitsirK/r8q-arch),
which brought mainline Linux and Arch Linux ARM to the Snapdragon S20 FE,
with display, GPU, touch, networking and charging support. Thanks to sitsirK
and the [Mu-Silicium](https://github.com/Project-Silicium/Mu-Silicium) UEFI
contributors for the foundation.

Our additions, developed on the Hong Kong **SM-G7810**, include:

- **Omarchy:** selected shell and theme components on a Hyprland phone desktop,
  with an on-screen keyboard, battery/charging indicators and Tokyo Night styling.
- **Reliable startup:** portable builds, boot diagnostics, unattended USB SSH
  recovery, coordinated hardware startup and persistent RTC timekeeping.
- **Audio:** protected internal stereo speaker playback integrated with PipeWire
  and the desktop's volume controls.
- **Power management:** idle screen blanking, side-button wake, automatic Wi-Fi
  power saving and measured reductions in battery draw; battery-only and
  wall-powered startup, conservative charging safeguards, and further deep-idle
  mitigation work.

System suspend, native panel power-off and faster charging remain unfinished.

For setup, read [prerequisites](PREREQUISITES.md) and
[installation](INSTALLATION.md); installation wipes userdata. Details of our
additions are in the [desktop](docs/r8q-desktop.md),
[audio](docs/r8q-audio.md) and [charging](docs/r8q-charging.md) notes.

A [touch-lock keypad preview](docs/r8q-lock.md) and
[optional encryption prerequisites](docs/r8q-encryption.md) are prepared for
further testing; automatic locking and encrypted-root boot are not enabled.
