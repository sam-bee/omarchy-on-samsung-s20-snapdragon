# R8Q selective Omarchy desktop

This document describes the reviewed SM-G7810 desktop payload. It records a
reproducible preparation path. The bounded Quickshell shell starts automatically
as `alarm` on the phone; its physical Qt plugin buttons still await user touch
validation.

## Packages

The review manifest is [rootfs/usr/share/r8q/omarchy/omarchy-runtime.packages](../rootfs/usr/share/r8q/omarchy/omarchy-runtime.packages).
The first synchronized official Arch Linux ARM transaction should query the
complete dependency closure and retain its signed receipt. The intended shell
names are `quickshell`, the three XDG portals, `wl-clipboard`, `wtype`,
`inotify-tools`, `hypridle`, `squeekboard`, `python-gobject`, `gtk3`, `jq`, `perl`,
`gum`, `libbsd`, `libmd`, and the available JetBrains Mono Nerd font package.
`libbsd` and `libmd` cover the packaged Squeekboard runtime's undeclared
shared-library closure. The resolver may add the Quickshell/portal Qt6,
PipeWire, polkit, PAM, Wayland and graphics dependencies.

Do not install `omarchy-settings`, the full `omarchy` package, SDDM, Mac/Asahi
packages, firewall or a general power-management stack for this gate. The full package
pair has broad dependencies and global hooks; the phone runtime is a source
overlay. A synchronized transaction is a bounded phone operation and must
preserve the existing kernel, firmware, boot, network and SSH package baseline.

## Pinned official source inputs

These pins and archive digests are part of the tracked audit. The runtime shell
source is Omarchy v4.0.4 at commit
[`c668141e9c42b13c80c9ca4ea108e11708c5e8a5`](https://github.com/omacom/omarchy/tree/c668141e9c42b13c80c9ca4ea108e11708c5e8a5),
from `basecamp-omarchy-c668141e9c42b13c80c9ca4ea108e11708c5e8a5.tar.gz`,
SHA-256 `8cc6b1d9d903c606600395e3b3d80ad9f15bd3ab78f0f19b0f49041b1df82013`.
The Quattro audit source is Omarchy commit
[`b5589faaf80c6f87c07d4560fca37c4a81722f28`](https://github.com/omacom/omarchy/tree/b5589faaf80c6f87c07d4560fca37c4a81722f28),
archive SHA-256
`8f1dab7ebcaca7815dbd7d13484499defc8f49b1b8754a703bb8fb20cbba34ca`.
The Mac/ARM comparison is
[`omacom/omarchy-mac@09f16de292febfc76225dee11ffa64497fc6f30d`](https://github.com/omacom/omarchy-mac/tree/09f16de292febfc76225dee11ffa64497fc6f30d),
archive SHA-256
`580f944ee6aff3528acbe8d55d8a2ba8b549b318a0262af95dd22e7d6b2a690d`.
The package recipe is
[`omacom/omarchy-pkgs@0a906801f1a876a739a6de902c9a366d295f43c9`](https://github.com/omacom/omarchy-pkgs/tree/0a906801f1a876a739a6de902c9a366d295f43c9),
archive SHA-256
`7929eb568cd08a062871c35eb9a1abdede644f95eabc058cd840fcf37d91bbe7`.

The preparer accepts only the c668 runtime archive and its pinned digest. The
other snapshots are audit evidence for the Quattro package and Apple-specific
installer comparison; no Mac installer or global Omarchy settings hook is part
of the phone payload.

## Offline preparer

Run the stdlib-only preparer on the laptop with a caller-supplied archive and a
new directory below `r8q-arch/out/`:

```text
python3 r8q-arch/scripts/prepare-omarchy-runtime.py \
  /absolute/path/basecamp-omarchy-c668141e9c42b13c80c9ca4ea108e11708c5e8a5.tar.gz \
  --expected-sha256 8cc6b1d9d903c606600395e3b3d80ad9f15bd3ab78f0f19b0f49041b1df82013 \
  --output /absolute/path/r8q-arch/out/omarchy-runtime-preparation-<fresh-id>
```

The expected hash and source commit are fixed in the script and in the pinned
source manifest. The preparer hashes the archive before reading it, copies only
`shell/`, `default/omarchy/`, the upstream `config/omarchy/shell.json`,
`bin/omarchy-launch-shell`, `bin/omarchy-shell`, `bin/omarchy-theme-bg-set`,
Tokyo Night's `colors.toml`, its `0-winding-road.jpg` and `1-quattro.jpg`
wallpapers, the Foot and Hyprland theme templates, `version`, and `LICENSE`,
then copies the tracked phone overlay from
`rootfs/usr/share/r8q/omarchy/`. The upstream shell config is retained as
`config/omarchy/upstream-shell.json`; the reviewed phone config becomes the
canonical `config/omarchy/shell.json`, with the package manifest and reviewed
phone helper/plugin files staged alongside it. Each change is recorded in
`manifest.json`, which also has SHA-256, byte count and mode for every regular
output file plus the two intentional absolute `/usr/bin` symlink targets. It
refuses an existing output directory and live/system paths. It performs no
network access, package operation, system configuration change, archive-script
execution or phone action.

The output represents a rootfs tree. Its runtime destination is
`/usr/share/omarchy`; the phone-specific source/provenance payload is retained
at `/usr/share/r8q/omarchy`. The preparer does not modify
`scripts/prepare-arch-rootfs.py` and does not auto-enable any unit.

## Manual deployment review

After recording the signed package receipt and preparer manifest, manually
copy the staged `rootfs/usr/share/omarchy` tree to the phone's
`/usr/share/omarchy`, preserving the existing filesystem and ownership policy.
Retain `/usr/share/r8q/omarchy` as the review/config source. Copy the
reviewed `phone-shell.json`, theme and `r8q.launcher` plugin into the normal
`alarm` user's corresponding `.config`/`.local/state` paths only after saving
the prior files. A user `~/.config/omarchy/shell.json` takes precedence over
the staged default, so keep it absent or byte-identical to the staged phone
config for this first gate. Set `OMARCHY_PATH=/usr/share/omarchy` in the
bounded desktop environment. Do not run an upstream `install.sh`,
`omarchy-settings` hook, first-run provisioning or package build script.

Before starting the desktop, check the manifest hashes on the target, verify
that only the two expected `/usr/bin` symlinks were added, and retain a copy of
the known-good Hyprland configuration for rollback. The manual procedure is
deliberately separate from the rootfs preparer; retain the rollback copy until
the bounded desktop checks complete.

## Service ordering

The tracked `r8q-desktop.service` is a normal-user service. Its recorded
ordering is:

```text
r8q-usb-route.service
  -> r8q-gpu.service and r8q-touch.service
  -> seatd.service
  -> r8q-desktop.service (alarm, private /run/r8q-desktop, seat groups)
```

The desktop service is guarded by the selected Lua, launcher, user shell
config and `r8q.launcher` manifest/QML paths. Its session helper verifies the
simpledrm display by-path, DSI-1 connection, Adreno render by-path,
`/run/seatd.sock`, required commands and Squeekboard's resolved libraries
before it runs `dbus-run-session -- start-hyprland`. Startup updates the shared
activation environment with `dbus-update-activation-environment --all`; it does
not import a nonexistent user-manager environment. The phone Lua starts the
already reviewed Squeekboard helper, launches `omarchy-launch-shell`, and starts
the separately configured display-only `hypridle` daemon. It
does not invoke Omarchy's power, idle, monitor-watch, automount, lock or
first-run hooks. Do not change the existing MAX77705 route ownership or add a
display manager.

The desktop unit requires only the USB route, GPU, touchscreen and seatd. It
keeps an `After=r8q-battery.service` ordering edge for deliberate sequential
trials, but has no `Requires` or `Wants` edge to activate battery drivers.
Leave `r8q-battery.service` disabled for UI boots. A battery trial must stop or
disable the desktop, complete separately, and only then permit an explicitly
started desktop; the battery helper rejects an already-running compositor.

## Battery acceptance status

Two cable-attached battery-only boots, identified by boot-ID prefixes
`0961d59a…` and `e8a91236…`, loaded the fuel-gauge, MAX77705 MFD and charger
modules. Both nevertheless failed acceptance: IRQ 215 produced an unhandled
storm and reached the 100,001 event cap before the kernel disabled the IRQ.
On the repeat boot, a sample at 62 seconds already showed about 67,000
unhandled events while telemetry still answered; the storm therefore preceded
the GENI SE0 timeouts. These are partial probe results, not a successful battery gate. The
battery service's automatic startup is disabled for the UI profile, and no
fully accepted charger or fuel-gauge runtime is claimed.

An isolated three-second regmap trace around a guarded battery start captured
2,377 successful INTSRC register `0x22` reads, all zero, plus the driver's
expected charger-unmask write. GPIO11 was low before and after; all 2,969 IRQ
deliveries were unhandled at capture end. The trace requested no extra I2C
transactions and was removed after capture. Zero status reads explain the
mainline handler's `IRQ_NONE`, but do not establish an electrical or device-tree
fix. The `spmi-gpio` hwirq10 is the expected zero-based encoding of GPIO11.
The next charging step is to resolve the stock pin/interrupt-source configuration
before changing polarity, bias, masks or IRQ handling.

## Desktop acceptance status

On 2026-10-10, boot `86957fa4-216c-4a47-b5ef-d84b6349d1a0` automatically
started the desktop as `alarm` with battery autoload disabled. Hyprland,
Quickshell, Squeekboard and the plugin monitor remained running with zero
service restarts through the final check more than six minutes after startup.
The bar and keyboard rendered at the expected portrait scale; the clock and
phone controls did not overlap. USB SSH and key-only Wi-Fi SSH both recovered.
Deployment and protected recovery hashes passed, no units failed, no MAX
modules were loaded, and no IRQ-storm or SE0 timeout appeared on this UI boot.

The portal ScreenCast, Screenshot and FileChooser version queries answered on
the private desktop bus. An actual portal transaction has not been tested.
The remaining Quickshell app-ID warning did not prevent rendering or these
queries. The earlier GTK touch/typing test passed, but a bounded passive
capture on this boot recorded no physical input. TERM/KB native Qt control
acceptance remains pending the operator's test. This gate does not establish
suspend, untethered boot or charging headroom for arbitrary applications.

## Recovery and SSH

Keep the USB MAX77705 recovery path and both USB and wireless SSH paths live
throughout package, config and reboot gates. Stop on any failed route, missing
SSH path, unexpected compositor process or changed BOOT/DTB/ESP/userdata hash.
The rollback is the saved Hyprland Lua/config, removal of the user shell
overlay and stopping the bounded desktop service; it does not involve a boot,
filesystem or firmware rewrite. Never enable UFW or an Omarchy service batch
while SSH recovery is still a required invariant.

## Hardware gates

The primary agent should pass each gate independently:

1. Confirm signed package metadata, architecture, complete transaction list and
   unchanged kernel/firmware/boot/network package set.
2. Run `Hyprland --verify-config` with the phone Lua, then verify DSI-1 portrait
   `1080x2400`, scale 2, simpledrm display and Adreno render path.
3. Verify the Zinitix touchscreen identity transform and physical touch in a
   Wayland app; verify Squeekboard visibility and text entry through the
   existing helper.
4. Start the limited Quattro shell as `alarm`; verify the bar, `TERM` foot
   button, keyboard toggle and no unexpected first-party service process.
5. Recheck both SSH routes, USB/MAX77705 route ownership and hashes after a
   bounded UI reboot/soak. Battery-driver acceptance remains a separate gate.

Display blanking has its own configuration and acceptance below. Suspend,
power-profile, firewall, SDDM, bootloader, filesystem and Apple-specific hardware
gates remain separate.

## Current limited shell

The actual current Omarchy shell is Quickshell, not a Waybar-labelled
substitute. The phone configuration enables workspaces, a clock, the image
background, audio controls and the small `r8q.launcher` plugin. The plugin's touch-sized
controls launch `foot`
and call the verified `sm.puri.OSK0.SetVisible` session method. Notifications,
Bluetooth, network, power, battery, idle, lock, OSD and polkit plugins
are explicitly disabled until their phone package and hardware gates pass.
The earlier GTK3 touch/application and Squeekboard text-entry trial passed;
that does not establish physical touch on the native Qt plugin buttons. The
current root overlay places the clock on the right with no center anchor, as
verified in the current deployment.

## Wallpaper gate

The first desktop gate disabled `omarchy.background` and used a solid Tokyo
Night background. The current phone configuration enables the upstream
background renderer. Hyprland's own default image remains disabled with
`misc.disable_hyprland_logo = true`,
`misc.disable_splash_rendering = true`, `misc.force_default_wallpaper = 0`,
and `misc.background_color = 0xff1a1b26`. Hyprland documents that
`background_color` requires `disable_hyprland_logo`, and that
`force_default_wallpaper` values 0 or 1 disable the anime background
([official variables reference](https://wiki.hypr.land/Configuring/Basics/Variables/));
the same `force_default_wallpaper` form appears in the pinned Omarchy Lua
source at `default/sddm/hyprland.lua`. `Hyprland --verify-config` passed on the
phone during the first gate, and the post-reboot screenshot confirmed the
solid Tokyo Night color.

The current preparer preserves the original bytes of two wallpapers from the
pinned v4.0.4 archive under `/usr/share/omarchy/themes/tokyo-night/backgrounds/`.
The usual `0-winding-road.jpg` is the initial selection; `1-quattro.jpg` is the
rally-car alternative. The upstream renderer uses `Image.PreserveAspectCrop`
with the Qt default center alignment: it scales uniformly to fill the display
and crops the sides of a landscape image on the portrait panel. It does not
distort the image's proportions. No edited or regenerated bitmap is needed
([Qt Image reference](https://doc.qt.io/qt-6/qml-qtquick-image.html#fillMode-prop)).

Before deploying the updated Lua, copy the reviewed theme files from
`/usr/share/r8q/omarchy/theme/tokyo-night/` to
`/home/alarm/.local/state/omarchy/current/theme/`, owned by `alarm`.
The Lua loads `hyprland.lua` from that directory. The Foot and Hyprland theme
files were generated using the pinned upstream `omarchy-theme-color` and
`omarchy-theme-set-templates` helpers with only their two staged templates in
an isolated offline HOME. They preserve upstream output exactly; the shell
palette and generated shell theme remain the existing Tokyo Night files.
Copy `phone-foot.ini` to `/home/alarm/.config/foot/foot.ini` after backing up
any prior config; it includes the current theme's Foot colors. Record
`tokyo-night` in `~/.local/state/omarchy/current/theme.name` and create
`~/.local/state/omarchy/current/background` as an `alarm`-owned symlink to the
selected wallpaper. Install the theme state before the Lua and shell configs.

To switch either supplied image from the phone's normal desktop terminal, use
`omarchy-theme-bg-set /usr/share/omarchy/themes/tokyo-night/backgrounds/1-quattro.jpg`
(substitute `0-winding-road.jpg` to restore the initial choice). The Lua already
puts `/usr/share/omarchy/bin` on the session PATH. The graphical image picker
remains disabled, and its selector helpers and the full theme installer are
excluded from this phone payload.

On 2026-10-10, the primary validated both generated configs on the phone,
applied the theme to the running desktop, and visually checked its original
1080x2400 screenshot. The centered wallpaper survived plugin re-instantiation
without an image IPC call, and a temporary Foot window rendered the Tokyo
Night foreground, background and ANSI colors. The test restored keyboard
visibility and left no temporary app clients. Hyprland and Quickshell retained
their PIDs, with zero desktop service restarts. The new UI checksum baseline is
`/root/r8q-desktop-tokyo-night.sha256`; the previous 140 baseline remains a
historical receipt. USB and wireless SSH and the protected payload hashes
passed. This change was checked through live config/plugin reloads, not a new
phone reboot.

The source/runtime pins and archive hashes are recorded above in this tracked
document; the tracked phone files are under `rootfs/usr/share/r8q/omarchy/`.
The ignored preparation directory may retain the downloaded snapshots and
manifests, but it is not required as the source of the audit record. This
source preparation has been validated on the laptop by staging the pinned local
archive into a fresh output and independently checking all manifest hashes. The
phone's rendered shell observation is complete; physical control acceptance
remains a separate gate.

## Idle blanking and side button

The phone profile starts `hypridle` with
`/usr/share/r8q/omarchy/phone-hypridle.conf`. After 300 seconds without seat
input it disables DPMS on `DSI-1`. The Lua binds a short Side/Power press on
release to a delayed DPMS toggle: one press blanks the display, another wakes
it. Automatic key/mouse wake and hypridle's `on-resume` action are disabled
so that a wake event cannot race the button toggle. Wake uses the side button;
touching the dark screen does not wake it. Idle inhibitors retain their default
behavior, so an application may intentionally keep the screen awake.

This policy does not start a lock screen or suspend Linux. The normal desktop,
USB route and Wi-Fi continue running. The display currently uses `simpledrm`:
its plane-disable implementation clears the firmware framebuffer to black.
The observed DRM `active=0` state and compositor DPMS status establish blanking;
they do not establish panel rail power-off or system suspend.

Deploy the signed phone `hypridle` package and both phone profiles before
updating the session. The offline preparer stages the idle profile under both
`/usr/share/r8q/omarchy/` and `/usr/share/omarchy/`. Separately install the
tracked `rootfs/etc/systemd/logind.conf.d/50-r8q-screen-button.conf` into the
phone's `/etc/systemd/logind.conf.d/`, along with the updated session helper.
The logind drop-in disables its poweroff action for the same button. Apply
with `systemctl reload systemd-logind` on the current `Type=notify-reload`
unit, then verify `HandlePowerKey` and `HandlePowerKeyLongPress` both return
`s "ignore"` via the login1 Manager D-Bus properties. Save the previous files
before replacement. Reload Hyprland and start hypridle within the desktop
session for an existing boot; the `hyprland.start` hook starts it on future
desktop sessions. Keep Omarchy's full idle/power/lock plugins disabled.

From a terminal in this desktop, SSH recovery can explicitly wake with:

```sh
hyprctl dispatch 'hl.dsp.dpms({ monitor = "DSI-1", action = "enable" })'
```

An SSH shell must run that command as `alarm` with the current compositor's
`XDG_RUNTIME_DIR=/run/r8q-desktop` and `HYPRLAND_INSTANCE_SIGNATURE`. Record
the real 300-second idle transition and physical Side/Power wake separately
from direct dispatcher tests. Recheck both SSH routes and the desktop PID after
testing. The current file baseline is `/root/r8q-desktop-screen-off.sha256`;
the wallpaper baseline is retained as a historical receipt. Backups and
ownership/mode metadata are in `/root/r8q-screen-off-backup/`.

The timer, bind flags and DPMS fields follow the official
[Hyprland dispatcher reference](https://wiki.hypr.land/configuring/core/dispatchers/)
and [hypridle configuration](https://wiki.hypr.land/Hypr-Ecosystem/hypridle/).

## Internal speaker audio

The desktop now starts PipeWire, WirePlumber and pipewire-pulse inside its
private D-Bus session. The Phone speakers output uses software volume, exposed
by the Omarchy audio panel and physical volume buttons. See
[r8q-audio.md](r8q-audio.md) for the protected driver/firmware path, exact-release
startup, packaging and recovery details.
