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

The tracked `r8q-desktop.service` is a normal-user service. The standalone
profile's startup graph is:

```text
r8q-hardware-prepare.service
  -> r8q-usb-gadget.service, r8q-gpu.service, r8q-touch.service,
     r8q-wifi.service, NetworkManager.service
  -> r8q-battery.service (after touch; before desktop/audio)
  -> r8q-audio-start.service and r8q-desktop.service
     (desktop also requires GPU, touch and seatd)
```

`r8q-hardware-prepare.service` is the sole early GPI/GENI owner. It runs the
source-bound route wrapper in optional mode: exact no-VBUS/unplugged and wall-DCP
sink tuples are successful deferred route results with no UIC reads or mailbox
writes, while an SDP laptop source uses the existing guarded UIC/opcode/
response/CONTROL1 transaction. The wrapper retains its identity, hash,
module-ownership, status, water/error and active-MAX guards in every mode.

The legacy `r8q-usb-route.service` remains installed as a read-only current-boot
route witness, but the rootfs profile disables it by default and no desktop,
Wi-Fi, NetworkManager, gadget or battery service requires it. It never invokes
the raw helper a second time. Cable-left-in USB route recovery remains covered
by the preparation unit; first USB recovery insertion and unplug/replug after
MAX bind still require physical testing and a kernel-owned MUIC/USBC/DWC3 event
path.

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

The desktop unit now requires hardware preparation, GPU, touchscreen, battery
and seatd. The battery helper starts before the compositor and rejects an
already-running compositor; the graph therefore treats the charger/telemetry
owner as a startup gate while keeping USB host configuration optional. The
gadget and network paths remain separate capabilities after hardware
preparation succeeds.

## Battery acceptance status

Standalone review point 1 is complete for the normal USB-host case: two
cable-attached automatic starts passed with battery autoload enabled. The
corrected persistent audio DTB is now the charger-startup baseline. Its
`max77705-int-default-state` has GPIO11 `bias-pull-up` and VIN selector 1, and
tracked DTS compilation reproduces deployed DTB SHA-256 prefix `d3a06549…`.
Two fresh cable-attached automatic starts, boot IDs
`83cb3e73-81e6-49ae-a627-2dc4920e9262` and
`822d6a6d-1fe6-4dbb-8fab-d8b7506df9f6`, ran with battery autoload enabled.
Each completed 25 samples over about six minutes with zero parent/charger/
CHGIN/AICL IRQ deliveries and zero unhandled counters, no IRQ disable or
MAX/SE0 journal fault, Good telemetry, 24 C temperature and unchanged
500000 uA input/charge limits. Desktop, audio, touch, GPU, Wi-Fi,
NetworkManager and both SSH paths passed on both boots.

| Boot | Mean sampled net current | Gauge charge |
| --- | ---: | ---: |
| `83cb3e73…` | +13162 uA | 3052000 -> 3057000 uAh |
| `822d6a6d…` | +21712 uA | 3061000 -> 3066000 uAh |

Normal USB-host and wall-power charger startup are accepted. The corrected
wall boot `668d5aac-691b-4b50-8bae-85b146dddcda` reached hardware, battery,
desktop, audio, GPU, touch, Wi-Fi, NetworkManager, SSH and UI readiness.
Its 25-sample monitor spans 359.98 s, has stable 500000-uA readbacks,
Good telemetry at 24 C, no unhandled IRQs or MAX/SE0 faults in the full
770-line kernel journal, and mean sampled net current +50599.96 uA.
Gauge charge rises 3156000 -> 3162000 uAh. Parent/charger/AICL totals stay
at two handled initial events and CHGIN stays zero. The startup health
guard passes. These idle-desktop/blanking measurements do not establish
heavy-load charging headroom.

Battery-only startup is accepted on boot
`b8346b4a-547f-421c-814e-7d54c21795d1`. Hardware, battery, desktop, GPU, touch,
Wi-Fi, NetworkManager, audio and SSH start with no cable. The source receipt
records canonical zero BC/CC/no-VBUS deferral, zero UIC reads and zero mailbox
writes. All 25 samples over 360 s show healthy fuel telemetry at 24 C, stable
500000/100000-uA input/charge settings, all four IRQ counters zero and no
charger/SE0 faults in the full 770-line kernel journal. Mean sampled current
is -551787.24 uA and charge falls 3145000 -> 3091000 uAh. Startup performs zero
limit writes, the automatic health guard passes, and the actual UI shows
`BAT↓ 77%`. This establishes bounded operation without a laptop, not discharge
endurance.

First host insertion after MAX bind also passed on this same battery-started
boot: a 25-sample/two-minute capture records online=0 -> 1 and UDC not attached
-> configured. The laptop enumerated `1d6b:0104`, its existing USB NIC regained
172.16.42.2, and direct pinned USB SSH succeeded without a reboot or laptop
configuration changes. Parent/charger/CHGIN totals rose 0 -> 1 with zero
unhandled counts; AICL remained zero and the full journal has no charger/SE0
faults. The 500000/100000-uA settings were retained and later gauge readings
show modest positive current. This establishes the observed insertion and
SSH recovery, not general USB-C role/negotiation support.

The subsequent laptop-to-wall transfer on that boot also passed a 25-sample/
120-s capture: source 1 -> 0 -> 1, parent/charger/CHGIN totals 1 -> 3,
AICL zero, healthy telemetry and no charger/SE0 faults. Wi-Fi SSH continued
with the laptop USB device/NIC absent. UDC remained stale `configured` after
removal, so source detection uses charger online rather than UDC state.
Both cable captures retained 500000/100000-uA settings. Lower firmware charge
settings can therefore persist after insertion; this work adds no automatic
increase or throughput guarantee. The temporary startup rollback guard is now
disabled after acceptance; original profile backups and protected manifests
remain available. Hardware preparation, battery, desktop, Wi-Fi and gadget
startup remain enabled.

The route witness remains disabled by default; the existing raw MUIC/USB-C
route helper must not be called after MAX bind.

### Conservative charger cap

Wall firmware can expose inherited limits higher than the safe review budget.
The first wall-power observation showed `input_current_limit=1750000` uA and
`constant_charge_current=2100000` uA, with AICL later reporting `1225000` uA.
The driver-owned `r8q-battery` startup helper now applies a conservative
`500000`-uA cap after bounded healthy-charger checks. It prevalidates both
inherited values in the accepted `100000..3200000`-uA range before any write.
Values at or below the cap are retained unchanged; only values above the cap
are lowered, and malformed or out-of-range values fail closed. The input setter
uses a `475000`-uA write because that driver's encoding reads back `500000` uA;
the charge setter writes `500000` uA. Final readback must equal the retained
original value or `500000` uA when lowered. No automatic BC1.2 higher-current
policy is added, and heavy-load charging headroom remains unverified.

### Battery indicator and warnings

The `r8q.battery` shell plugin reads
`/sys/class/power_supply/max170xx_battery` and
`/sys/class/power_supply/max77705-charger` directly. It keeps charger `online`
separate from gauge net current because the fuel gauge remains IRQ-less and
reports `POWER_SUPPLY_STATUS=Unknown`, while the charger can report
`Charging` during a negative-current sample. The bar uses `USB↑` for a
confirmed source with positive current, `USB↓` for a confirmed source while
the pack is under load, `BAT↓` for negative current without a confirmed source,
and `USB?`/`BAT?` when direction or source is unknown; it never turns unknown
status into `CHG`.

The warning policy enters low at credible capacity <=10% and critical at <=5%.
Low clears above 15%, critical clears above 10% and may first return to low,
and each hysteresis transition produces at most one notification. Missing or
invalid readings preserve the last delivered band and cannot re-arm a warning.
A labeled critical-urgency test notification rendered in the actual shell,
and wall screenshots show both `USB↑ 77%` and `USB↓ 77%`. Threshold fixtures
passed. Polling runs every 30 seconds and notifications respect existing DND. Actual 10%/5%
depletion and warning delivery at those thresholds remain untested, as does a
discharge endurance test.

With no cable, the pinned driver can report charger `online=0`,
`status=Discharging` and `health=Unspecified failure` from its offline
`BAT_DTLS` default. Startup accepts only offline `Good` or `Unspecified failure`
with `Discharging`; online charger health must be `Good`. Both paths still
require a healthy, present fuel gauge with plausible telemetry.

## Desktop acceptance status

On 2026-10-10, the earlier UI-only boot `86957fa4-216c-4a47-b5ef-d84b6349d1a0`
automatically started the desktop as `alarm` with battery autoload disabled.
The later normal cable-attached profile uses the accepted battery autoload
described above. Hyprland,
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
   bounded UI reboot/soak. USB-host, wall-charger and battery-only startup are accepted; post-bind
   host insertion and direct USB SSH also passed on the battery-started boot.

Display blanking has its own configuration and acceptance below. Suspend,
power-profile, firewall, SDDM, bootloader, filesystem and Apple-specific hardware
gates remain separate.

## Current limited shell

The actual current Omarchy shell is Quickshell, not a Waybar-labelled
substitute. The phone configuration enables workspaces, a clock, the image
background, audio controls, the direct-telemetry `r8q.battery` plugin and the small `r8q.launcher` plugin. The plugin's touch-sized
controls launch `foot`
and call the verified `sm.puri.OSK0.SetVisible` session method. Notifications
are enabled for passive battery warnings. Bluetooth, network, power, generic Omarchy battery, idle, lock, OSD and polkit
plugins remain explicitly disabled. The selected battery plugin has no power
action. Warning rendering passed a labeled test; actual low-charge depletion
remains untested.
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

## Wi-Fi standby policy

The phone-local `r8q-wifi-standby.service` changes only
`iw dev wlp1s0 set power_save on/off`. It enables saving when `DSI-1` reports
DPMS Off, MAX77705 reports offline/Discharging, the fuel gauge is present and
healthy (15–100%, 0–40 C, 2.5–4.5 V), and Wi-Fi is associated. It requests Off
when any condition fails. Display/source/carrier checks run every two seconds;
association and actual runtime-state checks run every ten seconds. Commands
have five-second limits, so transitions may take longer if a command stalls.
Normal exit and separate `ExecStopPost` cleanup both restore Off, with two
bounded attempts. NetworkManager's saved powersave setting remains `2` (Off).
No PCI/ASPM, charger-limit, CPU-idle or display policy is changed by this service.

Install the helper at `/usr/local/sbin/r8q-wifi-standby.py` and the unit at
`/etc/systemd/system/r8q-wifi-standby.service`. Verify the helper/unit hashes,
reload systemd and test runtime behavior before enabling the unit for boot.
`/run/r8q-wifi-standby/status.json` records the last decision without SSID/BSSID
information. Stop or disable the service to return to the saved Off default.

The October 11 repeated blank-display off/on/off/on comparison passed 52
samples and all CPU, fuel, IRQ, association and restoration checks. Average
battery draw was 452.4 mA Off versus 357.4 mA On: 95.0 mA/21.0% lower.
Charge movement independently corroborated approximately 460 versus 360 mA.
Mean monitored idle power with saving enabled remained about 1.41 W, with
temperature stable at 24 C. Wi-Fi SSH worked in both enabled phases. This is
not a long-duration endurance or throughput acceptance claim.

The automatic policy passed dispatcher wake (Off in 0.76 s), reblank (On in
1.02 s), service-stop cleanup and restart. Actual wall-charger insertion also
selected Off; physical source removal selected On again. The service also
started automatically on fresh battery-only boot `548b2bc6…`. That boot passed
all five dispatcher/cleanup checks: wake selected Off in 2.04 s, reblank
selected On in 0.77 s, stop restored Off and restart selected On. All eight
CPUs retained zero deep-state usage throughout. The protected additive helper/unit baseline is `/root/r8q-wifi-standby.sha256`;
phone evidence is in `/root/r8q-standby-20261011/` and local receipts in
`out/standby-20261011/`.

## Standby kernel and USB status

Patch `0013-r8q-cpuidle-default-off.patch` translates the board-local
`samsung,r8q-cpuidle-off` property to `CPUIDLE_FLAG_OFF` when the idle driver
registers. Both r8q rail-power-collapse states carry the property. The states
remain visible for diagnostics; WFI and frequency scaling remain available.
The fresh battery-only boot `548b2bc6-dacb-4be3-9fed-dddea553049d` retained
`disable=1` and `usage=0` on all eight CPUs, with WFI and CPU accounting
advancing. This closes the window before the existing userspace workaround
runs. It does not repair the deep-idle implementation or establish suspend.
The initial candidate boot/peripheral checks passed; final candidate acceptance
is pending cable recovery and operator screen-wake checks. Protected desktop,
audio, graphics, Wi-Fi, standalone-startup and new standby manifests passed.

A temporary USB runtime-PM gate detached the configfs gadget and requested
autosuspend on the DWC3 child, PHY and legacy QCOM parent while on battery.
Although 48 samples reported all three suspended, the kernel logged
`dwc3-qcom-legacy a6f8800.usb: port-1 HS-PHY not in L2`. The gate failed:
the legacy callback reports success after that failed PHY invariant. All
cleanup paths restored the devices active and rebound the UDC. USB runtime-PM
remains at the accepted awake default; the longer USB power comparison is
unrun. A driver repair must pass a fresh suspend/resume gate and host-cable
enumeration before an automatic USB saving policy is considered.

Native panel power-off, deep idle/system suspend and discharge endurance remain
open. The current blank-display Wi-Fi-saving measurement is about 1.41 W.

## Internal speaker audio

The desktop now starts PipeWire, WirePlumber and pipewire-pulse inside its
private D-Bus session. The Phone speakers output uses software volume, exposed
by the Omarchy audio panel and physical volume buttons. See
[r8q-audio.md](r8q-audio.md) for the protected driver/firmware path, exact-release
startup, packaging and recovery details.
