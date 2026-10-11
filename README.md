# Linux on the Samsung Galaxy S20 FE 5G (`r8q`)

Mainline Linux + **Arch Linux ARM** on the Samsung Galaxy S20 FE 5G Snapdragon
(codename **`r8q`**, SoC **SM8250 "kona" / Snapdragon 865**), booted through
**[Mu-Silicium](https://github.com/Project-Silicium/Mu-Silicium) UEFI** — not a
downstream Android kernel, the **real mainline kernel**.

Everything here exists so that **anyone with their own r8q** can reproduce it
from clean upstream sources: the device-tree change that lights the panel, the
kernel config, the switch-root initramfs, the systemd services, and a small set
of scripts that take you from a UEFI flash to a booting Arch install you can SSH
into.

> **Read [`PREREQUISITES.md`](PREREQUISITES.md) first** (unlocked bootloader,
> host packages, and the fact that this **wipes your userdata**), then follow
> **[`INSTALLATION.md`](INSTALLATION.md)**.

> **No proprietary firmware is shipped.** Storage, USB and display run on
> built-in mainline drivers with no firmware at all. GPU acceleration needs the
> Adreno 650 firmware from **linux-firmware** (`a650_sqe.fw`, `a650_gmu.bin`)
> plus the **Samsung-signed zap shader from your own device's stock firmware**
> (Samsung's TrustZone only accepts Samsung's signature) — see
> [`INSTALLATION.md` §9](INSTALLATION.md).

---

## What works today

| # | Milestone | State |
|---|-----------|-------|
| 1 | Mainline kernel boots — BusyBox/switch-root initramfs, output on the phone screen | ✅ |
| 2 | **UFS storage** — all LUNs and the full GPT show up as `/dev/sd*` (first try, no hacks) | ✅ |
| 3 | **Display** — a *persistent, live* mainline framebuffer console on the AMOLED panel | ✅ |
| 4 | **Arch Linux ARM + systemd** on userdata, root autologin on the panel (`tty1`) | ✅ |
| 5 | **SSH over USB** — `ssh root@172.16.42.1`, plus **USB tethering** (internet + `pacman`) | ✅ |
| 6 | **GPU acceleration** — Adreno 650 via freedreno/turnip (GLES 3.2 + Vulkan 1.3) | ✅ |
| 7 | **GNOME 50** on the panel — gdm autologin, mutter rendering on the Adreno (sway still available as a fallback) | ✅ |
| 8 | **Touchscreen** — STM FTS5CU56A multitouch, working under Plasma Mobile and GNOME; the Zinitix ZT7650 variant works too | ✅ |
| 9 | **Faster boot** — console `loglevel=3` (dropped `ignore_loglevel`) + a printk sysctl the initramfs can't override; ~12 s to userspace | ✅ |
| 10 | **Volume-Up key** — remapped to `pm8150l_gpios` gpio3, emits `KEY_VOLUMEUP` | ✅ |
| 11 | **Battery** — MAX77705 fuel gauge (`max17042`) telemetry **+ charging** (`max77705` MFD + charger) | ✅ normal USB-host, wall-power and battery-only startup accepted; post-bind USB insertion/SSH passed |
| 12 | **Wi-Fi** — QCA6390 over PCIe via `ath11k_pci` + MHI; `wlp1s0` scans and associates | ✅ |
| 13 | **KDE Plasma Mobile** — `sddm` autologin → mobile shell on the Adreno, ~12 s cold boot (GNOME still installed as a fallback) | ✅ |
| 14 | **CPU idle mitigation** — deep state1 is disabled on all eight CPUs; WFI and frequency scaling remain available | ✅ current monitored desktop keeps all eight CPUs live; deep-idle root cause and suspend remain unresolved |

| 15 | **Internal speaker playback** — protected CS35L41 stereo output through Q6AFE/ADSP and desktop PipeWire; survives reboot | Playback, startup and user listening check passed |

See the [**Roadmap**](#roadmap) below for what's next (Bluetooth, USB host mode,
capture audio, a greeter/lock screen). Internal speaker details are in
[docs/r8q-audio.md](docs/r8q-audio.md).

The CPU idle mitigation marks the two r8q rail-power-collapse states with
`samsung,r8q-cpuidle-off`. The cpuidle DT parser translates that property to
`CPUIDLE_FLAG_OFF` during driver registration, so the states remain visible
for diagnostics while architectural WFI and its counters remain available.
A fresh battery-only candidate boot (`548b2bc6-dacb-4be3-9fed-dddea553049d`)
reported `disable=1` and `usage=0` for state1 on all eight CPUs from the
startup acceptance check. This is a recoverable mitigation; it does not repair
the deep-idle implementation or enable suspend.

Mu-Silicium is
flashed to `BOOT`; the ESP is the `cache` partition reformatted vfat (`R8QESP`);
the rootfs is the `userdata` partition; the kernel is mainline **Linux 7.1.2**.

### Cable-left-in USB route recovery

The r8q rootfs includes a fail-closed, one-shot route check for the Samsung
MAX77705 USB controller. It is based on the exact SM-G7810 downstream source
snapshot `BeneficialCode/android_kernel_samsung_smg7810` at commit
`efbb7d3b9d0c36bd86bd098a9f0c9fc7cc6b2488`. At boot the helper reads
CONTROL1 with opcode `0x05`; it writes the stock AP route (`0x06`, payload
`0x09`) only when the guarded initial state is `COM_OPEN` (`0x3f`) or
`COM_USB_CP` (`0xa4`), then requires the chip's matching opcode response and
readback. An already-AP route is left unchanged, and failed identity, module,
status, or transaction checks stop without a retry.

On the SM-G7810 running `7.1.2-r8q-rtc2`, startup readback showed the open
route despite valid USB cable/SINK status. Selecting the AP route restored
USB enumeration and SSH with the cable connected. The persistent service
reproduced this through a warm reboot and an automatic restart following a
power-off request; no button presses or cable movement were required. The
power-off request automatically started the phone again while USB was connected,
so that test is not described as a manually controlled cold start.

The image preparation script installs the early hardware-preparation unit,
read-only route witness, helper, pinned protocol binding, and GENI FIFO modprobe
policy. The standalone profile enables `r8q-hardware-prepare.service` and
leaves the legacy `r8q-usb-route.service` disabled by default; the witness does
not invoke the raw helper a second time. The phone needs the `i2c-tools`
package (`i2ctransfer`); the package declaration is stored at
`usr/share/r8q/r8q-usb-route.packages` for the phone-side bootstrap. The host
does not install this package during image preparation.

The canonical early route decision is source-bound and fail-closed. The
hardware-preparation wrapper loads only the pinned GPI/GENI pair, validates
identity, hashes, module ownership and the MAX guard, then performs the
non-clearing PMIC/BC/CC reads. With `VBUSDet=0`, `CHGTYP=0`, unplugged
`CC_STATE=0`, `DCDTmo=0`, and a clear `CC_STATUS1` safety mask, it records a
deferred no-VBUS/no-host result with zero UIC reads and zero mailbox writes.
With `VBUSDet=1`, wall sink `CHGTYP=0x03` (DCP), `CC_STATE=1`, `DCDTmo=0`, and
the same clear safety mask, it records a deferred wall-DCP result with the same
zero-write property. Sink-without-VBUS, inconsistent BC/CC combinations,
source, water/short/overcurrent/error, unknown status, PMIC, and I2C failures
remain hard failures. A laptop SDP source (`CHGTYP=0x01`) keeps the existing
guarded UIC/opcode/response/CONTROL1 route transaction. These deferrals allow
the desktop and charger owner to start without weakening the raw-I2C or active-
MAX ownership guards. First USB recovery insertion after MAX bind, plus
unplug/replug route recovery, remains untested and must not be repaired by
relaxing those guards.

The generic image deliberately does not create `/etc/r8q-usb-route.env`.
That file is generated by the reviewed deployment step after the final image
and target identity are known. The currently validated RTC2 target uses kernel
release `7.1.2-r8q-rtc2`; its deployment file is still generated for the
specific handset and final BOOT receipt. It must contain the nine `EXPECTED_*` values in
`etc/r8q-usb-route.env.example`, including the final BOOT, module, helper, and
protocol SHA-256 values; `EXPECTED_VERMAGIC` is quoted because it contains
spaces. Until that file exists, the enabled service is inert through its
`ConditionPathExists` guard. Never derive target values from a generic image's
machine-id or placeholder template.

---

## Repository layout

```
r8q-arch/
├── README.md                     ← you are here
├── PREREQUISITES.md              ← read first (bootloader, host packages, data wipe)
├── INSTALLATION.md               ← the step-by-step
├── dts/                          ← display fix, touchscreen, battery and QCA6390 Wi-Fi nodes (sm8250-samsung-common.dtsi + r8q.dts)
├── patches/                      ← kernel patches (GPU zap-shader; i2c FIFO force; FTS5CU56A touch driver)
├── config/                       ← r8q_bringup.config, cmdline.txt
├── initramfs/                    ← switch-root /init (+ irfs.devnodes)
├── rootfs/                       ← systemd services, networkd, Plasma Mobile/sddm wiring, cpuidle workaround, gadget script, GPU + touch + battery + Wi-Fi services
└── scripts/                      ← build-uefi / flash / deploy-esp / install-arch / host-tether / build_kernel
```

## Roadmap

The device boots to an accelerated KDE Plasma Mobile session you can touch and
SSH into. What's left, roughly in the order it's worth doing:

| Goal | What it needs | Notes |
|------|---------------|-------|
| **Bluetooth** | QCA6390 BT (`hci_qca` over UART/serdev) | Same chip as Wi-Fi, and the `qca6390-pmu` in the DT already drives its BT_EN line — so the power sequencing is done and this is the cheapest remaining win. |
| **USB host mode** | dwc3 role switch + VBUS (`pm8150b` regulator or powered OTG hub) | Currently peripheral-only (that's how SSH works). Host mode gets a real keyboard/mouse. Needs a role-switch path and VBUS supply. |
| **Greeter / lock screen** | Replace sddm autologin with a real login | Plasma Mobile already ships `plasma-keyboard` as an on-screen keyboard, so a headless login is now viable. Pure userspace/config work; no kernel changes. |
| **Microphone / headset audio** | Additional capture/codec routes and userspace configuration | The current CS35L41 card exposes internal stereo playback only. |

## The short version of how it boots

Download mode → `heimdall` flashes **Mu-Silicium UEFI** (with our DTB embedded)
to `BOOT` → UEFI auto-runs `\EFI\BOOT\BOOTAA64.EFI` (our kernel `Image`, EFI-stub,
with an embedded **switch-root initramfs**) → the initramfs mounts `userdata` and
`switch_root`s into **Arch Linux ARM / systemd** → NCM USB gadget comes up →
`ssh root@172.16.42.1`.

Mu-Silicium exposes a baseline DTB through `DtPlatformDxe`. The RTC kernel
loads a matching external `/EFI/BOOT/R8Q-RTC.DTB` from the ESP, allowing Linux
device-tree updates alongside `BOOTAA64.EFI`. Deploy both files together.
This configuration uses the native PM8150 counter and bypasses Mu's dummy
EFI clock. The counter is protected from writes, so the driver adds a UTC
offset stored in `RTCInfo`. `r8q-rtc.service` restores that offset from the
Linux root filesystem before binding the driver, then saves it on shutdown.
The initial offset must be bootstrapped from NTP-correct UTC and this phone's
raw counter; see INSTALLATION.md and the project log.

## How the GPU works (short version)

There is no mainline panel driver yet, so display and GPU are split: the panel
keeps scanning out of the firmware-lit `simple-framebuffer` (`card0`), while the
`msm` module is loaded post-boot with `separate_gpu_kms=1` and provides only the
Adreno 650 **render node** (`renderD128`). Compositors render on the GPU and
blit into the dumb buffer.

Two r8q-specific things make the GPU actually render (both in
[`patches/`](patches/)):
- Samsung's TrustZone rejects the generic zap shader from linux-firmware, and
  the GPU then stays locked in secure mode — every render write is silently
  dropped. You need the **Samsung-signed zap** from your own stock firmware.
- Loading that zap into the DT carveout hard-resets the SoC (Samsung's TZ
  rejects the region); the `msm.r8q_zap_dyn=1` patch loads it into dynamically
  allocated RAM instead, exactly like stock Android's `pil-tz-generic` does.

`rootfs/` ships the pieces: `r8q-gpu.service` (loads `msm` after boot — never
at coldplug, and **never unload it**), the modprobe options, and the desktop
wiring for whichever session you run. The drop-in ordering the display manager
after `r8q-gpu.service` matters either way: compositors choose their render
device once at startup, so if the display manager wins that race the whole
session silently runs on the CPU.

- **KDE Plasma Mobile (default)** — `sddm` autologin into `plasma-mobile.desktop`.
  KWin needs **no** GPU glue: it has a real split display/render-device concept,
  treats every `DRM_BUS_PLATFORM` node as compatible and prefers the one that
  isn't a software renderer, so it pairs `card0` (simpledrm) with `renderD128`
  (Adreno) by itself. It also derives scale **2.7** from the panel's DPI, which
  works only because the connector is DSI and the DT carries `width-mm`/`height-mm`.
- **GNOME (fallback, still installed)** — needs the `mutter-device-preferred-primary`
  udev tag so mutter renders on the Adreno and scans out on simpledrm, plus a gdm
  drop-in and gdm autologin. Switch back with
  `systemctl disable sddm && systemctl enable gdm`.
- A tty1 autologin profile that starts **sway** on the GPU is kept as a second fallback.
  
### Touchscreen

The STM **FTS5CU56A** touch controller sits on `i2c5` (`qupv3_se5`), powered by
a fixed LDO on **TLMM GPIO 92** that the firmware leaves off. No mainline driver
speaks its Samsung-TSP protocol, so `patches/fts5cu56a.c` is a small from-scratch
driver (device-ID handshake, system reset, the touchtype/scan-on command
sequence, and the 16-byte FIFO event format). Two quirks make the bus usable:
the SE5 GPI-DMA channels are TrustZone-owned and its FIFO writes hang, so
`patches/0003` adds `i2c-qcom-geni.r8q_force_fifo=1` (skip GPI, route data
through the SE-DMA path). `r8q-touch.service` loads the stack after boot.

r8q is **dual-sourced**: Samsung's overlay puts two touch controllers on i2c5 —
the STM part at 0x49 and a **Zinitix ZT7650 at 0x20** — and only the one that is
fitted answers. Both DT nodes stay enabled and each driver checks for its own
chip before registering anything, so a single DTB covers both variants (they
also share one interrupt line, so a driver binding to a chip that is not there
would take the IRQ from the one that should have it). Mainline's `zinitix`
driver only knows the older BT4xx/BT5xx generation, so `patches/0007` adds the
ZT7650: the vendor commands moved, the touch points moved from 0x0080 to 0x0200
and became one 16-byte event per contact with 12-bit packed coordinates, and
"point mode" is 0 rather than 2. `r8q-touch.service` only loads `zinitix.ko`
when the STM part did not bind. The ZT7650 path is **confirmed working on a
ZT7650-fitted r8q** (tested by an owner of one — this phone has the STM part);
on an STM unit the zinitix probe declines cleanly and touch is unaffected.

Touch **follows display rotation** (portrait and landscape both land correctly).
That took making the display look like a real built-in panel — see below.

### Display panel & power

The panel is scanned out by **simpledrm** from the framebuffer the UEFI lit — there
is no real mainline display driver yet. Two small touches make it behave like the
built-in panel it is:

- `patches/0006` makes simpledrm advertise a **DSI** connector instead of
  `Unknown`. mutter decides "is this a built-in panel?" purely from the connector
  type (eDP/LVDS/DSI/DPI), and only a built-in panel gets an integrated touchscreen
  mapped to it with the output rotation transform applied — so this is what makes
  touch follow rotation. A DT `panel` node (`width-mm`/`height-mm`) gives it a real
  physical size so it stops showing up as a 27″ display.
- **Suspend is disabled** on purpose. s2idle hard-resets this SoC, so the systemd
  sleep targets are masked; and now that a battery gauge and a built-in display
  exist, GNOME would otherwise idle- or critical-battery-suspend into that reset.
  A locked system dconf default (`rootfs/etc/dconf/…`) forces every power action to
  `nothing` and disables idle detection.

The October 11 battery comparisons measured 602.6 mA with the display lit
versus 444.4 mA blank, a 26.3% reduction. With the display blank, Wi-Fi power
saving reduced a separate repeated comparison from 452.4 to 357.4 mA (21.0%).
Temperature stayed 24 C, charge movement corroborated both comparisons, and
Wi-Fi SSH stayed usable. These are bounded measurements with telemetry/UI
polling, not overnight endurance results. Simpledrm blanking still leaves the
firmware display powered; native panel shutdown and system sleep remain work.

`r8q-wifi-standby.service` enables the runtime Wi-Fi power-save switch only
while the display is blank, the charger is offline and battery/link readings
are healthy. Wake, source insertion, missing telemetry or carrier loss request
power saving Off. The NetworkManager profile retains Off as the recovery
default; PCI runtime PM and ASPM are unchanged. See
[standby policy and acceptance](docs/r8q-desktop.md#wi-fi-standby-policy).

### Battery

The phone's charger and fuel gauge live in a Maxim **MAX77705** companion PMIC on
`i2c0` (`qupv3_se0`), which rides the same `r8q_force_fifo=1` geni path as the
touchscreen. Three i2c slaves matter: the ModelGauge fuel gauge at `0x36`, the top
PMIC/MUIC at `0x66`, and the charger at `0x69`.

- **Telemetry (read-only):** the fuel gauge is register-compatible with the
  mainline `max17042_battery` driver (`compatible = "maxim,max77705-battery"`), so
  the DT just adds a `fuel-gauge@36` node — no new driver.
  `/sys/class/power_supply/max170xx_battery` reports capacity, voltage, current and
  temperature.
- **Charging:** the `max77705` MFD (`pmic@66`) + `max77705-charger` (`charger@69`)
  drivers, with a `simple-battery` node supplying the charge parameters, drive the
  charger so the phone actually refills (`max77705-charger` shows `status =
  Charging`). This unit reports PMIC ID **0x15**, revision **0x02**, which
  mainline's MFD rejects (it only whitelists revision 0x03), so `patches/0005`
  accepts revision 0x02. Samsung names this silicon MD15 PASS2 and maps it to
  its logical `MAX77705_PASS5` enum; see the IRQ investigation below.

`r8q-battery.service` now requires the early hardware-preparation unit and
touch readiness, then loads fuel gauge → MFD → charger before the desktop and
audio. It no longer requires a configured USB UDC, a gadget, or a successful
route mutation. The identity, private module hash, client-ownership,
current-limit, IRQ-pin and telemetry guards remain. The fuel-gauge node is
deliberately IRQ-less; telemetry uses polling. The legacy route unit remains
installed as a read-only current-boot witness but is disabled by default.

The corrected persistent DTB is now live: GPIO11 uses `bias-pull-up` and VIN
selector 1, and tracked DTS compilation reproduces the deployed audio DTB
(`d3a06549…`). Two fresh cable-attached automatic starts with battery autoload
enabled completed their 25-sample monitors with zero parent/charger/CHGIN/AICL
IRQ deliveries, no unhandled counters, no IRQ disable or MAX/SE0 journal fault,
and healthy telemetry. Both started the desktop, audio, touch, GPU, Wi-Fi,
NetworkManager and USB/Wi-Fi SSH paths. This accepts normal USB-host/cable-left-
in charger startup. The corrected wall-power reboot (`668d5aac…`) also
passed hardware, battery, desktop, audio, GPU, touch, Wi-Fi, NetworkManager,
SSH/UI and the six-minute charger monitor: 25 healthy samples, stable 500 mA
readbacks, no charger/SE0 faults or unhandled IRQs, and charge rising
3156000 -> 3162000 uAh. Battery-only boot `b8346b4a…` also passed: all required services/UI
started with no cable, canonical no-VBUS preparation performed zero UIC reads
or mailbox writes, and 25 samples over 360 s stayed healthy at 24 C with all
four IRQ totals zero. The firmware's input/charge settings of 500000/100000 uA
were retained with zero limit writes. Gauge charge fell 3145000 -> 3091000 uAh,
consistent with the sampled discharge current. First host insertion after MAX bind also passed without a reboot:
UDC changed from not attached to configured, the laptop enumerated the gadget,
and direct USB SSH succeeded. The two-minute source/IRQ capture stayed healthy.
The guarded raw helper was not rerun after MAX bind. The subsequent laptop-to-wall
transfer also passed without charger/SE0 faults; Wi-Fi SSH remained available.
The retained 100 mA charge setting can persist after insertion, so charging
throughput remains a separate policy decision.

Mainline has no driver for the MAX77705's MUIC, so the
source type is not supplied to the charger driver and there is no automatic
BC1.2 higher-current policy. Wall-charger firmware can nevertheless leave higher inherited limits:
the first wall-power observation showed `input_current_limit=1750000` uA and
`constant_charge_current=2100000` uA, with AICL later reporting 1225000 uA.
The driver-owned startup helper now applies a conservative 500000-uA cap after
the charger is healthy. It prevalidates both inherited values in the accepted
100000..3200000-uA range before any write. Values at or below the cap are
retained unchanged; only values above the cap are lowered, and malformed or
out-of-range values fail closed. The input setter writes 475000 uA because that
driver's encoding reads back 500000 uA; the charge setter writes 500000 uA.
Final readback must equal the retained original value or 500000 uA when lowered.
The guards, 500000-uA input/charge cap and no-higher-current assumption remain. The
accepted normal USB-host boots measured mean net current of about +13 mA and
+22 mA, with charge increasing by about 5,000 uAh in each six-minute monitor.
These are idle-desktop observations and do not establish heavy-load headroom.
Judge net charging from gauge current and accumulated charge over time, rather
than charger status.

The selected shell's `r8q.battery` plugin reads the fuel-gauge and charger
power-supply attributes directly. It reports source-connected state separately
from net gauge current: `USB↑` means a confirmed source with positive current,
`USB↓` means a confirmed source while the pack is still under negative current,
and unknown fuel status never becomes `CHG`. `BAT↓` and `BAT?` preserve the
same distinction when the source is absent or unknown. Low-charge warnings use
credible capacity at <=10% and critical warnings at <=5%; low clears above 15%
and critical above 10%, with a single notification per hysteresis transition.
Missing or invalid telemetry cannot re-arm a warning. A labeled critical-urgency test notification rendered in the actual shell;
wall screenshots show both `USB↑ 77%` and `USB↓ 77%`. Threshold fixtures passed. Actual 10%/5% depletion and warning
delivery at those thresholds have not been run.

With no cable, the pinned driver can report charger `online=0`,
`status=Discharging` and `health=Unspecified failure` from its offline
`BAT_DTLS` default. Startup accepts only offline `Good` or `Unspecified failure`
with `Discharging`; online charger health must be `Good`. Both paths still
require a healthy, present fuel gauge with plausible telemetry.

The selective normal-user Hyprland/Omarchy Quattro desktop, package manifest,
offline runtime preparer and recovery procedure are documented in
[docs/r8q-desktop.md](docs/r8q-desktop.md).

### Wi-Fi

Wi-Fi is a discrete Qualcomm **QCA6390** on **PCIe** (not the on-SoC WCSS), driven
by `ath11k_pci` + MHI. Nothing needs to be enabled in the kernel config — ATH11K,
MHI, QRTR, `PCIE_QCOM`, `PCI_PWRCTRL_PWRSEQ` and `POWER_SEQUENCING_QCOM_WCN` are
all in `arm64` defconfig — and the firmware ships in `linux-firmware`
(`/lib/firmware/ath11k/QCA6390/hw2.0/`). The work is all device tree: a
`qca6390-pmu` that power-sequences the chip and drives WLAN_EN (tlmm gpio90) /
BT_EN (gpio76), `&pcie0` + `&pcie0_phy`, a `wifi@0` endpoint under `&pcieport0`,
and the PMIC rails those need (`vreg_s5a_1p9`, `vreg_s6a_0p95`, and a pm8150l
`regulators-1` node for `vreg_s8c_1p35`).

Two things will cost you a lot of time if you don't know them:

- **`PHY_QCOM_QMP_PCIE` is a module.** Until `phy-qcom-qmp-pcie.ko` is loaded,
  `1c00000.pcie` sits silently in `/sys/kernel/debug/devices_deferred` — the host
  bridge defers on the missing phy and prints nothing at all.
- **`qrtr-mhi.ko` must be installed and loaded.** MHI creates an `IPCR` channel
  device when the chip enters mission mode, and `qrtr-mhi` is what binds to it to
  carry QMI. Without it, ath11k stops at `Wait for device to enter SBL or Mission
  mode` and never says anything else — which reads exactly like a firmware that
  won't boot, even though the firmware is already running. If you hit that, build
  `mhi.ko` with `CONFIG_MHI_BUS_DEBUG=y` and read
  `/sys/kernel/debug/mhi/*/regdump`: `BHI_EXECENV: 0x2` means the device is in
  mission mode and the problem is above MHI, not in the firmware.

`r8q-wifi.service` loads the stack deliberately, in order, only after the
successful `r8q-hardware-prepare.service`: `sha256` → `phy-qcom-qmp-pcie` → `pwrseq-qcom-wcn` →
`pci-pwrctrl-pwrseq` → wait for the QCA6390 endpoint → `qrtr-mhi` → `ath11k_pci`
→ wait for its associated PHY. The service has both a systemd dependency and an
active-state precheck, so Wi-Fi cannot start before the early preparation gate.
The hardware-preparation service owns the GPI/GENI bring-up; Wi-Fi does not pull in
`r8q-battery.service` or `r8q-touch.service`. `r8q-wifi-blacklist.conf` stops
udev from coldplugging any of the Wi-Fi modules, while the service loads them
deliberately. The NetworkManager service drop-in also waits for hardware
preparation: probing the `nl80211` generic-netlink family can otherwise request
`cfg80211` and its `rfkill` dependency before the early adapter gate. These modules are now
blacklisted along with the rest of the wireless stack. Install this policy
before adding the modules; do not copy the legacy full overlay wholesale.

RTC2 also needs `crypto/sha256.ko` for the Crypto API used to verify the signed
regulatory database; its low-level SHA-256 library is built in, but its API
registration is modular. Both Wi-Fi and NetworkManager explicitly load it after
the hardware-preparation gate. Its aliases are blacklisted during early boot. The original
`regulatory.db` warning disappeared after installing this exact matching module
and reloading the database with signature enforcement intact.

The endpoint and PHY waits are dynamic and bounded. The helper accepts a PHY
only when its sysfs device path belongs to the discovered QCA6390 PCI endpoint;
it does not assume a fixed PCI BDF or `phy0`. ASPM is disabled only when the
kernel exposes the corresponding controls, and an absent control is logged and
left at its default.

Association is **NetworkManager**, so you can join a network from GNOME's own
Wi-Fi menu on the touchscreen instead of editing config over SSH. The one thing
that must be right is `NetworkManager/conf.d/10-r8q.conf`: it marks **`usb0`
unmanaged**, because that interface is the SSH lifeline and is configured
statically by systemd-networkd — let NM take it over and it will reconfigure the
interface out from under your session. The drop-in uses `dns=systemd-resolved`,
so Wi-Fi DHCP DNS is handed to resolved while the USB link remains networkd-
managed. Wi-Fi profiles use route metric 50 and the USB fallback uses metric
1000, so an associated Wi-Fi default route wins without disturbing the on-link
SSH route. The NM connectivity probe is intentionally disabled: during bring-up
a failed external probe added 20000 to the Wi-Fi metric even after association,
making USB win for the wrong reason. The drop-in also requests the stable Wi-Fi
cloned-MAC policy; the firmware still reports `board_id 0xff` and no
calibration data, so ath11k has no reliable stored hardware address.
Power saving is disabled during bring-up to keep incoming SSH and neighbor
discovery responsive.

On the current `7.1.2-r8q-rtc2` image, the first Wi-Fi-enabled boot failed
because `cfg80211` was already loaded when the strict USB route wrapper ran.
The exact early loader was not traced. The NetworkManager hardware-preparation
gate and full Wi-Fi alias blacklist are now deployed. One USB-only baseline boot and four
consecutive Wi-Fi-enabled reboots recovered USB automatically; the last two
also started GPU and touch services. All wireless boots associated, obtained
DHCP, and passed Wi-Fi-bound DNS, ping and HTTPS checks; `usb0` stayed unmanaged.
Wireless key SSH passed separately.
Normal reboot/reconnection is validated; longer soak, power-removal and suspend
remain untested.

Two things worth knowing about the log noise Wi-Fi produces:

- **AER correctable errors.** With PCIe ASPM enabled, the QCA6390 misses replay
  deadlines coming out of L0s/L1 and the link reports a stream of `Data Link
  Layer ... [12] Timeout` *correctable* errors whenever Wi-Fi goes active. They
  are harmless — the packet is retransmitted — but they flood the log. Measured
  over three scans: 6 with ASPM on, 0 with it off. `r8q-wifi.service` therefore
  disables ASPM on that one link after the endpoint's associated PHY appears:
  ath11k disables ASPM for the firmware download and then calls `aspm_restore`,
  which puts it back. If the kernel has no per-link ASPM controls, the helper
  leaves them alone.
- **They were reaching the panel because of the initramfs.** `/init` raises the
  console log level to 8 so early boot lands in the ESP logs, and nothing lowers
  it again — so `loglevel=3` on the cmdline is overridden for the whole session
  and every kernel message gets CPU-blitted onto the framebuffer.
  `sysctl.d/50-r8q-printk.conf` puts it back to 4 once userspace is up. That is
  worth more than quiet: it took boot from 21 s back down to **~12 s**, the same
  lever as the original `loglevel=3` change.

---
