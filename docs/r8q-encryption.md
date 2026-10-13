# r8q encryption prerequisites and early-unlock plan

Date: 2026-10-13

This document records the optional kernel prerequisites and isolated boot
candidate tooling. The fragment
[`config/r8q_encryption.config`](../config/r8q_encryption.config)
is not wired into the default build. It is insufficient by itself to encrypt
or unlock a root. The later candidate build does not install or encrypt anything.

## Live and repository baseline

The current live checkpoint supplied from read-only phone inspection is the
same October 12 kernel #5 boot (`760acab7`), with `/dev/sda36` as the ext4
root and `cryptsetup` 2.8.8 present in the running root. Live `/proc/config.gz`
still reports `DM_CRYPT` absent. The live root is therefore a plaintext ext4
root and the fragment must not be treated as a migration or deployment step.

The repository's current early path independently shows the same limitation:
the embedded initramfs finds GPT `userdata`, mounts it directly as ext4, and
executes systemd
([`init`: 238-269](../initramfs/init)). The build embeds that custom initramfs through
[`build_kernel.sh`: 114-141](../scripts/build_kernel.sh), while the staged
mkinitcpio configuration has no active `encrypt` or `sd-encrypt` hook
([`mkinitcpio.conf`: 7-55](../out/arch-preparation-20261009/rootdir/etc/mkinitcpio.conf)).

The current desktop is an `alarm` user Hyprland service on VT7
([`r8q-desktop.service`: 16-29](../rootfs/etc/systemd/system/r8q-desktop.service)). The tracked SDDM/Plasma
file is legacy configuration and does not establish the running session; its
autologin and `--no-lockscreen` settings must not be used as current runtime
evidence ([`10-r8q.conf`: 8-18](../rootfs/etc/sddm.conf.d/10-r8q.conf)). The active phone shell still disables
`omarchy.lock` ([`phone-shell.json`: 42-56](../rootfs/usr/share/r8q/omarchy/phone-shell.json)), and the current idle policy only blanks DPMS after a timeout
([`phone-hypridle.conf`: 1-12](../rootfs/usr/share/r8q/omarchy/phone-hypridle.conf)). Blanking is not session locking.

## What the optional fragment does

The matching Linux 7.1.2 Kconfig sources show the direct dependency choices:

* `BLK_DEV_DM` provides device-mapper core and `DM_CRYPT` depends on it
  ([`drivers/md/Kconfig`: 224-240, 294-315](../out/sources-usb-diagnostic-20261007/linux-7.1.2/drivers/md/Kconfig)).
* `DM_CRYPT` selects the crypto core, CBC/ESSIV compatibility pieces, and
  AES/MD5 crypto libraries. `CRYPTO_XTS` selects the skcipher and template
  manager plus ECB ([`crypto/Kconfig`: 649-653, 676-680, 736-740](../out/sources-usb-diagnostic-20261007/linux-7.1.2/crypto/Kconfig)).
* `CRYPTO_AES_ARM64_CE_BLK` implements AES ECB/CBC/CTR/XTS with ARMv8 Crypto
  Extensions and selects the skcipher, AES, and SHA-256 libraries; it requires
  `KERNEL_MODE_NEON`, already enabled in the candidate config
  ([`arch/arm64/crypto/Kconfig`: 17-23](../out/sources-usb-diagnostic-20261007/linux-7.1.2/arch/arm64/crypto/Kconfig)).

The fragment therefore makes only five direct selections: device-mapper,
dm-crypt, generic AES fallback, XTS, and the ARM64 accelerated AES block
implementation. It deliberately does not force every visible `CONFIG_CRYPTO_*`
symbol. After merging, `olddefconfig` must show all selected dependencies as
`=y`; a dependency that resolves to `=m` is a failed early-root candidate.
`CONFIG_CRYPTO_SHA256=y` is not a direct requirement of AES-XTS in this
Kconfig: the ARM64 driver selects `CONFIG_CRYPTO_LIB_SHA256`, and LUKS2 key
derivation is principally userspace work. Add a kernel SHA implementation only
if the selected initramfs or a tested dm-crypt mode actually requests it.

This fragment does not change UFS, ext4, EFI, devtmpfs, display, input, or
USB configuration. The existing candidate already has the UFS/QCOM UFS,
ext4, initramfs, devtmpfs mount, simpledrm/framebuffer console, and PM8941
power-key path built in ([`r8q_bringup.config`: 4-72](../config/r8q_bringup.config)). Those are still necessary but do not create an unlock prompt.

## What remains outside the fragment

An encrypted `userdata` root needs all of the following, in a separately
reviewed candidate:

1. A disposable LUKS2 volume containing ext4, a recorded UUID, a verified
   header backup, and a rollback image. Do not re-encrypt the live `/dev/sda36`
   in place as an experiment.
2. An initramfs owner that discovers the partition, reads a credential, invokes
   the aarch64 `cryptsetup`/systemd machinery, opens `/dev/mapper/cryptroot`,
   mounts ext4, and only then hands PID 1 to the root filesystem. The current
   initramfs has none of these operations.
3. A complete userspace closure. The staged `cryptsetup` is dynamically linked
   and reaches `libcryptsetup`, `libdevmapper`, `libudev`, `libcrypto`,
   `libjson-c`, `libpopt`, `libuuid`, `libblkid`, libc, and the loader. A
   systemd `sd-encrypt` path additionally needs systemd ask-password,
   generators, udev rules, token plugins, and OpenSSL providers. File presence
   and `readelf` output are offline checks, not a working ARM unlock test.
4. A fail-closed path. Wrong credentials, malformed headers, missing crypto
   providers, a timeout, or a mount failure must never fall back to mounting
   raw ext4 `userdata`.

The two initramfs designs remain open until the boot integration is proven:

* **Custom BusyBox:** extend the current embedded initramfs with an audited
  static or dynamic cryptsetup closure and explicit prompt/mapping/mount logic.
  This keeps the board-specific GPT wait and switch-root behavior visible, but
  makes the project own more early-boot code.
* **Systemd/mkinitcpio:** generate a `sd-encrypt` initramfs with keyboard,
  block, mapping, filesystems, and fsck hooks, then prove that the current EFI
  arrangement really embeds or loads that image. Merely enabling the staged
  hook cannot replace the custom embedded image.

The fragment itself selects neither design. The isolated October 13 candidate
uses the custom BusyBox path described below. The first candidate
must have one owner for device discovery, passphrase prompting, mapping,
filesystem checks, and root handoff; do not combine both prompt systems.

## Early touch and module ownership

The absence of early touch is a real limitation, but converting every touch
driver to built-in is not the only option. The current chain is intentionally
modular:

* GPI and `i2c-qcom-geni` are loaded by the hardware-preparation helper, with
  `r8q_force_fifo=1` and GPI before GENI
  ([`r8q-usb-route-up.sh`: 129-230](../rootfs/usr/local/sbin/r8q-usb-route-up.sh)).
* `r8q-touch.service` then loads or observes FTS5CU56A and Zinitix and waits
  for an input event ([`r8q-touch-up.sh`: 22-85](../rootfs/usr/local/sbin/r8q-touch-up.sh)).
* The DT keeps both possible i2c5 controllers enabled at `0x20` and `0x49`,
  with only the fitted part expected to ACK
  ([`sm8250-samsung-r8q.dts`: 115-165](../dts/sm8250-samsung-r8q.dts)).

For a touch-first LUKS prompt, evaluate these two paths explicitly:

1. **Bundle the exact modules in the initramfs.** Carry GPI, GENI with its
   FIFO parameter, both candidate touch modules, their `modules.dep`/modprobe
   metadata, and the required firmware/devices. Load them in the same order,
   wait for a real event node, then hand ownership to the root services. The
   current route helper rejects unexpected preloaded modules and insists on
   exactly one GPI/GENI instance ([`r8q-usb-route-up.sh`: 151-230](../rootfs/usr/local/sbin/r8q-usb-route-up.sh)); this handoff needs a reviewed
   marker or service adjustment before deployment. Do not let a later service
   reload a bound controller.
2. **Convert the relevant chain to built-in.** This removes module loading from
   the prompt path but requires a kernel/init ordering proof, preserves the
   FIFO parameter, and must handle both board touch variants. It is a later
   high-risk experiment, not a requirement imposed by `r8q_encryption.config`.

The touch prompt itself also needs an early framebuffer/DRM UI such as the
project's evaluated unl0kr/BuffyBox direction, correct portrait coordinates,
input focus, retry handling, and passphrase memory clearing. The current
simpledrm framebuffer only establishes a possible display surface. A USB OTG
keyboard or token is a contingency requiring a separate host-role proof; the
current board DT declares the USB controller peripheral-only
([`sm8250-samsung-common.dtsi`: 287-292](../dts/sm8250-samsung-common.dtsi)). It is not a dependency of the touch-first plan. The current unauthenticated debug telnet shell is not an acceptable production unlock path.

Battery, MAX77705, and charger modules remain post-root. Pulling them into the
unlock initramfs would add I2C ownership races and change the existing charging
startup gate. Test battery and wall-charger waits separately after the crypto
path works.

## Lock-first sequence

The selected project order is:

1. Complete and validate the userspace lock surface in the current Hyprland /
   Omarchy session. Use the pinned Quickshell `WlSessionLock`/PAM design and a
   touch keypad; a preview surface is not an authentication test. Start locked
   on service/compositor restart, lock before DPMS blanking, keep wrong
   credentials in the lock surface, and test side-button wake and the existing
   Squeekboard integration.
2. Audit live-session bypasses: root tty autologin, SSH policy, VT switching,
   compositor restart behavior, and recovery/debug paths. A lock overlay does
   not revoke root access or remove plaintext keys from RAM.
3. Separately prove the early touch modules/UI and a disposable LUKS2 root,
   using the optional kernel fragment only after its merged Kconfig is checked.
4. Convert the real USERDATA root only after cold-boot, wrong-password,
   no-input, battery, charger, and rollback tests pass.

This ordering keeps routine screen unlocking convenient while reserving the
strong LUKS passphrase for a reboot. Do not add a short screen PIN as any
LUKS credential or wire `cryptsetup luksSuspend` to screen blanking.

## Offline checks before a future candidate

No package installation or phone access is required for these checks:

* Apply the optional fragment to a disposable copy of the current config,
  resolve with the kernel tree's `olddefconfig`, and assert `BLK_DEV_DM`,
  `DM_CRYPT`, `CRYPTO_AES`, `CRYPTO_XTS`, `CRYPTO_AES_ARM64_CE_BLK`, and all
  Kconfig-selected dependencies are `=y`. Do not wire the fragment into
  `build_kernel.sh` yet.
* Confirm the final candidate still has built-in UFS/QCOM UFS, ext4,
  devtmpfs mount, EFI/simpledrm, and the forced command line. Use the same LLVM
  toolchain as the current image to keep unrelated compiler
  features unchanged. `BLK_DEV_DM_BUILTIN` is an internal selected symbol, not
  proof that the core `BLK_DEV_DM=m` is available before root.
* Produce a read-only manifest of every binary, library, loader, udev rule,
  module, firmware file, and device node required by the chosen initramfs.
  Inspect ELF architecture and `DT_NEEDED`; do not run the aarch64 binary as
  if it were a native laptop executable.
* For the bundled-module touch option, inspect module vermagic, dependencies,
  parameters, and the exact early-to-root ownership handoff. Confirm that the
  root `r8q-hardware-prepare` and `r8q-touch` services will observe, rather
  than duplicate, the early devices.
* Prepare a disposable ARM boot test that records the mapper UUID, early logs,
  and root handoff. Test correct/wrong/empty credentials, retry exhaustion,
  malformed headers, no input, reboot, battery, wall charging, and recovery.
  Prove every failure leaves the mapper closed and raw ext4 unmounted.
* Separately validate the lock surface's PAM policy, secure compositor lock
  state, touch keypad, side-button wake, startup/restart lock state, and no
  desktop exposure while authentication is pending.

The unlocked bootloader and replaceable EFI/initramfs remain a trust limitation:
LUKS2 protects USERDATA at rest, but a modified early image can capture its
passphrase. Verified boot or a hardware-bound unlock key is a separate project.

## Preparation results on 2026-10-13

The fragment was merged into a disposable copy of the running phone config
and resolved with matching Linux 7.1.2 source and LLVM/Clang 21.1.8. All
required mapper/cipher dependencies resolved to built-ins; UFS, ext4 and
simpledrm remained built in. Kconfig additionally promoted CBC, AUTHENC,
ESSIV, the MD5 library and the existing PNFS_BLOCK feature because of the
mapper dependency. CC_CAN_LINK appeared from compiler capability detection.
At that preparation checkpoint no kernel image was built or installed.
Default build wiring remains unchanged.

On the phone, a disposable 32 MiB file in `/run` tmpfs was formatted as LUKS2
with AES-XTS metadata and Argon2id. Correct-key testing passed and a wrong
key was rejected. No mapper was opened; the test file and random synthetic
keys were removed. USERDATA and root mount identity were unchanged. At a
64 MiB/two-thread setting, the roughly one-second Argon2id test succeeded.
These parameters are a test setting, not a final credential policy.

The kernel AES-XTS benchmark reported the cipher unavailable through its
benchmark interface, so no data-path throughput result is claimed. The live
kernel still lacks dm-crypt. Keyslot tests prove the existing userspace can
create/verify LUKS2 credentials; they do not prove encrypted-root I/O, early
touch, charging at the prompt, or successful boot.

## Isolated boot candidate and backup

The operator subsequently authorized a backup and unattended build. The
private artifacts are under `out/encryption-build-20261013/`; they are ignored
by Git and must not be committed. `backup/manifest.json` and `backup/SHA256SUMS`
cover the raw BOOT, RECOVERY, CACHE, DTBO and both VBMETA images, the captured
EFI files and GPT metadata, and the root archive verification receipts.
Each unmounted raw partition was hashed before and after streaming, with a
matching local hash and byte count. CACHE passed `fsck.fat -n`. Primary and
backup GPT headers and partition-entry arrays passed CRC checks for the four
exported UFS logical units.

`backup/rootfs.tar.zst` is a **live file archive**, not an offline USERDATA
image or atomic snapshot. It includes numeric ownership, modes, hardlinks,
sparse files, ACLs and xattrs; it excludes the contents of proc, sys, dev, run
and tmp. Zstd integrity and every regular-file payload were checked. The only
tar warnings were skipped sockets and changing metadata for the excluded sys
directory. Offline extraction, filesystem checks and bootable restore
acceptance remain required before storage conversion. The backup contains
private data and must stay access-controlled. It does not contain a full
stock SUPER image or a fresh PIT capture.

The custom candidate has a separate static BusyBox 1.38.0 with the required
module/FIFO/process applets and module-parameter parsing. Networking applets,
including telnetd, are disabled. Its full optional configuration is in
`config/r8q-encryption-busybox.config`; the normal boot BusyBox is unchanged.
Unl0kr 3.3.0 was built natively on the phone from the pinned BuffyBox mirror
commit `7e481313a01edf02f283e57f70cb94323ae7be53` and LVGL commit
`7f07a129e8d77f4984fff8e623fd5be18ff42e74`. Phone build packages came from
the signed ARM repositories after the backup. No laptop package was installed.

`scripts/prepare-encryption-initramfs.py` accepts an explicit ARM runtime
staging tree, cryptsetup, unl0kr, udevadm, dmsetup and the exact four touch
modules. It checks ELF architecture, interpreter/library closure and module
vermagic, then manifests every added runtime asset. Supply the input rules,
hardware database, libinput quirks, XKB and libwacom data, and the optional
`config/r8q-unl0kr.conf` through repeatable `--extra-path` arguments. A complete
ELF closure is necessary but does not prove runtime data files or BusyBox
applets; execute the resulting tools and applet checks in an isolated ARM
chroot before building. The ordinary raw-root init is never embedded as a
fallback.

The generated init mounts a private `/run`, starts minimal udev, loads GPI
then GENI with FIFO forced, and selects the responding touch controller.
It requires a LUKS2 header, pipes unl0kr output directly to cryptsetup with
`-n` forced to avoid an extra newline, and permits three timed attempts.
It explicitly creates mapper nodes and mounts only `/dev/mapper/cryptroot`.
After unlocking it stops udev and unloads the four early touch modules in
reverse order, so the current root startup helpers retain their existing
ownership checks. This teardown and subsequent reload need a cold-boot test.
Failure never mounts plaintext USERDATA or starts a network/debug shell.
Pre-handoff failure handlers clean tracked mounts and attempt mapper close.
The final BusyBox `switch_root` must replace PID 1 with `exec`; calling it in
a child would fail its PID check. After that boundary, a switch-root/systemd
failure reaches kernel PID-1 panic/reset rather than returning to the shell.
Do not claim that this late failure explicitly closes the mapper before reset.

`scripts/build-encryption-candidate.sh` accepts the existing patched source,
captured live config, prepared initramfs, captured active DTB and a new output
directory under `out/`. It pins the accepted baseline config, compiler and
DTB, rejects source/initramfs output overlap and unrelated config changes,
and builds only an Image. The kernel release remains `7.1.2-r8q-rtc2` to
match the exact existing touch bundle; `MODVERSIONS` is disabled. The payload
contains that EFI Image and the unchanged active DTB. It has no flash, reboot,
formatting, deployment or real-credential step. It intentionally cannot boot
the phone's current plaintext USERDATA.

`scripts/validate-encryption-candidate.py` checks the produced ARM64 EFI
header and confirms the generated compressed initramfs is actually embedded
at the kernel's initramfs symbol. It audits the complete cpio path/type set,
file hashes, modes, root ownership, symlinks and explicit device numbers,
and compares kernel source receipts before and after the build. The candidate
manifest states separately that installation, cold boot and encrypted I/O
have not been tested. Shell protocol fixtures test retries, UI failure,
timeout, mapper creation, cleanup and rejection of plaintext fallback.

The ARM chroot checks exercise the collected binaries and a synthetic RAM
LUKS keyslot. They do not run PID 1, start a second live udev daemon, acquire
the live display, load/unload phone hardware, or expose real block devices.
Before deployment, prove direct DRM rendering and touch orientation, the
mapper's encrypted read/write path, module handoff, charger/battery behavior,
wrong/empty/no-input failure, and offline restore on a disposable boot/root
test. Then choose the private boot passphrase and perform the actual root
migration. Routine screen locking remains the separate PAM/session-lock
work described in `docs/r8q-lock.md`.

The final local payload is
`out/encryption-build-20261013/kernel02/payload/BOOTAA64.EFI` (67,484,160
bytes, SHA-256
`6e6854c77eb124bb588c327c22b424d8178922164dcee25af48588e855186d9e`)
with the captured `R8Q-RTC.DTB`. The final embedded audit passed for 1,240
staged files, the full cpio metadata/device allowlist and 98,638 unchanged
kernel source files/symlinks. The first compiled image was rejected because
reviewed runtime changes had not yet been re-embedded; regenerating the cpio
and relinking produced this accepted payload. Its receipt is
`kernel02/candidate-manifest.json`. These are build/audit results, not a boot
or real encrypted-volume test.
