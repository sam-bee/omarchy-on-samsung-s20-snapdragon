# Waydroid kernel candidate

The optional Waydroid kernel adds built-in Binder and binderfs, active PSI,
and native nftables/NAT to the accepted Linux 7.1.2 configuration. The first
candidate, `7.1.2-r8q-waydroid1`, passed offline validation on October 13.
The combined encrypted-root candidate, `7.1.2-r8q-waydroid2`, passed offline
validation and was installed for an authorized boot trial on October 15.
After private handset unlock on October 16 (UK local time), the encrypted
boot and all thirteen functional regression checks passed. The operator
confirmed the desktop and side-button PIN lock/unlock. Stereo playback
passed; physical listening confirmation remains pending.

The network configuration targets the native nftables rules in
[Waydroid 1.6.3's helper](https://raw.githubusercontent.com/waydroid/waydroid/1.6.3/data/scripts/waydroid-net.sh).
Linux 7.1.2 builds its counter, payload, metadata and set expressions into
`nf_tables`; NAT and masquerade have separate selected modules. Confirm the
installed helper uses this backend before its first container start.

The first candidate preserves the accepted plaintext boot initramfs. It does
not perform encryption migration. Encrypted boot was subsequently accepted
on 2026-10-15 with the production04 EFI recorded in
[the encryption documentation](r8q-encryption.md). Before a Waydroid kernel
trial, prepare a separate boot payload with built-in device-mapper, dm-crypt
and the accepted crypto dependencies, as well as the accepted encrypted
initramfs with matching early modules. The Waydroid1 configuration lacks
dm-crypt; changing its archive alone is insufficient. Its retained plaintext
payload cannot boot the phone's current encrypted root.

## Combined encrypted candidate

The October 15 build reuses the pinned private source and copies generated
Waydroid1 build state into a separate output. It quarantines old final modules
and lets kbuild rebuild the configuration dependencies. The resolved delta
from Waydroid1 is eleven options: release, archive input and the built-in
encryption dependency closure. Audio, Binder, PSI and networking selections
remain unchanged.

Stage 1 uses the accepted production04 archive as an intermediate. Its
embedded RTC2 modules are deliberately temporary, so this stage is not
deployable. Once matching modules have been staged,
`prepare-waydroid-encrypted-initramfs.py` clones the accepted runtime and
replaces exactly the four early modules, their release paths and their hashes.
The kernel must then be relinked with the new archive and pass
`validate-waydroid-encrypted-candidate.py`.

Hardware preparation preserves the accepted RTC2 global helpers, units,
module tree and private audio/battery payloads byte-for-byte. The new helpers
live under `/usr/local/lib/r8q-kernel-profiles/7.1.2-r8q-waydroid2/`; five
service drop-ins select the old or new profile by the exact running release.
Only the curated matching module closure enters normal module lookup.
This makes restoration of the accepted encrypted EFI compatible with the
rootfs hardware configuration. The raw Samsung BOOT/UEFI partition and
active DTB are preserved.

The original 297-entry screen-lock protection manifest remains the baseline.
Deployment must verify those files and append only the reviewed new file
hashes, with a private rollback copy. It must install the new rootfs profile
and modules before replacing CACHE's EFI, keep the accepted encrypted EFI
for recovery, and leave running hardware services alone until reboot.

The final EFI is 67,631,616 bytes, SHA-256
`f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b`.
Offline validation checked 1,568 matching modules, all four early modules at
mode 0744, and 1,234 unchanged accepted runtime files. The hardware bundle
selects 78 modules, with 14 freshly generated indexes and 18 audited module
lookup plans. Its exact five dispatch drop-ins and 113 new rootfs files
were independently reviewed before installation.

The first live transaction stopped before replacing EFI because the public
metadata check required the appended protection manifest to retain its old
size/hash. It rolled back completely; an independent SSH check verified the
297-entry baseline and healthy services. The corrected verifier accepts only
the exact computed appended manifest while retaining all ownership/mode
checks. Eleven transaction/rollback fixtures passed with the actual manifest
metadata row included. The retry installed successfully. Independent checks
then passed all 410 protected entries, all 147 public hardware metadata
records (allowing only the planned manifest append), and zero failed services
on the still-running RTC2 kernel.

The accepted EFI04 is saved on CACHE as
`EFI/BOOT/BOOTAA64.EFI.WAYDROID2-SAVED-FOR-ROLLBACK` and locally in
`deployment-preparation/rollback/BOOTAA64.EFI.ENCRYPTED04-SAVED`. Its accepted
SHA-256 is
`730627f49b8d41b9bdc6ef7931fe94911636003c61596c84d769d532ad27c49b`.
The raw Samsung BOOT/UEFI partition and external DTB remain unchanged.

Artifacts and transport receipts are under
`out/waydroid-encrypted-20261015/`. Android images and Waydroid userspace are
a subsequent step after encrypted boot, native locking and hardware pass
their regression checks on the new kernel.

## Encrypted boot acceptance

The observed Waydroid2 boot ID is
`1a7fa1b5-c8f9-4da4-b77c-5c3294f8d1c7`. The root remains
`/dev/mapper/cryptroot` with the accepted root/LUKS UUIDs and `sda36` backing
partition. The running configuration matches the audited build. All 410
protected entries, 147 public hardware metadata records, matching module
files, early adapter handoff, udev/GPU permissions and required services pass.
The raw Samsung BOOT partition remains unchanged.

Binderfs created and opened `binder`, `hwbinder` and `vndbinder`, with
protocol version 8 on all three devices. memfd and CPU/memory/I/O pressure
interfaces pass. An isolated namespace test created bridge/veth devices,
nftables filtering, NAT/masquerade and writable overlay storage, then
removed its resources. These are host prerequisites; Android app startup
and end-to-end container connectivity remain later acceptance gates.

The first functional run exposed a diagnostic bug: after successful unmount,
`findmnt --target` reported the containing `/run` filesystem. Cleanup now
queries the exact `--mountpoint` and treats unexpected observation results
as errors. Regression fixtures and the corrected full phone probe pass;
independent final inspection found no remaining test resources or failed
services. The original failed report and probe are retained for provenance.

The Phone speakers stream passed stereo S16_LE at 48 kHz through the existing
PipeWire sink. Software volume remained 0.85; mute and protected amplifier
settings were unchanged. The quiet top-receiver/bottom-speaker listening
check awaits the operator's confirmation. Detailed results and receipt hashes
are in `out/waydroid-encrypted-20261015/kernel-boot-acceptance01.json`.

## Historical Waydroid1 build

Use the existing compiler recorded by the accepted build. The scripts require
the matching kernel source and retained RTC2 artifacts; they refuse different
identities and overlapping input/output paths. Missing laptop tools require
operator approval before installation under the project AGENTS.md.

Run from the repository root, with a fresh workspace name:

```sh
python3 -I scripts/prepare-waydroid-kernel-source.py \
  out/sources-usb-diagnostic-20261007/linux-7.1.2 \
  out/kernel-rtc-offset-20261009 \
  out/waydroid-kernel-20261013/source

R8Q_WAYDROID_JOBS=2 bash scripts/build-waydroid-candidate.sh \
  out/waydroid-kernel-20261013/source \
  out/kernel-rtc-offset-20261009 \
  out/encryption-build-20261013/backup/R8Q-RTC.DTB \
  out/waydroid-kernel-20261013/kernel
```

These are build commands. The output directory must be new; select another
`out/waydroid-*/` directory to repeat a build. The source preparer can audit an
existing private copy with `--use-existing-copy`, before any build starts.
Preserve the source receipt once compilation begins. For a configuration
inspection without compilation, set `R8Q_WAYDROID_CONFIG_ONLY=1` and select a
separate output directory.

The source preparer copies the shared source and reapplies the accepted RTC
offset patch. It integrates canonical speaker and Q6AFE patches 0010 through
0012, checks their source hashes against the accepted audio receipts, and
retains the active DTB separately. It omits inherited build history and
checks the complete tree against a fixed reconstruction from the pinned
Linux archive, project patches, FTS driver and audited DTS inputs. Relative
symlink targets must remain inside the private tree. The build merges
`config/r8q_audio_integration.config` and `config/r8q_waydroid.config` into the
accepted configuration. This rebuilds the current hardware module closure
against the candidate's headers and exports.

The build checks configuration changes before compiling, verifies that the
accepted cpio is embedded in the known-good Image, and embeds those exact
archive bytes in the new Image. It then builds and stages all selected modules
under its private output directory. The validator checks the ARM64 EFI
header, embedded archive, required configuration, unchanged build source,
module identity, dependencies and imported symbols.

## Output and acceptance

The 2026-10-13 candidate passed offline validation with 1,576 matching modules,
22 intended configuration changes and eight rejection checks. Its artifacts
are under `out/waydroid-kernel-20261013/kernel/`; the adjacent build, staging,
validation and configuration-preview logs record the work. It has not been
deployed or boot-tested.

The build directory contains:

- `payload/BOOTAA64.EFI` and `payload/R8Q-RTC.DTB`.
- `modules/lib/modules/7.1.2-r8q-waydroid1/`, a module catalogue for the
  candidate.
- The resolved configuration, configuration delta, source receipts, module
  inventory and candidate manifest.

To repeat artifact validation without rebuilding:

```sh
python3 -I -B scripts/validate-waydroid-candidate.py \
  out/waydroid-kernel-20261013/kernel \
  out/waydroid-kernel-20261013/source \
  out/kernel-rtc-offset-20261009 \
  out/waydroid-kernel-20261013/kernel/accepted-initramfs.cpio
```

The staged module tree is a build artifact. Before deployment, prepare the
controlled hardware loaders and private module paths for the new release.
Preserve the existing load order and prevent automatic loading of drivers
managed by the GPU, battery, audio and USB preparation services. Update the
release, vermagic and SHA256 guards as one reviewed bundle. Keep all RTC2
modules and helpers available for recovery.

PSI changes kernel structures. Old RTC2 modules cannot be reused with the new
kernel based only on similar source or vermagic. The separate release prevents
normal module lookup from silently selecting the old module tree.

An offline validation pass establishes a compiled candidate. The manifest
retains `installed=false` and `boot_tested=false`. Deploy only a reviewed,
root-state-compatible Image/initramfs/DTB/module/helper bundle with the
accepted boot available for rollback.

The boot trial must establish Binder allocation and container access, PSI,
required networking modules, native nftables NAT/masquerade expressions,
authenticated USB recovery, charging, Wi-Fi, desktop, touch, speakers and
native locking. Android boot and Adreno rendering are subsequent gates.
