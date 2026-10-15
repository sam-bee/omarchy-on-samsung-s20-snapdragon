# Waydroid kernel candidate

The optional Waydroid kernel adds built-in Binder and binderfs, active PSI,
and native nftables/NAT to the accepted Linux 7.1.2 configuration. Its release
is `7.1.2-r8q-waydroid1`. The default kernel build and phone startup profile
continue to use their existing configuration.

The network configuration targets the native nftables rules in
[Waydroid 1.6.3's helper](https://raw.githubusercontent.com/waydroid/waydroid/1.6.3/data/scripts/waydroid-net.sh).
Linux 7.1.2 builds its counter, payload, metadata and set expressions into
`nf_tables`; NAT and masquerade have separate selected modules. Confirm the
installed helper uses this backend before its first container start.

The first candidate preserves the accepted plaintext boot initramfs. It does
not perform encryption migration. Encrypted boot was subsequently accepted
on 2026-10-15 with the production04 EFI recorded in
[the encryption documentation](r8q-encryption.md). Before a Waydroid kernel
trial, prepare a separate boot payload with that accepted encrypted initramfs
and matching early modules, and validate the exact payload. The retained
plaintext payload cannot boot the phone's current encrypted root.

## Prepare and build offline

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
