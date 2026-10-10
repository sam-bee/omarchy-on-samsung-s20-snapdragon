# R8Q internal speaker audio

The SM-G7810 uses the top receiver as the left channel and bottom speaker as
right. The deployed Linux `7.1.2-r8q-rtc2` kernel uses a private 36-module
closure, Samsung ADSP and Protection firmware, and this handset's factory
calibration. PipeWire exposes a stereo **Phone speakers** output. This card
currently exposes playback only.

## Normal use

The phone's volume buttons adjust PipeWire volume by 5%, capped at 100%.
Omarchy's audio panel controls the same output. Inside a desktop terminal:

```sh
wpctl status
wpctl set-volume --limit 1 @DEFAULT_AUDIO_SINK@ 5%+
wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle
pw-play example.wav
```

PipeWire, WirePlumber and pipewire-pulse share the desktop's private D-Bus
session and `/run/r8q-desktop` runtime. An SSH command must run as `alarm` with
that runtime and the current desktop D-Bus address. The ACP profile opens
`hw:0,0` as stereo S16LE at 48 kHz. Desktop volume/mute use software gain;
hardware mixer-path selection is disabled to preserve protected amplifier
routes. WirePlumber's state directory is created with alarm ownership.

The hardware bootstrap sets analog gain 0 and digital volume 700 on both
amplifiers. Generic ALSA restore/state services are skipped while the private
R8Q initialization script is installed, because their fallback initialization
otherwise overwrites a channel. Physical mute, power transitions and DSP
commands remain driver-owned.

## Protected kernel path

The tracked patches are:

1. `patches/0010-r8q-cs35l41-card.patch`: machine driver and Kconfig/Makefile
   hooks, including Qualcomm CPU channel offsets `{0,4}` in bytes.
2. `patches/0011-r8q-cs35l41-protected-speakers.patch`: board-specific codec
   behavior, factory calibration, stock boost setup and Samsung IRQ mailbox.
3. `patches/0012-r8q-q6afe-tdm-fields.patch`: forwards data-out, inverted-sync
   and data-delay properties into the DSP's TDM configuration packet.

The ASP codec slot pairs are receiver `{0,1}` and bottom `{1,0}`. The primary
TDM link uses four 32-bit slots at 48 kHz, DSP_A framing and a one-bit delay.
The ADSP reserved-memory layout and audio graph live in the three
`dts/sm8250-samsung-r8q-audio*.dtsi` files. CDSP and SLPI remain disabled.

The codec applies factory calibration under mute. Main AMP POST_PMU enables
power before sending RESUME; physical unmute requires an IRQ acknowledgement
and DSP RUNNING readback. The success latch clears on a new mailbox command,
failure, PAUSE or DSP teardown. Shutdown mutes, pauses the DSP, then disables
power. Audio-lock to mailbox-lock ordering is consistent. R8Q avoids the
modern hibernate command unsupported by its stock Protection firmware.

## Firmware and calibration inputs

Use the complete Samsung ADSP package from this phone's APNHLOS image,
including `adsp.mbn`, all MDT-listed loadable segments and the two service JSON
files. Install under `/usr/lib/firmware/qcom/sm8250/Samsung/r8q/`.
A header-only file does not supply the DSP program.

The retained Samsung kernel source is
`BeneficialCode/android_kernel_samsung_smg7810` commit
`efbb7d3b9d0c36bd86bd098a9f0c9fc7cc6b2488`.
Its normal speaker Protection files retain their stock names:

```text
cirrus/cs35l40-bot-dsp1-spk-prot.wmfw
cirrus/cs35l40-bot-dsp1-spk-prot.bin
cirrus/cs35l40-rcv-dsp1-spk-prot.wmfw
cirrus/cs35l40-rcv-dsp1-spk-prot.bin
```

Despite the filenames, the installed silicon is CS35L41. Separate calibration
procedure firmware is not a substitute for the normal Protection coefficients.
The firmware binaries remain private runtime inputs.

`scripts/prepare-speaker-calibration.py` takes an explicitly supplied directory
of seven raw Cirrus files copied from read-only secondary EFS, plus their
retained SHA-256 manifest and a new output directory. Run `--help` for the
arguments. It verifies lengths, hashes, mapping and signed-field ranges,
then emits mode-0600 R8QC version-1 records for bottom I2C address 0x40 and
receiver address 0x41. Install these root-owned under
`/usr/lib/firmware/r8q/`. The driver checks both records and DSP readbacks;
missing or invalid inputs prevent protected playback. Raw factory values and
records are not committed. The current scripts pin their hashes for this
single handset; do not reuse those pins for another phone.

## Exact RTC2 startup and packaging

The enabled `r8q-audio-start.service` runs the private loader and initialization
scripts under `/opt/r8q-audio/7.1.2-r8q-rtc2/`, before the desktop. The loader
checks the compatible string, release, module hashes/names/vermagic, firmware
and calibration inputs, ADSP state, actual APR driver links, and ALSA PCM.
It records owned modules in `/run/r8q-audio-loaded.modules` and initialization
in `/run/r8q-audio/status`. Read failures with:

```sh
systemctl status r8q-audio-start.service
journalctl -b -u r8q-audio-start.service
```

`scripts/audio/` contains the reviewed startup templates; the systemd unit is
also staged under `rootfs/etc/systemd/system/`. Keep those unit copies aligned.
To reconstruct the reviewed frozen release, place its exact 36 module files
in a private directory with the relative paths specified by the packager:

```sh
python3 scripts/prepare-audio-bundle.py \
  --modules-directory /absolute/private/modules \
  --templates-directory scripts/audio \
  --output /absolute/new/bundle
```

The packager verifies the frozen hashes, names, vermagic and dependency
closure, then emits load order, manifests and a deterministic archive.
No firmware or calibration payload is included. Install the checked archive
root-owned at the private path, copy its unit into `/etc/systemd/system/`,
install the desktop/ALSA drop-ins and profiles, reload systemd, and enable
without hot-starting over audio modules loaded outside its ownership marker.
Use a clean reboot for deployment acceptance.

To disable the current audio release, disable `r8q-audio-start.service` and
remove the desktop's `20-audio.conf` Wants drop-in before a clean reboot. Retain USB/Wi-Fi recovery and the matched prior EFI
kernel/DTB. The pre-audio DTB is retained in the ESP as `PRE-AUDIO.DTB`.
Do not live-unload modules with PCM or codec users. GUI startup uses Wants,
so audio failure leaves the recovery desktop available.

## Future kernel builds and evidence

`scripts/build_kernel.sh` applies the tracked patches, copies the three audio
DTS includes, appends the aggregator after the full board definition, and
merges `config/r8q_audio_integration.config`. It reads no ignored audio staging
path. Build into fresh private output and record the kernel, DTB, config,
Module.symvers, source and module hashes. The current module release requires
exact vermagic `7.1.2-r8q-rtc2 SMP preempt mod_unload aarch64`.

The frozen six-module codec/card set and matched Q6AFE pair were compiled
against retained RTC2 artifacts, checked with modpost and undefined-symbol
analysis, then exercised on hardware. Canonical source reproduces the codec
and Q6AFE bytes; the card's metadata wording was normalized after its frozen
build. CONFIG_MODVERSIONS is absent, so the checks do not establish CRC ABI
equivalence. A changed kernel/config requires rebuilding and reviewing the
entire matching module closure, updating startup pins and testing it again.

The tracked DTS compiles to the deployed DTB hash
`d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca`.
Direct ALSA and desktop PipeWire tests verified stereo PCM, both physical DSP
RUNNING states, factory readbacks, mute/power-down, and repeated idle wake.
The final clean reboot restored both hardware gains, all 36 owned modules and
the saved 60% desktop volume; both USB and Wi-Fi SSH remained available. The user accepted the listening check on 2026-10-11 after louder, separate
top-receiver and bottom-speaker tones were played through the desktop. The test
used four-second tones at a peak of 16384, about 12 dB above the initial test,
with the tested amplifier settings retained. Previous desktop volume and mute
were restored afterward.

The software/mixer settings follow the official
[PipeWire property reference](https://docs.pipewire.org/page_man_pipewire-props_7.html).
