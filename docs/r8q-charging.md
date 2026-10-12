# Charging performance

Slow recovery after the depleted battery is real. Gauge endpoints on October
11 gained 1.608 Ah over 7.60 hours, about 211.5 mA net on average. The reported
full/design capacity is 4.079 Ah; it is gauge metadata, not an independently
measured capacity. Normal startup acceptance established healthy services and
charging, not acceptable throughput for every source or workload.

## Current limits and source evidence

`r8q-battery-up.sh` conservatively caps both inherited input and constant-charge
settings at 500000 uA. It retains smaller settings. The overnight #5 boot
`d2aa17ca-e0ea-47b9-b5bb-3549f845dade` inherited 500000/500000 uA, so that
startup performed no limit writes. Earlier wall firmware inherited 1.75 A input
and 2.1 A charge; AICL reduced input to 1.225 A before the helper applied its
500 mA cap. Those inherited values do not establish a safe requested setting.

The current boot's early route receipt reports BC 0x81 (SDP) and CC_STATUS0
0x51. In the pinned Samsung source, BIT_CCIStat is bits 5:4; code 1 means
500 mA. This is historical boot evidence, not a live source budget. The
charger driver exposes no live BC1.2/Rp capability interface, always reports
supply type USB, and its charge_type Fast means a charging phase rather than
a negotiated protocol. No higher input current is authorized by the observed
laptop source. USB 2.0 SDP limits are described by the
[USB-IF compliance policies](https://compliance.usb.org/index.asp?Format=Standard&UpdateFile=Policies).
The Linux [Type-C class](https://www.kernel.org/doc/html/latest/driver-api/usb/typec.html)
distinguishes default, 1.5 A, 3 A and PD power modes.

The board's simple-battery profile specifies 1.5 A constant charge and 4.35 V.
The driver's 3.2 A property range and an inherited 2.1 A value are not battery
profile approval. The input setter also has a 25 mA encoding/readback offset:
475000 uA writes read back as 500000 uA. Battery current reported by the fuel
gauge is net current after system load; input current and battery current are
different electrical measurements and cannot simply be subtracted.

## Improvements installed on October 12

The Wi-Fi standby policy now permits saving on healthy connected charging
power while DPMS is Off, as well as on battery. Two repeated pairs measured
180.1 mA net charge with saving Off versus 254.7 mA On, +74.6 mA/41.4%.
Charge endpoints corroborated the gain. Both charger limits remained 500 mA,
temperature stayed 30.1–30.3 C, and association/source/health stayed valid.
Live wake, reblank, service-stop cleanup and restart passed after installation.
See [the policy](r8q-desktop.md#wi-fi-standby-policy) for guards and evidence.

The USB gadget had been advertising only 2 mA because ConfigFS MaxPower was
unset. The NCM startup wrapper now uses `r8q-gadget-maxpower.py` to advertise
500 mA. The helper validates the exact known gadget identity, UDC, strings,
MACs and configuration link before changing a bound gadget. A bound value of
2 is unbound, corrected and rebound to the same UDC; any failure attempts to
restore the original value/binding. An already-correct bound 500 is a no-op.
Unknown bound values or layouts fail before mutation. Fresh unbound gadgets
are prepared before the wrapper's final bind.

At 480 Mb/s, ConfigFS 500 mA encodes as 250 two-mA descriptor units. The laptop
verified bMaxPower=500mA after correction, fresh USB SSH worked, Wi-Fi SSH
remained available, and rerunning the startup service was a no-op. This fixes
enumeration metadata; it is not evidence of extra electrical capability or a
measured charging-rate gain. The helper and wrapper are protected by the new
additive `/root/r8q-gadget-maxpower.sha256`; the existing six manifests were
unchanged during that installation. Original wrapper and receipt are in
`/root/r8q-charging-rate-20261012/gadget-install01/`. The rootfs preparer copies
the helper. The minimal archived rootfs lacks Python: an unbound gadget can
still set 500 mA using the shell wrapper, while a known bound legacy 2 mA
gadget keeps its binding and logs a deferral until phone Python 3 is installed.
A bound 500 mA gadget needs no interpreter to remain available. The current
phone already has Python; no laptop packages were installed.

## Battery-side ceiling diagnostic

A guarded 500 mA / 1 A / 500 mA comparison used 25 samples over six minutes
per run, with input held at 500 mA, DPMS Off and Wi-Fi saving On. Mean net
current was 223.1, 220.0 and 220.9 mA respectively. Charge-counter gains were
21,000, 20,000 and 19,000 uAh. Raising only the battery-side ceiling therefore
showed no useful benefit in this state. Omitting the initial 30 seconds does
not establish a gain: means were 234.1, 233.2 and 223.8 mA, with charge gains
19,000, 18,000 and 18,000 uAh across the remaining 330 seconds.

All 75 rows passed source, limits, fuel, temperature, DPMS, Wi-Fi, IRQ and
available CPU-counter guards; temperature stayed 30.1–30.4 C. EXIT cleanup
and an independent ExecStopPost restored the original 500 mA setting, verified
by readback, with no active/pending trial marker left. The larger ceiling is
not installed as a persistent profile. The diagnostic changed no input limit,
voltage, module binding, EFI file or kernel. The final original #5 boot stayed
healthy at 64%, 30.2 C, DPMS Off, Wi-Fi saving On and both SSH routes available.
All seven protected manifests passed after the final wrapper update.

The complete local archive is
`out/charging-rate-20261012/charging-final-evidence01.tar`, SHA256
`8f97be498951d84d756f143fcf82b304bd7d1d897f2236f9df7d0ad9fd90dd07`.
Primary and Luna independently checked the measurements and restoration.

## Fresh wall-source check on October 12

The operator connected an adapter with a USB-A-to-C cable; its output rating
was unknown. The phone was already 100%/Full, healthy at about 30 C. The
existing boot's source receipt still described the laptop connection, and
Type-C, extcon and USB-role interfaces were absent. A programmed 500 mA input
limit and a stale configured UDC therefore could not identify the new source.

After verifying all seven protected manifests and the original #5 EFI/DTB
hashes, an ordinary wall-connected reboot captured fresh source status before
MAX driver binding. Boot `760acab7-af53-4c5d-be34-16274831aaf1` reports BC
`0x83`, charger type `0x03` (DCP), no DCD timeout, CC `0x51/0x08`, and VBUS
present. Preparation correctly deferred the USB host route with zero UIC
reads and zero mailbox writes. This establishes dedicated-charger
classification; it does not measure the adapter's exact rated amperage.
A DCP may become current limited and its voltage may drop above 500 mA; the
classification alone is not proof of a particular 1.5 or 2.1 A rating. See
[NXP's BC1.2 explanation, page 45](https://www.nxp.com/docs/en/application-note/AN11060.pdf).

The startup log distinguishes firmware settings from the Linux policy:

| Setting | Inherited firmware readback | After Linux startup cap |
| --- | ---: | ---: |
| Input current limit | 1.8 A | 0.5 A |
| Battery-side charge ceiling | 2.1 A | 0.5 A |

These inherited register settings are not an adapter-rating measurement or
approval to use a 2.1 A battery target. The current board profile remains
1.5 A. They do confirm that the software cap reduces wall-boot settings.

All required services and Wi-Fi SSH returned, all seven manifests passed,
and full-boot journal review found no charger/kernel faults. The usual six
known warnings remained. One handled parent/charger/AICL delivery was visible,
with zero unhandled counts; debugfs disable flags remained unavailable.
The screen was reblanked and the persistent policy selected Wi-Fi saving On
with charger status Full. The corrected 500 mA gadget descriptor survived this
fresh startup. No kernel candidate or higher-current profile was installed.

No ceiling throughput experiment was run at 100%/Full, where taper or
maintenance would dominate. A private guarded 500/1000/500 mA comparison is
prepared for a lower battery level, with input kept at 500 mA and automatic
restoration. Its revised cleanup restores CC500 even if AICL changes the input
limit, recording that change without writing the input property. Full-capacity
and input-change fixtures pass. This future experiment isolates the
battery-side ceiling; it cannot measure higher wall-source capability while
the input cap stays at 500 mA. A useful next charge comparison needs roughly
70–80% battery. There is no evidence yet that an adapter replacement is needed.

Local source/startup evidence is
`out/charging-wall-20261012/wall-source-evidence01.tar`, SHA256
`292b5a0c5a980a3f0aa31c2a02943d92879dcfb991b8fc4535acefb19614e60d`.

## Remaining work

- Expose live source type/current capability through a kernel-owned MUIC/CCIC
  or Type-C interface. Do not use raw post-bind I2C to bypass the driver owner.
- Repair the charger's AICL decrement floor before accepting higher input
  settings; the current unsigned decrement can underflow.
- Make charging policy respect the live input budget and battery profile,
  with health/temperature checks and a conservative fallback when source
  information is unavailable. The present blanket cap still limits wall power;
  low inherited settings such as a 100 mA battery-only boot also need
  source-appropriate handling after insertion.
- Test a known capable wall charger, source removal/insertion, thermal behavior,
  current-limit readback, IRQ/journal health, and net charge over longer runs.
- Reduce the remaining standby load. CPU/USB kernel acceptance remains held;
  native panel shutdown and system sleep are still unfinished.

Short gauge comparisons do not predict full-charge duration: voltage, thermal
behavior, workload and charging taper can change over the cycle.
