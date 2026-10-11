# Battery helper fixtures

`test_r8q_battery.py` executes a temporary path-rewritten copy of the tracked
`r8q-battery-up.sh` against synthetic `/etc`, `/proc`, `/sys`, and private
payload trees. It uses fake `systemctl`, `findmnt`, `insmod`, `modinfo`, and
hash commands, so it never reads host sysfs, loads a host module, or contacts a
phone.

The fixtures require failure before `insmod` for wrong kernel/identity, an
inactive hardware preparation, invalid live IRQ pin configuration, a
pre-existing MAX module, and a module hash mismatch. No configured UDC is
required. Success fixtures check fuel-gauge → MFD → charger load order,
telemetry, and conservative current limits at or below 500000 uA.

Wall-source fixtures cover inherited limits of 1750000/2100000 uA and the
pinned charger's input encoding: a 475000-uA write reads back 500000 uA.
Both inherited values must validate before either write; input is lowered
first. Values in 100000..500000 uA remain unchanged, including the firmware's
battery-only 100000-uA charge setting. Mixed high/low and both-below-cap
fixtures verify only higher settings are lowered; each final readback must
match its unchanged original or 500000 uA if lowered. Missing, malformed,
below-minimum, out-of-range, write-failure and readback-failure fixtures remain
fail-closed. Offline fixtures require Discharging and charger health Good or
Unspecified failure; online health must be Good. Independent healthy fuel
telemetry remains required, and invalid offline health/status values reject.
The fixture models the input setter/getter arithmetic and uses temporary
ordinary files; production writes only the bound charger's sysfs properties.

Run from `r8q-arch/`:

```sh
python3 -B tests/r8q-battery/test_r8q_battery.py
```
