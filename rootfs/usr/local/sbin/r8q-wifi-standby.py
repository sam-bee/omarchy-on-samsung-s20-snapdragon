#!/usr/bin/env python3
"""Use Wi-Fi power saving while the r8q display is blank with healthy power readings.

The NetworkManager profile keeps powersave disabled as the recovery default.
This service changes only the runtime iw switch, never PCI PM or ASPM.
Missing telemetry, an awake display, an unvalidated source state or lost
association requests off. A healthy connected charging source is accepted
alongside the existing battery-only state. A failed iw operation exits after
a final off attempt.
"""
from pathlib import Path
import argparse
import json
import os
import signal
import subprocess
import time

IFACE = "wlp1s0"
STATE = Path("/run/r8q-wifi-standby/status.json")
SYS = Path("/sys")
STOP = False


def read(path):
    return path.read_text().strip()


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if result.returncode:
        # Do not log link output, which includes SSID/BSSID information.
        raise RuntimeError(f"{args[0]} operation failed ({result.returncode})")
    return result.stdout


def actual_power():
    result = command("/usr/bin/iw", "dev", IFACE, "get", "power_save").strip().lower()
    if result not in ("power save: on", "power save: off"):
        raise RuntimeError("unrecognized iw power-save result")
    return result.split(": ")[1]


def set_power(value):
    command("/usr/bin/iw", "dev", IFACE, "set", "power_save", value)
    if actual_power() != value:
        raise RuntimeError("Wi-Fi power-save readback mismatch")


def decision(sysroot=SYS):
    """Pure reads: only a complete healthy blank/source snapshot allows on."""
    try:
        if read(sysroot / "class/drm/card0-DSI-1/dpms") != "Off":
            return "off", "display-awake-or-unavailable"
        charger = sysroot / "class/power_supply/max77705-charger"
        fuel = sysroot / "class/power_supply/max170xx_battery"
        online = read(charger / "online")
        if online not in ("0", "1"):
            return "off", "source-connected-or-unavailable"
        status = read(charger / "status")
        if online == "0":
            if status != "Discharging":
                return "off", "charger-status"
            on_reason = "blank-on-battery"
        else:
            if status not in ("Charging", "Full") or read(charger / "health") != "Good":
                return "off", "charger-status-or-health"
            on_reason = "blank-on-charging"
        if read(fuel / "present") != "1" or read(fuel / "health") != "Good":
            return "off", "fuel-health"
        capacity, temperature = int(read(fuel / "capacity")), int(read(fuel / "temp"))
        voltage = int(read(fuel / "voltage_now"))
        if not (15 <= capacity <= 100 and 0 <= temperature <= 400 and 2500000 <= voltage <= 4500000):
            return "off", "fuel-range"
        if read(sysroot / f"class/net/{IFACE}/carrier") != "1":
            return "off", "link-down"
        return "on", on_reason
    except (OSError, ValueError):
        return "off", "telemetry-unavailable"


def associated():
    result = command("/usr/bin/iw", "dev", IFACE, "link")
    return result.lstrip().lower().startswith("connected to ")


def status(power, reason):
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {"schema": "r8q-wifi-standby/v1", "boot_id": read(Path("/proc/sys/kernel/random/boot_id")),
               "monotonic": time.monotonic(), "power_save": power, "reason": reason}
    temporary = STATE.with_name(f".status-{os.getpid()}.json")
    temporary.write_text(json.dumps(payload) + "\n")
    os.replace(temporary, STATE)


def identity(check_root_uuid=True):
    if os.geteuid() != 0 or os.uname().release != "7.1.2-r8q-rtc2":
        raise RuntimeError("requires the accepted r8q RTC2 kernel and root")
    if read(Path("/etc/machine-id")) != "1290f2212bd743569044571db21a6c96":
        raise RuntimeError("unexpected phone machine-id")
    if check_root_uuid and command("/usr/bin/findmnt", "-n", "-o", "UUID", "/").strip() != "217b9308-40c7-4eb0-90a9-09ed4e233173":
        raise RuntimeError("unexpected phone root UUID")


def restore_off():
    # Cleanup remains possible if mount discovery failed after startup. Root,
    # accepted kernel and machine identity still constrain the target phone.
    identity(check_root_uuid=False)
    failure = None
    for attempt in range(2):
        try:
            set_power("off")
            status("off", "service-stop")
            return
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            failure = exc
            if attempt == 0:
                time.sleep(0.25)
    raise failure


def stop(_sig, _frame):
    global STOP
    STOP = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore-off", action="store_true")
    args = parser.parse_args()
    if args.restore_off:
        restore_off()
        return
    identity()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last, previous_reason, check_at = None, None, 0
    # Establish the recovery default before considering standby.
    try:
        set_power("off")
        while not STOP:
            wanted, reason = decision()
            now = time.monotonic()
            # sysfs wake/source checks run every 2 s. Recheck association and
            # actual runtime state every 10 s, including NetworkManager resets.
            verify = now >= check_at or wanted != last
            if wanted == "on" and verify and not associated():
                wanted, reason = "off", "not-associated"
            if verify or wanted != last:
                actual = actual_power()
                if actual != wanted:
                    set_power(wanted)
                check_at = now + 10
            if wanted != last or reason != previous_reason:
                status(wanted, reason)
                print(f"Wi-Fi power save {wanted}: {reason}", flush=True)
            last, previous_reason = wanted, reason
            time.sleep(2)
    finally:
        restore_off()


if __name__ == "__main__":
    main()
