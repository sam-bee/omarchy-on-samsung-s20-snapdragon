#!/usr/bin/env python3
"""Offline sysfs and link-state tests for the charging-aware Wi-Fi standby policy."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from tempfile import TemporaryDirectory


CANDIDATE = Path(__file__).resolve().parents[2] / "rootfs/usr/local/sbin/r8q-wifi-standby.py"
SPEC = spec_from_file_location("r8q_wifi_candidate", CANDIDATE)
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def put(root, relative, value):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(value) + "\n")


def baseline(root):
    put(root, "class/drm/card0-DSI-1/dpms", "Off")
    put(root, "class/power_supply/max77705-charger/online", "0")
    put(root, "class/power_supply/max77705-charger/status", "Discharging")
    # Offline battery operation preserves the tracked policy: charger health
    # is only required when online=1 and status claims a source is charging.
    put(root, "class/power_supply/max77705-charger/health", "Unspecified failure")
    put(root, "class/power_supply/max170xx_battery/present", "1")
    put(root, "class/power_supply/max170xx_battery/health", "Good")
    put(root, "class/power_supply/max170xx_battery/capacity", "55")
    put(root, "class/power_supply/max170xx_battery/temp", "240")
    put(root, "class/power_supply/max170xx_battery/voltage_now", "3800000")
    put(root, "class/net/wlp1s0/carrier", "1")


def check(name, change, expected):
    with TemporaryDirectory(prefix="r8q-wifi-fixture-") as directory:
        root = Path(directory)
        baseline(root)
        change(root)
        actual = MODULE.decision(root)
        if actual != expected:
            raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")


def charging(root, status="Charging", health="Good"):
    put(root, "class/power_supply/max77705-charger/online", "1")
    put(root, "class/power_supply/max77705-charger/status", status)
    put(root, "class/power_supply/max77705-charger/health", health)


def main():
    cases = 0

    check("battery", lambda root: None, ("on", "blank-on-battery")); cases += 1
    check(
        "battery-offline-bad-charger-health-preserved",
        lambda root: put(root, "class/power_supply/max77705-charger/health", "Bad"),
        ("on", "blank-on-battery"),
    ); cases += 1
    check("charging", charging, ("on", "blank-on-charging")); cases += 1
    check(
        "full",
        lambda root: charging(root, status="Full"),
        ("on", "blank-on-charging"),
    ); cases += 1
    check(
        "charging-bad-health",
        lambda root: charging(root, health="Unspecified failure"),
        ("off", "charger-status-or-health"),
    ); cases += 1
    check(
        "charging-missing-health",
        lambda root: (charging(root), (root / "class/power_supply/max77705-charger/health").unlink()),
        ("off", "telemetry-unavailable"),
    ); cases += 1
    check(
        "online-discharging-inconsistent",
        lambda root: charging(root, status="Discharging"),
        ("off", "charger-status-or-health"),
    ); cases += 1
    check(
        "offline-charging-inconsistent",
        lambda root: put(root, "class/power_supply/max77705-charger/status", "Charging"),
        ("off", "charger-status"),
    ); cases += 1
    check(
        "online-malformed",
        lambda root: put(root, "class/power_supply/max77705-charger/online", "2"),
        ("off", "source-connected-or-unavailable"),
    ); cases += 1
    check(
        "online-empty",
        lambda root: put(root, "class/power_supply/max77705-charger/online", ""),
        ("off", "source-connected-or-unavailable"),
    ); cases += 1
    check(
        "online-missing",
        lambda root: (root / "class/power_supply/max77705-charger/online").unlink(),
        ("off", "telemetry-unavailable"),
    ); cases += 1
    check(
        "display-awake",
        lambda root: put(root, "class/drm/card0-DSI-1/dpms", "On"),
        ("off", "display-awake-or-unavailable"),
    ); cases += 1
    check(
        "carrier-down",
        lambda root: put(root, "class/net/wlp1s0/carrier", "0"),
        ("off", "link-down"),
    ); cases += 1
    check(
        "missing-fuel",
        lambda root: (root / "class/power_supply/max170xx_battery/health").unlink(),
        ("off", "telemetry-unavailable"),
    ); cases += 1
    check(
        "malformed-fuel",
        lambda root: put(root, "class/power_supply/max170xx_battery/capacity", "NaN"),
        ("off", "telemetry-unavailable"),
    ); cases += 1

    # Bounds are inclusive: capacity is percent, temperature is deci-C, and
    # voltage_now is microvolts, matching the tracked implementation.
    for value in (15, 100):
        check(f"capacity-bound-{value}", lambda root, v=value: put(root, "class/power_supply/max170xx_battery/capacity", v), ("on", "blank-on-battery")); cases += 1
    for value in (14, 101):
        check(f"capacity-out-{value}", lambda root, v=value: put(root, "class/power_supply/max170xx_battery/capacity", v), ("off", "fuel-range")); cases += 1
    for value in (0, 400):
        check(f"temperature-bound-{value}", lambda root, v=value: put(root, "class/power_supply/max170xx_battery/temp", v), ("on", "blank-on-battery")); cases += 1
    for value in (-1, 401):
        check(f"temperature-out-{value}", lambda root, v=value: put(root, "class/power_supply/max170xx_battery/temp", v), ("off", "fuel-range")); cases += 1
    for value in (2500000, 4500000):
        check(f"voltage-bound-{value}", lambda root, v=value: put(root, "class/power_supply/max170xx_battery/voltage_now", v), ("on", "blank-on-battery")); cases += 1
    for value in (2499999, 4500001):
        check(f"voltage-out-{value}", lambda root, v=value: put(root, "class/power_supply/max170xx_battery/voltage_now", v), ("off", "fuel-range")); cases += 1

    # A source transition while blank and healthy remains eligible in both
    # accepted states; no sticky charger state is used by decision().
    with TemporaryDirectory(prefix="r8q-wifi-transition-") as directory:
        root = Path(directory)
        baseline(root)
        charging(root)
        if MODULE.decision(root) != ("on", "blank-on-charging"):
            raise AssertionError("charging-to-battery: charging state was not accepted")
        put(root, "class/power_supply/max77705-charger/online", "0")
        put(root, "class/power_supply/max77705-charger/status", "Discharging")
        put(root, "class/power_supply/max77705-charger/health", "Bad")
        if MODULE.decision(root) != ("on", "blank-on-battery"):
            raise AssertionError("charging-to-battery: battery state was not accepted")
    cases += 1

    saved_command = MODULE.command
    try:
        MODULE.command = lambda *args: "  Connected to 00:11:22:33:44:55 (on wlp1s0)\n"
        if not MODULE.associated():
            raise AssertionError("associated connected fixture was rejected")
        MODULE.command = lambda *args: "Not connected.\n"
        if MODULE.associated():
            raise AssertionError("associated disconnected fixture was accepted")
    finally:
        MODULE.command = saved_command
    cases += 1

    print(f"PASS: {cases} offline sysfs/link cases")


if __name__ == "__main__":
    main()
