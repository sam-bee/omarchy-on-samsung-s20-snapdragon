#!/usr/bin/env python3
"""Read the pinned fuel-gauge and charger supplies and print one JSON sample.

This helper only reads power_supply attributes. It does not access I2C, write
sysfs, change a charger policy, or invoke a service. R8Q_BATTERY_SYSFS_ROOT is
only for offline fixtures; runtime defaults to /sys.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

SIGNED = re.compile(r"^-?[0-9]+$")
UNSIGNED = re.compile(r"^[0-9]+$")


def read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        result = subprocess.run(
            ["cat", str(path)], check=False, capture_output=True,
            text=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def read_attr(base: Path, name: str) -> str | None:
    return read_text(base / name)


def parse_int(value: str | None, signed: bool = True) -> int | None:
    if value is None:
        return None
    pattern = SIGNED if signed else UNSIGNED
    if not pattern.fullmatch(value):
        return None
    return int(value)


def parse_bool01(value: str | None) -> bool | None:
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def read_sample(sysfs_root: Path) -> dict[str, object]:
    supplies = sysfs_root / "class" / "power_supply"
    fuel = supplies / "max170xx_battery"
    charger = supplies / "max77705-charger"

    fuel_present = parse_bool01(read_attr(fuel, "present"))
    capacity = parse_int(read_attr(fuel, "capacity"), signed=False)
    if capacity is not None and not 0 <= capacity <= 100:
        capacity = None

    current_now = parse_int(read_attr(fuel, "current_now"))
    current_avg = parse_int(read_attr(fuel, "current_avg"))
    net_current = current_now if current_now is not None else current_avg

    online = parse_bool01(read_attr(charger, "online"))
    sample = {
        "schema": "r8q-battery-telemetry/v1",
        "fuel": {
            "present": fuel_present is True,
            "capacity_percent": capacity,
            "status": read_attr(fuel, "status") or "Unknown",
            "health": read_attr(fuel, "health") or "Unknown",
            "current_now_ua": current_now,
            "current_avg_ua": current_avg,
            "credible": fuel_present is True and capacity is not None,
        },
        "source": {
            "connected": online,
            "status": read_attr(charger, "status") or "Unknown",
            "health": read_attr(charger, "health") or "Unknown",
        },
        "net_current_ua": net_current,
        "battery_load": net_current is not None and net_current < 0,
    }
    return sample


def main() -> int:
    root = Path(os.environ.get("R8Q_BATTERY_SYSFS_ROOT", "/sys"))
    print(json.dumps(read_sample(root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
