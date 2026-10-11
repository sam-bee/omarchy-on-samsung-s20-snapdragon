#!/usr/bin/env python3
"""Offline fixtures for the read-only power_supply sampler."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parents[1] / "rootfs/usr/share/r8q/omarchy/plugin/r8q.battery/r8q-battery-telemetry.py"
spec = importlib.util.spec_from_file_location("r8q_battery_telemetry", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(root: Path, *, status: str, online: str, current: str, capacity: str = "73") -> dict:
    fuel = root / "class" / "power_supply" / "max170xx_battery"
    charger = root / "class" / "power_supply" / "max77705-charger"
    fuel.mkdir(parents=True)
    charger.mkdir(parents=True)
    for name, value in {
        "present": "1", "capacity": capacity, "status": "Unknown",
        "health": "Good", "current_now": current, "current_avg": current,
    }.items():
        (fuel / name).write_text(value)
    for name, value in {"online": online, "status": status, "health": "Good"}.items():
        (charger / name).write_text(value)
    return module.read_sample(root)


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    current = fixture(root, status="Charging", online="1", current="-20000")
    assert current["fuel"]["status"] == "Unknown"
    assert current["source"]["connected"] is True
    assert current["net_current_ua"] == -20000
    assert current["battery_load"] is True

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    unplugged = fixture(root, status="Unknown", online="0", current="-20000")
    assert unplugged["source"]["connected"] is False
    assert unplugged["battery_load"] is True

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    charging = fixture(root, status="Charging", online="1", current="20000")
    assert charging["source"]["connected"] is True
    assert charging["battery_load"] is False

print("battery telemetry sysfs fixtures: ok")
