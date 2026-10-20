#!/usr/bin/env python3
"""Stream bounded read-only CPU-stall diagnostics from an R8Q Linux boot."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import glob
import json
import os
from pathlib import Path
import re
import time
from typing import Any


SCHEMA = "r8q-cpu-stall-monitor/v1"
INTERVAL_SECONDS = 2.0
MAX_SECONDS = 900
CPU_COUNT = 8
IRQ_TOKENS = ("arch_timer", "archtimer", "pmu", "ipi")
WATCHDOG_SYSCTLS = (
    "watchdog",
    "watchdog_thresh",
    "watchdog_cpumask",
    "nmi_watchdog",
    "softlockup_all_cpu_backtrace",
    "hardlockup_all_cpu_backtrace",
    "hung_task_all_cpu_backtrace",
    "hung_task_timeout_secs",
    "softlockup_panic",
    "hardlockup_panic",
    "hung_task_panic",
    "panic_on_warn",
    "panic_on_oops",
)
CPUIDLE_FIELDS = ("name", "disable", "usage", "time", "rejected")
THERMAL_FIELDS = ("type", "temp", "policy", "mode")
BATTERY_FIELDS = (
    "status",
    "health",
    "capacity",
    "capacity_level",
    "temp",
    "voltage_now",
    "current_now",
    "power_now",
    "charge_now",
    "energy_now",
)
OOM_FIELDS = (
    "oom_kill",
    "oom_reaper",
    "allocstall",
    "allocstall_dma",
    "allocstall_dma32",
    "allocstall_normal",
    "allocstall_movable",
    "pgscan_kswapd",
    "pgscan_direct",
    "pgsteal_kswapd",
    "pgsteal_direct",
)


class FileRoot:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")


def error_value(path: Path, error: BaseException) -> dict[str, Any]:
    return {"error": {"type": type(error).__name__, "message": str(error), "path": str(path)}}


def read_text(root: FileRoot, absolute: str) -> dict[str, Any]:
    path = root.path(absolute)
    try:
        return {"value": path.read_text(encoding="utf-8", errors="replace").rstrip("\n"),
                "path": absolute}
    except BaseException as error:
        return error_value(path, error)


def read_integer(root: FileRoot, absolute: str) -> dict[str, Any]:
    result = read_text(root, absolute)
    if "error" in result:
        return result
    try:
        return {"value": int(result["value"].strip(), 10), "path": absolute}
    except BaseException as error:
        return error_value(root.path(absolute), error)


def parse_key_value_text(root: FileRoot, absolute: str) -> dict[str, str] | dict[str, Any]:
    result = read_text(root, absolute)
    if "error" in result:
        return result
    values: dict[str, str] = {}
    for line in result["value"].splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2:
            values[fields[0].rstrip(":")] = fields[1].strip()
    return values


def parse_cpu_stat(root: FileRoot) -> dict[str, Any]:
    result = read_text(root, "/proc/stat")
    if "error" in result:
        return result
    rows: dict[str, list[int] | dict[str, Any]] = {}
    for line in result["value"].splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r"cpu(?:[0-9]+)?", fields[0]):
            continue
        try:
            rows[fields[0]] = [int(value) for value in fields[1:]]
        except BaseException as error:
            rows[fields[0]] = {"error": {"type": type(error).__name__, "message": str(error)}}
    for cpu_number in range(CPU_COUNT):
        name = f"cpu{cpu_number}"
        if name not in rows:
            rows[name] = {"error": {"type": "MissingField", "message": "CPU row missing",
                                     "path": "/proc/stat"}}
    return {"rows": rows, "path": "/proc/stat"}


def parse_interrupts(root: FileRoot) -> dict[str, Any]:
    result = read_text(root, "/proc/interrupts")
    if "error" in result:
        return result
    rows = []
    for line in result["value"].splitlines():
        lowered = line.lower()
        if not any(token in lowered for token in IRQ_TOKENS):
            continue
        fields = line.split()
        if not fields:
            continue
        counts: list[int | str] = []
        for field in fields[1:]:
            try:
                counts.append(int(field))
            except ValueError:
                break
        label_index = 1 + len(counts)
        rows.append({"irq": fields[0].rstrip(":"), "counts": counts,
                     "label": " ".join(fields[label_index:]), "raw": line})
    return {"rows": rows, "tokens": IRQ_TOKENS, "path": "/proc/interrupts"}


def parse_softirqs(root: FileRoot) -> dict[str, Any]:
    result = read_text(root, "/proc/softirqs")
    if "error" in result:
        return result
    lines = result["value"].splitlines()
    header = lines[0].split() if lines else []
    rows: dict[str, list[int] | dict[str, Any]] = {}
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        name = fields[0].rstrip(":")
        try:
            rows[name] = [int(value) for value in fields[1:]]
        except BaseException as error:
            rows[name] = {"error": {"type": type(error).__name__, "message": str(error)}}
    return {"header": header, "rows": rows, "path": "/proc/softirqs"}


def pressure(root: FileRoot) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("cpu", "io", "memory"):
        result[name] = read_text(root, f"/proc/pressure/{name}")
    return result


def load_and_memory(root: FileRoot) -> dict[str, Any]:
    meminfo = parse_key_value_text(root, "/proc/meminfo")
    vmstat = parse_key_value_text(root, "/proc/vmstat")
    if isinstance(vmstat, dict) and "error" not in vmstat:
        vmstat = {
            key: vmstat[key] if key in vmstat else {
                "error": {"type": "MissingField", "message": "vmstat counter missing",
                           "path": "/proc/vmstat"}
            }
            for key in OOM_FIELDS
        }
    return {"loadavg": read_text(root, "/proc/loadavg"), "meminfo": meminfo,
            "vmstat_oom_and_pressure": vmstat}


def cpuidle(root: FileRoot) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for cpu_number in range(CPU_COUNT):
        cpu_path = f"/sys/devices/system/cpu/cpu{cpu_number}/cpuidle"
        entry: dict[str, Any] = {"states": {}}
        try:
            state_paths = sorted(glob.glob(str(root.path(cpu_path + "/state*"))))
            state_names = [Path(path).name for path in state_paths
                           if re.fullmatch(r"state[0-9]+", Path(path).name)]
            if not state_names:
                entry["error"] = {"type": "FileNotFoundError", "message": "no cpuidle states",
                                   "path": cpu_path}
            for state_name in state_names:
                state_entry: dict[str, Any] = {}
                for field in CPUIDLE_FIELDS:
                    absolute = f"{cpu_path}/{state_name}/{field}"
                    state_entry[field] = read_text(root, absolute) if field == "name" else read_integer(root, absolute)
                entry["states"][state_name] = state_entry
        except BaseException as error:
            entry["error"] = error_value(root.path(cpu_path), error)["error"]
        result[f"cpu{cpu_number}"] = entry
    return result


def thermal_and_battery(root: FileRoot) -> dict[str, Any]:
    thermal: dict[str, Any] = {}
    thermal_pattern = str(root.path("/sys/class/thermal/thermal_zone*"))
    for path_string in sorted(glob.glob(thermal_pattern)):
        path = Path(path_string)
        name = path.name
        thermal[name] = {field: (read_text(root, f"/sys/class/thermal/{name}/{field}")
                                 if field in {"type", "policy", "mode"}
                                 else read_integer(root, f"/sys/class/thermal/{name}/{field}"))
                         for field in THERMAL_FIELDS}
    batteries: dict[str, Any] = {}
    power_pattern = str(root.path("/sys/class/power_supply/*"))
    for path_string in sorted(glob.glob(power_pattern)):
        path = Path(path_string)
        name = path.name
        if not re.search(r"battery|bms|^bat[0-9]", name, re.IGNORECASE):
            continue
        batteries[name] = {}
        for field in BATTERY_FIELDS:
            absolute = f"/sys/class/power_supply/{name}/{field}"
            batteries[name][field] = read_text(root, absolute)
    return {"thermal_zones": thermal, "batteries": batteries}


def sysctl_readbacks(root: FileRoot) -> dict[str, Any]:
    values = {name: read_text(root, f"/proc/sys/kernel/{name}") for name in WATCHDOG_SYSCTLS}
    cmdline = read_text(root, "/proc/cmdline")
    pseudo_nmi: dict[str, Any] = {"cmdline": cmdline,
                                  "bootarg": {"value": None, "present": False}}
    if "value" in cmdline:
        for token in cmdline["value"].split():
            if token.startswith("irqchip.gicv3_pseudo_nmi="):
                value = token.split("=", 1)[1]
                pseudo_nmi["bootarg"] = {"value": value, "present": True}
                break
    return {
        "pseudo_nmi": pseudo_nmi,
        "rcu_cpu_stall_cputime": read_text(
            root, "/sys/module/rcupdate/parameters/rcu_cpu_stall_cputime"),
        "watchdog_sysctl_readbacks": values,
        "interpretation": "Readbacks are telemetry only; they do not prove effective pseudo-NMI or watchdog activation.",
    }


def metadata(root: FileRoot, args: argparse.Namespace, affinity: dict[str, Any]) -> dict[str, Any]:
    uname = os.uname()
    excluded_sections = ["thermal_and_battery"] if args.no_thermal else []
    return {
        "schema": SCHEMA,
        "kind": "r8q-cpu-stall-metadata",
        "sample_interval_seconds": INTERVAL_SECONDS,
        "requested_seconds": args.seconds,
        "excluded_sections": excluded_sections,
        "boot_id": read_text(root, "/proc/sys/kernel/random/boot_id"),
        "boot_monotonic_seconds": time.monotonic(),
        "uptime": read_text(root, "/proc/uptime"),
        "uname": {"sysname": uname.sysname, "nodename": uname.nodename,
                   "release": uname.release, "version": uname.version, "machine": uname.machine},
        "cmdline": read_text(root, "/proc/cmdline"),
        "affinity": affinity,
        "read_only": True,
        "diagnostic_readiness": sysctl_readbacks(root),
    }


def sample(root: FileRoot, sample_number: int, start_monotonic: float,
           include_thermal: bool) -> dict[str, Any]:
    now = time.time()
    record = {
        "schema": SCHEMA,
        "kind": "r8q-cpu-stall-sample",
        "type": "sample",
        "sample": sample_number,
        "monotonic_seconds": time.monotonic() - start_monotonic,
        "boot_monotonic_seconds": time.monotonic(),
        "uptime": read_text(root, "/proc/uptime"),
        "wall_time_utc": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "proc_stat": parse_cpu_stat(root),
        "interrupts": parse_interrupts(root),
        "softirqs": parse_softirqs(root),
        "pressure": pressure(root),
        "load_and_memory": load_and_memory(root),
        "cpuidle": cpuidle(root),
        "clocksource": read_text(root, "/sys/devices/system/clocksource/clocksource0/current_clocksource"),
    }
    if include_thermal:
        record["thermal_and_battery"] = thermal_and_battery(root)
    return record


def apply_affinity(args: argparse.Namespace) -> dict[str, Any]:
    if args.no_affinity:
        return {"requested": False, "value": None}
    try:
        os.sched_setaffinity(0, {args.affinity_cpu})
        return {"requested": True, "cpu": args.affinity_cpu, "applied": True}
    except BaseException as error:
        return {"requested": True, "cpu": args.affinity_cpu, "applied": False,
                "error": {"type": type(error).__name__, "message": str(error)}}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=300,
                        help="bounded monitoring duration in seconds; default 300, maximum 900")
    parser.add_argument("--affinity-cpu", type=int, default=0,
                        help="CPU for this monitor process; default 0")
    parser.add_argument("--no-affinity", action="store_true",
                        help="do not request process-local CPU affinity")
    parser.add_argument("--no-thermal", action="store_true",
                        help="exclude thermal zones and battery/power-supply reads")
    parser.add_argument("--root", type=Path, default=Path("/"),
                        help="offline fixture root; default /")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.seconds < 1 or args.seconds > MAX_SECONDS:
        raise SystemExit(f"--seconds must be between 1 and {MAX_SECONDS}")
    if args.affinity_cpu < 0:
        raise SystemExit("--affinity-cpu must be non-negative")
    root = FileRoot(args.root.expanduser().resolve())
    affinity = apply_affinity(args)
    metadata_record = metadata(root, args, affinity)
    print(json.dumps({"schema": SCHEMA, "kind": "r8q-cpu-stall-metadata",
                      "type": "metadata", "record": metadata_record,
                      "sample": metadata_record}, sort_keys=True), flush=True)
    start = time.monotonic()
    deadline = start + args.seconds
    sample_number = 0
    while True:
        now = time.monotonic()
        if now >= deadline and sample_number:
            break
        print(json.dumps(sample(root, sample_number, start, not args.no_thermal),
                          sort_keys=True), flush=True)
        sample_number += 1
        next_sample = start + sample_number * INTERVAL_SECONDS
        sleep_for = min(max(0.0, next_sample - time.monotonic()),
                        max(0.0, deadline - time.monotonic()))
        if sleep_for <= 0.0:
            if time.monotonic() >= deadline:
                break
            continue
        time.sleep(sleep_for)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
