#!/usr/bin/env python3
"""Offline fixture tests for monitor-r8q-cpu-stall.py."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/monitor-r8q-cpu-stall.py"


class MonitorFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.write("proc/sys/kernel/random/boot_id", "fixture-boot\n")
        self.write("proc/cmdline", "console=tty0 irqchip.gicv3_pseudo_nmi=1\n")
        self.write("proc/stat", "\n".join([
            "cpu  1 2 3 4 5 6 7 8 9 10",
            *[f"cpu{index} 1 2 3 4 5 6 7 8 9 10" for index in range(8)],
        ]) + "\n")
        self.write("proc/interrupts", "           CPU0 CPU1\n"
                   "  1:       10 20 arch_timer\n"
                   "  2:        3  4 pmu\n"
                   "  3:        5  6 IPI reschedule\n")
        self.write("proc/softirqs", "                    CPU0       CPU1\n"
                   "TIMER:                  4          5\n"
                   "RCU:                    6          7\n")
        self.write("proc/pressure/cpu", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
        self.write("proc/pressure/io", "some avg10=0.01 avg60=0.02 avg300=0.03 total=4\n")
        self.write("proc/pressure/memory", "some avg10=0.04 avg60=0.05 avg300=0.06 total=8\n")
        self.write("proc/loadavg", "0.10 0.20 0.30 1/100 42\n")
        self.write("proc/meminfo", "MemTotal:       100 kB\nMemAvailable:    50 kB\n")
        self.write("proc/vmstat", "\n".join([
            "oom_kill 2", "oom_reaper 1", "allocstall 3", "pgscan_kswapd 4",
            "pgscan_direct 5", "pgsteal_kswapd 6", "pgsteal_direct 7",
        ]) + "\n")
        self.write("proc/sys/kernel/watchdog", "1\n")
        self.write("proc/sys/kernel/watchdog_thresh", "10\n")
        self.write("proc/sys/kernel/nmi_watchdog", "1\n")
        self.write("proc/sys/kernel/softlockup_panic", "0\n")
        self.write("proc/sys/kernel/hardlockup_panic", "0\n")
        self.write("proc/sys/kernel/hung_task_panic", "0\n")
        self.write("proc/sys/kernel/panic_on_warn", "0\n")
        self.write("proc/sys/kernel/panic_on_oops", "0\n")
        self.write("sys/devices/system/clocksource/clocksource0/current_clocksource", "arch_sys_counter\n")
        for cpu_number in range(8):
            state = f"sys/devices/system/cpu/cpu{cpu_number}/cpuidle/state0"
            self.write(f"{state}/name", "WFI\n")
            self.write(f"{state}/disable", "0\n")
            self.write(f"{state}/usage", f"{cpu_number}\n")
            self.write(f"{state}/time", f"{cpu_number * 10}\n")
            self.write(f"{state}/rejected", "0\n")
        self.write("sys/class/thermal/thermal_zone0/type", "cpu-thermal\n")
        self.write("sys/class/thermal/thermal_zone0/temp", "42000\n")
        self.write("sys/class/thermal/thermal_zone0/policy", "step_wise\n")
        self.write("sys/class/thermal/thermal_zone0/mode", "enabled\n")
        self.write("sys/class/power_supply/BAT0/status", "Discharging\n")
        self.write("sys/class/power_supply/BAT0/capacity", "77\n")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def run_monitor(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", "-I", "-B", str(SCRIPT), "--root", str(self.root),
             "--seconds", "1", "--no-affinity", *arguments],
            capture_output=True, text=True, check=False, timeout=10,
        )

    def test_stream_contains_metadata_and_all_required_sections(self) -> None:
        result = self.run_monitor()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertGreaterEqual(len(lines), 2)
        self.assertEqual(lines[0]["kind"], "r8q-cpu-stall-metadata")
        self.assertEqual(lines[0]["type"], "metadata")
        metadata = lines[0]["record"]
        self.assertEqual(metadata, lines[0]["sample"])
        self.assertEqual(metadata["excluded_sections"], [])
        sample = lines[1]
        self.assertEqual(sample["type"], "sample")
        self.assertEqual(metadata["boot_id"]["value"], "fixture-boot")
        self.assertTrue(metadata["diagnostic_readiness"]["pseudo_nmi"]["bootarg"]["present"])
        self.assertEqual(set(sample["proc_stat"]["rows"]) & {f"cpu{n}" for n in range(8)},
                         {f"cpu{n}" for n in range(8)})
        self.assertEqual(len(sample["interrupts"]["rows"]), 3)
        self.assertIn("oom_kill", sample["load_and_memory"]["vmstat_oom_and_pressure"])
        self.assertEqual(set(sample["cpuidle"]), {f"cpu{n}" for n in range(8)})
        self.assertEqual(sample["clocksource"]["value"], "arch_sys_counter")
        self.assertIn("BAT0", sample["thermal_and_battery"]["batteries"])

    def test_no_thermal_excludes_all_thermal_and_battery_reads(self) -> None:
        thermal_type = self.root / "sys/class/thermal/thermal_zone0/type"
        thermal_type.unlink()
        os.mkfifo(thermal_type)
        battery_status = self.root / "sys/class/power_supply/BAT0/status"
        battery_status.unlink()
        os.mkfifo(battery_status)
        result = self.run_monitor("--no-thermal")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        metadata = lines[0]["record"]
        sample = lines[1]
        self.assertEqual(metadata["excluded_sections"], ["thermal_and_battery"])
        self.assertNotIn("thermal_and_battery", sample)

    def test_missing_fields_are_reported_without_aborting(self) -> None:
        (self.root / "proc/stat").unlink()
        (self.root / "proc/meminfo").unlink()
        for path in (self.root / "sys/devices/system/cpu/cpu7/cpuidle").glob("state0/*"):
            path.unlink()
        (self.root / "sys/devices/system/cpu/cpu7/cpuidle/state0").rmdir()
        result = self.run_monitor()
        self.assertEqual(result.returncode, 0, result.stderr)
        sample = json.loads(result.stdout.splitlines()[1])
        self.assertIn("error", sample["proc_stat"])
        self.assertIn("error", sample["load_and_memory"]["meminfo"])
        self.assertIn("error", sample["cpuidle"]["cpu7"])

    def test_duration_bound_is_enforced(self) -> None:
        result = subprocess.run(
            ["python3", "-I", "-B", str(SCRIPT), "--root", str(self.root), "--seconds", "901",
             "--no-affinity"], capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("900", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
