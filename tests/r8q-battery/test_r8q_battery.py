#!/usr/bin/env python3
"""Offline fixture checks for the route-gated battery helper.

A temporary path-rewritten copy is used because the production helper has
fixed target paths by design. The shell control flow and guard ordering are
unchanged. Fake commands and synthetic sysfs/proc trees never touch host
sysfs, load modules, or contact the phone.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "rootfs/usr/local/sbin/r8q-battery-up.sh"
SERVICE = REPO_ROOT / "rootfs/etc/systemd/system/r8q-battery.service"
KERNEL = "7.1.2-r8q-rtc2"
MACHINE_ID = "1290f2212bd743569044571db21a6c96"
ROOT_UUID = "217b9308-40c7-4eb0-90a9-09ed4e233173"
VERMAGIC = "7.1.2-r8q-rtc2 SMP preempt mod_unload aarch64"
MODULE_HASHES = {
    "max17042_battery.ko": "dab402c9a954140ba1fb9d4ee7cc5b0ba4fdd710ceef6f3e690b81b8d7e3d0e0",
    "max77705.ko": "d762ba600f60aeb861ba9bb74c963213db19eb4db9f928ef8538a1c27472a072",
    "max77705_charger.ko": "724ce35de17beb52dbec938a695b01a9e2e0ee757a4c864ae05b8f59e3cca593",
}


def write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def make_fixture(root: Path, *, usb_configured: bool = True, max_module: bool = False, pin_state: str = "valid") -> None:
    sysfs = root / "sys"
    proc = root / "proc"
    etc = root / "etc"
    payload = root / "usr/local/lib/r8q-battery/7.1.2-r8q-rtc2"
    fake_bin = root / "bin"
    fake_bin.mkdir(parents=True)
    (root / "fakecmd.py").write_text(FAKE_COMMAND, encoding="utf-8")
    (root / "fakecmd.py").chmod(0o755)
    for name in ("id", "uname", "findmnt", "sleep", "systemctl", "sha256sum", "modinfo", "insmod"):
        (fake_bin / name).symlink_to(root / "fakecmd.py")

    for address in ("0036", "0066", "0069"):
        (sysfs / "bus/i2c/devices" / f"0-{address}").mkdir(parents=True)
    (sysfs / "bus/i2c/drivers/simple-mfd-i2c").mkdir(parents=True)
    (sysfs / "bus/i2c/devices/0-0036/driver").symlink_to(
        sysfs / "bus/i2c/drivers/simple-mfd-i2c"
    )
    if usb_configured:
        write(sysfs / "class/udc/fixture-udc/state", "configured\n")
        write(sysfs / "class/net/usb0/operstate", "up\n")

    pin_state_dir = sysfs / "firmware/devicetree/base/soc/pmic/gpio@c000/max77705-int-default-state"
    write(pin_state_dir / "pins", ("gpio10" if pin_state == "wrong-pin" else "gpio11") + "\0")
    if pin_state != "missing-pull-up":
        write(pin_state_dir / "bias-pull-up", "")
    if pin_state == "bias-disable":
        write(pin_state_dir / "bias-disable", "")
    write(pin_state_dir / "power-source", "\0\0\0\1" if pin_state != "bad-power-source" else "\0\0\0\0")

    modules = "i2c_core 32768 0 - Live 0x0\n"
    if max_module:
        modules += "max77705 123 0 - Live 0x0\n"
    write(proc / "modules", modules)
    write(etc / "machine-id", MACHINE_ID + "\n")
    write(
        etc / "r8q-usb-route.env",
        f"EXPECTED_KERNEL={KERNEL}\n"
        f"EXPECTED_MACHINE_ID={MACHINE_ID}\n"
        f"EXPECTED_ROOT_UUID={ROOT_UUID}\n",
    )
    for name in MODULE_HASHES:
        write(payload / name, "fixture module\n")


FAKE_COMMAND = r'''#!/usr/bin/python3
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
root = Path(os.environ["R8Q_FIXTURE"])
case = os.environ.get("R8Q_CASE", "")
args = sys.argv[1:]

if name == "id":
    print("0")
elif name == "uname":
    print(os.environ.get("R8Q_FAKE_KERNEL", "7.1.2-r8q-rtc2"))
elif name == "findmnt":
    print(os.environ.get("R8Q_FAKE_ROOT_UUID", "217b9308-40c7-4eb0-90a9-09ed4e233173"))
elif name == "sleep":
    pass
elif name == "systemctl":
    joined = " ".join(args)
    if "r8q-hardware-prepare.service" in joined and case == "routeinactive" and "ActiveState" in joined:
        print("inactive")
    elif "ActiveState" in joined:
        print("active")
    elif "Result" in joined:
        print("success")
elif name == "sha256sum":
    if case == "modulehash":
        digest = "0" * 64
    else:
        digest = next(
            value for suffix, value in {
                "max17042_battery.ko": "dab402c9a954140ba1fb9d4ee7cc5b0ba4fdd710ceef6f3e690b81b8d7e3d0e0",
                "max77705.ko": "d762ba600f60aeb861ba9bb74c963213db19eb4db9f928ef8538a1c27472a072",
                "max77705_charger.ko": "724ce35de17beb52dbec938a695b01a9e2e0ee757a4c864ae05b8f59e3cca593",
            }.items()
            if suffix in args[0]
        )
    print(f"{digest}  {args[0]}")
elif name == "modinfo":
    print("7.1.2-r8q-rtc2 SMP preempt mod_unload aarch64")
elif name == "insmod":
    module = Path(args[0]).name
    with (root / "insmod.log").open("a", encoding="utf-8") as stream:
        stream.write(module + "\n")
    proc = root / "proc/modules"
    if module == "max17042_battery.ko":
        proc.write_text(proc.read_text() + "max17042_battery 123 0 - Live 0x0\n")
        base = root / "sys/class/power_supply/max170xx_battery"
        for name, value in {
            "health": "Good\n", "present": "1\n", "capacity": "70\n",
            "voltage_now": "3900000\n", "temp": "240\n",
        }.items():
            write_path = base / name
            write_path.parent.mkdir(parents=True, exist_ok=True)
            write_path.write_text(value)
    elif module == "max77705.ko":
        proc.write_text(proc.read_text() + "max77705 123 0 - Live 0x0\n")
        driver = root / "sys/bus/i2c/drivers/max77705"
        driver.mkdir(parents=True, exist_ok=True)
        (root / "sys/bus/i2c/devices/0-0066/driver").symlink_to(driver)
    elif module == "max77705_charger.ko":
        proc.write_text(proc.read_text() + "max77705_charger 123 0 - Live 0x0\n")
        driver = root / "sys/bus/i2c/drivers/max77705-charger"
        driver.mkdir(parents=True, exist_ok=True)
        (root / "sys/bus/i2c/devices/0-0069/driver").symlink_to(driver)
        base = root / "sys/class/power_supply/max77705-charger"
        for name, value in {
            "health": os.environ.get("R8Q_FAKE_CHARGER_HEALTH", "Good") + "\n",
            "online": os.environ.get("R8Q_FAKE_CHARGER_ONLINE", "1") + "\n",
            "status": os.environ.get("R8Q_FAKE_CHARGER_STATUS", "Charging") + "\n",
            "input_current_limit": os.environ.get("R8Q_FAKE_INPUT", "500000") + "\n",
            "constant_charge_current": os.environ.get("R8Q_FAKE_CHARGE", "500000") + "\n",
        }.items():
            if case == "missing-current" and name == "input_current_limit":
                continue
            write_path = base / name
            write_path.parent.mkdir(parents=True, exist_ok=True)
            write_path.write_text(value)
    else:
        raise SystemExit(1)
else:
    raise SystemExit(f"unexpected fake command: {name}")
'''


def materialize_helper(root: Path) -> Path:
    text = HELPER.read_text(encoding="utf-8")
    for old, new in (
        ("/usr/local/lib/r8q-battery", str(root / "usr/local/lib/r8q-battery")),
        ("/var/lib/r8q-battery", str(root / "var/lib/r8q-battery")),
        ("/etc/", str(root / "etc") + "/"),
        ("/sys/", str(root / "sys") + "/"),
        ("/proc/", str(root / "proc") + "/"),
    ):
        text = text.replace(old, new)
    text = text.replace(
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        f"PATH={root / 'bin'}:/usr/bin:/bin:/usr/sbin:/sbin",
    )
    # The real MAX77705 driver translates a CHGIN write of 475000uA to a
    # 500000uA readback (its getter adds one 25mA step).  Keep that exact
    # driver behavior in the offline fixture without weakening production
    # helper semantics or adding a production test hook.
    old_writer = '''write_sysfs_value() {
    value=$1
    path=$2
    printf '%s\\n' "$value" > "$path" || return 1
}'''
    new_writer = f'''write_sysfs_value() {{
    value=$1
    path=$2
    if [ "$R8Q_CASE" = writefail ]; then
        return 1
    fi
    printf '%s\\n' "$value" >> "{root / 'sysfs-write.log'}" || return 1
    printf '%s\\n' "$value" > "$path" || return 1
    case "$path:$value" in
        *input_current_limit:*)
            if [ "$R8Q_CASE" = readbackfail ]; then
                printf '525000\\n' > "$path"
            else
                printf '%s\\n' "$(( (value / 25000 + 1) * 25000 ))" > "$path"
            fi
            ;;
    esac
}}'''
    if old_writer not in text:
        raise AssertionError("battery writer function missing from candidate helper")
    text = text.replace(old_writer, new_writer)
    helper = root / "helper.sh"
    write(helper, text)
    helper.chmod(0o755)
    return helper


def run_case(
    root: Path,
    name: str,
    *,
    usb_configured: bool = True,
    max_module: bool = False,
    wrong_machine: bool = False,
    wrong_root_uuid: bool = False,
    wrong_kernel: bool = False,
    pin_state: str = "valid",
    input_current: str | None = None,
    charge_current: str | None = None,
    charger_online: str = "1",
    charger_health: str = "Good",
    charger_status: str = "Charging",
) -> subprocess.CompletedProcess[str]:
    make_fixture(root, usb_configured=usb_configured, max_module=max_module, pin_state=pin_state)
    if wrong_machine:
        write(root / "etc/machine-id", "wrong-machine-id\n")
    helper = materialize_helper(root)
    env = os.environ.copy()
    env.update(
        {
            "R8Q_FIXTURE": str(root),
            "R8Q_INSMOD_LOG": str(root / "insmod.log"),
            "R8Q_CASE": name,
            "PATH": f"{root / 'bin'}:{env['PATH']}",
        }
    )
    if input_current is not None:
        env["R8Q_FAKE_INPUT"] = input_current
    if charge_current is not None:
        env["R8Q_FAKE_CHARGE"] = charge_current
    env["R8Q_FAKE_CHARGER_ONLINE"] = charger_online
    env["R8Q_FAKE_CHARGER_HEALTH"] = charger_health
    env["R8Q_FAKE_CHARGER_STATUS"] = charger_status
    if wrong_kernel:
        env["R8Q_FAKE_KERNEL"] = "wrong-kernel"
    if wrong_root_uuid:
        env["R8Q_FAKE_ROOT_UUID"] = "wrong-root-uuid"
    return subprocess.run(
        [str(helper)], env=env, text=True, capture_output=True, timeout=5
    )


def assert_rejected(root: Path, name: str, expected: str, **kwargs: object) -> None:
    result = run_case(root, name, **kwargs)
    assert result.returncode != 0, (
        f"{name} unexpectedly passed:\n{result.stdout}\n{result.stderr}"
    )
    assert expected in result.stderr, f"{name}: missing {expected!r}: {result.stderr}"
    assert not (root / "insmod.log").exists(), f"{name} reached insmod"


def main() -> int:
    service = SERVICE.read_text(encoding="utf-8")
    assert "Requires=r8q-hardware-prepare.service r8q-touch.service" in service
    assert "After=r8q-hardware-prepare.service r8q-touch.service" in service
    assert "ExecStart=/usr/local/sbin/r8q-battery-up.sh" in service
    assert "ExecStartPost" not in service
    assert "700000" not in service and "1000000" not in service

    with tempfile.TemporaryDirectory(prefix="r8q-battery-fixture-") as temp:
        base = Path(temp)
        assert_rejected(
            base / "wrong-kernel", "wrongkernel", "unexpected kernel", wrong_kernel=True
        )
        assert_rejected(
            base / "wrong-identity", "identity", "unexpected machine-id",
            wrong_machine=True,
        )
        assert_rejected(
            base / "wrong-root-uuid", "rootuuid", "unexpected root UUID",
            wrong_root_uuid=True,
        )
        assert_rejected(
            base / "route-inactive", "routeinactive",
            "r8q-hardware-prepare.service is not active",
        )
        standalone_root = base / "standalone-no-udc"
        result = run_case(standalone_root, "standalone-no-udc", usb_configured=False)
        assert result.returncode == 0, f"standalone no-UDC fixture failed: {result.stderr}"
        assert (standalone_root / "insmod.log").read_text(encoding="utf-8").splitlines() == [
            "max17042_battery.ko", "max77705.ko", "max77705_charger.ko",
        ]
        assert_rejected(
            base / "wrong-pin-state", "wrongpin", "IRQ pin is not gpio11",
            pin_state="wrong-pin",
        )
        assert_rejected(
            base / "missing-pull-up", "missingpull", "lacks bias-pull-up",
            pin_state="missing-pull-up",
        )
        assert_rejected(
            base / "bias-disabled", "biasdisable", "has bias-disable",
            pin_state="bias-disable",
        )
        assert_rejected(
            base / "bad-power-source", "badpower", "power-source is not big-endian 1",
            pin_state="bad-power-source",
        )
        assert_rejected(
            base / "max-module", "maxmodule",
            "MAX module is already loaded", max_module=True,
        )
        assert_rejected(
            base / "module-hash", "modulehash",
            "hash mismatch for",
        )

        success_root = base / "success"
        result = run_case(success_root, "success")
        assert result.returncode == 0, (
            f"success fixture failed:\n{result.stdout}\n{result.stderr}"
        )
        assert (success_root / "insmod.log").read_text(
            encoding="utf-8"
        ).splitlines() == [
            "max17042_battery.ko",
            "max77705.ko",
            "max77705_charger.ko",
        ]
        assert "fuel_stage=pass" in result.stdout
        assert "mfd_stage=pass" in result.stdout
        assert "charger_stage=pass" in result.stdout
        assert not (success_root / "sysfs-write.log").exists(), (
            "exact 500000uA inherited limits must not trigger sysfs writes"
        )

        low_root = base / "valid-low"
        result = run_case(
            low_root,
            "valid-low",
            input_current="500000",
            charge_current="100000",
        )
        assert result.returncode == 0, (
            f"valid lower inherited-current fixture failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "input_expected_uA=500000" in result.stdout
        assert "charge_expected_uA=100000" in result.stdout
        assert "input_readback_uA=500000" in result.stdout
        assert "charge_readback_uA=100000" in result.stdout
        assert not (low_root / "sysfs-write.log").exists(), (
            "valid lower inherited limits must not trigger sysfs writes"
        )

        both_low_root = base / "both-below-cap"
        result = run_case(
            both_low_root,
            "both-below-cap",
            input_current="400000",
            charge_current="450000",
        )
        assert result.returncode == 0, (
            f"both below-cap inherited-current fixture failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "input_expected_uA=400000" in result.stdout
        assert "charge_expected_uA=450000" in result.stdout
        assert "input_readback_uA=400000" in result.stdout
        assert "charge_readback_uA=450000" in result.stdout
        assert not (both_low_root / "sysfs-write.log").exists(), (
            "both valid below-cap limits must not trigger sysfs writes"
        )

        mixed_charge_root = base / "mixed-charge-high"
        result = run_case(
            mixed_charge_root,
            "mixed-charge-high",
            input_current="100000",
            charge_current="2100000",
        )
        assert result.returncode == 0, (
            f"mixed lower-input/high-charge fixture failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "input_expected_uA=100000" in result.stdout
        assert "charge_expected_uA=500000" in result.stdout
        assert "input_readback_uA=100000" in result.stdout
        assert "charge_readback_uA=500000" in result.stdout
        assert (mixed_charge_root / "sysfs-write.log").read_text(
            encoding="utf-8"
        ).splitlines() == ["500000"]

        mixed_input_root = base / "mixed-input-high"
        result = run_case(
            mixed_input_root,
            "mixed-input-high",
            input_current="1750000",
            charge_current="100000",
        )
        assert result.returncode == 0, (
            f"mixed high-input/lower-charge fixture failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "input_expected_uA=500000" in result.stdout
        assert "charge_expected_uA=100000" in result.stdout
        assert "input_readback_uA=500000" in result.stdout
        assert "charge_readback_uA=100000" in result.stdout
        assert (mixed_input_root / "sysfs-write.log").read_text(
            encoding="utf-8"
        ).splitlines() == ["475000"]

        offline_unspecified_root = base / "offline-unspecified"
        result = run_case(
            offline_unspecified_root,
            "offline-unspecified",
            charger_online="0",
            charger_health="Unspecified failure",
            charger_status="Discharging",
        )
        assert result.returncode == 0, (
            f"offline Unspecified failure fixture failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "charger_plausibility=health:Unspecified failure online:0 status:Discharging" in result.stdout

        offline_good_root = base / "offline-good"
        result = run_case(
            offline_good_root,
            "offline-good",
            charger_online="0",
            charger_health="Good",
            charger_status="Discharging",
        )
        assert result.returncode == 0, (
            f"offline Good fixture failed:\n{result.stdout}\n{result.stderr}"
        )

        for case, kwargs, expected in (
            (
                "offline-unspecified-charging",
                {
                    "charger_online": "0",
                    "charger_health": "Unspecified failure",
                    "charger_status": "Charging",
                },
                "offline charger status is not Discharging",
            ),
            (
                "offline-dead",
                {
                    "charger_online": "0",
                    "charger_health": "Dead",
                    "charger_status": "Discharging",
                },
                "unexpected offline charger health",
            ),
            (
                "online-unspecified",
                {
                    "charger_online": "1",
                    "charger_health": "Unspecified failure",
                    "charger_status": "Charging",
                },
                "charger health is not Good while online",
            ),
            (
                "malformed-status",
                {
                    "charger_online": "0",
                    "charger_health": "Good",
                    "charger_status": "not-a-status",
                },
                "invalid charger status",
            ),
        ):
            result = run_case(base / case, case, **kwargs)
            assert result.returncode != 0, (
                f"{case} unexpectedly passed:\n{result.stdout}\n{result.stderr}"
            )
            assert expected in result.stderr, f"{case}: missing {expected!r}: {result.stderr}"

        for bad_health in ("Overvoltage", "Undervoltage", "No battery", "Unknown", "", "bad-health"):
            case = "offline-bad-health-" + (bad_health.replace(" ", "-") or "empty")
            result = run_case(base / case, case, charger_online="0", charger_health=bad_health, charger_status="Discharging")
            assert result.returncode != 0 and "unexpected offline charger health" in result.stderr, (case, result.stdout, result.stderr)
        for bad_status in ("Unknown", "Full", "Not charging", ""):
            case = "offline-bad-status-" + (bad_status.replace(" ", "-") or "empty")
            result = run_case(base / case, case, charger_online="0", charger_health="Good", charger_status=bad_status)
            assert result.returncode != 0, (case, result.stdout, result.stderr)

        wall_root = base / "wall-inherited"
        result = run_case(
            wall_root,
            "wall-inherited",
            input_current="1750000",
            charge_current="2100000",
        )
        assert result.returncode == 0, (
            f"wall inherited-current fixture failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "current_limit_policy=conservative_cap" in result.stdout
        assert "input_inherited_uA=1750000" in result.stdout
        assert "charge_inherited_uA=2100000" in result.stdout
        assert "input_write_uA=475000" in result.stdout
        assert "charge_write_uA=500000" in result.stdout
        assert "input_readback_uA=500000" in result.stdout
        assert "charge_readback_uA=500000" in result.stdout
        assert (wall_root / "sysfs-write.log").read_text(encoding="utf-8").splitlines() == [
            "475000",
            "500000",
        ]

        for case, kwargs, expected in (
            (
                "malformed-current",
                {"input_current": "not-a-number", "charge_current": "2100000"},
                "input_current_limit_uA is not an unsigned integer",
            ),
            (
                "missing-current",
                {"input_current": "1750000", "charge_current": "2100000"},
                "input_current_limit_uA is not an unsigned integer",
            ),
            (
                "below-min-input",
                {"input_current": "99999", "charge_current": "2100000"},
                "input_current_limit_uA out of range",
            ),
            (
                "below-min-charge",
                {"input_current": "1750000", "charge_current": "99999"},
                "constant_charge_current_uA out of range",
            ),
            (
                "out-of-range-current",
                {"input_current": "5000000", "charge_current": "2100000"},
                "out of range",
            ),
            (
                "writefail",
                {"input_current": "1750000", "charge_current": "2100000"},
                "failed to write input_current_limit_uA",
            ),
            (
                "readbackfail",
                {"input_current": "1750000", "charge_current": "2100000"},
                "input_current_limit_uA readback is not 500000",
            ),
        ):
            failure_root = base / case
            result = run_case(failure_root, case, **kwargs)
            assert result.returncode != 0, (
                f"{case} unexpectedly passed:\n{result.stdout}\n{result.stderr}"
            )
            assert expected in result.stderr, f"{case}: missing {expected!r}: {result.stderr}"
            if case in {"malformed-current", "below-min-input", "below-min-charge", "out-of-range-current"}:
                assert not (failure_root / "sysfs-write.log").exists(), (
                    f"{case} wrote before validating both inherited values"
                )
            if case == "missing-current":
                assert not (failure_root / "sysfs-write.log").exists(), (
                    "missing property wrote before validation"
                )
            if case == "readbackfail":
                assert (failure_root / "sysfs-write.log").read_text(
                    encoding="utf-8"
                ).splitlines() == ["475000"], (
                    "readback failure must stop before the charge-current write"
                )

    print("PASS: battery identity, prep/DT, no-UDC, ordered-load, conservative-cap, and failure fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
