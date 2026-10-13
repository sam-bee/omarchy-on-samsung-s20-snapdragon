#!/usr/bin/env python3
"""Offline fixtures for the production CONTROL1 USB-route helper."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import shutil


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "rootfs/usr/local/sbin/r8q-usb-route-ensure.sh"
ROOT_DEVICE_HELPER = REPO_ROOT / "rootfs/usr/local/sbin/r8q-root-device"
PROTOCOL = REPO_ROOT / "rootfs/usr/local/lib/r8q-usb-route/protocol-binding.env"
SOURCE_DIR = REPO_ROOT / "out/unattended-boot-20261009/usb-handoff-review/exact-smg7810-source"
BOOT_SHA = "e08db773c7231bbeac02493fb07220fe176c20bebbf134470d0980c07f0ee725"
BOOT_ID = "62ed6bf0-f658-43df-8398-8075c8792855"
PINNED_SOURCE = {
    "SOURCE_REPOSITORY": "BeneficialCode/android_kernel_samsung_smg7810",
    "SOURCE_COMMIT": "efbb7d3b9d0c36bd86bd098a9f0c9fc7cc6b2488",
    "SOURCE_MANIFEST_SHA256": "021f36ceefa0fc9e6f762cd4bacb859f00af357a8d4d28cbfd566ccc64860863",
    "SOURCE_VERIFICATION_SHA256": "9eb387c140cb31dc38c97695a99eb77ff20e2c99d74e3086ecc1f9bc539a8b2e",
    "SOURCE_VERIFIED_FILES": "31",
}


def symlink(target: Path, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)


def bindings() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in PROTOCOL.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def make_tree(root: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    sysfs = root / "sys"
    proc = root / "proc"
    etc = root / "etc"
    fake_bin = root / "bin"
    state = root / "state"
    protocol_dir = root / "usr/local/lib/r8q-usb-route"

    adapter = sysfs / "devices/platform/soc/980000.i2c/i2c-7"
    of_node = sysfs / "firmware/devicetree/base/soc@0/geniqup@9c0000/i2c@980000"
    adapter.mkdir(parents=True)
    of_node.mkdir(parents=True)
    symlink(of_node, adapter / "of_node")
    symlink(adapter, sysfs / "bus/i2c/devices/i2c-7")
    pmic = sysfs / "bus/i2c/devices/7-0066"
    pmic.mkdir(parents=True)
    symlink(of_node, pmic / "of_node")

    udc_state = sysfs / "class/udc/a600000.usb/state"
    udc_state.parent.mkdir(parents=True)
    udc_state.write_text("configured\n", encoding="utf-8")
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text(f"{BOOT_ID}\n", encoding="utf-8")
    (proc / "uptime").write_text("42.00 1.00\n", encoding="utf-8")
    (proc / "modules").parent.mkdir(parents=True, exist_ok=True)
    (proc / "modules").write_text("i2c_core 32768 0 - Live 0x0\n", encoding="utf-8")
    etc.mkdir(parents=True)
    (etc / "machine-id").write_text("1290f2212bd743569044571db21a6c96\n", encoding="utf-8")
    (etc / "r8q-usb-route.env").write_text(
        "EXPECTED_KERNEL=7.1.2-r8q-rtc2\n"
        "EXPECTED_MACHINE_ID=1290f2212bd743569044571db21a6c96\n"
        "EXPECTED_ROOT_UUID=217b9308-40c7-4eb0-90a9-09ed4e233173\n"
        f"EXPECTED_BOOT_SHA256={BOOT_SHA}\n",
        encoding="utf-8",
    )
    with (etc / "r8q-usb-route.env").open("a", encoding="utf-8") as config:
        config.write("EXPECTED_VERMAGIC='7.1.2-r8q-rtc2 SMP preempt mod_unload aarch64'\n")
        config.write("EXPECTED_GPI_SHA256=" + ("0" * 64) + "\n")
        config.write("EXPECTED_GENI_SHA256=" + ("1" * 64) + "\n")
        config.write(f"EXPECTED_HELPER_SHA256={hashlib.sha256(HELPER.read_bytes()).hexdigest()}\n")
        config.write(f"EXPECTED_PROTOCOL_SHA256={hashlib.sha256(PROTOCOL.read_bytes()).hexdigest()}\n")
    protocol_dir.mkdir(parents=True)
    shutil.copy2(PROTOCOL, protocol_dir / "protocol-binding.env")
    root_helper = root / "usr/local/sbin/r8q-root-device"
    root_helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT_DEVICE_HELPER, root_helper)
    root_helper.chmod(0o755)

    fake_bin.mkdir(parents=True)
    (fake_bin / "findmnt").write_text(
        "#!/bin/sh\n"
        "case \" $* \" in\n"
        "  *' -o SOURCE '*) printf '%s\\n' /dev/sda36 ;;\n"
        "  *' -o FSTYPE '*) printf '%s\\n' ext4 ;;\n"
        "  *' -o UUID '*) printf '%s\\n' 217b9308-40c7-4eb0-90a9-09ed4e233173 ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    (fake_bin / "stat").write_text(
        "#!/bin/sh\n"
        "test \"$1\" = -c && test \"$2\" = '%u:%g:%a' || exit 1\n"
        "printf '%s\\n' 0:0:600\n",
        encoding="utf-8",
    )
    (fake_bin / "uname").write_text("#!/bin/sh\nprintf '%s\\n' 7.1.2-r8q-rtc2\n", encoding="utf-8")
    (fake_bin / "blkid").write_text(
        "#!/bin/sh\nprintf '%s\\n' 217b9308-40c7-4eb0-90a9-09ed4e233173\n", encoding="utf-8"
    )
    (fake_bin / "sha256sum").write_text(
        f"#!/bin/sh\ncase \"$1\" in *boot23) printf '%s  %s\\n' {BOOT_SHA} \"$1\" ;; *) exec /usr/bin/sha256sum \"$@\" ;; esac\n",
        encoding="utf-8",
    )
    fake_i2c = r'''#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$R8Q_FAKE_LOG"
read_count() { cat "$1" 2>/dev/null || printf '0'; }
inc_count() { printf '%s\n' $(( $(read_count "$1") + 1 )) > "$1"; }
case "$*" in
  *'w1@0x66 0x00 r1'*) printf '0x15\n' ;;
  *'w1@0x66 0x01 r1'*) printf '0x02\n' ;;
  *'w1@0x25 0x08 r1'*)
    case "$R8Q_MODE" in
      nohost|nohost-nc) printf '0x00\n' ;;
      nohost-bc) printf '0x01\n' ;;
      nohost-dcd) printf '0x04\n' ;;
      nohost-sink) printf '0x00\n' ;;
      wall) printf '0x83\n' ;;
      wall-no-vbus) printf '0x03\n' ;;
      wall-dcd) printf '0x87\n' ;;
      wall-wrong-bc) printf '0x80\n' ;;
      unknown-bc) printf '0x80\n' ;;
      *) printf '0x81\n' ;;
    esac
    ;;
  *'w1@0x25 0x0a r1'*)
    case "$R8Q_MODE" in
      nohost|nohost-nc|nohost-bc|nohost-dcd) printf '0x50\n' ;;
      nohost-sink) printf '0x51\n' ;;
      wall-no-cc) printf '0x50\n' ;;
      source) printf '0x52\n' ;;
      cc-unknown) printf '0x53\n' ;;
      i2c-failure) exit 7 ;;
      *) printf '0x51\n' ;;
    esac
    ;;
  *'w1@0x25 0x0b r1'*)
    case "$R8Q_MODE" in
      water) printf '0x02\n' ;;
      short) printf '0x80\n' ;;
      overcurrent) printf '0x20\n' ;;
      *) printf '0x08\n' ;;
    esac
    ;;
  *'w1@0x25 0x02 r1'*)
    inc_count "$R8Q_FAKE_UIC"
    n=$(read_count "$R8Q_FAKE_UIC")
    if test "$n" -eq 1; then
      case "$R8Q_MODE" in
        route3f|routea4|write-failure|post-mismatch) printf '0x32\n' ;;
        initial-disallowed) printf '0x40\n' ;;
        *) printf '0x00\n' ;;
      esac
    elif test "$n" -eq 2; then
      printf '0x00\n'
    elif test "$R8Q_MODE" = concurrent; then
      printf '0x40\n'
    elif test "$R8Q_MODE" = timeout; then
      printf '0x00\n'
    else
      printf '0x80\n'
    fi
    ;;
  *'w2@0x25 0x21 0x05'*)
    inc_count "$R8Q_FAKE_READS"
    ;;
  *'w2@0x25 0x41 0x00'*) : ;;
  *'w3@0x25 0x21 0x06 0x09'*)
    test "$R8Q_MODE" != write-failure || exit 7
    inc_count "$R8Q_FAKE_WRITES"
    ;;
  *'w1@0x25 0x51 r2'*)
    n=$(read_count "$R8Q_FAKE_READS")
    case "$R8Q_MODE:$n" in
      route09:*) printf '0x05 0x09\n' ;;
      route3f:1|routea4:1|write-failure:1|post-mismatch:1) test "$R8Q_MODE" = routea4 && printf '0x05 0xa4\n' || printf '0x05 0x3f\n' ;;
      route3f:2|routea4:2) printf '0x05 0x09\n' ;;
      post-mismatch:1|post-mismatch:2) printf '0x05 0x3f\n' ;;
      unknown:*) printf '0x05 0x01\n' ;;
      *) printf '0x05 0x09\n' ;;
    esac
    ;;
  *'w1@0x25 0x51 r1'*) printf '0x06\n' ;;
  *) exit 91 ;;
esac
'''
    (fake_bin / "i2ctransfer").write_text(fake_i2c, encoding="utf-8")
    for path in fake_bin.iterdir():
        path.chmod(0o755)
    boot = root / "boot23"
    boot.write_text("offline boot fixture\n", encoding="utf-8")
    state.mkdir(parents=True)
    return sysfs, proc, etc, fake_bin, boot, protocol_dir


def run_fixture(root: Path, sysfs: Path, proc: Path, etc: Path, fake_bin: Path, boot: Path, protocol_dir: Path, mode: str, *, hardware_mode: str = "1", optional_nohost: str = "0") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "PATH": str(fake_bin) + os.pathsep + env["PATH"],
            "R8Q_OFFLINE_FIXTURE": "1",
            "R8Q_USB_ROUTE_HARDWARE_MODE": hardware_mode,
            "R8Q_USB_ROUTE_OPTIONAL_NOHOST": optional_nohost,
            "R8Q_PROTOCOL_DIR": str(protocol_dir),
            "R8Q_CONFIG_FILE": str(etc / "r8q-usb-route.env"),
            "R8Q_SYSFS_ROOT": str(sysfs),
            "R8Q_PROC_ROOT": str(proc),
            "R8Q_ETC_ROOT": str(etc),
            "R8Q_STATE_ROOT": str(root / "state"),
            "R8Q_BOOT_DEVICE": str(boot),
            "R8Q_ROOT_DEVICE": "/dev/fake-root",
            "R8Q_ROOT_DEVICE_FINDMNT": str(fake_bin / "findmnt"),
            "R8Q_ROOT_DEVICE_BLKID": str(fake_bin / "blkid"),
            "R8Q_ROOT_DEVICE_STAT": str(fake_bin / "stat"),
            "R8Q_POLL_LIMIT": "3",
            "R8Q_POLL_SLEEP": "0",
            "R8Q_MODE": mode,
            "R8Q_FAKE_MODE": mode,
            "R8Q_FAKE_LOG": str(root / "i2ctransfer.log"),
            "R8Q_FAKE_UIC": str(root / "uic-count"),
            "R8Q_FAKE_READS": str(root / "read-count"),
            "R8Q_FAKE_WRITES": str(root / "write-count"),
        }
    )
    return subprocess.run([str(HELPER)], env=env, text=True, capture_output=True)


def commands(raw: Path) -> list[str]:
    return [line.removeprefix("command=") for line in raw.read_text().splitlines() if line.startswith("command=")]


def verify_source_binding() -> None:
    fields = bindings()
    assert "EXPECTED_KERNEL" not in fields
    assert "EXPECTED_MACHINE_ID" not in fields
    assert "EXPECTED_ROOT_UUID" not in fields
    assert "EXPECTED_BOOT_SHA256" not in fields
    for key, value in PINNED_SOURCE.items():
        assert fields.get(key) == value, key
    expected = {
        "include/linux/ccic/max77705.h": "SOURCE_CCIC_H_SHA256",
        "include/linux/muic/max77705-muic.h": "SOURCE_MUIC_H_SHA256",
        "include/linux/mfd/max77705-private.h": "SOURCE_PRIVATE_H_SHA256",
        "drivers/mfd/max77705.c": "SOURCE_MFD_C_SHA256",
        "drivers/mfd/max77705-irq.c": "SOURCE_IRQ_C_SHA256",
        "drivers/ccic/max77705_usbc.c": "SOURCE_USBC_C_SHA256",
        "drivers/muic/max77705-muic.c": "SOURCE_MUIC_C_SHA256",
    }
    manifest_path = SOURCE_DIR / "manifest.json"
    verification_path = SOURCE_DIR / "primary-source-verification.json"
    if manifest_path.is_file() and verification_path.is_file():
        manifest_bytes = manifest_path.read_bytes()
        verification_bytes = verification_path.read_bytes()
        assert hashlib.sha256(manifest_bytes).hexdigest() == fields["SOURCE_MANIFEST_SHA256"]
        assert hashlib.sha256(verification_bytes).hexdigest() == fields["SOURCE_VERIFICATION_SHA256"]
        by_path = {item["path"]: item["sha256"] for item in json.loads(manifest_bytes)["files"]}
        for path, field in expected.items():
            source_file = SOURCE_DIR / path
            assert source_file.is_file(), path
            assert by_path[path] == fields[field], path
            assert hashlib.sha256(source_file.read_bytes()).hexdigest() == fields[field], path
        print("INFO: exact source manifest and seven-file verification available: PASS")
    else:
        print("INFO: exact source manifest/file verification unavailable; pinned constants validated")


def assert_common(commands_list: list[str], fake_i2c: Path) -> None:
    joined = "\n".join(commands_list)
    assert all("-f" not in command and "i2cdetect" not in command for command in commands_list)
    assert "0x0e" not in joined and "0x0f" not in joined and "0x10" not in joined and "0x11" not in joined
    assert "reset" not in joined.lower() and "mask" not in joined.lower()
    assert commands_list[0] == f"{fake_i2c} -y 7 w1@0x66 0x00 r1"
    assert commands_list[1] == f"{fake_i2c} -y 7 w1@0x66 0x01 r1"


def main() -> int:
    verify_source_binding()
    modes = ("route09", "route3f", "routea4", "concurrent", "water", "short", "overcurrent", "unknown", "timeout", "write-failure", "post-mismatch", "initial-disallowed")
    with tempfile.TemporaryDirectory(prefix="r8q-control1-boot-route-") as temp:
        base = Path(temp)
        for mode in modes:
            root = base / mode
            root.mkdir()
            sysfs, proc, etc, fake_bin, boot, protocol_dir = make_tree(root)
            disabled = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, mode, hardware_mode="0")
            assert disabled.returncode != 0 and "hardware mode is disabled" in disabled.stderr
            result = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, mode)
            state = root / "state" / BOOT_ID
            receipt = state / "receipt.txt"
            raw = state / "i2c.raw"
            assert receipt.exists() and raw.exists(), mode
            text = receipt.read_text()
            command_list = commands(raw)
            if mode == "route09":
                assert result.returncode == 0, result.stderr
                assert "route_outcome=already_AP" in text and "write06_attempted=false" in text
                assert "mailbox_writes_attempted=2" in text and "mailbox_writes_succeeded=2" in text
                assert not (root / "state" / "once.attempt").exists()
                assert not any("w3@0x25" in command for command in command_list)
                assert_common(command_list, fake_bin / "i2ctransfer")
                before = (root / "i2ctransfer.log").read_text()
                again = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, mode)
                assert again.returncode != 0 and "refusing retry" in again.stderr
                assert (root / "i2ctransfer.log").read_text() == before
            elif mode in ("route3f", "routea4"):
                assert result.returncode == 0, result.stderr
                expected_name = "COM_OPEN" if mode == "route3f" else "COM_USB_CP"
                expected_before = "0x3f" if mode == "route3f" else "0xa4"
                assert f"route_name={expected_name}" in text and f"route_before_write={expected_before}" in text
                assert "route_outcome=changed_to_AP" in text and "post_control1=0x09" in text
                assert "mailbox_writes_attempted=6" in text and "mailbox_writes_succeeded=6" in text
                assert any("w3@0x25 0x21 0x06 0x09" in command for command in command_list)
                assert_common(command_list, fake_bin / "i2ctransfer")
            elif mode in ("water", "short", "overcurrent", "initial-disallowed"):
                assert result.returncode != 0, mode
                assert "w2@" not in raw.read_text() and "w3@" not in raw.read_text()
                assert "mailbox_writes_attempted=0" in text
            elif mode == "unknown":
                assert result.returncode != 0 and "unknown CONTROL1 route" in result.stderr
                assert "mailbox_writes_attempted=2" in text and "mailbox_writes_succeeded=2" in text
                assert "w3@" not in raw.read_text()
            elif mode == "concurrent":
                assert result.returncode != 0 and "unexpected UIC_INT bits" in result.stderr
                assert "mailbox_writes_attempted=2" in text and "mailbox_writes_succeeded=2" in text
            elif mode == "timeout":
                assert result.returncode != 0 and "pre response timeout" in result.stderr
                assert "phase_pre_poll_count=3" in text
            elif mode == "write-failure":
                assert result.returncode != 0 and "transaction 12" in result.stderr
                assert "mailbox_writes_attempted=3" in text and "mailbox_writes_succeeded=2" in text
                assert "manual_cleanup_required=1" in text
            elif mode == "post-mismatch":
                assert result.returncode != 0 and "post-write CONTROL1" in result.stderr
                assert "mailbox_writes_attempted=6" in text and "mailbox_writes_succeeded=6" in text
                assert "manual_cleanup_required=1" in text
        strict_cases = {
            "unknown-variable": "UNEXPECTED=1\n",
            "unknown-identity-variable": "EXPECTED_ROOT_UUID_EXTRA=1\n",
            "duplicate-variable": "EXPECTED_KERNEL=7.1.2-r8q-rtc2\n",
            "bad-boot-hash": "EXPECTED_BOOT_SHA256=not-a-hash\n",
        }
        for name, suffix in strict_cases.items():
            root = base / name
            root.mkdir()
            sysfs, proc, etc, fake_bin, boot, protocol_dir = make_tree(root)
            config = (etc / "r8q-usb-route.env").read_text(encoding="utf-8")
            if name == "bad-boot-hash":
                config = config.replace(f"EXPECTED_BOOT_SHA256={BOOT_SHA}", "EXPECTED_BOOT_SHA256=not-a-hash")
            else:
                config += suffix
            (etc / "r8q-usb-route.env").write_text(config, encoding="utf-8")
            result = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, "route09")
            assert result.returncode != 0, name
            assert not (root / "state" / BOOT_ID).exists(), name
        print("PASS: strict deployment identity config rejection")
        optional_cases = (("nohost", "deferred_no_vbus_no_connection"), ("wall", "deferred_wall_dcp"))
        for mode, expected_outcome in optional_cases:
            root = base / ("optional-" + mode)
            root.mkdir()
            sysfs, proc, etc, fake_bin, boot, protocol_dir = make_tree(root)
            result = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, mode, optional_nohost="1")
            state = root / "state" / BOOT_ID
            receipt = state / "receipt.txt"
            raw = state / "i2c.raw"
            assert result.returncode == 0, (mode, result.stderr)
            text = receipt.read_text()
            raw_text = raw.read_text()
            assert "outcome=deferred" in text and "startup_gate=pass" in text
            assert "optional_nohost=true" in text and "uic_reads=0" in text
            assert "mailbox_writes_attempted=0" in text and "mailbox_writes_succeeded=0" in text
            assert "w1@0x25 0x02" not in raw_text and "w2@" not in raw_text and "w3@" not in raw_text
            assert f"route_outcome={expected_outcome}" in text

        root = base / "optional-host"
        root.mkdir()
        sysfs, proc, etc, fake_bin, boot, protocol_dir = make_tree(root)
        result = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, "route09", optional_nohost="1")
        receipt = (root / "state" / BOOT_ID / "receipt.txt").read_text()
        raw = root / "state" / BOOT_ID / "i2c.raw"
        command_list = commands(raw)
        assert result.returncode == 0, result.stderr
        assert "route_outcome=already_AP" in receipt and "outcome=pass" in receipt
        assert "mailbox_writes_attempted=2" in receipt and "mailbox_writes_succeeded=2" in receipt
        assert_common(command_list, fake_bin / "i2ctransfer")
        assert not any("w3@0x25" in command for command in command_list)

        root = base / "optional-nohost-legacy"
        root.mkdir()
        sysfs, proc, etc, fake_bin, boot, protocol_dir = make_tree(root)
        result = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, "nohost", optional_nohost="0")
        receipt = (root / "state" / BOOT_ID / "receipt.txt").read_text()
        assert result.returncode != 0 and "CC_STATUS0 is not SINK" in result.stderr
        assert "mailbox_writes_attempted=0" in receipt

        for mode, reason in (("source", "SOURCE"), ("cc-unknown", "unknown state"), ("unknown-bc", "unknown"), ("nohost-sink", "SINK while VBUSDet"), ("nohost-bc", "no-host CC status has BC"), ("nohost-dcd", "DCDtmo"), ("wall-no-vbus", "SINK while VBUSDet"), ("wall-no-cc", "no-host CC status has VBUS"), ("wall-dcd", "DCDTmo"), ("wall-wrong-bc", "unknown"), ("water", "water"), ("i2c-failure", "i2ctransfer failed")):
            root = base / ("optional-fail-" + mode)
            root.mkdir()
            sysfs, proc, etc, fake_bin, boot, protocol_dir = make_tree(root)
            result = run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, mode, optional_nohost="1")
            receipt = (root / "state" / BOOT_ID / "receipt.txt").read_text()
            raw = (root / "state" / BOOT_ID / "i2c.raw").read_text()
            assert result.returncode != 0 and reason.lower() in result.stderr.lower(), (mode, result.stderr)
            assert "mailbox_writes_attempted=0" in receipt and "w2@" not in raw and "w3@" not in raw
        print("PASS: opt-in, source bindings, route09 skip, COM_OPEN/COM_USB_CP write+verify, UIC/status fail-closed guards, concurrency, timeout, transaction failure, post-write mismatch, one-shot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
