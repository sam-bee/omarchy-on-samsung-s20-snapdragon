#!/usr/bin/env python3
"""Offline safety tests for prepare-encryption-initramfs.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/prepare-encryption-initramfs.py"
RELEASE = "7.1.2-r8q-rtc2"


def load_module():
    spec = importlib.util.spec_from_file_location("prepare_encryption_initramfs", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREPARER = load_module()


def fake_elf(path: Path, needed=(), interpreter=None) -> None:
    """Create a small AArch64 ELF-shaped fixture for the closure parser."""
    path.parent.mkdir(parents=True, exist_ok=True)
    strings = bytearray(b"\0")
    offsets = {}

    def add_string(value: str) -> int:
        offsets[value] = len(strings)
        strings.extend(value.encode() + b"\0")
        return offsets[value]

    for value in needed:
        add_string(value)
    if interpreter:
        add_string(interpreter)
    string_offset = 0x300
    dynamic_offset = 0x400
    program_headers = 3 if interpreter else 2
    dynamic_entries = [(5, string_offset), (10, len(strings))]
    dynamic_entries.extend((1, offsets[value]) for value in needed)
    dynamic_entries.append((0, 0))
    dynamic_size = len(dynamic_entries) * 16
    interp_offset = 0x280
    interp_data = (interpreter.encode() + b"\0") if interpreter else b""
    total = 0x600
    data = bytearray(total)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        3,
        183,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        program_headers,
        0,
        0,
        0,
    )
    data[:64] = header
    ph = []
    ph.append(struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000))
    ph.append(struct.pack("<IIQQQQQQ", 2, 4, dynamic_offset, dynamic_offset, 0, dynamic_size, dynamic_size, 8))
    if interpreter:
        ph.append(struct.pack("<IIQQQQQQ", 3, 4, interp_offset, interp_offset, 0, len(interp_data), len(interp_data), 1))
    for index, value in enumerate(ph):
        data[64 + index * 56 : 64 + (index + 1) * 56] = value
    for index, (tag, value) in enumerate(dynamic_entries):
        data[dynamic_offset + index * 16 : dynamic_offset + (index + 1) * 16] = struct.pack("<qQ", tag, value)
    data[string_offset : string_offset + len(strings)] = strings
    if interpreter:
        data[interp_offset : interp_offset + len(interp_data)] = interp_data
    path.write_bytes(data)
    path.chmod(0o755)


def fake_module(path: Path, release: str = RELEASE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + b"\0" * 64 + f"vermagic={release} SMP preempt mod_unload aarch64\0".encode())
    path.chmod(0o644)


class EncryptionInitramfsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r8q-encryption-test-")
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        (self.base / "bin").mkdir(parents=True)
        (self.base / "init").write_text("#!/bin/busybox sh\nmount -t ext4 raw /newroot\n", encoding="utf-8")
        (self.base / "init").chmod(0o755)
        fake_elf(self.base / "bin/busybox")
        self.runtime = self.root / "runtime"
        fake_elf(self.runtime / "lib/ld-linux-aarch64.so.1", interpreter=None)
        fake_elf(self.runtime / "usr/bin/cryptsetup", ["libcryptsetup.so.12", "libpopt.so.0", "libuuid.so.1", "libblkid.so.1", "libc.so.6"], "/lib/ld-linux-aarch64.so.1")
        fake_elf(self.runtime / "usr/bin/unl0kr", ["libc.so.6"], "/lib/ld-linux-aarch64.so.1")
        fake_elf(self.runtime / "usr/bin/udevadm", ["libc.so.6"], "/lib/ld-linux-aarch64.so.1")
        fake_elf(self.runtime / "usr/bin/dmsetup", ["libc.so.6"], "/lib/ld-linux-aarch64.so.1")
        fake_elf(self.runtime / "usr/lib/libcryptsetup.so.12", ["libdevmapper.so.1.02", "libcrypto.so.3", "libjson-c.so.5", "libblkid.so.1", "libuuid.so.1", "libc.so.6"])
        fake_elf(self.runtime / "usr/lib/libdevmapper.so.1.02", ["libudev.so.1", "libm.so.6", "libc.so.6"])
        for name in ("libpopt.so.0", "libuuid.so.1", "libblkid.so.1", "libcrypto.so.3", "libjson-c.so.5", "libc.so.6", "libudev.so.1", "libm.so.6"):
            fake_elf(self.runtime / "usr/lib" / name)
        self.ui = self.runtime / "usr/bin/unl0kr"
        self.cryptsetup = self.runtime / "usr/bin/cryptsetup"
        self.udevadm = self.runtime / "usr/bin/udevadm"
        self.dmsetup = self.runtime / "usr/bin/dmsetup"
        self.modules = self.root / "modules"
        for name in PREPARER.MODULES:
            fake_module(self.modules / "drivers" / name)

    def tearDown(self):
        self.temp.cleanup()

    def run_prepare(self, output: Path, *extra: str):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--base-initramfs", str(self.base), "--runtime-root", str(self.runtime), "--cryptsetup", str(self.cryptsetup), "--unl0kr", str(self.ui), "--udevadm", str(self.udevadm), "--dmsetup", str(self.dmsetup), "--touch-module-dir", str(self.modules), "--kernel-release", RELEASE, "--output", str(output), *extra],
            text=True,
            capture_output=True,
        )


    def _write_executable(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _protocol_harness(self, candidate: Path, mode: str, attempts: int = 3, timeout: int = 180):
        """Run the generated protocol with shell stubs, never host mounts/devices."""
        harness = self.root / ("protocol-" + mode)
        fake_root = harness / "root"
        fake_bin = harness / "bin"
        fake_root.mkdir(parents=True)
        for directory in ("dev", "proc", "sys", "run", "newroot"):
            (fake_root / directory).mkdir(parents=True)
        (fake_root / "sys/class/block/sda36").mkdir(parents=True)
        (fake_root / "sys/class/block/sda36/uevent").write_text("PARTNAME=userdata\n", encoding="utf-8")
        (fake_root / "dev/sda36").write_bytes(b"userdata-fixture")
        (fake_root / "dev/mapper").mkdir(parents=True)
        qroot = shlex.quote(str(fake_root))
        log = fake_root / "protocol.log"

        self._write_executable(fake_bin / "busybox", """#!/bin/sh
case "$1" in
  --install) exit 0 ;;
  basename) exec /usr/bin/basename "$2" ;;
  dirname) exec /usr/bin/dirname "$2" ;;
esac
exit 0
""")
        self._write_executable(fake_bin / "mount", f"""#!/bin/sh
root={qroot}
printf 'mount %s\\n' "$*" >> "$root/protocol.log"
target=''
for arg in "$@"; do target=$arg; done
case "$target" in
  */newroot)
    case " $* " in *' ext4 '*)
      if [ {shlex.quote(mode)} != systemd-missing ]; then
        mkdir -p "$target/usr/lib/systemd"; : > "$target/usr/lib/systemd/systemd"; chmod +x "$target/usr/lib/systemd/systemd"
      fi
      ;;
    esac ;;
  */newroot/dev)
    if [ {shlex.quote(mode)} = newroot-dev-failure ]; then exit 1; fi ;;
  */newroot/run)
    if [ {shlex.quote(mode)} = run-move-failure ]; then exit 1; fi ;;
esac
exit 0
""")
        self._write_executable(fake_bin / "umount", f"""#!/bin/sh
printf 'umount %s\\n' "$*" >> {qroot}/protocol.log
exit 0
""")
        self._write_executable(fake_bin / "rm", f"""#!/bin/sh
printf 'rm %s\\n' "$*" >> {qroot}/protocol.log
exec /bin/rm "$@"
""")
        self._write_executable(fake_bin / "switch_root", f"""#!/bin/sh
printf 'switch_root %s\\n' "$*" >> {qroot}/protocol.log
exit 0
""")
        self._write_executable(fake_bin / "mknod", f"""#!/bin/sh
root={qroot}
target=''
while [ "$#" -gt 0 ]; do
  case "$1" in -m) shift 2 ;; *) target=$1; break ;; esac
done
case "$target" in "$root"/*) : > "$target" ;; *) exit 1 ;; esac
exit 0
""")
        self._write_executable(fake_bin / "insmod", f"""#!/bin/sh
root={qroot}
module=$(basename "$1" .ko)
printf 'insmod %s\\n' "$module" >> "$root/protocol.log"
case "$module" in
  gpi) name=gpi ;;
  i2c-qcom-geni) name=i2c_qcom_geni; mkdir -p "$root/sys/module/i2c_qcom_geni/parameters"; printf 1 > "$root/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo" ;;
  fts5cu56a) name=fts5cu56a; mkdir -p "$root/sys/bus/i2c/drivers/fts5cu56a/5-0049" ;;
  zinitix) name=zinitix; mkdir -p "$root/sys/bus/i2c/drivers/Zinitix-TS/5-0020" ;;
  *) exit 1 ;;
esac
mkdir -p "$root/sys/module/$name"
exit 0
""")
        self._write_executable(fake_bin / "rmmod", f"""#!/bin/sh
root={qroot}
printf 'rmmod %s\\n' "$1" >> "$root/protocol.log"
rm -rf "$root/sys/module/$1"
case "$1" in
  fts5cu56a) rm -rf "$root/sys/bus/i2c/drivers/fts5cu56a" ;;
  zinitix) rm -rf "$root/sys/bus/i2c/drivers/Zinitix-TS" ;;
esac
exit 0
""")
        self._write_executable(fake_bin / "udevadm", f"""#!/bin/sh
root={qroot}
printf 'udevadm %s\\n' "$*" >> "$root/protocol.log"
case "$1" in
  trigger)
    mkdir -p "$root/sys/bus/i2c/drivers/fts5cu56a/5-0049/input/input0"
    : > "$root/sys/bus/i2c/drivers/fts5cu56a/5-0049/input/input0/event0" ;;
  settle|control) : ;;
esac
exit 0
""")
        self._write_executable(fake_bin / "udevd", f"""#!/bin/sh
root={qroot}
# The test sandbox cannot bind a new Unix socket.  Point the disposable
# fixture at the desktop's existing udev control socket; the generated init
# still checks socket type and this stub remains a tracked live daemon.
ln -s /run/udev/control "$root/run/udev/control"
trap 'exit 0' TERM INT
while :; do /usr/bin/sleep 1; done
""")
        self._write_executable(fake_bin / "cryptsetup", f"""#!/bin/sh
root={qroot}
printf 'cryptsetup %s\\n' "$*" >> "$root/protocol.log"
case "$1" in
  isLuks) exit 0 ;;
  close) rm -f "$root/dev/mapper/cryptroot"; exit 0 ;;
  open)
    keyfile=''
    for arg in "$@"; do case "$arg" in --key-file=*) keyfile=${{arg#*=}} ;; esac; done
    n=$(cat "$root/attempts" 2>/dev/null || printf 0); n=$((n + 1)); printf '%s' "$n" > "$root/attempts"
    key=$(cat "$keyfile" 2>/dev/null || :)
    [ "$key" = right ] && exit 0
    exit 1 ;;
esac
exit 2
""")
        self._write_executable(fake_bin / "dmsetup", f"""#!/bin/sh
root={qroot}
printf 'dmsetup %s\\n' "$*" >> "$root/protocol.log"
case "$1" in mknodes) : > "$root/dev/mapper/cryptroot" ;; esac
exit 0
""")
        if mode == "wrong-right":
            ui_body = "n=$(cat \"$root/ui-attempts\" 2>/dev/null || printf 0); n=$((n + 1)); printf '%s' \"$n\" > \"$root/ui-attempts\"; [ \"$n\" -eq 1 ] && printf wrong || printf right"
        elif mode == "wrong":
            ui_body = "printf wrong"
        elif mode == "death":
            ui_body = "exit 1"
        elif mode == "timeout":
            ui_body = "/usr/bin/sleep 5; printf right"
        elif mode in ("systemd-missing", "newroot-dev-failure", "run-move-failure"):
            ui_body = "printf right"
        else:
            raise AssertionError(mode)
        self._write_executable(fake_bin / "unl0kr", f"""#!/bin/sh
root={qroot}
printf 'unl0kr %s\\n' "$*" >> "$root/protocol.log"
{ui_body}
""")

        script = (candidate / "init").read_text(encoding="utf-8")
        script = script.replace("#!/bin/busybox sh", "#!/bin/sh", 1)
        script = script.replace("BB=/bin/busybox", f"BB={shlex.quote(str(fake_bin / 'busybox'))}")
        script = script.replace('[ -b "$ROOT" ]', '[ -e "$ROOT" ]')
        script = script.replace('[ -b /dev/mapper/$MAPPER ]', '[ -e /dev/mapper/$MAPPER ]')
        for old, new in (
            ("/usr/bin/cryptsetup", fake_bin / "cryptsetup"),
            ("/usr/bin/unl0kr", fake_bin / "unl0kr"),
            ("/usr/bin/udevadm", fake_bin / "udevadm"),
            ("/usr/bin/dmsetup", fake_bin / "dmsetup"),
            ("/usr/lib/systemd/systemd-udevd", fake_bin / "udevd"),
        ):
            script = script.replace(old, shlex.quote(str(new)))
        for old in ("/sys", "/dev", "/proc", "/run", "/newroot"):
            replacement = shlex.quote(str(fake_root / old.lstrip("/")))
            script = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(old)}(?=(?:/|[\s\"'])|$)", replacement, script)
        script = script.replace("PATH=/bin:/sbin:/usr/bin:/usr/sbin", f"PATH={shlex.quote(str(fake_bin))}:/usr/bin:/bin")
        script = script.replace("ATTEMPTS=3", f"ATTEMPTS={attempts}")
        script = script.replace("UI_TIMEOUT=180", f"UI_TIMEOUT={timeout}")
        transformed = harness / "init"
        transformed.write_text(script, encoding="utf-8")
        transformed.chmod(0o755)
        result = subprocess.run(["/bin/sh", str(transformed)], text=True, capture_output=True, timeout=12)
        return result, fake_root, log

    def test_candidate_is_deterministic_and_preserves_normal_init(self):
        first = self.root / "candidate-one"
        second = self.root / "candidate-two"
        self.assertEqual(self.run_prepare(first, "--ui-arg=--test-contract").returncode, 0)
        self.assertEqual(self.run_prepare(second, "--ui-arg=--test-contract").returncode, 0)
        manifest_one = json.loads((first / "etc/r8q-encryption-manifest.json").read_text())
        manifest_two = json.loads((second / "etc/r8q-encryption-manifest.json").read_text())
        self.assertEqual(manifest_one, manifest_two)
        self.assertFalse((first / "init.normal").exists())
        generated = (first / "init").read_text()
        self.assertIn('"$BB" --install -s /bin', generated)
        self.assertIn("unl0kr' '-n'", generated)
        self.assertIn("isLuks --type luks2", generated)
        self.assertIn("open --type luks2", generated)
        self.assertIn("mknodes", generated)
        self.assertIn("udevadm", generated)
        self.assertIn("/dev/mapper/$MAPPER", generated)
        self.assertIn("FAIL CLOSED", generated)
        self.assertNotIn("telnetd", generated)
        self.assertNotIn('mount -t ext4 "$ROOT"', generated)
        self.assertNotIn("init.normal", generated)
        self.assertTrue(manifest_one["fail_closed"])
        self.assertTrue(manifest_one["udevd_alias_from_udevadm"])
        self.assertEqual(manifest_one["udevd"], "usr/lib/systemd/systemd-udevd")
        self.assertEqual(manifest_one["touch_order"][:2], ["gpi.ko", "i2c-qcom-geni.ko (r8q_force_fifo=1)"])
        syntax = subprocess.run(["sh", "-n", str(first / "init")], text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def _make_protocol_candidate(self, name: str) -> Path:
        candidate = self.root / name
        result = self.run_prepare(candidate)
        self.assertEqual(result.returncode, 0, result.stderr)
        return candidate

    def test_protocol_wrong_then_right_retries_and_tears_down_in_order(self):
        candidate = self._make_protocol_candidate("candidate-protocol-success")
        result, fake_root, log = self._protocol_harness(candidate, "wrong-right")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("cryptsetup open ") for line in lines), 2)
        self.assertEqual(sum(line.startswith("dmsetup mknodes ") for line in lines), 1)
        self.assertIn("unl0kr -n", "\n".join(lines))
        unloads = [line.split(maxsplit=1)[1] for line in lines if line.startswith("rmmod ")]
        self.assertEqual(unloads, ["fts5cu56a", "i2c_qcom_geni", "gpi"])
        self.assertTrue(any(line.startswith("mount -t ext4 ") and "/newroot" in line for line in lines))
        self.assertFalse(any(line.startswith("mount -t ext4 ") and "sda36" in line for line in lines))
        self.assertFalse((fake_root / "run/r8q-encryption-passphrase").exists())
        self.assertFalse((fake_root / "run/r8q-unl0kr.stderr").exists())
        lines = log.read_text(encoding="utf-8").splitlines()
        udev_log_remove = next(i for i, line in enumerate(lines) if line.startswith("rm ") and "r8q-udevd.log" in line)
        run_move = next(i for i, line in enumerate(lines) if line.startswith("mount -o move "))
        self.assertLess(udev_log_remove, run_move)
        self.assertTrue((fake_root / "dev/mapper/cryptroot").exists())

    def test_protocol_mount_failure_unmounts_candidate_before_mapper_close(self):
        candidate = self._make_protocol_candidate("candidate-protocol-mount-failure")
        result, fake_root, log = self._protocol_harness(candidate, "systemd-missing", attempts=1)
        self.assertEqual(result.returncode, 111, result.stderr)
        lines = log.read_text(encoding="utf-8").splitlines()
        root_unmount = next(i for i, line in enumerate(lines) if line.startswith("umount ") and line.endswith("/newroot"))
        mapper_close = next(i for i, line in enumerate(lines) if line.startswith("cryptsetup close "))
        self.assertLess(root_unmount, mapper_close)
        self.assertFalse(any(line.startswith("umount ") and line.endswith("/newroot/dev") for line in lines))

    def test_protocol_handoff_failure_unmounts_newroot_dev_then_root(self):
        candidate = self._make_protocol_candidate("candidate-protocol-handoff-failure")
        result, fake_root, log = self._protocol_harness(candidate, "run-move-failure", attempts=1)
        self.assertEqual(result.returncode, 111, result.stderr)
        lines = log.read_text(encoding="utf-8").splitlines()
        dev_unmount = next(i for i, line in enumerate(lines) if line.startswith("umount ") and line.endswith("/newroot/dev"))
        root_unmount = next(i for i, line in enumerate(lines) if line.startswith("umount ") and line.endswith("/newroot"))
        mapper_close = next(i for i, line in enumerate(lines) if line.startswith("cryptsetup close "))
        self.assertLess(dev_unmount, root_unmount)
        self.assertLess(root_unmount, mapper_close)

    def test_protocol_three_wrong_keys_fail_closed_without_plaintext_mount(self):
        candidate = self._make_protocol_candidate("candidate-protocol-failure")
        result, fake_root, log = self._protocol_harness(candidate, "wrong")
        self.assertEqual(result.returncode, 111, result.stderr)
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.startswith("cryptsetup open ") for line in lines), 3)
        self.assertFalse(any(line.startswith("dmsetup mknodes ") for line in lines))
        self.assertFalse(any(line.startswith("mount -t ext4 ") for line in lines))
        self.assertFalse((fake_root / "run/r8q-encryption-passphrase").exists())
        self.assertFalse((fake_root / "run/r8q-unl0kr.stderr").exists())

    def test_protocol_ui_death_cleans_fifo_without_hanging(self):
        candidate = self._make_protocol_candidate("candidate-protocol-death")
        result, fake_root, log = self._protocol_harness(candidate, "death", attempts=1)
        self.assertEqual(result.returncode, 111, result.stderr)
        self.assertEqual(sum(line.startswith("cryptsetup open ") for line in log.read_text().splitlines()), 1)
        self.assertFalse((fake_root / "run/r8q-encryption-passphrase").exists())
        self.assertFalse((fake_root / "run/r8q-unl0kr.stderr").exists())

    def test_protocol_ui_timeout_kills_children_and_cleans_fifo(self):
        candidate = self._make_protocol_candidate("candidate-protocol-timeout")
        result, fake_root, log = self._protocol_harness(candidate, "timeout", attempts=1, timeout=1)
        self.assertEqual(result.returncode, 111, result.stderr)
        self.assertEqual(sum(line.startswith("cryptsetup open ") for line in log.read_text().splitlines()), 1)
        self.assertFalse((fake_root / "run/r8q-encryption-passphrase").exists())
        self.assertFalse((fake_root / "run/r8q-unl0kr.stderr").exists())

    def test_explicit_runtime_asset_is_copied_and_manifested(self):
        asset = self.runtime / "usr/share/unl0kr/theme.bin"
        asset.parent.mkdir(parents=True, exist_ok=True)
        asset.write_bytes(b"theme-data")
        output = self.root / "candidate-with-asset"
        result = self.run_prepare(output, "--extra-path", "usr/share/unl0kr/theme.bin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / "usr/share/unl0kr/theme.bin").read_bytes(), b"theme-data")
        metadata = json.loads((output / "etc/r8q-encryption-manifest.json").read_text())
        self.assertEqual(metadata["extra_paths"], ["usr/share/unl0kr/theme.bin"])
        self.assertEqual(metadata["files"]["usr/share/unl0kr/theme.bin"]["kind"], "runtime-asset")

    def test_arch_lib_symlink_preserves_loader_lookup_alias(self):
        loader = self.runtime / "lib/ld-linux-aarch64.so.1"
        staged_loader = self.runtime / "usr/lib/ld-linux-aarch64.so.1"
        loader.rename(staged_loader)
        (self.runtime / "lib").rmdir()
        (self.runtime / "lib").symlink_to("usr/lib", target_is_directory=True)
        output = self.root / "candidate-lib-alias"
        result = self.run_prepare(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads((output / "etc/r8q-encryption-manifest.json").read_text())
        self.assertIn("lib/ld-linux-aarch64.so.1", metadata["files"])
        self.assertEqual(metadata["files"]["lib/ld-linux-aarch64.so.1"]["kind"], "elf")
        self.assertTrue((output / "lib/ld-linux-aarch64.so.1").is_file())

    def test_extra_asset_must_stay_under_runtime_root(self):
        outside = self.root / "outside-theme"
        outside.write_bytes(b"theme-data")
        result = self.run_prepare(self.root / "candidate", "--extra-path", str(outside))
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside runtime root", result.stderr)

    def test_non_arm_busybox_is_rejected(self):
        busybox = self.base / "bin/busybox"
        busybox.write_bytes(b"laptop-busybox")
        result = self.run_prepare(self.root / "candidate")
        self.assertEqual(result.returncode, 2)
        self.assertIn("ELF64", result.stderr)

    def test_missing_ui_is_rejected_without_output(self):
        missing = self.root / "missing-unl0kr"
        output = self.root / "candidate"
        result = subprocess.run([sys.executable, str(SCRIPT), "--base-initramfs", str(self.base), "--runtime-root", str(self.runtime), "--cryptsetup", str(self.cryptsetup), "--unl0kr", str(missing), "--udevadm", str(self.udevadm), "--dmsetup", str(self.dmsetup), "--touch-module-dir", str(self.modules), "--kernel-release", RELEASE, "--output", str(output)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertIn("unl0kr", result.stderr)

    def test_runtime_system_root_is_rejected(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--base-initramfs", str(self.base), "--runtime-root", "/usr", "--cryptsetup", "/usr/bin/cryptsetup", "--unl0kr", str(self.ui), "--udevadm", str(self.udevadm), "--dmsetup", str(self.dmsetup), "--touch-module-dir", str(self.modules), "--kernel-release", RELEASE, "--output", str(self.root / "candidate")], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("staging tree", result.stderr)

    def test_duplicate_touch_module_is_rejected(self):
        fake_module(self.modules / "duplicate" / "gpi.ko")
        result = self.run_prepare(self.root / "candidate")
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicates", result.stderr)

    def test_vermagic_mismatch_is_rejected(self):
        fake_module(self.modules / "drivers" / "gpi.ko", "7.1.2-r8q-rtc1")
        result = self.run_prepare(self.root / "candidate")
        self.assertEqual(result.returncode, 2)
        self.assertIn("vermagic", result.stderr)

    def test_sensitive_ui_name_is_rejected(self):
        sensitive = self.runtime / "usr/bin/private.key"
        fake_elf(sensitive)
        result = subprocess.run([sys.executable, str(SCRIPT), "--base-initramfs", str(self.base), "--runtime-root", str(self.runtime), "--cryptsetup", str(self.cryptsetup), "--unl0kr", str(sensitive), "--udevadm", str(self.udevadm), "--dmsetup", str(self.dmsetup), "--touch-module-dir", str(self.modules), "--kernel-release", RELEASE, "--output", str(self.root / "candidate")], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("sensitive", result.stderr)

    def test_external_ui_artifact_uses_fixed_candidate_path(self):
        external = self.root / "supplied-artifacts/unl0kr"
        fake_elf(external, ["libc.so.6"], "/lib/ld-linux-aarch64.so.1")
        output = self.root / "candidate-external-ui"
        result = subprocess.run([sys.executable, str(SCRIPT), "--base-initramfs", str(self.base), "--runtime-root", str(self.runtime), "--cryptsetup", str(self.cryptsetup), "--unl0kr", str(external), "--udevadm", str(self.udevadm), "--dmsetup", str(self.dmsetup), "--touch-module-dir", str(self.modules), "--kernel-release", RELEASE, "--output", str(output)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads((output / "etc/r8q-encryption-manifest.json").read_text())
        self.assertEqual(metadata["unl0kr"], "usr/lib/r8q-encryption/unl0kr")
        self.assertTrue((output / "usr/lib/r8q-encryption/unl0kr").exists())


if __name__ == "__main__":
    unittest.main()
