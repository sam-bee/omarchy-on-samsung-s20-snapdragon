#!/usr/bin/env python3
"""Build a disposable rollback-first encryption boot probe.

This only creates a new initramfs directory. It never writes a phone, formats
a real partition, edits the accepted candidate, or contacts a device. The
generated init has no root handoff: it restores the supplied known-good EFI
and RTC DTB before any UI, performs volatile dm-crypt/ext4 I/O, and reboots.
The passphrase and marker are public synthetic test data.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat


HERE = Path(__file__).resolve().parents[1]
PREPARER_PATH = HERE / "scripts" / "prepare-encryption-initramfs.py"
PUBLIC_PASSPHRASE = "test"
PUBLIC_MARKER = "r8q-dmcrypt-public-probe-v1"
TEST_BYTES = 96 * 1024 * 1024
REQUIRED_APPLETS = (
    "basename", "cat", "cp", "cut", "dd", "dirname", "echo", "grep",
    "insmod", "kill", "mkdir", "mkfifo", "mknod", "mount", "mv", "poweroff",
    "printf", "reboot", "rm", "rmmod", "sha256sum", "sleep", "sync", "tr", "umount",
)
BUSYBOX_CONFIG_KEYS = {
    "basename": "CONFIG_BASENAME", "cat": "CONFIG_CAT", "cp": "CONFIG_CP",
    "cut": "CONFIG_CUT", "dd": "CONFIG_DD", "dirname": "CONFIG_DIRNAME",
    "echo": "CONFIG_ECHO", "grep": "CONFIG_GREP", "insmod": "CONFIG_INSMOD",
    "kill": "CONFIG_KILL", "mkdir": "CONFIG_MKDIR", "mkfifo": "CONFIG_MKFIFO",
    "mknod": "CONFIG_MKNOD", "mount": "CONFIG_MOUNT", "mv": "CONFIG_MV",
    "poweroff": "CONFIG_POWEROFF", "printf": "CONFIG_PRINTF", "reboot": "CONFIG_REBOOT",
    "rm": "CONFIG_RM", "rmmod": "CONFIG_RMMOD", "sha256sum": "CONFIG_SHA256SUM",
    "sleep": "CONFIG_SLEEP", "sync": "CONFIG_SYNC", "tr": "CONFIG_TR",
    "umount": "CONFIG_UMOUNT",
}
TRIAL_HASH_RECEIPT = "/EFI/BOOT/R8Q-PROBE-TRIAL-HASHES"
RESULT_RECEIPT = "/EFI/BOOT/R8Q-PROBE-RESULT"
CACHE_PARTUUID = "5594c694-c871-4b5f-90b1-690a6f68e0f7"
CACHE_SECTORS = "1228800"


def die(message: str) -> None:
    raise SystemExit(f"make-probe-init.py: error: {message}")


def load_preparer():
    if not PREPARER_PATH.is_file():
        die(f"production closure helper is missing: {PREPARER_PATH}")
    spec = importlib.util.spec_from_file_location("r8q_prepare_encryption", PREPARER_PATH)
    if spec is None or spec.loader is None:
        die(f"cannot load closure helper: {PREPARER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path: Path, label: str) -> Path:
    if not path.is_file() or path.is_symlink():
        die(f"{label} must be a regular non-symlink file: {path}")
    return path


def copy_regular(source: Path, destination: Path, label: str) -> None:
    regular(source, label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(stat.S_IMODE(source.stat().st_mode) | stat.S_IRUSR | stat.S_IWUSR)


def safe_relative(path: Path, label: str) -> Path:
    if path.is_absolute() or ".." in path.parts:
        die(f"{label} has unsafe relative path: {path}")
    return path


def stage_closure(preparer, runtime_root: Path, entry: Path, output: Path, label: str):
    regular(entry, label)
    records = preparer.closure(runtime_root, entry, label, external_destination=Path("usr/bin") / label)
    staged = []
    for real, record in sorted(records.items(), key=lambda item: item[1]["source"]):
        source = Path(real)
        source_rel = safe_relative(Path(record["source"]), f"{label} closure member")
        target = output / source_rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if not target.is_file() or sha256(target) != sha256(source):
                die(f"closure collision at {target}")
        else:
            copy_regular(source, target, f"{label} closure member")
        for alias in record.get("aliases", []):
            alias_path = output / safe_relative(Path(alias), f"{label} alias")
            alias_path.parent.mkdir(parents=True, exist_ok=True)
            if alias_path.exists():
                if not alias_path.is_file() or sha256(alias_path) != sha256(source):
                    die(f"closure alias collision at {alias_path}")
            else:
                copy_regular(source, alias_path, f"{label} closure alias")
        staged.append({
            "source": str(source),
            "destination": record["source"],
            "sha256": record["sha256"],
            "size": record["size"],
            "aliases": list(record.get("aliases", [])),
            "label": record["label"],
        })
    return staged


def init_source(known_efi_hash: str, known_dtb_hash: str,
                kernel_release: str) -> str:
    return f"""#!/bin/busybox sh
set -eu
BB=/bin/busybox
PATH=/bin:/sbin:/usr/bin:/usr/sbin
LC_ALL=C
export PATH LC_ALL
PUBLIC_PASSPHRASE='{PUBLIC_PASSPHRASE}'
PUBLIC_MARKER='{PUBLIC_MARKER}'
KERNEL_RELEASE='{kernel_release}'
KNOWN_EFI_SHA256='{known_efi_hash}'
KNOWN_DTB_SHA256='{known_dtb_hash}'
EFI='/EFI/BOOT/BOOTAA64.EFI'
DTB='/EFI/BOOT/R8Q-RTC.DTB'
TRIAL_HASH_RECEIPT='/EFI/BOOT/R8Q-PROBE-TRIAL-HASHES'
RESULT_RECEIPT='/EFI/BOOT/R8Q-PROBE-RESULT'
CACHE_PARTUUID='{CACHE_PARTUUID}'
CACHE_SECTORS='{CACHE_SECTORS}'
SYSFS_ROOT=/sys
CACHE_MOUNT=/run/r8q-cache
ROLLBACK_DIR=/r8q-probe-rollback
TEST_MOUNT=/run/r8q-test-root
TEST_IMAGE=/run/r8q-test.img
TEST_LOOP=
MAPPER=r8q_probe_crypt
TEST_MOUNTED=0
MAPPER_OPEN=0
CACHE_RESTORED=0
UDEV_STARTED=0
UDEVD_PID=
TOUCH_LOADED=0
UIPID=
CRYPTPID=

log() {{ echo "r8q-probe: $*" >&2; }}
sha_file() {{ "$BB" sha256sum "$1" | "$BB" cut -d ' ' -f 1; }}
terminate_pid() {{
    pid=$1
    [ -n "$pid" ] || return 0
    "$BB" kill "$pid" 2>/dev/null || :
    tries=0
    while "$BB" kill -0 "$pid" 2>/dev/null; do
        [ "$tries" -lt 5 ] || break
        tries=$((tries + 1))
        "$BB" sleep 1
    done
    "$BB" kill -9 "$pid" 2>/dev/null || :
    wait "$pid" 2>/dev/null || :
}}
find_cache() {{
    for u in "$SYSFS_ROOT"/class/block/*/uevent; do
        [ -f "$u" ] || continue
        "$BB" grep -qi '^PARTNAME=cache$' "$u" || continue
        "$BB" grep -qi "^PARTUUID=$CACHE_PARTUUID$" "$u" || continue
        node=$("$BB" basename "$("$BB" dirname "$u")")
        [ "$("$BB" cat "$SYSFS_ROOT/class/block/$node/size" 2>/dev/null)" = "$CACHE_SECTORS" ] || continue
        echo "$node"
        return 0
    done
    return 1
}}
wait_for_cache() {{
    i=0
    while [ "$i" -lt 60 ]; do
        cache=$(find_cache) && [ -b "/dev/$cache" ] && {{
            echo "$cache"
            return 0
        }}
        "$BB" sleep 1
        i=$((i + 1))
    done
    return 1
}}
stop_udev() {{
    [ "$UDEV_STARTED" -eq 1 ] || return 0
    /usr/bin/udevadm control --exit 2>/dev/null || :
    terminate_pid "$UDEVD_PID"
    UDEVD_PID=
    UDEV_STARTED=0
}}
close_test_volume() {{
    if [ "$TEST_MOUNTED" -eq 1 ]; then
        "$BB" umount "$TEST_MOUNT" 2>/dev/null || :
        TEST_MOUNTED=0
    fi
    if [ "$MAPPER_OPEN" -eq 1 ] || [ -b "/dev/mapper/$MAPPER" ]; then
        /usr/bin/cryptsetup close "$MAPPER" 2>/dev/null || :
        /usr/bin/dmsetup mknodes "$MAPPER" 2>/dev/null || :
        MAPPER_OPEN=0
    fi
    if [ -n "$TEST_LOOP" ]; then
        /usr/bin/losetup --detach "$TEST_LOOP" 2>/dev/null || :
        TEST_LOOP=
    fi
    "$BB" rm -f "$TEST_IMAGE" 2>/dev/null || :
}}
cleanup_test() {{
    terminate_pid "$UIPID"
    terminate_pid "$CRYPTPID"
    UIPID=
    CRYPTPID=
    close_test_volume
    if [ "$TOUCH_LOADED" -eq 1 ]; then
        "$BB" rmmod zinitix 2>/dev/null || "$BB" rmmod zinitix_ts 2>/dev/null || :
        "$BB" rmmod fts5cu56a 2>/dev/null || "$BB" rmmod fts5cu56 2>/dev/null || :
        "$BB" rmmod i2c_qcom_geni 2>/dev/null || "$BB" rmmod i2c-qcom-geni 2>/dev/null || :
        "$BB" rmmod gpi 2>/dev/null || :
        TOUCH_LOADED=0
    fi
    "$BB" rm -f /run/r8q-unlock.fifo /run/r8q-unl0kr.log /run/r8q-cryptsetup.log 2>/dev/null || :
    stop_udev
}}
stop_probe() {{
    log "HALT: $*"
    cleanup_test
    "$BB" umount "$CACHE_MOUNT" 2>/dev/null || :
    "$BB" poweroff -f 2>/dev/null || "$BB" poweroff 2>/dev/null || :
    while :; do "$BB" sleep 60; done
}}
reboot_known_good() {{
    log "rebooting after CACHE rollback"
    "$BB" sync
    "$BB" reboot -f 2>/dev/null || "$BB" reboot 2>/dev/null || :
    while :; do "$BB" sleep 60; done
}}
fail_probe() {{
    log "FAIL: $*"
    cleanup_test
    if [ "$CACHE_RESTORED" -eq 1 ]; then
        write_result FAIL "$*"
        reboot_known_good
    fi
    stop_probe "$*"
}}
write_result() {{
    result=$1
    detail=$2
    cache=$(wait_for_cache) || stop_probe "exact CACHE identity missing for result"
    "$BB" mkdir -p "$CACHE_MOUNT"
    "$BB" mount -t vfat -o rw "/dev/$cache" "$CACHE_MOUNT" ||
        stop_probe "CACHE mount failed for result"
    {{
        printf 'R8Q-PROBE-RESULT %s\\n' "$result"
        printf 'DETAIL %s\\n' "$detail"
        printf 'EFI-SHA256 %s\\n' "$KNOWN_EFI_SHA256"
        printf 'DTB-SHA256 %s\\n' "$KNOWN_DTB_SHA256"
    }} > "$CACHE_MOUNT$RESULT_RECEIPT.NEW" || stop_probe "result receipt write failed"
    "$BB" grep -q "^R8Q-PROBE-RESULT $result$" "$CACHE_MOUNT$RESULT_RECEIPT.NEW" ||
        stop_probe "result receipt verification failed"
    "$BB" sync
    "$BB" mv "$CACHE_MOUNT$RESULT_RECEIPT.NEW" "$CACHE_MOUNT$RESULT_RECEIPT" ||
        stop_probe "result receipt rename failed"
    "$BB" sync
    "$BB" umount "$CACHE_MOUNT" || stop_probe "CACHE unmount failed after result"
}}
rollback_cache() {{
    cache=$(wait_for_cache) || stop_probe "exact CACHE identity was not available"
    "$BB" mkdir -p "$CACHE_MOUNT"
    "$BB" mount -t vfat -o rw "/dev/$cache" "$CACHE_MOUNT" ||
        stop_probe "CACHE mount failed"
    receipt="$CACHE_MOUNT$TRIAL_HASH_RECEIPT"
    [ -f "$receipt" ] || stop_probe "trial hash receipt is missing"
    "$BB" grep -q '^EFI [0-9a-f]\\{{64\\}}$' "$receipt" ||
        stop_probe "trial EFI hash receipt is malformed"
    "$BB" grep -q '^DTB [0-9a-f]\\{{64\\}}$' "$receipt" ||
        stop_probe "trial DTB hash receipt is malformed"
    TRIAL_EFI_SHA256=$("$BB" grep '^EFI ' "$receipt" | "$BB" cut -d ' ' -f 2)
    TRIAL_DTB_SHA256=$("$BB" grep '^DTB ' "$receipt" | "$BB" cut -d ' ' -f 2)
    [ "$(sha_file "$CACHE_MOUNT$EFI")" = "$TRIAL_EFI_SHA256" ] ||
        stop_probe "active EFI is not the expected trial image"
    [ "$(sha_file "$CACHE_MOUNT$DTB")" = "$TRIAL_DTB_SHA256" ] ||
        stop_probe "active DTB is not the expected trial image"
    "$BB" cp "$ROLLBACK_DIR/BOOTAA64.EFI" "$CACHE_MOUNT$EFI.NEW" ||
        stop_probe "could not stage known-good EFI"
    "$BB" cp "$ROLLBACK_DIR/R8Q-RTC.DTB" "$CACHE_MOUNT$DTB.NEW" ||
        stop_probe "could not stage known-good DTB"
    [ "$(sha_file "$CACHE_MOUNT$EFI.NEW")" = "$KNOWN_EFI_SHA256" ] ||
        stop_probe "known-good EFI staging hash mismatch"
    [ "$(sha_file "$CACHE_MOUNT$DTB.NEW")" = "$KNOWN_DTB_SHA256" ] ||
        stop_probe "known-good DTB staging hash mismatch"
    "$BB" mv "$CACHE_MOUNT$EFI.NEW" "$CACHE_MOUNT$EFI" ||
        stop_probe "known-good EFI replacement failed"
    "$BB" mv "$CACHE_MOUNT$DTB.NEW" "$CACHE_MOUNT$DTB" ||
        stop_probe "known-good DTB replacement failed"
    "$BB" sync
    [ "$(sha_file "$CACHE_MOUNT$EFI")" = "$KNOWN_EFI_SHA256" ] ||
        stop_probe "known-good EFI verification failed"
    [ "$(sha_file "$CACHE_MOUNT$DTB")" = "$KNOWN_DTB_SHA256" ] ||
        stop_probe "known-good DTB verification failed"
    "$BB" umount "$CACHE_MOUNT" || stop_probe "CACHE unmount failed"
    CACHE_RESTORED=1
}}
start_udev() {{
    "$BB" mkdir -p /run/udev
    /usr/lib/systemd/systemd-udevd --resolve-names=never >/run/r8q-udevd.log 2>&1 &
    UDEVD_PID=$!
    UDEV_STARTED=1
    i=0
    while [ "$i" -lt 5 ]; do
        "$BB" kill -0 "$UDEVD_PID" 2>/dev/null && [ -S /run/udev/control ] &&
            return 0
        "$BB" sleep 1
        i=$((i + 1))
    done
    fail_probe "udevd control socket did not become ready"
}}
check_display() {{
    /usr/bin/udevadm trigger --action=add --subsystem-match=drm 2>/dev/null || :
    /usr/bin/udevadm settle --timeout=5 2>/dev/null || :
    [ -e /dev/dri/card0 ] || [ -e /dev/fb0 ] ||
        fail_probe "no early DRM or framebuffer device"
}}
has_ready_event() {{
    path=$1
    [ -d "$path" ] || return 1
    for event in "$path"/input/input*/event*; do
        [ -e "$event" ] && return 0
    done
    return 1
}}
wait_for_ready() {{
    path=$1
    i=0
    while [ "$i" -lt 10 ]; do
        has_ready_event "$path" && return 0
        i=$((i + 1))
        "$BB" sleep 1
    done
    return 1
}}
touch_up() {{
    "$BB" insmod /lib/modules/$KERNEL_RELEASE/r8q-encryption/gpi.ko ||
        fail_probe "GPI load failed"
    "$BB" insmod /lib/modules/$KERNEL_RELEASE/r8q-encryption/i2c-qcom-geni.ko r8q_force_fifo=1 ||
        fail_probe "GENI load failed"
    FIFO_PARAM=/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo
    [ -f "$FIFO_PARAM" ] || fail_probe "GENI FIFO parameter missing"
    case "$("$BB" cat "$FIFO_PARAM" 2>/dev/null | "$BB" tr -d '\\r\\n')" in
        1|Y|y) ;;
        *) fail_probe "GENI FIFO parameter disabled" ;;
    esac
    "$BB" insmod /lib/modules/$KERNEL_RELEASE/r8q-encryption/fts5cu56a.ko 2>/dev/null || :
    /usr/bin/udevadm trigger --subsystem-match=input --action=add ||
        fail_probe "FTS udev trigger failed"
    /usr/bin/udevadm settle --timeout=10 || fail_probe "FTS udev settle failed"
    if ! wait_for_ready /sys/bus/i2c/drivers/fts5cu56a/5-0049; then
        "$BB" insmod /lib/modules/$KERNEL_RELEASE/r8q-encryption/zinitix.ko 2>/dev/null || :
        /usr/bin/udevadm trigger --subsystem-match=input --action=add ||
            fail_probe "Zinitix udev trigger failed"
        /usr/bin/udevadm settle --timeout=10 || fail_probe "Zinitix udev settle failed"
        wait_for_ready /sys/bus/i2c/drivers/Zinitix-TS/5-0020 ||
            fail_probe "touch controller event missing"
    fi
    TOUCH_LOADED=1
}}
make_test_volume() {{
    "$BB" dd if=/dev/zero of="$TEST_IMAGE" bs=1M count=96 ||
        fail_probe "RAM test image creation failed"
    TEST_LOOP=$(/usr/bin/losetup --sector-size 4096 --find --show "$TEST_IMAGE") ||
        fail_probe "loop setup failed"
    printf '%s' "$PUBLIC_PASSPHRASE" |
        /usr/bin/cryptsetup luksFormat --type luks2 --batch-mode --cipher aes-xts-plain64 --key-size 512 --sector-size 4096 --pbkdf argon2id --pbkdf-memory 131072 --pbkdf-parallel 2 --iter-time 1000 \\
            --key-file=- "$TEST_LOOP" || fail_probe "LUKS2 format failed"
}}
run_unlock_and_io() {{
    "$BB" mkdir -p "$TEST_MOUNT"
    "$BB" rm -f /run/r8q-unlock.fifo
    "$BB" mkfifo /run/r8q-unlock.fifo || fail_probe "unlock FIFO creation failed"
    /usr/lib/r8q-encryption/unl0kr -n -d 400 -m "TEST ONLY: enter test" \\
        >/run/r8q-unlock.fifo 2>/run/r8q-unl0kr.log &
    UIPID=$!
    /usr/bin/cryptsetup open --type luks2 --batch-mode --tries 1 --key-file=/run/r8q-unlock.fifo \\
        "$TEST_LOOP" "$MAPPER" >/run/r8q-cryptsetup.log 2>&1 &
    CRYPTPID=$!
    i=0
    while "$BB" kill -0 "$CRYPTPID" 2>/dev/null; do
        [ "$i" -lt 180 ] || fail_probe "unlock UI/cryptsetup timeout"
        "$BB" sleep 1
        i=$((i + 1))
    done
    STATUS=0
    wait "$CRYPTPID" || STATUS=$?
    CRYPTPID=
    terminate_pid "$UIPID"
    UIPID=
    [ "$STATUS" -eq 0 ] || fail_probe "unl0kr/cryptsetup unlock failed"
    MAPPER_OPEN=1
    /usr/bin/dmsetup mknodes "$MAPPER" || fail_probe "mapper node creation failed"
    [ -b "/dev/mapper/$MAPPER" ] || fail_probe "mapper node absent after UI unlock"
    /usr/bin/mkfs.ext4 -q "/dev/mapper/$MAPPER" ||
        fail_probe "ext4 format on mapper failed"
    "$BB" mount -t ext4 "/dev/mapper/$MAPPER" "$TEST_MOUNT" ||
        fail_probe "mapper mount failed"
    TEST_MOUNTED=1
    printf '%s\\n' "$PUBLIC_MARKER" > "$TEST_MOUNT/marker"
    "$BB" sync
    [ "$("$BB" cat "$TEST_MOUNT/marker")" = "$PUBLIC_MARKER" ] ||
        fail_probe "marker read-back failed"
    "$BB" sha256sum "$TEST_MOUNT/marker" >&2
}}

# The production base contains only bin/busybox. Install its applet farm
# before the first mkdir or mount.
"$BB" --install -s /bin || stop_probe "BusyBox applet farm failed"
"$BB" mkdir -p /proc /sys /dev /run "$CACHE_MOUNT" "$ROLLBACK_DIR"
"$BB" mount -t proc proc /proc || stop_probe "proc mount failed"
"$BB" mount -t sysfs sysfs /sys || stop_probe "sysfs mount failed"
"$BB" mount -t devtmpfs devtmpfs /dev || stop_probe "devtmpfs mount failed"
"$BB" mkdir -p /dev/mapper
"$BB" mknod -m 0600 /dev/mapper/control c 10 236 2>/dev/null ||
    [ -e /dev/mapper/control ] || stop_probe "device-mapper control node failed"
"$BB" mount -t tmpfs -o size=128M,mode=0755 tmpfs /run || stop_probe "run tmpfs mount failed"
rollback_cache
start_udev
check_display
touch_up
make_test_volume
printf '%s\\n' "PUBLIC TEST PASSPHRASE: $PUBLIC_PASSPHRASE" >&2
run_unlock_and_io
cleanup_test
write_result PASS "volatile-dm-crypt-ext4-marker-ok"
log "PASS: volatile {TEST_BYTES} byte dm-crypt/ext4 marker I/O completed"
reboot_known_good
"""


def verify_busybox_config(path: Path) -> dict[str, str]:
    regular(path, "BusyBox configuration")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip()
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-len(" is not set")]] = "n"
    missing = [applet for applet, key in BUSYBOX_CONFIG_KEYS.items() if values.get(key) != "y"]
    if missing:
        die(f"test BusyBox is missing required applets: {', '.join(missing)}")
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a separate volatile dm-crypt boot probe.")
    parser.add_argument("--production-initramfs", type=Path, required=True)
    parser.add_argument("--test-busybox", type=Path, required=True)
    parser.add_argument("--busybox-config", type=Path)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--losetup", type=Path, required=True)
    parser.add_argument("--mkfs-ext4", type=Path, required=True)
    parser.add_argument("--known-good-efi", type=Path, required=True)
    parser.add_argument("--known-good-dtb", type=Path, required=True)
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.production_initramfs.is_dir():
        die(f"production initramfs directory is missing: {args.production_initramfs}")
    if args.output.exists():
        die(f"refusing to overwrite existing output: {args.output}")
    source_tree = args.production_initramfs.resolve()
    output_tree = args.output.resolve()
    if source_tree == output_tree or source_tree in output_tree.parents or output_tree in source_tree.parents:
        die("output must be a distinct sibling tree, not inside production initramfs")
    preparer = load_preparer()
    runtime_root = args.runtime_root.resolve()
    if not runtime_root.is_dir():
        die(f"runtime root is missing: {runtime_root}")
    regular(args.test_busybox, "test BusyBox")
    info = preparer.elf_info(args.test_busybox)
    if info["interpreter"] or info["needed"]:
        die("test BusyBox must be a static AArch64 binary")
    if "busybox" not in args.test_busybox.name.lower():
        die("test BusyBox filename must identify BusyBox")
    busybox_config = args.busybox_config or (args.test_busybox.parent / ".config")
    verify_busybox_config(busybox_config)
    for path, label in ((args.losetup, "losetup"), (args.mkfs_ext4, "mkfs.ext4")):
        regular(path, label)
        preparer.elf_info(path)
    regular(args.known_good_efi, "known-good EFI")
    regular(args.known_good_dtb, "known-good DTB")
    known_efi_hash = sha256(args.known_good_efi)
    known_dtb_hash = sha256(args.known_good_dtb)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(args.production_initramfs, args.output, symlinks=True)
    try:
        copy_regular(args.test_busybox, args.output / "bin/busybox", "test BusyBox")
        rollback = args.output / "r8q-probe-rollback"
        copy_regular(args.known_good_efi, rollback / "BOOTAA64.EFI", "known-good EFI")
        copy_regular(args.known_good_dtb, rollback / "R8Q-RTC.DTB", "known-good DTB")
        closures = {
            "losetup": stage_closure(preparer, runtime_root, args.losetup, args.output, "losetup"),
            "mkfs.ext4": stage_closure(preparer, runtime_root, args.mkfs_ext4, args.output, "mkfs.ext4"),
        }
        init = args.output / "init"
        init.write_text(
            init_source(known_efi_hash, known_dtb_hash, args.kernel_release),
            encoding="utf-8",
        )
        init.chmod(0o755)
        generated = init.read_text(encoding="utf-8")
        if "userdata" in generated.lower() or "/dev/sda" in generated:
            die("generated probe init contains a real-root reference")
        manifest = {
            "kind": "r8q-test-only-encryption-boot-probe",
            "production_candidate_unchanged": True,
            "phone_operations_performed": False,
            "userdata_referenced": False,
            "public_test_passphrase": PUBLIC_PASSPHRASE,
            "public_marker": PUBLIC_MARKER,
            "ram_loop_volume_bytes": TEST_BYTES,
            "ram_loop_volume_path": "/run/r8q-test.img",
            "luks_type": "luks2",
            "root_handoff": False,
            "cache_partname_required": "cache",
            "cache_partuuid_required": CACHE_PARTUUID,
            "cache_size_bytes_required": 629145600,
            "known_good_efi_sha256": known_efi_hash,
            "known_good_dtb_sha256": known_dtb_hash,
            "kernel_release": args.kernel_release,
            "required_busybox_applets": list(REQUIRED_APPLETS),
            "busybox_config_sha256": sha256(busybox_config),
            "cache_trial_hash_receipt_path": TRIAL_HASH_RECEIPT,
            "cache_result_receipt_path": RESULT_RECEIPT,
            "external_tools": {"losetup": "/usr/bin/losetup", "mkfs.ext4": "/usr/bin/mkfs.ext4"},
            "closure": closures,
            "files": {
                "busybox_sha256": sha256(args.test_busybox),
                "init_sha256": sha256(init),
                "known_good_efi_sha256": sha256(rollback / "BOOTAA64.EFI"),
                "known_good_dtb_sha256": sha256(rollback / "R8Q-RTC.DTB"),
            },
            "required_inputs": [
                "static AArch64 BusyBox with the listed applets",
                "AArch64 losetup and complete runtime-root closure",
                "AArch64 mkfs.ext4 and complete runtime-root closure",
                "accepted staged cryptsetup, dmsetup, udevadm/systemd-udevd, unl0kr, and input assets",
                "accepted exact-release GPI, GENI, FTS/Zinitix module bundle",
                "original known-good EFI and RTC DTB files",
            ],
        }
        (args.output / "r8q-probe-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except Exception:
        shutil.rmtree(args.output, ignore_errors=True)
        raise
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
