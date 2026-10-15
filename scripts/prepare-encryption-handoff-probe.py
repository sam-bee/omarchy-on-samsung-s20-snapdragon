#!/usr/bin/env python3
"""Create a separate public native root-handoff probe.

This generator deliberately starts from the accepted final native probe tree,
then adds only a public negative UI shim and a static BusyBox PID 1 stub.  It
never edits the accepted tree, the production initramfs, or a phone.  The
generated image still uses only a volatile 96 MiB loop-backed LUKS volume and
restores the known-good CACHE EFI/DTB before doing any UI or storage test.

The generated probe is a distinct test kind.  Its root handoff is deliberately
to a tiny BusyBox init, so it proves the PID 1/switch_root boundary, touch
controller teardown, and retained GPI/GENI adapter state without pretending to
prove a production systemd boot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat


PUBLIC_PASSPHRASE = "test"
PUBLIC_MARKER = "r8q-dmcrypt-public-probe-v1"
ROOT_MARKER = "r8q-native-root-handoff-v1"
TOUCH_MARKER = "r8q-touch-drivers-unloaded-v2"
ADAPTER_MARKER = "r8q-gpi-geni-adapters-retained-v1"
TEST_BYTES = 96 * 1024 * 1024
# Keep this probe's CACHE state disjoint from the already accepted positive
# probe and the failed retained-adapter trial.  A sibling stager must use
# matching ROOT-HANDOFF2-SAVED/NEW names.
TRIAL_HASH_RECEIPT = "/EFI/BOOT/R8Q-ROOT-HANDOFF2-TRIAL-HASHES"
RESULT_RECEIPT = "/EFI/BOOT/R8Q-ROOT-HANDOFF2-RESULT"
RESULT_PREFIX = "R8Q-ROOT-HANDOFF2-RESULT"
CACHE_PARTUUID = "5594c694-c871-4b5f-90b1-690a6f68e0f7"
CACHE_SECTORS = "1228800"
KERNEL_RELEASE = "7.1.2-r8q-rtc2"
NEGATIVE_UI = "usr/lib/r8q-probe/negative-ui"
ROOT_INIT = "usr/lib/r8q-probe/native-root-init"


def die(message: str) -> None:
    raise SystemExit(f"make-root-handoff-probe.py: error: {message}")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def regular(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        die(f"{label} is missing: {path}")
    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        die(f"{label} must be a regular non-symlink file: {path}")


def copy_regular(source: Path, destination: Path, label: str) -> None:
    regular(source, label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(stat.S_IMODE(source.stat().st_mode))


def negative_ui_source() -> str:
    return r"""#!/bin/busybox sh
set -eu
COUNT_FILE=/run/r8q-negative-ui-count
count=0
if [ -f "$COUNT_FILE" ]; then
    read count < "$COUNT_FILE"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$COUNT_FILE"
case "$count" in
    1)
        printf '%s\n' wrong > /run/r8q-negative-ui-1
        printf 'wrong'
        ;;
    2)
        printf '%s\n' empty-eof > /run/r8q-negative-ui-2
        ;;
    3)
        printf '%s\n' noinput-watchdog > /run/r8q-negative-ui-3
        exec /bin/busybox sleep 181
        ;;
    *)
        exit 125
        ;;
esac
"""


def native_root_init_source(known_efi: str, known_dtb: str) -> str:
    # This is intentionally a shell stub, not systemd.  It verifies the
    # actual switch_root PID boundary and the pre-handoff teardown marker,
    # writes only a public CACHE receipt, and then reboots to known-good EFI.
    return f"""#!/bin/busybox sh
set -eu
BB=/bin/busybox
PATH=/bin:/sbin:/usr/bin:/usr/sbin
LC_ALL=C
KNOWN_EFI_SHA256='{known_efi}'
KNOWN_DTB_SHA256='{known_dtb}'
RESULT_RECEIPT='{RESULT_RECEIPT}'
ROOT_MARKER='{ROOT_MARKER}'
TOUCH_MARKER='{TOUCH_MARKER}'
ADAPTER_MARKER='{ADAPTER_MARKER}'
ROOT_DEVICE='/dev/mapper/r8q_probe_crypt'
export PATH LC_ALL

"$BB" --install -s /bin

reboot_after_result() {{
    "$BB" sync
    "$BB" reboot -f 2>/dev/null || "$BB" reboot 2>/dev/null || :
    while :; do "$BB" sleep 60; done
}}

write_result() {{
    result=$1
    detail=$2
    cache_node=$3
    "$BB" mkdir -p /run/r8q-cache
    "$BB" mount -t vfat -o rw,nosuid,nodev,noexec "/dev/$cache_node" /run/r8q-cache || return 1
    {{
        printf '{RESULT_PREFIX} %s\\n' "$result"
        printf 'DETAIL %s\\n' "$detail"
        printf 'EFI-SHA256 %s\\n' "$KNOWN_EFI_SHA256"
        printf 'DTB-SHA256 %s\\n' "$KNOWN_DTB_SHA256"
    }} > "/run/r8q-cache$RESULT_RECEIPT.NEW" || return 1
    "$BB" grep -q "^{RESULT_PREFIX} $result$" "/run/r8q-cache$RESULT_RECEIPT.NEW" || return 1
    "$BB" sync
    "$BB" mv "/run/r8q-cache$RESULT_RECEIPT.NEW" "/run/r8q-cache$RESULT_RECEIPT" || return 1
    "$BB" sync
    "$BB" umount /run/r8q-cache || return 1
}}

fail_closed() {{
    detail=$1
    cache_node=''
    if [ -f /r8q-cache-node ]; then
        read cache_node < /r8q-cache-node || cache_node=''
    fi
    case "$cache_node" in
        ''|*[!A-Za-z0-9_/-]*) ;;
        *) write_result FAIL "$detail" "$cache_node" || : ;;
    esac
    reboot_after_result
}}

[ "$$" -eq 1 ] || fail_closed pid-not-one
[ -x /bin/busybox ] || fail_closed busybox-missing
[ -f /r8q-handoff-marker ] || fail_closed handoff-marker-missing
[ "$("$BB" cat /r8q-handoff-marker)" = "$ROOT_MARKER" ] || fail_closed handoff-marker-invalid
[ -f /r8q-touch-chain ] || fail_closed touch-marker-missing
[ "$("$BB" cat /r8q-touch-chain)" = "$TOUCH_MARKER" ] || fail_closed touch-marker-invalid
[ -f /r8q-adapters ] || fail_closed adapter-marker-missing
[ "$("$BB" cat /r8q-adapters)" = "$ADAPTER_MARKER" ] || fail_closed adapter-marker-invalid
[ -f /marker ] || fail_closed positive-marker-missing
[ "$("$BB" cat /marker)" = '{PUBLIC_MARKER}' ] || fail_closed positive-marker-invalid
[ -d /proc ] || fail_closed proc-mountpoint-missing
[ -d /sys ] || fail_closed sys-mountpoint-missing
"$BB" mount -t proc proc /proc || fail_closed proc-mount-failed
"$BB" mount -t sysfs sysfs /sys || fail_closed sysfs-mount-failed
"$BB" mount | "$BB" grep -q "$ROOT_DEVICE on / type ext4 " || fail_closed root-device-or-fstype-invalid
[ -d /sys/module/gpi ] || fail_closed gpi-adapter-missing
[ -d /sys/module/i2c_qcom_geni ] || fail_closed geni-adapter-missing
[ -f /sys/module/i2c_qcom_geni/parameters/r8q_force_fifo ] || fail_closed geni-fifo-parameter-missing
case "$("$BB" cat /sys/module/i2c_qcom_geni/parameters/r8q_force_fifo 2>/dev/null | "$BB" tr -d '\\r\\n')" in
    1|Y|y) ;;
    *) fail_closed geni-fifo-disabled ;;
esac
for module in fts5cu56a fts5cu56 zinitix zinitix_ts; do
    [ ! -d "/sys/module/$module" ] || fail_closed "touch-module-still-loaded-$module"
done
[ -f /r8q-cache-node ] || fail_closed cache-node-missing
cache_node=$("$BB" cat /r8q-cache-node)
case "$cache_node" in
    ''|*[!A-Za-z0-9_/-]*) fail_closed cache-node-invalid ;;
esac
write_result PASS native-root-handoff-pid1-retained-adapters "$cache_node" || fail_closed cache-result-write
reboot_after_result
"""


def transform_init(source: str, known_efi: str, known_dtb: str) -> str:
    """Keep the final probe's hardware/rollback helpers and replace its test tail."""
    marker = "run_unlock_and_io() {"
    if marker not in source:
        die("source probe init no longer has the expected native unlock function")
    prefix, remainder = source.split(marker, 1)
    tail_marker = "\n\n# The production base contains only bin/busybox."
    if tail_marker not in remainder:
        die("source probe init no longer has the expected startup tail")
    _old_body, _old_tail = remainder.split(tail_marker, 1)

    prefix = prefix.replace(
        "CRYPTPID=\n",
        "CRYPTPID=\nWATCHDOG_PID=\nNEGATIVE_UI=/usr/lib/r8q-probe/negative-ui\nHANDOFF_ROOT_INIT=/usr/lib/r8q-probe/native-root-init\n",
        1,
    )
    prefix = prefix.replace(
        "MAPPER_OPEN=0\n",
        "MAPPER_OPEN=0\nROOT_DEV_MOUNTED=0\n",
        1,
    )
    prefix = prefix.replace(
        "TEST_MOUNT=/run/r8q-test-root\n",
        "TEST_MOUNT=/newroot\nNEGATIVE_UNLOCK_TIMEOUT=5\nNATIVE_UNLOCK_TIMEOUT=180\n",
        1,
    )
    prefix = prefix.replace(
        "TRIAL_HASH_RECEIPT='/EFI/BOOT/R8Q-PROBE-TRIAL-HASHES'\n",
        f"TRIAL_HASH_RECEIPT='{TRIAL_HASH_RECEIPT}'\n",
        1,
    )
    prefix = prefix.replace(
        "RESULT_RECEIPT='/EFI/BOOT/R8Q-PROBE-RESULT'\n",
        f"RESULT_RECEIPT='{RESULT_RECEIPT}'\n",
        1,
    )
    prefix = prefix.replace("R8Q-PROBE-RESULT", RESULT_PREFIX)
    prefix, efi_replacements = re.subn(
        r"^KNOWN_EFI_SHA256='[0-9a-f]{64}'$",
        f"KNOWN_EFI_SHA256='{known_efi}'",
        prefix,
        count=1,
        flags=re.MULTILINE,
    )
    prefix, dtb_replacements = re.subn(
        r"^KNOWN_DTB_SHA256='[0-9a-f]{64}'$",
        f"KNOWN_DTB_SHA256='{known_dtb}'",
        prefix,
        count=1,
        flags=re.MULTILINE,
    )
    if efi_replacements != 1 or dtb_replacements != 1:
        die("source replacement missed known-good EFI/DTB hashes")
    prefix = prefix.replace(
        "close_test_volume() {\n    if [ \"$TEST_MOUNTED\" -eq 1 ]; then",
        "close_test_volume() {\n    if [ \"$ROOT_DEV_MOUNTED\" -eq 1 ]; then\n        \"$BB\" umount \"$TEST_MOUNT/dev\" 2>/dev/null || :\n        ROOT_DEV_MOUNTED=0\n    fi\n    if [ \"$TEST_MOUNTED\" -eq 1 ]; then",
        1,
    )
    prefix = prefix.replace(
        "    terminate_pid \"$CRYPTPID\"\n    UIPID=\n    CRYPTPID=\n",
        "    terminate_pid \"$CRYPTPID\"\n    terminate_pid \"$WATCHDOG_PID\"\n    UIPID=\n    CRYPTPID=\n    WATCHDOG_PID=\n",
        1,
    )
    prefix = prefix.replace(
        "        \"$BB\" rmmod i2c_qcom_geni 2>/dev/null || \"$BB\" rmmod i2c-qcom-geni 2>/dev/null || :\n",
        "",
        1,
    )
    prefix = prefix.replace(
        "        \"$BB\" rmmod gpi 2>/dev/null || :\n",
        "",
        1,
    )
    for old in (
        "R8Q-PROBE-TRIAL-HASHES",
        "R8Q-PROBE-RESULT",
        "TEST_MOUNT=/run/r8q-test-root",
        "rmmod i2c_qcom_geni",
        "rmmod i2c-qcom-geni",
        "rmmod gpi",
    ):
        if old in prefix:
            die(f"source replacement left old probe contract: {old}")
    for required in (
        f"TRIAL_HASH_RECEIPT='{TRIAL_HASH_RECEIPT}'",
        f"RESULT_RECEIPT='{RESULT_RECEIPT}'",
        "ROLLBACK_DIR=/r8q-probe-rollback",
        "TEST_MOUNT=/newroot",
        "NEGATIVE_UNLOCK_TIMEOUT=5",
        "NATIVE_UNLOCK_TIMEOUT=180",
    ):
        if required not in prefix:
            die(f"source replacement missed required handoff contract: {required}")

    replacement = r'''run_ui_attempt() {
    ui=$1
    preserve_mapper=${2:-0}
    timeout=${3:-180}
    "$BB" rm -f /run/r8q-watchdog-fired
    "$BB" rm -f /run/r8q-unlock.fifo /run/r8q-unl0kr.log /run/r8q-cryptsetup.log
    "$BB" mkfifo /run/r8q-unlock.fifo || fail_probe "unlock FIFO creation failed"
    "$ui" -n -d 400 -m "TEST ONLY: enter test" \
        >/run/r8q-unlock.fifo 2>/run/r8q-unl0kr.log &
    UIPID=$!
    /usr/bin/cryptsetup open --type luks2 --batch-mode --tries 1 --key-file=/run/r8q-unlock.fifo \
        "$TEST_LOOP" "$MAPPER" >/run/r8q-cryptsetup.log 2>&1 &
    CRYPTPID=$!
    watchdog_attempt() {
        trap 'kill "${SLEEP_PID:-}" 2>/dev/null || :; exit 0' TERM INT
        "$BB" sleep "$timeout" &
        SLEEP_PID=$!
        wait "$SLEEP_PID"
        printf fired > /run/r8q-watchdog-fired
        terminate_pid "$UIPID"
        terminate_pid "$CRYPTPID"
    }
    watchdog_attempt &
    WATCHDOG_PID=$!
    STATUS=0
    wait "$CRYPTPID" || STATUS=$?
    terminate_pid "$UIPID"
    terminate_pid "$WATCHDOG_PID"
    UIPID=
    CRYPTPID=
    WATCHDOG_PID=
    MAPPER_PRESENT=0
    [ -b "/dev/mapper/$MAPPER" ] && MAPPER_PRESENT=1
    "$BB" rm -f /run/r8q-unlock.fifo /run/r8q-unl0kr.log /run/r8q-cryptsetup.log
    if [ "$preserve_mapper" -eq 0 ]; then
        /usr/bin/cryptsetup close "$MAPPER" 2>/dev/null || :
        /usr/bin/dmsetup mknodes "$MAPPER" 2>/dev/null || :
    fi
    return "$STATUS"
}

run_negative_attempts() {
    attempt=1
    while [ "$attempt" -le 3 ]; do
        STATUS=0
        run_ui_attempt "$NEGATIVE_UI" 0 "$NEGATIVE_UNLOCK_TIMEOUT" || STATUS=$?
        [ "$STATUS" -ne 0 ] || fail_probe "negative UI case unexpectedly unlocked"
        [ "$MAPPER_PRESENT" -eq 0 ] || fail_probe "negative case left mapper open"
        if [ "$attempt" -eq 3 ]; then
            [ -f /run/r8q-watchdog-fired ] || fail_probe "no-input watchdog did not fire"
        fi
        attempt=$((attempt + 1))
    done
    [ "$("$BB" cat /run/r8q-negative-ui-1)" = wrong ] || fail_probe "wrong-byte case was not first"
    [ "$("$BB" cat /run/r8q-negative-ui-2)" = empty-eof ] || fail_probe "empty-EOF case was not second"
    [ "$("$BB" cat /run/r8q-negative-ui-3)" = noinput-watchdog ] || fail_probe "no-input watchdog case was not third"
    [ ! -e /run/r8q-unlock.fifo ] || fail_probe "negative FIFO remained"
}

prepare_native_root() {
    STATUS=0
    run_ui_attempt /usr/lib/r8q-encryption/unl0kr 1 "$NATIVE_UNLOCK_TIMEOUT" || STATUS=$?
    [ "$STATUS" -eq 0 ] || fail_probe "native touchscreen unlock failed"
    MAPPER_OPEN=1
    /usr/bin/dmsetup mknodes "$MAPPER" || fail_probe "native mapper node creation failed"
    [ -b "/dev/mapper/$MAPPER" ] || fail_probe "native mapper node absent"
    /usr/bin/mkfs.ext4 -q "/dev/mapper/$MAPPER" || fail_probe "native root ext4 format failed"
    "$BB" mkdir -p "$TEST_MOUNT"
    "$BB" mount -t ext4 "/dev/mapper/$MAPPER" "$TEST_MOUNT" || fail_probe "native root mount failed"
    TEST_MOUNTED=1
    "$BB" mkdir -p "$TEST_MOUNT/bin" "$TEST_MOUNT/dev" "$TEST_MOUNT/proc" "$TEST_MOUNT/sys" "$TEST_MOUNT/run"
    printf '%s\n' 'r8q-dmcrypt-public-probe-v1' > "$TEST_MOUNT/marker"
    "$BB" sync
    [ "$("$BB" cat "$TEST_MOUNT/marker")" = 'r8q-dmcrypt-public-probe-v1' ] ||
        fail_probe "native root marker read-back failed"
    "$BB" cp "$BB" "$TEST_MOUNT/bin/busybox" || fail_probe "root BusyBox copy failed"
    "$BB" cp "$HANDOFF_ROOT_INIT" "$TEST_MOUNT/init" || fail_probe "root PID1 stub copy failed"
    [ -x "$TEST_MOUNT/bin/busybox" ] || fail_probe "root BusyBox is not executable"
    [ -x "$TEST_MOUNT/init" ] || fail_probe "root PID1 stub is not executable"
    cache=$(wait_for_cache) || fail_probe "exact CACHE identity missing for handoff"
    printf '%s\n' "$cache" > "$TEST_MOUNT/r8q-cache-node"
    printf '%s\n' 'r8q-native-root-handoff-v1' > "$TEST_MOUNT/r8q-handoff-marker"
    "$BB" mount -t devtmpfs devtmpfs "$TEST_MOUNT/dev" || fail_probe "root devtmpfs mount failed"
    ROOT_DEV_MOUNTED=1
}

handoff_native_root() {
    # Retain the GPI/GENI adapters for root-side verification.  Only the
    # touch-controller modules are removed before the PID1 boundary.
    stop_udev
    "$BB" rm -f /run/r8q-udevd.log
    for module in fts5cu56a zinitix; do
        if [ -d "/sys/module/$module" ]; then
            "$BB" rmmod "$module" 2>/dev/null || fail_probe "rmmod-$module"
        fi
        [ ! -d "/sys/module/$module" ] || fail_probe "module-still-loaded-$module"
    done
    [ -d /sys/module/gpi ] || fail_probe "adapter-gpi-missing"
    [ -d /sys/module/i2c_qcom_geni ] || fail_probe "adapter-geni-missing"
    FIFO_PARAM=/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo
    [ -f "$FIFO_PARAM" ] || fail_probe "adapter-geni-fifo-parameter-missing"
    case "$("$BB" cat "$FIFO_PARAM" 2>/dev/null | "$BB" tr -d '\\r\\n')" in
        1|Y|y) ;;
        *) fail_probe "adapter-geni-fifo-disabled" ;;
    esac
    printf '%s\n' 'r8q-touch-drivers-unloaded-v2' > "$TEST_MOUNT/r8q-touch-chain"
    printf '%s\n' 'r8q-gpi-geni-adapters-retained-v1' > "$TEST_MOUNT/r8q-adapters"
    "$BB" mkdir -p "$TEST_MOUNT/run"
    "$BB" mount -o move /run "$TEST_MOUNT/run" || fail_probe "run-move"
    "$BB" umount /proc 2>/dev/null || :
    "$BB" umount /sys 2>/dev/null || :
    # switch_root must replace PID 1; its failure is intentionally terminal.
    exec switch_root "$TEST_MOUNT" /init
}
'''
    startup = r'''

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
run_negative_attempts
prepare_native_root
handoff_native_root
'''
    generated = prefix + replacement + startup
    if "userdata" in generated.lower() or "/dev/sda" in generated:
        die("generated handoff probe contains a real-root reference")
    return generated


def manifest_files(metadata: dict, output: Path, probe_manifest: Path) -> None:
    inherited = json.loads(probe_manifest.read_text(encoding="utf-8"))
    metadata["source_probe_manifest_sha256"] = digest(probe_manifest)
    for field in ("required_busybox_applets", "busybox_config_sha256", "external_tools", "closure", "required_inputs"):
        if not metadata.get(field) and inherited.get(field) is not None:
            metadata[field] = inherited[field]
    records = metadata.setdefault("files", {})
    init = output / "init"
    records["init"] = {
        **records.get("init", {}),
        "sha256": digest(init),
        "size": init.stat().st_size,
    }
    for relative, label in ((NEGATIVE_UI, "generated-test-negative-ui"),
                            (ROOT_INIT, "generated-native-root-init")):
        path = output / relative
        records[relative] = {
            "source": "generated",
            "sha256": digest(path),
            "size": path.stat().st_size,
            "kind": label,
        }
    metadata["extra_paths"] = sorted(set(metadata.get("extra_paths", [])) | {NEGATIVE_UI, ROOT_INIT})
    metadata["kind"] = "r8q-test-root-handoff-encryption-boot-probe"
    metadata["root_handoff"] = True
    metadata["userdata_targeted"] = False
    metadata["root_handoff_mode"] = "native-pid1-busybox-stub-retained-adapters"
    metadata["negative_ui_cases"] = ["wrong-bytes", "empty-eof", "noinput-watchdog"]
    metadata["positive_unlock"] = "native-unl0kr-touchscreen"
    metadata["public_root_marker"] = ROOT_MARKER
    metadata["public_touch_teardown_marker"] = TOUCH_MARKER
    metadata["public_adapter_retention_marker"] = ADAPTER_MARKER
    metadata["unloaded_touch_modules"] = ["fts5cu56a.ko", "zinitix.ko"]
    metadata["retained_adapter_modules"] = ["gpi.ko", "i2c-qcom-geni.ko"]
    metadata["retained_adapter_fifo_parameter"] = "r8q_force_fifo=1"
    metadata["required_busybox_applets"] = sorted(
        set(metadata.get("required_busybox_applets", [])) | {"switch_root"}
    )
    metadata["files"] = dict(sorted(records.items()))

    probe = {
        "kind": "r8q-test-root-handoff-encryption-boot-probe",
        "production_candidate_unchanged": True,
        "phone_operations_performed": False,
        "userdata_referenced": False,
        "public_test_passphrase": PUBLIC_PASSPHRASE,
        "public_marker": PUBLIC_MARKER,
        "ram_loop_volume_bytes": TEST_BYTES,
        "ram_loop_volume_path": "/run/r8q-test.img",
        "luks_type": "luks2",
        "root_handoff": True,
        "root_handoff_mode": "native-pid1-busybox-stub-retained-adapters",
        "negative_ui_cases": ["wrong-bytes", "empty-eof", "noinput-watchdog"],
        "positive_unlock": "native-unl0kr-touchscreen",
        "public_touch_teardown_marker": TOUCH_MARKER,
        "public_adapter_retention_marker": ADAPTER_MARKER,
        "unloaded_touch_modules": ["fts5cu56a.ko", "zinitix.ko"],
        "retained_adapter_modules": ["gpi.ko", "i2c-qcom-geni.ko"],
        "retained_adapter_fifo_parameter": "r8q_force_fifo=1",
        "cache_partname_required": "cache",
        "cache_partuuid_required": CACHE_PARTUUID,
        "cache_size_bytes_required": 629145600,
        "known_good_efi_sha256": metadata["known_good_efi_sha256"],
        "known_good_dtb_sha256": metadata["known_good_dtb_sha256"],
        "kernel_release": KERNEL_RELEASE,
        "required_busybox_applets": sorted(set(metadata.get("required_busybox_applets", [])) | {"switch_root"}),
        "busybox_config_sha256": metadata.get("busybox_config_sha256"),
        "cache_trial_hash_receipt_path": TRIAL_HASH_RECEIPT,
        "cache_result_receipt_path": RESULT_RECEIPT,
        "external_tools": metadata.get("external_tools", {}),
        "closure": metadata.get("closure", {}),
        "files": {
            "busybox_sha256": metadata["files"]["bin/busybox"]["sha256"],
            "init_sha256": digest(output / "init"),
            "negative_ui_sha256": digest(output / NEGATIVE_UI),
            "native_root_init_sha256": digest(output / ROOT_INIT),
        },
        "required_inputs": list(metadata.get("required_inputs", [])) + [
            "generated public wrong/empty/no-input UI shim",
            "generated native BusyBox PID1 root stub",
        ],
    }
    probe_manifest.write_text(json.dumps(probe, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    records["r8q-probe-manifest.json"] = {
        **records.get("r8q-probe-manifest.json", {}),
        "sha256": digest(probe_manifest),
        "size": probe_manifest.stat().st_size,
    }
    metadata["files"] = dict(sorted(records.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an isolated public native root-handoff probe tree.")
    parser.add_argument("--source-probe", type=Path, required=True)
    parser.add_argument("--known-good-efi", type=Path, required=True)
    parser.add_argument("--known-good-dtb", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_probe.resolve()
    output = args.output.resolve()
    if not source.is_dir():
        die(f"source probe tree is missing: {source}")
    if output.exists():
        die(f"refusing to overwrite output: {output}")
    if source == output or source in output.parents or output in source.parents:
        die("output must be a distinct sibling tree")
    for path, label in ((args.known_good_efi, "known-good EFI"), (args.known_good_dtb, "known-good DTB")):
        regular(path, label)
    metadata_path = source / "etc/r8q-encryption-manifest.json"
    probe_manifest = source / "r8q-probe-manifest.json"
    init_path = source / "init"
    for path, label in ((metadata_path, "source encryption manifest"), (probe_manifest, "source probe manifest"), (init_path, "source init")):
        regular(path, label)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("root_handoff") is not False or metadata.get("userdata_targeted") is not False:
        die("source must be the final volatile probe with no root handoff")
    known_efi = digest(args.known_good_efi)
    known_dtb = digest(args.known_good_dtb)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, output, symlinks=True)
    try:
        negative = output / NEGATIVE_UI
        negative.parent.mkdir(parents=True, exist_ok=True)
        negative.write_text(negative_ui_source(), encoding="utf-8")
        negative.chmod(0o755)
        root_init = output / ROOT_INIT
        root_init.parent.mkdir(parents=True, exist_ok=True)
        root_init.write_text(native_root_init_source(known_efi, known_dtb), encoding="utf-8")
        root_init.chmod(0o755)
        generated_init = transform_init(init_path.read_text(encoding="utf-8"), known_efi, known_dtb)
        (output / "init").write_text(generated_init, encoding="utf-8")
        (output / "init").chmod(0o755)
        metadata = json.loads((output / "etc/r8q-encryption-manifest.json").read_text(encoding="utf-8"))
        metadata["known_good_efi_sha256"] = known_efi
        metadata["known_good_dtb_sha256"] = known_dtb
        metadata["root_init_path"] = "/" + ROOT_INIT
        manifest_files(metadata, output, output / "r8q-probe-manifest.json")
        (output / "etc/r8q-encryption-manifest.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
