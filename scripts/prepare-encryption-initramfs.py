#!/usr/bin/env python3
"""Offline preparer for a disposable r8q encrypted-root initramfs candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
from typing import Iterable


MAGIC = b"\x7fELF"
EM_AARCH64 = 183
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_RPATH, DT_RUNPATH = 0, 1, 5, 10, 15, 29
MODULES = ("gpi.ko", "i2c-qcom-geni.ko", "fts5cu56a.ko", "zinitix.ko")
SENSITIVE = {"authorized_keys", "known_hosts", "passwd", "shadow", "gshadow", "crypttab"}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".asc", ".gpg", ".token")
VERMAGIC = re.compile(rb"vermagic=([^\x00]+)")
RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@-]{0,127}$")


class PrepareError(RuntimeError):
    pass


def error(message: str):
    raise PrepareError(message)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_file_name(path: Path) -> bool:
    name = path.name.lower()
    return (
        name not in SENSITIVE
        and not name.startswith("id_")
        and "private" not in name
        and "secret" not in name
        and not name.endswith(SENSITIVE_SUFFIXES)
    )


def safe_runtime_path(path: Path) -> bool:
    """Reject sensitive names in any component of a staged runtime path."""
    return all(part not in ("", ".", "..") and safe_file_name(Path(part)) for part in path.parts)


def under(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def reject_system_tree(path: Path, label: str) -> None:
    resolved = Path(os.path.realpath(path))
    if resolved in {Path("/"), Path("/bin"), Path("/sbin"), Path("/usr"), Path("/lib"), Path("/lib64"), Path("/etc"), Path("/opt")}:
        error(f"{label} must be a supplied staging tree, not {resolved}")


def regular(path: Path, label: str, symlink_ok: bool = False) -> Path:
    if not path.exists() or not path.is_file():
        error(f"{label} is not a regular file: {path}")
    if path.is_symlink() and not symlink_ok:
        error(f"{label} must not be a symlink: {path}")
    if not safe_file_name(path):
        error(f"refusing sensitive {label}: {path.name}")
    return path


def elf_info(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != MAGIC or data[4:6] != b"\x02\x01":
        error(f"{path} is not little-endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    if header[2] != EM_AARCH64:
        error(f"{path} is not AArch64 (machine {header[2]})")
    _, _, _, _, _, phoff, _, _, _, phentsize, phnum, _, _, _ = header
    if phentsize < 56 or phnum > 256 or phoff + phentsize * phnum > len(data):
        error(f"{path} has invalid program headers")
    loads = []
    dyn = None
    interp = None
    for index in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize
        )
        if p_offset + p_filesz > len(data):
            error(f"{path} has an out-of-range program segment")
        if p_type == PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz, p_memsz))
        elif p_type == PT_DYNAMIC:
            dyn = (p_offset, p_filesz)
        elif p_type == PT_INTERP:
            interp = data[p_offset : p_offset + p_filesz].split(b"\0", 1)[0].decode()
    if not loads:
        error(f"{path} has no PT_LOAD segment")

    def address_to_offset(address: int) -> int:
        for p_offset, p_vaddr, p_filesz, p_memsz in loads:
            if p_vaddr <= address < p_vaddr + max(p_filesz, p_memsz):
                result = p_offset + address - p_vaddr
                if result <= len(data):
                    return result
        error(f"{path} has an unmappable dynamic address 0x{address:x}")

    needed, searches = [], []
    if dyn:
        dynamic_offset, dynamic_size = dyn
        if dynamic_offset + dynamic_size > len(data):
            error(f"{path} has an invalid PT_DYNAMIC")
        entries = []
        strtab = strsize = None
        for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
            if offset + 16 > len(data):
                error(f"{path} has truncated dynamic entries")
            tag, value = struct.unpack_from("<qQ", data, offset)
            entries.append((tag, value))
            if tag == DT_NULL:
                break
            if tag == DT_STRTAB:
                strtab = value
            elif tag == DT_STRSZ:
                strsize = value
        if strtab is not None and strsize is not None:
            start = address_to_offset(strtab)
            strings = data[start : start + strsize]
            if len(strings) != strsize:
                error(f"{path} has an out-of-range string table")

            def string_at(index: int) -> str:
                if index >= len(strings):
                    error(f"{path} has an invalid dynamic string offset")
                return strings[index:].split(b"\0", 1)[0].decode()

            for tag, value in entries:
                if tag == DT_NEEDED:
                    needed.append(string_at(value))
                elif tag in (DT_RPATH, DT_RUNPATH):
                    searches.append(string_at(value))
    return {"interpreter": interp, "needed": sorted(set(needed)), "search": searches}


def root_relative(path: Path, root: Path, label: str) -> tuple[Path, Path]:
    root = Path(os.path.realpath(root))
    resolved = Path(os.path.realpath(path))
    if not under(resolved, root):
        error(f"{label} resolves outside runtime root: {path}")
    relative = resolved.relative_to(root)
    if not safe_runtime_path(relative):
        error(f"refusing sensitive runtime file: {relative}")
    regular(resolved, label)
    return resolved, relative


def find_library(name: str, root: Path, current: Path, searches: Iterable[str]) -> Path:
    candidates = []
    if name.startswith("/"):
        candidates.append(root / name.lstrip("/"))
    candidates.append(current.parent / name)
    for entry in searches:
        if entry.startswith("/"):
            candidates.append(root / entry.lstrip("/") / name)
        else:
            candidates.append(current.parent / entry / name)
    for directory in ("lib", "usr/lib", "lib64", "usr/lib64"):
        candidates.append(root / directory / name)
    seen = set()
    for candidate in candidates:
        if not candidate.exists():
            continue
        resolved = Path(os.path.realpath(candidate))
        if resolved in seen:
            continue
        seen.add(resolved)
        if under(resolved, root) and resolved.is_file() and safe_file_name(resolved):
            candidate_relative = Path(candidate).relative_to(root)
            if not safe_runtime_path(candidate_relative):
                error(f"refusing sensitive runtime dependency path: {candidate_relative}")
            regular(resolved, "runtime dependency")
            # Preserve the lookup name (including a staged symlink alias) so
            # the loader can request exactly the DT_NEEDED soname in output.
            return candidate
    error(f"AArch64 dependency {name!r} for {current} was not found under runtime root")


def closure(root: Path, entry: Path, label: str, external_destination: Path | None = None) -> dict[Path, dict]:
    root = Path(os.path.realpath(root))
    resolved_entry = Path(os.path.realpath(entry))
    if under(resolved_entry, root):
        resolved, relative = root_relative(entry, root, label)
    else:
        if external_destination is None:
            error(f"{label} resolves outside runtime root: {entry}")
        reject_system_tree(resolved_entry.parent, label)
        resolved = regular(resolved_entry, label)
        relative = external_destination
    queue = [(resolved, relative, label)]
    result = {}
    while queue:
        current, current_relative, current_label = queue.pop(0)
        real_current = Path(os.path.realpath(current))
        if real_current in result:
            aliases = result[real_current].setdefault("aliases", [])
            relative_name = current_relative.as_posix()
            if relative_name != result[real_current]["source"] and relative_name not in aliases:
                aliases.append(relative_name)
            continue
        info = elf_info(real_current)
        result[real_current] = {
            "source": current_relative.as_posix(),
            "sha256": digest(current),
            "size": current.stat().st_size,
            "kind": "elf",
            "label": current_label,
            "aliases": [],
        }
        if info["interpreter"]:
            loader = find_library(info["interpreter"], root, real_current, info["search"])
            queue.append((loader, Path(loader).relative_to(root), "dynamic-loader"))
        for name in info["needed"]:
            dependency = find_library(name, root, real_current, info["search"])
            queue.append((dependency, Path(dependency).relative_to(root), f"needed-by:{current_relative.as_posix()}"))
    return result


def vermagic(path: Path) -> str:
    matches = VERMAGIC.findall(path.read_bytes())
    if len(matches) != 1:
        error(f"touch module has no unique vermagic metadata: {path}")
    return matches[0].decode()


def touch_bundle(directory: Path, release: str) -> dict[str, Path]:
    reject_system_tree(directory, "touch module directory")
    if not directory.is_dir():
        error(f"touch module directory is missing: {directory}")
    found = {name: [] for name in MODULES}
    for path in sorted(directory.rglob("*.ko")):
        if path.is_symlink() or not path.is_file():
            error(f"touch module is not a regular non-symlink file: {path}")
        if path.name in found:
            found[path.name].append(path)
    missing = [name for name, paths in found.items() if not paths]
    duplicates = [name for name, paths in found.items() if len(paths) > 1]
    if missing:
        error(f"touch module bundle is missing: {', '.join(missing)}")
    if duplicates:
        error(f"touch module bundle has duplicates: {', '.join(duplicates)}")
    result = {name: paths[0] for name, paths in found.items()}
    for name, path in result.items():
        value = vermagic(path)
        if not value.startswith(release + " "):
            error(f"{name} vermagic does not match {release!r}: {value!r}")
    return result


def validate_base(base: Path) -> None:
    """Require the known static ARM64 BusyBox used by the custom init."""
    busybox = base / "bin/busybox"
    if busybox.is_symlink() or not busybox.is_file():
        error("base initramfs must contain a regular non-symlink bin/busybox")
    if not (busybox.stat().st_mode & 0o111):
        error("base initramfs bin/busybox is not executable")
    info = elf_info(busybox)
    if info["interpreter"] or info["needed"]:
        error("base initramfs bin/busybox must be a self-contained static AArch64 ELF")


def extra_runtime_files(runtime: Path, paths: Iterable[Path]) -> dict[Path, dict]:
    """Resolve explicitly named non-ELF runtime assets under the supplied root."""
    result = {}
    for supplied in paths:
        candidate = supplied if supplied.is_absolute() else runtime / supplied
        resolved, relative = root_relative(candidate, runtime, "extra runtime asset")
        if resolved in result:
            error(f"duplicate extra runtime asset: {supplied}")
        result[resolved] = {
            "source": relative.as_posix(),
            "sha256": digest(resolved),
            "size": resolved.stat().st_size,
            "kind": "runtime-asset",
            "label": "explicit-extra-path",
        }
    return result


def merge_file_records(target: dict[Path, dict], additions: dict[Path, dict], label_suffix: str) -> None:
    for path, info in additions.items():
        if path not in target:
            target[path] = info
            continue
        existing = target[path]
        existing["label"] = existing["label"] + label_suffix
        aliases = existing.setdefault("aliases", [])
        for relative_name in [info["source"], *info.get("aliases", [])]:
            if relative_name != existing["source"] and relative_name not in aliases:
                aliases.append(relative_name)


def quote(value: str) -> str:
    return "''" if not value else "'" + value.replace("'", "'\\''") + "'"


def make_init(
    release: str,
    cryptsetup: str,
    ui: str,
    udevadm: str,
    udevd: str,
    dmsetup: str,
    ui_args: list[str],
    module_hashes: dict[str, str],
) -> str:
    modules = f"/lib/modules/{release}/r8q-encryption"
    # BuffyBox/unl0kr appends a newline by default. The -n contract is
    # mandatory because a LUKS passphrase must not gain an implicit byte.
    ui_command = " ".join([quote("/" + ui), quote("-n")] + [quote(arg) for arg in ui_args])
    crypt = "/" + cryptsetup
    udevadm_path = "/" + udevadm
    udevd_path = "/" + udevd
    dmsetup_path = "/" + dmsetup
    gpi_sha256 = module_hashes["gpi.ko"]
    geni_sha256 = module_hashes["i2c-qcom-geni.ko"]
    fts_sha256 = module_hashes["fts5cu56a.ko"]
    zinitix_sha256 = module_hashes["zinitix.ko"]
    return f'''#!/bin/busybox sh
# Generated disposable r8q encrypted-root init. No plaintext-init fallback is embedded.
set -eu
BB=/bin/busybox
PATH=/bin:/sbin:/usr/bin:/usr/sbin
HOME=/ TERM=linux
export PATH HOME TERM
# The source initramfs contains BusyBox itself, not its applet symlinks.
"$BB" --install -s /bin || exit 111
umask 077
MAPPER=cryptroot
PASSFIFO=/run/r8q-encryption-passphrase
UI_LOG=/run/r8q-unl0kr.stderr
UDEV_LOG=/run/r8q-udevd.log
ATTEMPTS=3
UI_TIMEOUT=180
ROOT=''
UIPID=''
CRYPTPID=''
WATCHDOG_PID=''
UDEVD_PID=''
NEWROOT_MOUNTED=0
NEWROOT_DEV_MOUNTED=0

terminate_pid() {{
    pid=$1
    [ -n "$pid" ] || return 0
    kill "$pid" 2>/dev/null || :
    TP_TRIES=0
    while kill -0 "$pid" 2>/dev/null; do
        [ "$TP_TRIES" -lt 2 ] || break
        TP_TRIES=$((TP_TRIES + 1)); sleep 1
    done
    kill -9 "$pid" 2>/dev/null || :
    wait "$pid" 2>/dev/null || :
}}

stop_udev() {{
    if [ -n "${{UDEVD_PID:-}}" ]; then
        {udevadm_path} control --exit >/dev/null 2>&1 || :
        terminate_pid "$UDEVD_PID"
        UDEVD_PID=''
    fi
}}

unload_touch_best_effort() {{
    # GPI has no module exit path in this kernel and must remain resident.
    # GENI owns the adapter needed by the production root and also remains
    # resident. Only the disposable controller drivers are best-effort here.
    for module in fts5cu56a zinitix; do
        if [ -d "/sys/module/$module" ]; then
            rmmod "$module" >/dev/null 2>&1 || :
        fi
    done
}}

cleanup_children() {{
    for pid in "${{WATCHDOG_PID:-}}" "${{UIPID:-}}" "${{CRYPTPID:-}}"; do
        terminate_pid "$pid"
    done
    WATCHDOG_PID=''; UIPID=''; CRYPTPID=''
}}

cleanup_newroot() {{
    # Only unmount mounts created by this init.  In particular, do not
    # blindly walk /newroot or /newroot/dev during an early failure.
    if [ "$NEWROOT_DEV_MOUNTED" = 1 ]; then
        umount /newroot/dev >/dev/null 2>&1 || :
        NEWROOT_DEV_MOUNTED=0
    fi
    if [ "$NEWROOT_MOUNTED" = 1 ]; then
        umount /newroot >/dev/null 2>&1 || :
        NEWROOT_MOUNTED=0
    fi
}}

fail_closed() {{
    reason=$1
    echo "r8q-encryption: FAIL CLOSED: $reason" >&2
    cleanup_children
    cleanup_newroot
    {crypt} close "$MAPPER" >/dev/null 2>&1 || :
    stop_udev
    unload_touch_best_effort
    rm -f "$PASSFIFO" "$UI_LOG" "$UDEV_LOG"
    # There is no raw-root mount, network gadget, debug shell, or plaintext
    # init fallback. Exit after cleanup rather than leaving child processes.
    exit 111
}}

mkdir -p /dev /proc /sys /run /newroot
mount -t proc proc /proc 2>/dev/null || fail_closed proc-mount
mount -t sysfs sysfs /sys 2>/dev/null || fail_closed sysfs-mount
mount -t devtmpfs devtmpfs /dev 2>/dev/null || $BB mdev -s 2>/dev/null || fail_closed devtmpfs-mount
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run 2>/dev/null || fail_closed run-mount
mkdir -p /run/udev /dev/mapper
mknod -m 0600 /dev/mapper/control c 10 236 2>/dev/null || [ -e /dev/mapper/control ] || fail_closed mapper-control

# Run udev in a tracked child. Parent-supplied rules and firmware are
# explicit --extra-path inputs; this does not import host state.
{udevd_path} --resolve-names=never >"$UDEV_LOG" 2>&1 &
UDEVD_PID=$!
kill -0 "$UDEVD_PID" 2>/dev/null || fail_closed udevd-start

wait_for_udev() {{
    i=0
    while [ "$i" -lt 5 ]; do
        kill -0 "$UDEVD_PID" 2>/dev/null || return 1
        [ -S /run/udev/control ] && return 0
        i=$((i + 1)); sleep 1
    done
    return 1
}}

wait_for_udev || fail_closed udevd-not-ready

load_once() {{
    name=$1; path=$2; shift 2
    [ -d "/sys/module/$name" ] && return 0
    insmod "$path" "$@" 2>/dev/null || fail_closed "insmod-$name"
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
    path=$1; i=0
    while [ "$i" -lt 10 ]; do
        has_ready_event "$path" && return 0
        i=$((i + 1)); sleep 1
    done
    return 1
}}

# The board touch path is ordered GPI -> GENI (FIFO forced) -> controller.
load_once gpi {modules}/gpi.ko
load_once i2c_qcom_geni {modules}/i2c-qcom-geni.ko r8q_force_fifo=1
FIFO_PARAM=/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo
[ -f "$FIFO_PARAM" ] || fail_closed geni-fifo-parameter-missing
case "$(cat "$FIFO_PARAM" 2>/dev/null | tr -d '\\r\\n')" in
    1|Y|y) ;;
    *) fail_closed geni-fifo-disabled ;;
esac
insmod {modules}/fts5cu56a.ko 2>/dev/null || :
{udevadm_path} trigger --subsystem-match=input --action=add >/dev/null 2>&1 || fail_closed udev-trigger-fts
{udevadm_path} settle --timeout=10 >/dev/null 2>&1 || fail_closed udev-settle-fts
if ! wait_for_ready /sys/bus/i2c/drivers/fts5cu56a/5-0049; then
    insmod {modules}/zinitix.ko 2>/dev/null || :
    {udevadm_path} trigger --subsystem-match=input --action=add >/dev/null 2>&1 || fail_closed udev-trigger-zinitix
    {udevadm_path} settle --timeout=10 >/dev/null 2>&1 || fail_closed udev-settle-zinitix
    wait_for_ready /sys/bus/i2c/drivers/Zinitix-TS/5-0020 || fail_closed touch-event-missing
fi

findpart() {{
    for u in /sys/class/block/*/uevent; do
        if grep -qi "^PARTNAME=$1$" "$u" 2>/dev/null; then
            echo "/dev/$($BB basename "$($BB dirname "$u")")"; return 0
        fi
    done
    return 1
}}
i=0
while [ "$i" -lt 30 ]; do
    ROOT=$(findpart userdata 2>/dev/null || :)
    [ -n "$ROOT" ] && break
    i=$((i + 1)); sleep 1
done
[ -b "$ROOT" ] || fail_closed userdata-not-found
{crypt} isLuks --type luks2 "$ROOT" >/dev/null 2>&1 || fail_closed not-luks2

run_attempt() {{
    rm -f "$PASSFIFO" "$UI_LOG"
    mkfifo "$PASSFIFO" 2>/dev/null || fail_closed passphrase-fifo
    # stdout is raw passphrase bytes; -n prevents an implicit newline.
    set -- {ui_command}
    "$@" >"$PASSFIFO" 2>"$UI_LOG" &
    UIPID=$!
    {crypt} open --type luks2 --batch-mode --tries 1 --key-file="$PASSFIFO" "$ROOT" "$MAPPER" >/dev/null 2>&1 &
    CRYPTPID=$!
    watchdog() {{
        trap 'kill "${{SLEEP_PID:-}}" 2>/dev/null || :; exit 0' TERM INT
        sleep "$UI_TIMEOUT" &
        SLEEP_PID=$!
        wait "$SLEEP_PID"
        terminate_pid "$UIPID"
        terminate_pid "$CRYPTPID"
    }}
    watchdog &
    WATCHDOG_PID=$!
    STATUS=0; wait "$CRYPTPID" || STATUS=$?
    terminate_pid "$UIPID"
    terminate_pid "$WATCHDOG_PID"
    WATCHDOG_PID=''; UIPID=''; CRYPTPID=''
    rm -f "$PASSFIFO" "$UI_LOG"
    return "$STATUS"
}}
i=1
while [ "$i" -le "$ATTEMPTS" ]; do
    if run_attempt; then
        {dmsetup_path} mknodes "$MAPPER" >/dev/null 2>&1 || fail_closed mapper-mknodes
        [ -b /dev/mapper/$MAPPER ] && break
    fi
    {crypt} close "$MAPPER" >/dev/null 2>&1 || :
    i=$((i + 1))
done
[ -b /dev/mapper/$MAPPER ] || fail_closed unlock-failed
mount -t ext4 "/dev/mapper/$MAPPER" /newroot 2>/dev/null || fail_closed decrypted-root-mount
NEWROOT_MOUNTED=1
[ -x /newroot/usr/lib/systemd/systemd ] || fail_closed systemd-missing
mount -t devtmpfs devtmpfs /newroot/dev 2>/dev/null || fail_closed newroot-dev
NEWROOT_DEV_MOUNTED=1

# GPI has no cleanup_module/remove path and cannot be safely unloaded. Keep
# GPI and GENI resident; the production helper explicitly validates and owns
# those exact preloaded modules. Remove only the disposable touch drivers.
stop_udev
rm -f "$UDEV_LOG"
for module in fts5cu56a zinitix; do
    if [ -d "/sys/module/$module" ]; then
        rmmod "$module" >/dev/null 2>&1 || fail_closed "rmmod-$module"
    fi
    [ ! -d "/sys/module/$module" ] || fail_closed "module-still-loaded-$module"
done
[ ! -e /sys/bus/i2c/drivers/fts5cu56a ] || fail_closed touch-driver-still-bound
[ ! -e /sys/bus/i2c/drivers/Zinitix-TS ] || fail_closed touch-driver-still-bound
[ -d /sys/module/gpi ] || fail_closed gpi-not-retained
[ -d /sys/module/i2c_qcom_geni ] || fail_closed geni-not-retained
I2C_ADAPTERS=0
for adapter in /sys/bus/i2c/devices/i2c-*; do
    [ -e "$adapter" ] || continue
    I2C_ADAPTERS=$((I2C_ADAPTERS + 1))
done
[ "$I2C_ADAPTERS" -gt 0 ] || fail_closed geni-adapter-missing
FIFO_HANDOFF=$(cat "$FIFO_PARAM" 2>/dev/null | tr -d '\r\n')
case "$FIFO_HANDOFF" in
    1|Y|y) ;;
    *) fail_closed geni-fifo-disabled-at-handoff ;;
esac
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n')
[ -n "$BOOT_ID" ] || fail_closed boot-id-missing
HANDOFF_MARKER=/run/r8q-encryption-adapter-handoff
{{
    printf 'schema=r8q-encryption-adapter-handoff/v1\n'
    printf 'boot_id=%s\n' "$BOOT_ID"
    printf 'kernel=%s\n' '{release}'
    printf 'gpi_module=lib/modules/{release}/r8q-encryption/gpi.ko\n'
    printf 'gpi_sha256=%s\n' '{gpi_sha256}'
    printf 'geni_module=lib/modules/{release}/r8q-encryption/i2c-qcom-geni.ko\n'
    printf 'geni_sha256=%s\n' '{geni_sha256}'
    printf 'fts_module=lib/modules/{release}/r8q-encryption/fts5cu56a.ko\n'
    printf 'fts_sha256=%s\n' '{fts_sha256}'
    printf 'zinitix_module=lib/modules/{release}/r8q-encryption/zinitix.ko\n'
    printf 'zinitix_sha256=%s\n' '{zinitix_sha256}'
    printf 'gpi_ownership=inherited\n'
    printf 'geni_ownership=inherited\n'
    printf 'i2c_adapters=%s\n' "$I2C_ADAPTERS"
    printf 'fifo=%s\n' "$FIFO_HANDOFF"
    printf 'touch_drivers=absent\n'
    printf 'touch_input_events=absent\n'
}} > "$HANDOFF_MARKER" || fail_closed adapter-handoff-marker
# umask 077 above makes this redirection-created marker mode 0600.  The
# production BusyBox intentionally omits the chmod applet, so do not depend
# on a second mode-changing command here.  The marker is new in this private
# tmpfs and no pre-existing file can be reused.
mkdir -p /newroot/run
mount -o move /run /newroot/run 2>/dev/null || fail_closed run-move
umount /proc 2>/dev/null || :
umount /sys 2>/dev/null || :
# BusyBox switch_root requires PID 1, so shell-level exec is mandatory.
# After this boundary, a switch_root/systemd failure terminates PID 1 and
# reaches kernel panic/reset; shell cleanup is no longer available.
exec switch_root /newroot /usr/lib/systemd/systemd
'''


def copy_base(base: Path, output: Path) -> None:
    reject_system_tree(base, "base initramfs")
    if not base.is_dir() or not (base / "init").is_file() or (base / "init").is_symlink():
        error("base initramfs must be a directory containing a regular init")
    shutil.copytree(base, output, symlinks=True)


def args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-initramfs", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--cryptsetup", type=Path, required=True)
    parser.add_argument("--unl0kr", type=Path, required=True)
    parser.add_argument("--udevadm", type=Path, required=True)
    parser.add_argument("--udevd", type=Path, help="optional distinct systemd-udevd; defaults to a staged udevadm alias")
    parser.add_argument("--dmsetup", type=Path, required=True)
    parser.add_argument("--touch-module-dir", type=Path, required=True)
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ui-arg", action="append", default=[])
    parser.add_argument(
        "--extra-path",
        action="append",
        type=Path,
        default=[],
        help="explicit regular runtime asset relative to --runtime-root (repeatable)",
    )
    return parser.parse_args(argv)


def prepare(options: argparse.Namespace) -> Path:
    if not RELEASE.fullmatch(options.kernel_release):
        error(f"invalid kernel release: {options.kernel_release!r}")
    base = Path(os.path.realpath(options.base_initramfs))
    runtime = Path(os.path.realpath(options.runtime_root))
    output = Path(os.path.realpath(options.output))
    reject_system_tree(runtime, "runtime root")
    reject_system_tree(output, "output")
    if output in (base, runtime) or under(output, base) or under(base, output):
        error("output must be separate from base initramfs and runtime root")
    if not base.is_dir() or not (base / "init").is_file() or (base / "init").is_symlink():
        error("base initramfs must be a directory containing a regular init")
    validate_base(base)
    regular(options.cryptsetup, "cryptsetup", symlink_ok=True)
    regular(options.unl0kr, "unl0kr", symlink_ok=True)
    regular(options.udevadm, "udevadm", symlink_ok=True)
    if options.udevd is not None:
        regular(options.udevd, "udevd", symlink_ok=True)
    regular(options.dmsetup, "dmsetup", symlink_ok=True)
    command_reals = [Path(os.path.realpath(value)) for value in (options.cryptsetup, options.unl0kr, options.udevadm, options.dmsetup)]
    if options.udevd is not None:
        command_reals.append(Path(os.path.realpath(options.udevd)))
    if len(set(command_reals)) != len(command_reals):
        error("cryptsetup, unl0kr, udevadm, udevd, and dmsetup must be distinct artifacts")
    modules = touch_bundle(options.touch_module_dir, options.kernel_release)
    crypt_external = Path("usr/lib/r8q-encryption/cryptsetup") if not under(Path(os.path.realpath(options.cryptsetup)), runtime) else None
    ui_external = Path("usr/lib/r8q-encryption/unl0kr") if not under(Path(os.path.realpath(options.unl0kr)), runtime) else None
    udevadm_external = Path("usr/lib/r8q-encryption/udevadm") if not under(Path(os.path.realpath(options.udevadm)), runtime) else None
    dmsetup_external = Path("usr/lib/r8q-encryption/dmsetup") if not under(Path(os.path.realpath(options.dmsetup)), runtime) else None
    udevd_external = Path("usr/lib/systemd/systemd-udevd") if options.udevd is not None and not under(Path(os.path.realpath(options.udevd)), runtime) else None
    crypt_files = closure(runtime, options.cryptsetup, "cryptsetup", crypt_external)
    ui_files = closure(runtime, options.unl0kr, "unl0kr", ui_external)
    udevadm_files = closure(runtime, options.udevadm, "udevadm", udevadm_external)
    dmsetup_files = closure(runtime, options.dmsetup, "dmsetup", dmsetup_external)
    udevd_files = closure(runtime, options.udevd, "udevd", udevd_external) if options.udevd is not None else {}
    asset_files = extra_runtime_files(runtime, options.extra_path)
    all_files = dict(crypt_files)
    merge_file_records(all_files, ui_files, "+unl0kr")
    merge_file_records(all_files, udevadm_files, "+udevadm")
    merge_file_records(all_files, dmsetup_files, "+dmsetup")
    merge_file_records(all_files, udevd_files, "+udevd")
    for path, info in asset_files.items():
        if path in all_files:
            existing = all_files[path]
            existing_names = [existing["source"], *existing.get("aliases", [])]
            if info["source"] not in existing_names or existing["sha256"] != info["sha256"]:
                error(f"extra runtime asset collides with ELF closure: {info['source']}")
        else:
            all_files[path] = info
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            error(f"output directory must be absent or empty: {output}")
        output.rmdir()
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_files = {}
    copy_base(base, output)
    for source in sorted(all_files, key=lambda value: str(value)):
        info = all_files[source]
        relative_names = [info["source"], *info.get("aliases", [])]
        for index, relative_name in enumerate(relative_names):
            rel = Path(relative_name)
            target = output / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            os.chmod(target, stat.S_IMODE(source.stat().st_mode))
            if rel.as_posix() in manifest_files and manifest_files[rel.as_posix()]["sha256"] != digest(source):
                error(f"runtime closure path collision: {rel}")
            manifest_files[rel.as_posix()] = {"source": rel.as_posix(), "sha256": digest(source), "size": source.stat().st_size, "kind": info["kind"] if index == 0 else "elf-alias", "label": info["label"]}
    udevadm_real = Path(os.path.realpath(options.udevadm))
    udevadm_rel = Path(all_files[udevadm_real]["source"])
    if options.udevd is None:
        # The supplied modern systemd multicall artifact is staged under the
        # daemon name as well. Parent must verify that this alias supports
        # systemd-udevd's foreground invocation before using the candidate.
        udevd_rel = Path("usr/lib/systemd/systemd-udevd")
        alias_target = output / udevd_rel
        alias_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(output / udevadm_rel, alias_target)
        os.chmod(alias_target, stat.S_IMODE((output / udevadm_rel).stat().st_mode))
        manifest_files[udevd_rel.as_posix()] = {"source": udevadm_rel.as_posix(), "sha256": digest(output / udevadm_rel), "size": alias_target.stat().st_size, "kind": "runtime-alias", "label": "systemd-udevd-alias-from-udevadm"}
    else:
        udevd_real = Path(os.path.realpath(options.udevd))
        udevd_rel = Path(all_files[udevd_real]["source"])
    module_paths = {}
    for name in MODULES:
        rel = Path("lib/modules") / options.kernel_release / "r8q-encryption" / name
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(modules[name], target)
        os.chmod(target, stat.S_IMODE(modules[name].stat().st_mode) | stat.S_IXUSR)
        module_paths[name] = rel.as_posix()
        manifest_files[rel.as_posix()] = {"source": modules[name].name, "sha256": digest(modules[name]), "size": modules[name].stat().st_size, "kind": "kernel-module", "vermagic": vermagic(modules[name])}
    module_hashes = {name: digest(modules[name]) for name in MODULES}
    crypt_real = Path(os.path.realpath(options.cryptsetup))
    ui_real = Path(os.path.realpath(options.unl0kr))
    dmsetup_real = Path(os.path.realpath(options.dmsetup))
    crypt_rel = Path(all_files[crypt_real]["source"]).as_posix()
    ui_rel = Path(all_files[ui_real]["source"]).as_posix()
    dmsetup_rel = Path(all_files[dmsetup_real]["source"]).as_posix()
    udevadm_rel = udevadm_rel.as_posix()
    udevd_rel = udevd_rel.as_posix()
    generated = output / "init"
    generated.write_text(make_init(options.kernel_release, crypt_rel, ui_rel, udevadm_rel, udevd_rel, dmsetup_rel, options.ui_arg, module_hashes), encoding="utf-8")
    os.chmod(generated, 0o755)
    manifest_files["init"] = {"source": "generated", "sha256": digest(generated), "size": generated.stat().st_size, "kind": "generated-encrypted-init"}
    metadata = {
        "schema": 1,
        "kind": "r8q-encryption-initramfs-candidate",
        "kernel_release": options.kernel_release,
        "cryptsetup": crypt_rel,
        "unl0kr": ui_rel,
        "udevadm": udevadm_rel,
        "udevd": udevd_rel,
        "udevd_alias_from_udevadm": options.udevd is None,
        "dmsetup": dmsetup_rel,
        "ui_contract": "stdout-raw-passphrase-no-newline",
        "ui_args": list(options.ui_arg),
        "extra_paths": [info["source"] for _, info in sorted(asset_files.items(), key=lambda item: item[1]["source"])],
        "mapper": "cryptroot",
        "touch_order": ["gpi.ko", "i2c-qcom-geni.ko (r8q_force_fifo=1)", "fts5cu56a.ko", "zinitix.ko"],
        "touch_modules": module_paths,
        "adapter_handoff": {
            "schema": "r8q-encryption-adapter-handoff/v1",
            "marker": "/run/r8q-encryption-adapter-handoff",
            "retained_modules": ["gpi.ko", "i2c-qcom-geni.ko"],
            "unloaded_modules": ["fts5cu56a.ko", "zinitix.ko"],
            "fifo": "r8q_force_fifo=1",
            "touch_drivers": "absent",
        },
        "fail_closed": True,
        "files": dict(sorted(manifest_files.items())),
    }
    manifest = output / "etc/r8q-encryption-manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    try:
        result = prepare(args(argv or sys.argv[1:]))
    except (PrepareError, OSError, ValueError, struct.error) as exc:
        print(f"prepare-encryption-initramfs: error: {exc}", file=sys.stderr)
        return 2
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
