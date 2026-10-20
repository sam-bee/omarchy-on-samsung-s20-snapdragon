#!/usr/bin/env python3
"""Prepare and verify the non-phone stage-2 R8Q diagnostic candidate."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
from typing import Any


REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"
KERNEL_OUTPUT = OUT / "diagnostic-kernel-20261020" / "kernel"
SOURCE = OUT / "waydroid-kernel-20261013" / "source"
BASE = OUT / "waydroid-encrypted-20261015" / "kernel"
ACCEPTED_CONFIG = BASE / ".config"
TEMPORARY_CPIO = KERNEL_OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"
ACTIVE_DTB = KERNEL_OUTPUT / "active-dtb.R8Q-RTC.DTB"
RELEASE = "7.1.2-r8q-diag1"
OLD_RELEASE = "7.1.2-r8q-waydroid2"
EFI_SHA256 = "f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b"
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
SOURCE_SHA256 = "04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b"
BASE_CONFIG_SHA256 = "0375c928a377e5507a4e217d2a6da0fce4b458f1785888dd3ea2a5c6e57b2ca1"
TEMPORARY_CPIO_SHA256 = "eaf69e92e8a30fc03f06736eb5f33169eeecae0a9cae5ce09193fffe27791abe"
MODULE_NAMES = ("gpi", "i2c_qcom_geni", "fts5cu56a", "zinitix")
MODULE_BASENAMES = {
    "gpi": "gpi.ko",
    "i2c_qcom_geni": "i2c-qcom-geni.ko",
    "fts5cu56a": "fts5cu56a.ko",
    "zinitix": "zinitix.ko",
}
ACCEPTED_EARLY_MODULE_MODE = 0o744
GUARD_HELPER_LINKS = ("cp", "mv", "readlink", "sha256sum", "stat")
DIAGNOSTIC_KEYS = {
    "CONFIG_ARM64_PSEUDO_NMI",
    "CONFIG_SOFTLOCKUP_DETECTOR",
    "CONFIG_HARDLOCKUP_DETECTOR",
    "CONFIG_HARDLOCKUP_DETECTOR_PERF",
    "CONFIG_DETECT_HUNG_TASK",
    "CONFIG_DETECT_HUNG_TASK_BLOCKER",
    "CONFIG_WQ_WATCHDOG",
    "CONFIG_RCU_EQS_DEBUG",
    "CONFIG_HAVE_PERF_EVENTS_NMI",
    "CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF",
    "CONFIG_HARDLOCKUP_DETECTOR_COUNTS_HRTIMER",
    "CONFIG_LOCKUP_DETECTOR",
    "CONFIG_BOOTPARAM_HUNG_TASK_PANIC",
    "CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC",
    "CONFIG_BOOTPARAM_WQ_STALL_PANIC",
    "CONFIG_DEFAULT_HUNG_TASK_TIMEOUT",
    "CONFIG_CMDLINE",
    "CONFIG_INITRAMFS_SOURCE",
    "CONFIG_LOCALVERSION",
}
VERMAGIC = RELEASE + " SMP preempt mod_unload aarch64"
GUARD_NONCE_PATTERN = re.compile(r"[0-9a-f]{32}")
GUARD_TAG_PATTERN = re.compile(r"[A-Za-z0-9._-]+")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("CONFIG_"):
            key, value = line.split("=", 1)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-11]] = "n"
    return values


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file(), f"Missing {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot parse {label}: {exc}") from exc
    require(isinstance(value, dict), f"{label} is not an object: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def regular(path: Path, label: str) -> None:
    require(path.is_file() and not path.is_symlink(), f"Missing regular {label}: {path}")


def directory(path: Path, label: str) -> None:
    require(path.is_dir() and not path.is_symlink(), f"Missing directory {label}: {path}")


def source_proof() -> dict[str, Any]:
    path = REPO / "scripts" / "prepare-waydroid-kernel-source.py"
    spec = importlib.util.spec_from_file_location("r8q_source_rules_finalizer", path)
    require(spec is not None and spec.loader is not None, f"Unable to load source rules: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proof = module.verify_complete_source_tree(SOURCE)
    require(proof.get("sha256") == SOURCE_SHA256, "Pinned complete source identity differs")
    return proof


def stage1(config_path: Path | None = None, require_stage1_image: bool = True) -> dict[str, Any]:
    directory(KERNEL_OUTPUT, "diagnostic kernel output")
    regular(BASE / "payload/BOOTAA64.EFI", "accepted v2 EFI payload")
    require(digest(BASE / "payload/BOOTAA64.EFI") == EFI_SHA256,
            "accepted v2 EFI bytes differ")
    regular(BASE / "payload/R8Q-RTC.DTB", "accepted v2 DTB payload")
    require(digest(BASE / "payload/R8Q-RTC.DTB") == DTB_SHA256,
            "accepted v2 DTB bytes differ")
    manifest = read_json(KERNEL_OUTPUT / "stage1-manifest.json", "stage1 manifest")
    require(manifest.get("kind") == "r8q-diagnostic-stage1-nondeployable",
            "stage1 manifest is not the completed non-deployable build")
    require(manifest.get("kernel_release") == RELEASE, "stage1 release differs")
    require(manifest.get("deployable") is False and manifest.get("stage2_required") is True,
            "stage1 deployment state is unsafe")
    require(manifest.get("source_complete_sha256") == SOURCE_SHA256,
            "stage1 source proof hash differs")
    require(manifest.get("base_efi_sha256") == EFI_SHA256, "stage1 EFI pin differs")
    require(manifest.get("dtb_sha256") == DTB_SHA256, "stage1 DTB pin differs")
    current_config = config_path or (KERNEL_OUTPUT / ".config")
    regular(current_config, "stage1 configuration")
    regular(KERNEL_OUTPUT / "acceptedv2.config", "accepted configuration copy")
    require(digest(KERNEL_OUTPUT / "acceptedv2.config") == BASE_CONFIG_SHA256,
            "accepted configuration copy differs")
    require(digest(current_config) == manifest.get("resolved_config_sha256"),
            "stage1 configuration hash differs from its manifest")
    require(digest(SOURCE / "Makefile") == "9e74f1c62c24972fc6b4e56e6761a28e3f497984978131d24119a0aaabba8a8c",
            "pinned source Makefile differs")
    proof = source_proof()
    require(proof.get("sha256") == manifest.get("source_complete_sha256"),
            "stage1 source proof does not match current source")
    stage1_config = config(current_config)
    accepted_config = config(KERNEL_OUTPUT / "acceptedv2.config")
    delta = {
        key: {"before": accepted_config.get(key, "n"), "after": stage1_config.get(key, "n")}
        for key in sorted(accepted_config.keys() | stage1_config.keys())
        if accepted_config.get(key, "n") != stage1_config.get(key, "n")
    }
    require(set(delta) == DIAGNOSTIC_KEYS, "stage1 diagnostic config closure differs")
    recorded_delta = read_json(KERNEL_OUTPUT / "config-delta.json", "stage1 config delta")
    require(recorded_delta == delta, "stage1 config delta receipt differs")
    require(stage1_config.get("CONFIG_LOCALVERSION") == json.dumps("-r8q-diag1"),
            "stage1 local version differs")
    require(stage1_config.get("CONFIG_INITRAMFS_SOURCE") == json.dumps(str(TEMPORARY_CPIO)),
            "stage1 initramfs source is not the temporary accepted cpio")
    require(stage1_config.get("CONFIG_DEBUG_INFO_BTF", "n") == "n" and
            stage1_config.get("CONFIG_DEBUG_INFO_BTF_MODULES", "n") == "n",
            "stage1 BTF is unexpectedly enabled")
    require(accepted_config.get("CONFIG_INITRAMFS_COMPRESSION_GZIP") == "y" and
            stage1_config.get("CONFIG_INITRAMFS_COMPRESSION_GZIP") == "y",
            "accepted/stage1 initramfs compression is not gzip")
    compiler = shutil.which("clang")
    require(compiler is not None, "Required existing tool missing: clang")
    compiler_text = subprocess.check_output([compiler, "--version"], text=True).splitlines()[0]
    require(stage1_config.get("CONFIG_CC_VERSION_TEXT") == json.dumps(compiler_text) and
            accepted_config.get("CONFIG_CC_VERSION_TEXT") == json.dumps(compiler_text),
            "current compiler identity differs from accepted configuration")
    regular(TEMPORARY_CPIO, "temporary accepted cpio")
    require(digest(TEMPORARY_CPIO) == TEMPORARY_CPIO_SHA256,
            "temporary accepted cpio differs")
    regular(ACTIVE_DTB, "active DTB")
    require(digest(ACTIVE_DTB) == DTB_SHA256, "active DTB differs")
    image = KERNEL_OUTPUT / "arch/arm64/boot/Image"
    payload = KERNEL_OUTPUT / "payload/BOOTAA64.EFI"
    payload_dtb = KERNEL_OUTPUT / "payload/R8Q-RTC.DTB"
    regular(image, "stage1 Image")
    regular(payload, "stage1 EFI payload")
    regular(payload_dtb, "stage1 DTB payload")
    if require_stage1_image:
        require(digest(image) == manifest.get("image_sha256"), "stage1 Image hash differs")
        require(digest(payload) == manifest.get("payload_image_sha256"), "stage1 payload hash differs")
        require(payload.read_bytes() == image.read_bytes(), "stage1 payload differs from Image")
    require(digest(payload_dtb) == DTB_SHA256 and payload_dtb.read_bytes() == ACTIVE_DTB.read_bytes(),
            "stage1 DTB payload differs")
    module_records = module_tree_records()
    expected_paths = sorted(manifest.get("module_paths", []))
    actual_paths = sorted(path for path in module_records if path.endswith(".ko"))
    require(expected_paths and actual_paths == expected_paths, "stage1 module inventory paths differ")
    require(manifest.get("module_count") == len(actual_paths) > 0, "stage1 module count differs")
    if require_stage1_image:
        inspect_image(KERNEL_OUTPUT, TEMPORARY_CPIO.read_bytes())
    return {"manifest": manifest, "config": stage1_config, "accepted_config": accepted_config,
            "config_delta": delta, "source_proof": proof, "module_records": module_records,
            "image": image, "payload": payload, "payload_dtb": payload_dtb}


def module_tree_records() -> dict[str, dict[str, Any]]:
    root = KERNEL_OUTPUT / "modules"
    directory(root, "stage1 installed modules")
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            records[relative] = {"type": "file", "mode": stat.S_IMODE(info.st_mode),
                                 "bytes": info.st_size, "sha256": digest(path)}
        elif stat.S_ISLNK(info.st_mode):
            records[relative] = {"type": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                 "target": os.readlink(path)}
        elif stat.S_ISDIR(info.st_mode):
            continue
        else:
            raise SystemExit(f"Unsupported installed module entry: {path}")
    require(any(path.endswith(".ko") for path in records), "stage1 module catalogue has no modules")
    return records


def runtime_tree_records(root: Path) -> dict[str, dict[str, Any]]:
    directory(root, "runtime initramfs")
    records: dict[str, dict[str, Any]] = {}
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        kept: list[str] = []
        for name in directory_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                records[relative] = {"type": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                     "target": os.readlink(path)}
                continue
            require(stat.S_ISDIR(info.st_mode), f"runtime tree contains special entry: {path}")
            records[relative] = {"type": "directory", "mode": stat.S_IMODE(info.st_mode)}
            kept.append(name)
        directory_names[:] = kept
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                records[relative] = {"type": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                     "target": os.readlink(path)}
            else:
                require(stat.S_ISREG(info.st_mode), f"runtime tree contains special entry: {path}")
                records[relative] = {"type": "file", "mode": stat.S_IMODE(info.st_mode),
                                     "bytes": info.st_size, "sha256": digest(path)}
    return records


def parse_devnodes(path: Path) -> dict[str, dict[str, Any]]:
    regular(path, "initramfs device list")
    records: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        require(len(fields) >= 5, f"Malformed device list line: {line}")
        kind, name, mode, uid, gid = fields[:5]
        name = name.lstrip("/")
        require(name and ".." not in name.split("/"), f"Unsafe device list path: {name}")
        require(name not in records, f"Duplicate device list path: {name}")
        row = {"type": "directory" if kind == "dir" else "device", "mode": int(mode, 8),
               "uid": int(uid), "gid": int(gid)}
        if kind == "nod":
            require(len(fields) >= 8 and fields[5] == "c", f"Malformed character device: {line}")
            row.update({"major": int(fields[6]), "minor": int(fields[7])})
        else:
            require(kind == "dir", f"Unsupported device list entry: {line}")
        records[name] = row
    return records


def parse_newc(data: bytes) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        require(header[:6] == b"070701", "embedded archive is not newc cpio")
        fields = [int(header[index:index + 8], 16) for index in range(6, 110, 8)]
        _, mode, uid, gid, _, _, size, _, _, major, minor, namesize, _ = fields
        offset += 110
        raw_name = data[offset:offset + namesize]
        require(len(raw_name) == namesize and raw_name.endswith(b"\0"), "invalid cpio name")
        name = raw_name[:-1].decode("utf-8")
        offset = (offset + namesize + 3) & ~3
        content = data[offset:offset + size]
        require(len(content) == size, "truncated cpio payload")
        offset = (offset + size + 3) & ~3
        if name == "TRAILER!!!":
            require(not any(data[offset:]), "unexpected data after cpio trailer")
            return records
        require(name and not name.startswith("/") and ".." not in name.split("/"),
                f"unsafe embedded cpio path: {name}")
        require(uid == 0 and gid == 0, f"non-root cpio ownership: {name}")
        record = {"mode": mode, "uid": uid, "gid": gid, "bytes": size,
                  "sha256": hashlib.sha256(content).hexdigest(), "major": major, "minor": minor}
        require(name not in records, f"duplicate cpio path: {name}")
        records[name] = record
    raise SystemExit("embedded cpio has no trailer")


def expected_archive(runtime: Path) -> dict[str, dict[str, Any]]:
    tree = runtime_tree_records(runtime)
    devices = parse_devnodes(REPO / "initramfs" / "irfs.devnodes")
    result: dict[str, dict[str, Any]] = {}
    for name, row in tree.items():
        path = runtime / name
        info = path.lstat()
        if row["type"] == "directory":
            mode = info.st_mode
            content = b""
        elif row["type"] == "symlink":
            mode = info.st_mode
            content = os.readlink(path).encode() + b"\0"
        else:
            mode = info.st_mode
            content = path.read_bytes()
        result[name] = {"mode": mode, "uid": 0, "gid": 0, "bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(), "major": 0, "minor": 0}
    for name, row in devices.items():
        require(name not in result, f"device list overlaps runtime tree: {name}")
        mode = stat.S_IFCHR | row["mode"] if row["type"] == "device" else stat.S_IFDIR | row["mode"]
        result[name] = {"mode": mode, "uid": row["uid"], "gid": row["gid"], "bytes": 0,
                        "sha256": hashlib.sha256(b"").hexdigest(),
                        "major": row.get("major", 0), "minor": row.get("minor", 0)}
    return result


def static_arm64_elf(path: Path) -> None:
    data = path.read_bytes()
    require(len(data) >= 64 and data[:4] == b"\x7fELF", "guard helper is not ELF")
    require(data[4] == 2 and data[5] == 1, "guard helper is not little-endian ELF64")
    require(struct.unpack_from("<H", data, 18)[0] == 183,
            "guard helper is not AArch64")
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    program_size = struct.unpack_from("<H", data, 54)[0]
    program_count = struct.unpack_from("<H", data, 56)[0]
    require(program_size == 56 or program_count == 0, "guard helper ELF program headers are malformed")
    require(program_count == 0 or program_offset + program_size * program_count <= len(data),
            "guard helper ELF program headers are truncated")
    for index in range(program_count):
        program_type = struct.unpack_from("<I", data, program_offset + index * program_size)[0]
        require(program_type != 3, "guard helper is dynamically linked")


def guard_helper_binding(runtime: Path) -> dict[str, Any]:
    links: dict[str, Path] = {}
    for current, directory_names, file_names in os.walk(runtime, topdown=True, followlinks=False):
        directory_names.sort()
        file_names.sort()
        for name in directory_names + file_names:
            path = Path(current) / name
            if path.is_symlink() and name in GUARD_HELPER_LINKS:
                require(name not in links, f"duplicate guard helper symlink: {name}")
                links[name] = path
    require(set(links) == set(GUARD_HELPER_LINKS),
            "runtime guard helper symlink set differs")
    runtime_root = runtime.resolve()
    targets: dict[str, str] = {}
    target_paths: set[Path] = set()
    for name in GUARD_HELPER_LINKS:
        link = links[name]
        target = os.readlink(link)
        target_path = (link.parent / target).resolve(strict=False)
        try:
            target_relative = target_path.relative_to(runtime_root).as_posix()
        except ValueError as exc:
            raise SystemExit(f"guard helper symlink escapes runtime: {link}") from exc
        regular(target_path, f"guard helper target for {name}")
        require(not target_path.is_symlink(), f"guard helper target is a symlink: {target_path}")
        targets[name] = target_relative
        target_paths.add(target_path)
    require(len(target_paths) == 1, "guard helper symlinks do not share one target")
    helper = next(iter(target_paths))
    require(helper.name != "busybox", "guard helper unexpectedly points to BusyBox")
    require(helper.stat().st_mode & 0o111, "guard helper is not executable")
    static_arm64_elf(helper)
    helper_relative = helper.relative_to(runtime_root).as_posix()
    helper_info = {"path": helper_relative, "sha256": digest(helper),
                   "bytes": helper.stat().st_size,
                   "symlinks": {name: targets[name] for name in GUARD_HELPER_LINKS}}
    return helper_info


def compare_helper_metadata(metadata: Any, helper: dict[str, Any], label: str) -> None:
    require(isinstance(metadata, dict), f"{label} helper metadata is missing")
    require(metadata.get("path") == helper["path"] and
            metadata.get("sha256") == helper["sha256"] and
            metadata.get("bytes") == helper["bytes"] and
            metadata.get("symlinks") == helper["symlinks"],
            f"{label} helper binding differs")


def stage1_module_bindings(stage: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = stage.get("module_records")
    require(isinstance(records, dict), "stage1 module inventory is missing")
    bindings: dict[str, dict[str, Any]] = {}
    for name in MODULE_NAMES:
        basename = MODULE_BASENAMES[name]
        matches = [relative for relative, row in records.items()
                   if Path(relative).name == basename and isinstance(row, dict) and
                   row.get("type") == "file"]
        require(len(matches) == 1,
                f"stage1 module inventory must contain one {name} source: {matches}")
        relative = matches[0]
        row = records[relative]
        module_path = (KERNEL_OUTPUT / "modules" / relative).resolve()
        regular(module_path, f"stage1 {name} module source")
        require(digest(module_path) == row.get("sha256") and
                module_path.stat().st_size == row.get("bytes") and
                stat.S_IMODE(module_path.stat().st_mode) == row.get("mode"),
                f"stage1 {name} module inventory readback differs")
        bindings[name] = {"relative": relative, "path": module_path,
                          "sha256": row["sha256"], "bytes": row["bytes"],
                          "mode": row["mode"]}
    return bindings


def runtime_manifest_file_inventory(runtime: Path,
                                    runtime_manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tree = runtime_tree_records(runtime)
    expected = {relative: row for relative, row in tree.items()
                if row["type"] == "file" and
                relative != "etc/r8q-encryption-manifest.json"}
    files = runtime_manifest.get("files")
    require(isinstance(files, dict) and set(files) == set(expected),
            "runtime manifest file inventory differs from the runtime tree")
    normalized: dict[str, dict[str, Any]] = {}
    for relative, expected_row in expected.items():
        row = files.get(relative)
        require(isinstance(row, dict) and row.get("source") == relative and
                row.get("sha256") == expected_row["sha256"] and
                type(row.get("mode")) is int and row["mode"] == expected_row["mode"],
                f"runtime manifest metadata differs for {relative}")
        size = row.get("bytes", row.get("size"))
        require(type(size) is int and size == expected_row["bytes"],
                f"runtime manifest byte count differs for {relative}")
        if "bytes" in row:
            require(row["bytes"] == size, f"runtime manifest bytes differ for {relative}")
        if "size" in row:
            require(row["size"] == size, f"runtime manifest size differs for {relative}")
        normalized[relative] = dict(row)
    return normalized


def validate_guard_hook(runtime: Path, guard: dict[str, Any]) -> None:
    nonce = guard.get("nonce")
    tag = guard.get("tag")
    require(isinstance(nonce, str) and GUARD_NONCE_PATTERN.fullmatch(nonce) is not None and
            isinstance(tag, str) and GUARD_TAG_PATTERN.fullmatch(tag) is not None,
            "runtime guard nonce/tag is malformed")
    guard_config = runtime / "etc/r8q-diagnostic-fallback.conf"
    regular(guard_config, "runtime guard configuration")
    config_lines = guard_config.read_text(encoding="utf-8").splitlines()
    require(config_lines == ["schema=r8q-diagnostic-fallback-config/v1",
                             f"trial_nonce={nonce}", f"trial_tag={tag}"],
            "runtime guard configuration is not exact")
    init_path = runtime / "init"
    regular(init_path, "runtime init")
    init_text = init_path.read_text(encoding="utf-8")
    hook_lines = [
        "DIAGNOSTIC_GUARD=/r8q-diagnostic-fallback.sh",
        f"DIAGNOSTIC_GUARD_NONCE={nonce!r}",
        f"DIAGNOSTIC_GUARD_TAG={tag!r}",
        f"DIAGNOSTIC_EXPECTED_EFI_SHA256={EFI_SHA256!r}",
        f"DIAGNOSTIC_EXPECTED_DTB_SHA256={DTB_SHA256!r}",
        '[ -x "$DIAGNOSTIC_GUARD" ] || fail_closed diagnostic-guard-missing',
        '"$DIAGNOSTIC_GUARD" --nonce "$DIAGNOSTIC_GUARD_NONCE" --tag "$DIAGNOSTIC_GUARD_TAG" --expected-efi-sha256 "$DIAGNOSTIC_EXPECTED_EFI_SHA256" --expected-dtb-sha256 "$DIAGNOSTIC_EXPECTED_DTB_SHA256" || fail_closed diagnostic-guard',
    ]
    hook = "\n".join(hook_lines) + "\n"
    require(init_text.count(hook) == 1, "runtime guard hook is not unique")
    run_mount = re.compile(r"(?m)^mount -t tmpfs .* /run 2>/dev/null \\|\\| fail_closed run-mount$")
    run_mount_match = run_mount.search(init_text)
    require(run_mount_match is not None, "runtime /run mount hook point is missing")
    hook_start = run_mount_match.end() + 1
    require(init_text.startswith(hook, hook_start),
            "runtime guard hook is not immediately after the /run mount")
    hook_end = hook_start + len(hook)
    udev_index = init_text.find("systemd-udevd", hook_end)
    luks_index = init_text.find("cryptsetup isLuks", hook_end)
    require(udev_index >= hook_end and luks_index >= hook_end,
            "runtime guard hook is not before udev and LUKS handling")


def validate_runtime(runtime: Path, stage: dict[str, Any], provenance_path: Path | None) -> dict[str, Any]:
    manifest_path = runtime / "etc/r8q-encryption-manifest.json"
    runtime_manifest = read_json(manifest_path, "runtime manifest")
    require(runtime_manifest.get("kind") == "r8q-diagnostic-initramfs-candidate",
            "runtime manifest kind differs")
    require(runtime_manifest.get("kernel_release") == RELEASE, "runtime release differs")
    require(runtime_manifest.get("fail_closed") is True, "runtime is not fail-closed")
    guard = runtime_manifest.get("diagnostic_guard")
    require(isinstance(guard, dict), "runtime diagnostic guard metadata is missing")
    require(guard.get("accepted_efi_sha256") == EFI_SHA256 and
            guard.get("accepted_dtb_sha256") == DTB_SHA256,
            "runtime accepted input pins differ")
    guard_path = runtime / "r8q-diagnostic-fallback.sh"
    regular(guard_path, "runtime diagnostic guard")
    require(guard_path.stat().st_mode & 0o111, "runtime diagnostic guard is not executable")
    require(guard.get("path") == "/r8q-diagnostic-fallback.sh", "runtime guard path differs")
    require(guard.get("sha256") == digest(guard_path),
            "runtime guard metadata hash differs")
    validate_guard_hook(runtime, guard)
    helper = guard_helper_binding(runtime)
    compare_helper_metadata(guard.get("helper"), helper, "runtime manifest")
    runtime_files = runtime_manifest_file_inventory(runtime, runtime_manifest)
    module_root = runtime / "lib/modules" / RELEASE / "r8q-encryption"
    directory(module_root, "runtime early module directory")
    stage_modules = stage1_module_bindings(stage)
    runtime_modules: dict[str, dict[str, Any]] = {}
    for name in MODULE_NAMES:
        path = module_root / MODULE_BASENAMES[name]
        regular(path, f"runtime {name} module")
        stage_module = stage_modules[name]
        runtime_relative = path.relative_to(runtime).as_posix()
        runtime_modules[name] = {"path": runtime_relative,
                                "sha256": digest(path), "bytes": path.stat().st_size,
                                "mode": stat.S_IMODE(path.stat().st_mode),
                                "stage1_path": stage_module["relative"]}
        require(runtime_modules[name]["sha256"] == stage_module["sha256"] and
                runtime_modules[name]["bytes"] == stage_module["bytes"] and
                runtime_modules[name]["mode"] == ACCEPTED_EARLY_MODULE_MODE,
                f"runtime module does not match accepted {name} initramfs mode/content")
    require(sorted(p.name for p in module_root.glob("*.ko")) ==
            sorted(MODULE_BASENAMES.values()), "runtime early module inventory differs")
    if provenance_path is None:
        provenance_path = runtime.parent / "provenance.json"
    provenance = read_json(provenance_path, "runtime provenance")
    require(provenance.get("schema") == "r8q-diagnostic-runtime-provenance/v1" and
            provenance.get("mode") == "initramfs", "runtime provenance kind differs")
    stage1_path = KERNEL_OUTPUT / "stage1-manifest.json"
    require(provenance.get("stage1_manifest_sha256") == digest(stage1_path),
            "runtime provenance stage1 binding differs")
    require(provenance.get("accepted_efi_sha256") == EFI_SHA256 and
            provenance.get("accepted_dtb_sha256") == DTB_SHA256,
            "runtime provenance accepted pins differ")
    require(provenance.get("stage1_manifest") == str(KERNEL_OUTPUT / "stage1-manifest.json"),
            "runtime provenance stage1 path differs")
    require(provenance.get("guard", {}).get("nonce") == guard.get("nonce") and
            provenance.get("guard", {}).get("tag") == guard.get("tag") and
            provenance.get("guard", {}).get("sha256") == digest(guard_path),
            "runtime provenance guard binding differs")
    provenance_modules = provenance.get("modules")
    require(isinstance(provenance_modules, dict) and set(provenance_modules) == set(MODULE_NAMES),
            "runtime provenance early module set differs")
    for name in MODULE_NAMES:
        row = provenance_modules[name]
        require(row.get("sha256") == runtime_modules[name]["sha256"] and
                row.get("bytes") == runtime_modules[name]["bytes"] and
                row.get("vermagic") == VERMAGIC and row.get("module_name") == name,
                f"runtime provenance module binding differs: {name}")
        source = Path(row.get("path", ""))
        require(source.is_absolute() and source.resolve() == stage_modules[name]["path"],
                f"runtime provenance source path differs: {name}")
        regular(source, f"staged {name} module")
        require(digest(source) == runtime_modules[name]["sha256"],
                f"runtime module does not match staged {name} module")
        manifest_row = runtime_files.get(runtime_modules[name]["path"])
        require(isinstance(manifest_row, dict) and
                manifest_row.get("sha256") == runtime_modules[name]["sha256"] and
                manifest_row.get("mode") == runtime_modules[name]["mode"],
                f"runtime manifest module binding differs: {name}")
    stage1_manifest_binding = runtime_manifest.get("stage1", {})
    require(stage1_manifest_binding.get("path") == str(stage1_path) and
            stage1_manifest_binding.get("manifest_sha256") == digest(stage1_path),
            "runtime manifest stage1 binding differs")
    compare_helper_metadata(provenance.get("helper"), helper, "runtime provenance")
    return {"manifest": runtime_manifest, "provenance": provenance,
            "provenance_path": provenance_path, "modules": runtime_modules,
            "guard": guard, "helper": helper, "files": runtime_files,
            "archive": expected_archive(runtime)}


def prepare_config(stage: dict[str, Any], runtime: Path) -> tuple[Path, dict[str, Any]]:
    output = KERNEL_OUTPUT / "stage2-finalization.config"
    require(not output.exists(), f"Refusing to overwrite stage2 config: {output}")
    value = (KERNEL_OUTPUT / ".config").read_text(encoding="utf-8")
    source_value = str(runtime) + " " + str(REPO / "initramfs" / "irfs.devnodes")
    lines = value.splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith("CONFIG_INITRAMFS_SOURCE=")]
    require(len(matches) == 1, "stage1 config must contain one INITRAMFS_SOURCE")
    lines[matches[0]] = "CONFIG_INITRAMFS_SOURCE=" + json.dumps(source_value)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    final_config = config(output)
    delta = {
        key: {"before": stage["config"].get(key, "n"), "after": final_config.get(key, "n")}
        for key in sorted(stage["config"].keys() | final_config.keys())
        if stage["config"].get(key, "n") != final_config.get(key, "n")
    }
    require(set(delta) == {"CONFIG_INITRAMFS_SOURCE"},
            "stage2 config changes more than INITRAMFS_SOURCE")
    require(final_config["CONFIG_INITRAMFS_SOURCE"] == json.dumps(source_value),
            "stage2 initramfs source differs")
    return output, delta


def inspect_image(output: Path, expected_cpio: bytes | None = None) -> dict[str, Any]:
    image = output / "arch/arm64/boot/Image"
    payload = output / "payload/BOOTAA64.EFI"
    regular(image, "final Image")
    regular(payload, "final EFI payload")
    data = image.read_bytes()
    require(payload.read_bytes() == data, "final EFI payload differs from Image")
    require(data[:2] == b"MZ" and data[56:60] == b"ARM\x64", "invalid ARM64 EFI header")
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    require(data[pe_offset:pe_offset + 4] == b"PE\0\0", "missing EFI PE signature")
    require(struct.unpack_from("<H", data, pe_offset + 4)[0] == 0xAA64,
            "final EFI architecture differs")
    require(struct.unpack_from("<H", data, pe_offset + 24 + 68)[0] == 10,
            "final EFI subsystem differs")
    runtime_size = struct.unpack_from("<Q", data, 16)[0]
    require(len(data) <= runtime_size < len(data) + 64 * 1024 * 1024,
            "invalid ARM64 runtime size")
    symbols: dict[str, int] = {}
    llvm_nm = shutil.which("llvm-nm")
    require(llvm_nm is not None, "Required existing tool missing: llvm-nm")
    for line in subprocess.check_output([llvm_nm, str(output / "vmlinux")], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in {"_text", "__initramfs_start"}:
            symbols[fields[2]] = int(fields[0], 16)
    require(set(symbols) == {"_text", "__initramfs_start"}, "embedded initramfs symbols missing")
    compressed = (output / "usr/initramfs_inc_data").read_bytes()
    offset = symbols["__initramfs_start"] - symbols["_text"]
    require(offset >= 0 and data[offset:offset + len(compressed)] == compressed,
            "final initramfs is not embedded in Image")
    cpio = gzip.decompress(compressed)
    if expected_cpio is not None:
        require(cpio == expected_cpio, "stage1 embedded cpio differs from temporary accepted cpio")
    else:
        raw = output / "usr/initramfs_data.cpio"
        regular(raw, "final raw initramfs cpio")
        require(cpio == raw.read_bytes(), "final compressed and raw cpio differ")
    return {"image": image, "payload": payload, "cpio": cpio, "records": parse_newc(cpio)}


def verify_module_tree(expected: dict[str, dict[str, Any]]) -> None:
    actual = module_tree_records()
    require(actual == expected, "final module inventory or module bytes changed")


def validate_final_outputs(stage: dict[str, Any], runtime_info: dict[str, Any],
                           final_config_path: Path,
                           config_delta: dict[str, Any]) -> dict[str, Any]:
    regular(final_config_path, "stage2 finalization config")
    final_values = config(final_config_path)
    actual_values = config(KERNEL_OUTPUT / ".config")
    require(actual_values == final_values, "built output config does not match stage2 config")
    actual_delta = {
        key: {"before": stage["config"].get(key, "n"), "after": final_values.get(key, "n")}
        for key in sorted(stage["config"].keys() | final_values.keys())
        if stage["config"].get(key, "n") != final_values.get(key, "n")
    }
    require(actual_delta == config_delta and set(config_delta) == {"CONFIG_INITRAMFS_SOURCE"},
            "stage2 config delta is not minimal")
    require(actual_values.get("CONFIG_LOCALVERSION") == json.dumps("-r8q-diag1"),
            "final release differs")
    require(actual_values.get("CONFIG_INITRAMFS_SOURCE") == final_values.get("CONFIG_INITRAMFS_SOURCE"),
            "final initramfs source differs")
    require(actual_values.get("CONFIG_DEBUG_INFO_BTF", "n") == "n" and
            actual_values.get("CONFIG_DEBUG_INFO_BTF_MODULES", "n") == "n",
            "final BTF is unexpectedly enabled")
    require((KERNEL_OUTPUT / "include/config/kernel.release").read_text().strip() == RELEASE,
            "generated kernel release differs")
    require(digest(KERNEL_OUTPUT / "payload/R8Q-RTC.DTB") == DTB_SHA256,
            "final DTB differs from accepted pin")
    require((KERNEL_OUTPUT / "payload/R8Q-RTC.DTB").read_bytes() == ACTIVE_DTB.read_bytes(),
            "final DTB differs from stage1 active DTB")
    verify_module_tree(stage["module_records"])
    final = inspect_image(KERNEL_OUTPUT)
    expected = runtime_info["archive"]
    require(set(final["records"]) == set(expected), "embedded runtime path inventory differs")
    for name, expected_row in expected.items():
        actual = final["records"][name]
        require(actual["mode"] == expected_row["mode"] and actual["uid"] == expected_row["uid"] and
                actual["gid"] == expected_row["gid"] and actual["bytes"] == expected_row["bytes"] and
                actual["sha256"] == expected_row["sha256"] and actual["major"] == expected_row["major"] and
                actual["minor"] == expected_row["minor"],
                f"embedded runtime entry differs: {name}")
    return final


def candidate_file_rows(stage: dict[str, Any], final: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = [final["image"], KERNEL_OUTPUT / "payload/BOOTAA64.EFI",
             KERNEL_OUTPUT / "payload/R8Q-RTC.DTB", KERNEL_OUTPUT / ".config",
             KERNEL_OUTPUT / "stage2-finalization.config", KERNEL_OUTPUT / "usr/initramfs_data.cpio",
             KERNEL_OUTPUT / "usr/initramfs_inc_data", KERNEL_OUTPUT / "include/config/kernel.release",
             KERNEL_OUTPUT / "embedded-initramfs-manifest.json"]
    files.extend(KERNEL_OUTPUT / "modules" / path
                 for path, row in sorted(stage["module_records"].items())
                 if row.get("type") == "file")
    file_rows: dict[str, dict[str, Any]] = {}
    for path in files:
        regular(path, f"candidate artifact {path.relative_to(KERNEL_OUTPUT)}")
        file_rows[str(path.relative_to(KERNEL_OUTPUT))] = {
            "bytes": path.stat().st_size, "sha256": digest(path)}
    return file_rows


def verify_final(stage: dict[str, Any], runtime: Path, runtime_info: dict[str, Any],
                 final_config_path: Path, config_delta: dict[str, Any]) -> dict[str, Any]:
    final = validate_final_outputs(stage, runtime_info, final_config_path, config_delta)
    write_json(KERNEL_OUTPUT / "embedded-initramfs-manifest.json", final["records"])
    file_rows = candidate_file_rows(stage, final)
    manifest = {
        "kind": "r8q-diagnostic-kernel-candidate",
        "kernel_release": RELEASE,
        "root_state": "encrypted",
        "deployable": True,
        "stage1_complete": True,
        "stage2_complete": True,
        "stage2_required": False,
        "source": str(SOURCE),
        "source_complete_sha256": SOURCE_SHA256,
        "complete_source_proof": stage["source_proof"],
        "base_efi_sha256": EFI_SHA256,
        "dtb_sha256": DTB_SHA256,
        "stage1_manifest_sha256": digest(KERNEL_OUTPUT / "stage1-manifest.json"),
        "runtime_provenance_sha256": digest(runtime_info["provenance_path"]),
        "runtime_guard": runtime_info["guard"],
        "guard_helper": runtime_info["helper"],
        "early_modules": runtime_info["modules"],
        "module_count": len(stage["module_records"]),
        "module_inventory_unchanged": True,
        "embedded_archive_entries": len(final["records"]),
        "embedded_initramfs_sha256": hashlib.sha256(final["cpio"]).hexdigest(),
        "config_delta": config_delta,
        "files": file_rows,
        "installed": False,
        "boot_tested": False,
        "deployment_prepared": False,
    }
    require(not (KERNEL_OUTPUT / "candidate-manifest.json").exists(),
            "refusing to overwrite existing candidate manifest")
    write_json(KERNEL_OUTPUT / "candidate-manifest.json", manifest)
    return manifest


def check_existing(stage: dict[str, Any], runtime_info: dict[str, Any],
                   final_config_path: Path, config_delta: dict[str, Any]) -> dict[str, Any]:
    final = validate_final_outputs(stage, runtime_info, final_config_path, config_delta)
    embedded_path = KERNEL_OUTPUT / "embedded-initramfs-manifest.json"
    embedded = read_json(embedded_path, "embedded initramfs manifest")
    require(embedded == final["records"], "embedded initramfs manifest differs")
    candidate = read_json(KERNEL_OUTPUT / "candidate-manifest.json", "candidate manifest")
    require(candidate.get("kind") == "r8q-diagnostic-kernel-candidate" and
            candidate.get("kernel_release") == RELEASE and
            candidate.get("deployable") is True and candidate.get("stage1_complete") is True and
            candidate.get("stage2_complete") is True and candidate.get("stage2_required") is False and
            candidate.get("installed") is False and candidate.get("boot_tested") is False and
            candidate.get("deployment_prepared") is False,
            "existing candidate manifest deployment state differs")
    require(candidate.get("source") == str(SOURCE) and
            candidate.get("source_complete_sha256") == SOURCE_SHA256 and
            candidate.get("complete_source_proof") == stage["source_proof"] and
            candidate.get("base_efi_sha256") == EFI_SHA256 and
            candidate.get("dtb_sha256") == DTB_SHA256,
            "existing candidate source or accepted pins differ")
    require(candidate.get("stage1_manifest_sha256") ==
            digest(KERNEL_OUTPUT / "stage1-manifest.json") and
            candidate.get("runtime_provenance_sha256") == digest(runtime_info["provenance_path"]),
            "existing candidate provenance binding differs")
    require(candidate.get("runtime_guard") == runtime_info["guard"] and
            candidate.get("guard_helper") == runtime_info["helper"] and
            candidate.get("early_modules") == runtime_info["modules"],
            "existing candidate runtime binding differs")
    require(candidate.get("module_count") == len(stage["module_records"]) and
            candidate.get("module_inventory_unchanged") is True and
            candidate.get("embedded_archive_entries") == len(final["records"]) and
            candidate.get("embedded_initramfs_sha256") == hashlib.sha256(final["cpio"]).hexdigest() and
            candidate.get("config_delta") == config_delta,
            "existing candidate output metadata differs")
    require(candidate.get("files") == candidate_file_rows(stage, final),
            "existing candidate file inventory differs")
    return candidate


def prepare(args: argparse.Namespace) -> None:
    stage = stage1()
    runtime = Path(args.runtime_initramfs).resolve()
    runtime_info = validate_runtime(runtime, stage,
                                    Path(args.runtime_provenance).resolve() if args.runtime_provenance else None)
    final_config, config_delta = prepare_config(stage, runtime)
    stage1_config_snapshot = KERNEL_OUTPUT / "stage1-before-finalization.config"
    require(not stage1_config_snapshot.exists(),
            f"Refusing to overwrite stage1 configuration snapshot: {stage1_config_snapshot}")
    shutil.copy2(KERNEL_OUTPUT / ".config", stage1_config_snapshot)
    snapshot_path = KERNEL_OUTPUT / "stage1-before-finalization.json"
    require(not snapshot_path.exists(), f"Refusing to overwrite stage1 snapshot: {snapshot_path}")
    write_json(snapshot_path, {
        "kind": "r8q-diagnostic-stage1-identity/v1",
        "stage1_manifest_sha256": digest(KERNEL_OUTPUT / "stage1-manifest.json"),
        "config_sha256": digest(KERNEL_OUTPUT / ".config"),
        "image_sha256": digest(KERNEL_OUTPUT / "arch/arm64/boot/Image"),
        "payload_image_sha256": digest(KERNEL_OUTPUT / "payload/BOOTAA64.EFI"),
        "dtb_sha256": digest(KERNEL_OUTPUT / "payload/R8Q-RTC.DTB"),
        "module_records": stage["module_records"],
    })
    preparation = {
        "kind": "r8q-diagnostic-stage2-ready-nondeployable",
        "kernel_release": RELEASE,
        "deployable": False,
        "relink_required": True,
        "phone_install_performed": False,
        "source_complete_sha256": SOURCE_SHA256,
        "stage1_manifest_sha256": digest(KERNEL_OUTPUT / "stage1-manifest.json"),
        "runtime_provenance_sha256": digest(runtime_info["provenance_path"]),
        "accepted_efi_sha256": EFI_SHA256,
        "accepted_dtb_sha256": DTB_SHA256,
        "stage1_config_sha256": digest(KERNEL_OUTPUT / ".config"),
        "stage2_config": str(final_config),
        "stage2_config_sha256": digest(final_config),
        "config_delta": config_delta,
        "module_inventory": stage["module_records"],
        "runtime_guard": runtime_info["guard"],
        "guard_helper": runtime_info["helper"],
        "early_modules": runtime_info["modules"],
        "expected_embedded_archive_entries": len(runtime_info["archive"]),
        "next_step": "Primary must apply stage2-finalization.config and relink Image before --verify-final.",
    }
    output = KERNEL_OUTPUT / "stage2-preparation-manifest.json"
    require(not output.exists(), f"Refusing to overwrite stage2 preparation manifest: {output}")
    write_json(output, preparation)
    print(json.dumps({"kind": preparation["kind"], "deployable": False,
                      "stage2_config": str(final_config), "config_delta": config_delta}, indent=2))


def verify(args: argparse.Namespace) -> None:
    snapshot = read_json(KERNEL_OUTPUT / "stage1-before-finalization.json",
                         "stage1 identity snapshot")
    require(snapshot.get("kind") == "r8q-diagnostic-stage1-identity/v1",
            "stage1 identity snapshot kind differs")
    require(snapshot.get("stage1_manifest_sha256") == digest(KERNEL_OUTPUT / "stage1-manifest.json"),
            "stage1 manifest changed after preparation")
    stage = stage1(KERNEL_OUTPUT / "stage1-before-finalization.config", False)
    require(snapshot.get("config_sha256") == digest(KERNEL_OUTPUT / "stage1-before-finalization.config"),
            "stage1 config snapshot differs")
    require(snapshot.get("image_sha256") == stage["manifest"].get("image_sha256") and
            snapshot.get("payload_image_sha256") == stage["manifest"].get("payload_image_sha256") and
            snapshot.get("dtb_sha256") == DTB_SHA256,
            "stage1 identity snapshot does not match its manifest")
    require(snapshot.get("module_records") == stage["module_records"],
            "stage1 module inventory changed after preparation")
    runtime = Path(args.runtime_initramfs).resolve()
    runtime_info = validate_runtime(runtime, stage,
                                    Path(args.runtime_provenance).resolve() if args.runtime_provenance else None)
    final_config = KERNEL_OUTPUT / "stage2-finalization.config"
    preparation = read_json(KERNEL_OUTPUT / "stage2-preparation-manifest.json",
                            "stage2 preparation manifest")
    require(preparation.get("kind") == "r8q-diagnostic-stage2-ready-nondeployable" and
            preparation.get("deployable") is False, "stage2 preparation state is unsafe")
    require(preparation.get("stage2_config_sha256") == digest(final_config),
            "stage2 config changed after preparation")
    config_delta = preparation.get("config_delta")
    require(isinstance(config_delta, dict), "stage2 config delta is missing")
    manifest = verify_final(stage, runtime, runtime_info, final_config, config_delta)
    print(json.dumps({"kind": manifest["kind"], "deployable": manifest["deployable"],
                      "embedded_archive_entries": manifest["embedded_archive_entries"],
                      "module_count": manifest["module_count"]}, indent=2))


def check_existing_mode(args: argparse.Namespace) -> None:
    snapshot = read_json(KERNEL_OUTPUT / "stage1-before-finalization.json",
                         "stage1 identity snapshot")
    require(snapshot.get("kind") == "r8q-diagnostic-stage1-identity/v1",
            "stage1 identity snapshot kind differs")
    require(snapshot.get("stage1_manifest_sha256") == digest(KERNEL_OUTPUT / "stage1-manifest.json"),
            "stage1 manifest changed after preparation")
    stage = stage1(KERNEL_OUTPUT / "stage1-before-finalization.config", False)
    require(snapshot.get("config_sha256") == digest(KERNEL_OUTPUT / "stage1-before-finalization.config") and
            snapshot.get("image_sha256") == stage["manifest"].get("image_sha256") and
            snapshot.get("payload_image_sha256") == stage["manifest"].get("payload_image_sha256") and
            snapshot.get("dtb_sha256") == DTB_SHA256 and
            snapshot.get("module_records") == stage["module_records"],
            "stage1 identity snapshot does not match its manifest")
    runtime = Path(args.runtime_initramfs).resolve()
    runtime_info = validate_runtime(runtime, stage,
                                    Path(args.runtime_provenance).resolve() if args.runtime_provenance else None)
    final_config = KERNEL_OUTPUT / "stage2-finalization.config"
    preparation = read_json(KERNEL_OUTPUT / "stage2-preparation-manifest.json",
                            "stage2 preparation manifest")
    require(preparation.get("kind") == "r8q-diagnostic-stage2-ready-nondeployable" and
            preparation.get("deployable") is False and
            preparation.get("stage2_config_sha256") == digest(final_config),
            "stage2 preparation state is unsafe")
    config_delta = preparation.get("config_delta")
    require(isinstance(config_delta, dict), "stage2 config delta is missing")
    candidate = check_existing(stage, runtime_info, final_config, config_delta)
    print(json.dumps({"kind": candidate["kind"], "deployable": candidate["deployable"],
                      "embedded_archive_entries": candidate["embedded_archive_entries"],
                      "module_count": candidate["module_count"],
                      "manifest_rewritten": False}, indent=2))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-initramfs", required=True,
                        help="runtime tree produced by prepare-r8q-diagnostic-runtime.py --initramfs")
    parser.add_argument("--runtime-provenance", help="optional runtime provenance.json path")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--prepare", action="store_true",
                       help="validate stage1/runtime and write stage2 config; never relinks")
    modes.add_argument("--verify-final", action="store_true",
                       help="verify an externally relinked Image and write the deployable manifest")
    modes.add_argument("--check-final-existing", action="store_true",
                       help="validate an existing final candidate without rewriting manifests")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require(args.runtime_initramfs, "runtime initramfs is required")
    if args.prepare:
        prepare(args)
    elif args.verify_final:
        verify(args)
    else:
        check_existing_mode(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
