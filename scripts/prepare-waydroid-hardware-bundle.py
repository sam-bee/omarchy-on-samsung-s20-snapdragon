#!/usr/bin/env python3
"""Prepare a guarded hardware-loader bundle for the encrypted Waydroid kernel.

This is an offline, fail-closed packager.  It accepts an explicitly supplied
public rootfs snapshot and a module catalogue produced by the matching kernel
build.  It never talks to a phone, changes an input tree, installs packages,
or writes outside the caller-selected preparation directory.

The output contains only the narrow hardware-loader closure: the route,
touch, battery, GPU, Wi-Fi, audio and Waydroid networking modules that
the reviewed services own, plus their catalogue dependencies.  It deliberately
does not copy all modules from a kernel build.  The accepted RTC2 helpers and
private modules remain byte-identical in the staged global namespace and are
also retained under ``rollback/`` for recovery.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"
TARGET_PARENT = OUT / "waydroid-encrypted-20261015"
TARGET_NAME = "hardware-preparation"

OLD_RELEASE = "7.1.2-r8q-rtc2"
RELEASE = "7.1.2-r8q-waydroid2"
VERMAGIC = f"{RELEASE} SMP preempt mod_unload aarch64"
PROFILE_REL = f"usr/local/lib/r8q-kernel-profiles/{RELEASE}/rootfs"
PROFILE_ABS = "/" + PROFILE_REL
EXPECTED_MACHINE_ID = "1290f2212bd743569044571db21a6c96"
EXPECTED_ROOT_UUID = "217b9308-40c7-4eb0-90a9-09ed4e233173"
# Accepted raw Samsung BOOT/UEFI partition identity.  CACHE EFI is the
# replaceable artifact; this value must survive the Waydroid2 transition.
EXPECTED_BOOT_SHA256 = "e08db773c7231bbeac02493fb07220fe176c20bebbf134470d0980c07f0ee725"
EXPECTED_SCREENLOCK_MANIFEST_SHA256 = (
    # The live accepted manifest is the 297-entry baseline.  The earlier
    # 294-entry hash belongs to the pre-final encrypted snapshot.
    "c157dc72e80c64799ca4161a00f96784874c87323ce2fb0af0f2ff8a472e2ae5"
)
EXPECTED_PUBLIC_SNAPSHOT = TARGET_PARENT / "phone-public-combined"
EXPECTED_PUBLIC_METADATA_SHA256 = "c9f06e873f9f35396b4c63ea3b3a32ae169d76eb195ab6eb94d257af03d80fe7"
EXPECTED_PUBLIC_METADATA_SCHEMA = "r8q-public-rootfs-snapshot/v1"
EXPECTED_PUBLIC_METADATA_FILES = 147
EXPECTED_SOURCE = OUT / "waydroid-kernel-20261013/source"
EXPECTED_SOURCE_PROOF_SHA256 = "04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b"

# The accepted initramfs retains these adapters across the encrypted-root
# handoff and unloads only the disposable touch controllers.
RETAINED_INITRAMFS_MARKER = "/run/r8q-encryption-adapter-handoff"
RETAINED_INITRAMFS_MODULES = ("gpi.ko", "i2c-qcom-geni.ko")
UNLOADED_INITRAMFS_MODULES = ("fts5cu56a.ko", "zinitix.ko")

AUDIO_MODULES = [
    ("qrtr", "qrtr.ko"),
    ("qrtr_smd", "qrtr-smd.ko"),
    ("qmi_helpers", "qmi_helpers.ko"),
    ("qcom_pdr_msg", "qcom_pdr_msg.ko"),
    ("pdr_interface", "pdr_interface.ko"),
    ("apr", "apr.ko"),
    ("qcom_glink_smem", "qcom_glink_smem.ko"),
    ("qcom_common", "qcom_common.ko"),
    ("qcom_pd_mapper", "qcom_pd_mapper.ko"),
    ("qcom_pil_info", "qcom_pil_info.ko"),
    ("mdt_loader", "mdt_loader.ko"),
    ("qcom_sysmon", "qcom_sysmon.ko"),
    ("qcom_q6v5", "qcom_q6v5.ko"),
    ("qcom_q6v5_pas", "qcom_q6v5_pas.ko"),
    ("soundcore", "soundcore.ko"),
    ("snd", "snd.ko"),
    ("snd_timer", "snd-timer.ko"),
    ("snd_pcm", "snd-pcm.ko"),
    ("snd_compress", "snd-compress.ko"),
    ("snd_pcm_dmaengine", "snd-pcm-dmaengine.ko"),
    ("snd_soc_core", "snd-soc-core.ko"),
    ("snd_soc_qcom_common", "snd-soc-qcom-common.ko"),
    ("snd_q6dsp_common", "snd-q6dsp-common.ko"),
    ("q6core", "q6core.ko"),
    ("q6afe", "q6afe.ko"),
    ("q6afe_dai", "q6afe-dai.ko"),
    ("q6adm", "q6adm.ko"),
    ("q6routing", "q6routing.ko"),
    ("q6asm", "q6asm.ko"),
    ("q6asm_dai", "q6asm-dai.ko"),
    ("cs_dsp", "cs_dsp.ko"),
    ("snd_soc_wm_adsp", "snd-soc-wm-adsp.ko"),
    ("snd_soc_cs35l41_lib", "snd-soc-cs35l41-lib.ko"),
    ("snd_soc_cs35l41", "snd-soc-cs35l41.ko"),
    ("snd_soc_cs35l41_i2c", "snd-soc-cs35l41-i2c.ko"),
    ("r8q_cs35l41_card", "r8q-cs35l41-card.ko"),
]
AUDIO_NAMES = tuple(name for name, _ in AUDIO_MODULES)
# These names are deliberately outside the generic module search tree.  The
# route wrapper owns the adapter copies under updates/r8q-usb-route, while the
# battery/audio loaders own their private payload namespaces.
PRIVATE_NAMES = (set(AUDIO_NAMES) |
                 {"gpi", "i2c_qcom_geni", "max17042_battery", "max77705", "max77705_charger"})

# The direct service requests are intentionally explicit.  Their dependency
# closure is resolved from the new catalogue, never inherited from old .ko
# files.  The audio and battery private objects are included as direct owners.
DIRECT_NAMES = {
    "gpi",
    "i2c_qcom_geni",
    "fts5cu56a",
    "zinitix",
    "msm",
    "sha256",
    "phy_qcom_qmp_pcie",
    "pwrseq_qcom_wcn",
    "pci_pwrctrl_pwrseq",
    "qrtr_mhi",
    "ath11k_pci",
    "max17042_battery",
    "max77705",
    "max77705_charger",
    *AUDIO_NAMES,
    # Waydroid's userspace network helper requests the bridge/veth/NAT path.
    "bridge",
    "veth",
    "overlay",
    "nf_tables",
    "nf_nat",
    "nft_chain_nat",
    "nft_masq",
}

# These are the explicit service requests observed in the accepted live
# loaders.  modprobe may add catalogue dependencies, but no service is
# allowed to invent a new direct owner during deployment.
SERVICE_LOAD_ORDERS = {
    "route": ["gpi", "i2c_qcom_geni"],
    "touch": ["fts5cu56a", "zinitix"],
    "gpu": ["msm"],
    "wifi": ["sha256", "phy_qcom_qmp_pcie", "pwrseq_qcom_wcn",
             "pci_pwrctrl_pwrseq", "qrtr_mhi", "ath11k_pci"],
    "battery": ["max17042_battery", "max77705", "max77705_charger"],
    "audio": list(AUDIO_NAMES),
    "waydroid-network": ["bridge", "veth", "overlay", "nf_tables", "nf_nat",
                         "nft_chain_nat", "nft_masq"],
}

PROFILE_DISPATCH = PROFILE_ABS + "/usr/local/sbin/r8q-kernel-profile-dispatch"

# The dispatch boundary is deliberately closed over these five services.  A
# suffix based allow-list would let a future, unrelated unit enter the new
# profile without review, while omitting one of these entries would leave a
# service calling the accepted RTC2 global helper after the EFI transition.
EXPECTED_DISPATCH_DROPINS = frozenset({
    "etc/systemd/system/r8q-hardware-prepare.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-battery.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-usb-gadget.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-audio-start.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-wifi-standby.service.d/90-r8q-waydroid2-dispatch.conf",
})

# These are metadata inputs from the matching kernel build.  depmod creates
# every generated index below in the curated staged tree; copying an old
# modules.*.bin would describe modules that are intentionally absent.
REQUIRED_BUILTIN_METADATA = ("modules.builtin", "modules.builtin.modinfo")
OPTIONAL_BUILTIN_METADATA = ("modules.builtin.ranges",)

PUBLIC_REQUIRED = (
    "etc/r8q-usb-route.env",
    "etc/r8q-encrypted-root.env",
    "etc/systemd/system/r8q-hardware-prepare.service",
    "etc/systemd/system/r8q-usb-route.service",
    "etc/systemd/system/r8q-usb-gadget.service",
    "etc/systemd/system/r8q-touch.service",
    "etc/systemd/system/r8q-battery.service",
    "etc/systemd/system/r8q-gpu.service",
    "etc/systemd/system/r8q-wifi.service",
    "etc/systemd/system/r8q-audio-start.service",
    "etc/systemd/system/r8q-wifi-standby.service",
    "etc/systemd/system/r8q-desktop.service",
    "etc/systemd/system/r8q-desktop.service.d/20-audio.conf",
    "etc/systemd/system/alsa-restore.service.d/50-r8q-protected-audio.conf",
    "etc/systemd/system/alsa-state.service.d/50-r8q-protected-audio.conf",
    "etc/systemd/system/NetworkManager.service.d/10-r8q-usb-route.conf",
    "etc/modprobe.d/r8q-usb-route.conf",
    "etc/modprobe.d/r8q-gpu.conf",
    "etc/modprobe.d/r8q-touch-blacklist.conf",
    "etc/modprobe.d/r8q-wifi-blacklist.conf",
    "usr/local/sbin/r8q-usb-route-up.sh",
    "usr/local/sbin/r8q-usb-route-ensure.sh",
    "usr/local/sbin/r8q-usb-route-witness.sh",
    "usr/local/sbin/r8q-usb-gadget-up.sh",
    "usr/local/sbin/r8q-root-device",
    "usr/local/sbin/r8q-touch-up.sh",
    "usr/local/sbin/r8q-battery-up.sh",
    "usr/local/sbin/r8q-wifi-up.sh",
    "usr/local/sbin/r8q-wifi-standby.py",
    # The standby candidate guard is retained as an inactive RTC2 helper.  It
    # is intentionally not dispatched to Waydroid2: its health proof embeds
    # the accepted RTC2 UTS/build identity and must fail closed on a new boot.
    "etc/systemd/system/r8q-standby-guard.service",
    "usr/local/sbin/r8q-standby-guard-20261011",
    "usr/local/sbin/r8q-standby-accept-20261011",
    "usr/local/libexec/r8q-standby-health-20261011.py",
    "usr/local/lib/r8q-usb-route/protocol-binding.env",
    "root/r8q-screen-lock-20261013.sha256",
    # These are source templates for the private namespace.  The modules
    # themselves come only from the new catalogue; old copies stay in the
    # rollback tree.
    "opt/r8q-audio/" + OLD_RELEASE + "/load-r8q-audio.sh",
    "opt/r8q-audio/" + OLD_RELEASE + "/init-r8q-audio.sh",
)


class PreparationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def regular(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PreparationError(f"{label} is unavailable: {path}: {exc}") from exc
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a regular non-symlink file: {path}")


def directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PreparationError(f"{label} is unavailable: {path}: {exc}") from exc
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a regular non-symlink directory: {path}")


def safe_rel(raw: str, label: str) -> str:
    path = Path(raw)
    require(not path.is_absolute() and ".." not in path.parts and "" not in path.parts,
            f"unsafe {label} path: {raw!r}")
    return path.as_posix()


def source_path(root: Path, relative: str, label: str) -> Path:
    relative = safe_rel(relative, label)
    path = root / relative
    require(path.parent == root / Path(relative).parent or root in path.parents,
            f"{label} escaped snapshot: {relative}")
    regular(path, label)
    return path


def copy_file(source: Path, destination: Path) -> None:
    regular(source, "copy source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode))


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    require(count == 1, f"{label}: expected one exact token, found {count}")
    return text.replace(old, new)


def replace_exact(text: str, old: str, new: str, count: int, label: str) -> str:
    """Replace a known number of literal guards, failing on drift."""
    actual = text.count(old)
    require(actual == count, f"{label}: expected {count} exact tokens, found {actual}")
    return text.replace(old, new)


def replace_line_value(text: str, key: str, value: str, label: str, quote: str = "") -> str:
    pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
    matches = list(pattern.finditer(text))
    require(len(matches) == 1, f"{label}: expected one {key} assignment")
    replacement = f"{key}={quote}{value}{quote}"
    return text[:matches[0].start()] + replacement + text[matches[0].end():]


def read_json(path: Path, label: str) -> Any:
    regular(path, label)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreparationError(f"cannot read {label}: {exc}") from exc


def load_inventory(catalogue: Path, inventory_path: Path | None) -> dict[str, dict[str, Any]]:
    directory(catalogue, "module catalogue")
    require(catalogue.name == RELEASE,
            f"module catalogue release is {catalogue.name!r}, expected {RELEASE!r}")
    if inventory_path is None:
        candidate = catalogue.parents[3] / "module-inventory.json"
        inventory_path = candidate
    rows = read_json(inventory_path, "module inventory")
    require(isinstance(rows, list) and rows, "module inventory is not a non-empty list")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        require(isinstance(row, dict), "module inventory contains a non-object row")
        name = row.get("name")
        relative = row.get("path")
        expected_hash = row.get("sha256")
        require(isinstance(name, str) and name and name not in result,
                f"module inventory name is missing or duplicated: {name!r}")
        require(isinstance(relative, str), f"module inventory path is missing: {name}")
        relative = safe_rel(relative, f"module {name}")
        require(isinstance(expected_hash, str) and re.fullmatch(r"[0-9a-f]{64}", expected_hash),
                f"module {name} hash is malformed")
        require(row.get("vermagic") == VERMAGIC,
                f"module {name} vermagic differs from {VERMAGIC!r}")
        deps = row.get("depends", [])
        require(isinstance(deps, list) and all(isinstance(item, str) for item in deps),
                f"module {name} dependencies are malformed")
        path = catalogue / "kernel" / relative
        regular(path, f"catalogue module {name}")
        actual = digest(path)
        require(actual == expected_hash,
                f"module {name} hash mismatch: {actual} != {expected_hash}")
        result[name] = {
            "name": name,
            "path": relative,
            "sha256": expected_hash,
            "bytes": path.stat().st_size,
            "vermagic": row["vermagic"],
            "depends": tuple(item.replace("-", "_") for item in deps),
        }
    for row in result.values():
        missing = sorted(set(row["depends"]) - result.keys())
        require(not missing,
                f"module {row['name']} has dependencies outside catalogue: {','.join(missing)}")
    return result


def closure(inventory: dict[str, dict[str, Any]]) -> tuple[list[str], list[str]]:
    missing = sorted(DIRECT_NAMES - inventory.keys())
    require(not missing, "matching module catalogue lacks required modules: " + ", ".join(missing))
    selected: set[str] = set()

    def visit(name: str) -> None:
        if name in selected:
            return
        selected.add(name)
        for dependency in inventory[name]["depends"]:
            visit(dependency)

    for name in sorted(DIRECT_NAMES):
        visit(name)
    # Stable topological order.  Dependencies are emitted before owners; the
    # direct adapter pair gets its reviewed GPI-before-GENI order explicitly.
    order: list[str] = []
    visiting: set[str] = set()

    def emit(name: str) -> None:
        if name in order:
            return
        require(name not in visiting, f"module dependency cycle at {name}")
        visiting.add(name)
        for dependency in sorted(inventory[name]["depends"]):
            if dependency in selected:
                emit(dependency)
        visiting.remove(name)
        order.append(name)

    for name in sorted(selected):
        emit(name)
    require(order.index("gpi") < order.index("i2c_qcom_geni"),
            "adapter load order does not retain GPI before GENI")
    return order, sorted(selected)


def validate_service_orders(selected: Iterable[str]) -> dict[str, list[str]]:
    selected_set = set(selected)
    for owner, names in SERVICE_LOAD_ORDERS.items():
        missing = sorted(set(names) - selected_set)
        require(not missing, f"{owner} load order is outside selected closure: {','.join(missing)}")
    return {owner: list(names) for owner, names in SERVICE_LOAD_ORDERS.items()}


def current_release(public_rootfs: Path) -> str:
    env = source_path(public_rootfs, "etc/r8q-usb-route.env", "USB route environment")
    values: dict[str, str] = {}
    for line in env.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        require("=" in line, f"malformed USB route environment line: {line!r}")
        key, value = line.split("=", 1)
        values[key] = value.strip().strip("'\"")
    require(values.get("EXPECTED_KERNEL") == OLD_RELEASE,
            "public snapshot is not the accepted RTC2 rootfs")
    require(values.get("EXPECTED_MACHINE_ID") == EXPECTED_MACHINE_ID,
            "machine-id identity differs from accepted encrypted root")
    require(values.get("EXPECTED_ROOT_UUID") == EXPECTED_ROOT_UUID,
            "root UUID differs from accepted encrypted root")
    require(values.get("EXPECTED_BOOT_SHA256") and
            re.fullmatch(r"[0-9a-f]{64}", values["EXPECTED_BOOT_SHA256"]),
            "public BOOT hash is missing or malformed")
    require(values["EXPECTED_BOOT_SHA256"] == EXPECTED_BOOT_SHA256,
            "public BOOT hash differs from the accepted raw Samsung BOOT/UEFI partition")
    return values["EXPECTED_BOOT_SHA256"]


def validate_snapshot(public_rootfs: Path) -> dict[str, str]:
    directory(public_rootfs, "public rootfs snapshot")
    boot_hash = current_release(public_rootfs)
    hashes: dict[str, str] = {}
    for relative in PUBLIC_REQUIRED:
        path = source_path(public_rootfs, relative, f"public snapshot {relative}")
        hashes[relative] = digest(path)
    lock_manifest = source_path(public_rootfs, "root/r8q-screen-lock-20261013.sha256",
                                "protected screen-lock manifest")
    require(digest(lock_manifest) == EXPECTED_SCREENLOCK_MANIFEST_SHA256,
            "protected screen-lock manifest hash differs from accepted baseline")
    # The public rootfs snapshot must expose module search/autoload policy.  A
    # missing policy tree would make it impossible to prove no new alias-driven
    # owner was introduced.
    for directory_name in ("etc/modprobe.d", "etc/modules-load.d", "etc/depmod.d"):
        policy_dir = public_rootfs / directory_name
        if not policy_dir.exists():
            # The accepted live snapshot has no modules-load.d or depmod.d;
            # absence is part of its policy and must not be filled in here.
            require(directory_name != "etc/modprobe.d",
                    f"required module policy directory is missing: {directory_name}")
            continue
        directory(policy_dir, f"module policy directory {directory_name}")
        for path in (public_rootfs / directory_name).rglob("*"):
            if path.is_dir():
                continue
            regular(path, f"module policy entry {path.relative_to(public_rootfs)}")
            hashes[path.relative_to(public_rootfs).as_posix()] = digest(path)
    # Record every accepted old module/private artifact that will be retained
    # in rollback.  This makes the exported path inventory complete without
    # allowing any of these old objects into the new generic search tree.
    for tree in (public_rootfs / "usr/lib/modules" / OLD_RELEASE,
                 public_rootfs / "opt/r8q-audio" / OLD_RELEASE,
                 public_rootfs / "usr/local/lib/r8q-battery" / OLD_RELEASE):
        if not tree.is_dir():
            continue
        for path in tree.rglob("*"):
            if path.is_dir():
                continue
            regular(path, f"accepted retained artifact {path.relative_to(public_rootfs)}")
            hashes[path.relative_to(public_rootfs).as_posix()] = digest(path)
    return {"boot_sha256": boot_hash, **hashes}


def validate_public_snapshot_metadata(public_rootfs: Path) -> dict[str, Any]:
    """Validate the phone-side metadata before consuming any snapshot bytes.

    The export is intentionally unprivileged on the laptop, so uid/gid values
    are evidence of the phone records and are not compared with the local
    extraction owner.  Mode, size, and content are compared against every
    recorded path.  The metadata file itself is the one permitted additional
    laptop-side file in the snapshot directory.
    """
    metadata_path = public_rootfs / "snapshot-metadata.json"
    regular(metadata_path, "public snapshot metadata")
    require(digest(metadata_path) == EXPECTED_PUBLIC_METADATA_SHA256,
            "public snapshot metadata hash differs from the reviewed combined export")
    metadata = read_json(metadata_path, "public snapshot metadata")
    require(isinstance(metadata, dict) and
            metadata.get("schema") == EXPECTED_PUBLIC_METADATA_SCHEMA,
            "public snapshot metadata schema is not the reviewed v1 schema")
    entries = metadata.get("files")
    require(isinstance(entries, dict) and len(entries) == EXPECTED_PUBLIC_METADATA_FILES,
            f"public snapshot metadata must contain exactly {EXPECTED_PUBLIC_METADATA_FILES} files")
    expected_paths: set[str] = set()
    for raw_path, record in entries.items():
        require(isinstance(raw_path, str) and raw_path.startswith("/"),
                f"public snapshot metadata path is not absolute: {raw_path!r}")
        relative = safe_rel(raw_path[1:], "public snapshot metadata path")
        require(relative and not relative.startswith("snapshot-metadata.json"),
                f"public snapshot metadata includes its own metadata file: {raw_path!r}")
        require(isinstance(record, dict), f"public snapshot metadata record is not an object: {raw_path}")
        require(type(record.get("bytes")) is int and record["bytes"] >= 0,
                f"public snapshot byte count is malformed: {raw_path}")
        require(type(record.get("uid")) is int and record["uid"] >= 0 and
                type(record.get("gid")) is int and record["gid"] >= 0,
                f"public snapshot phone ownership record is malformed: {raw_path}")
        require(record["uid"] == 0 and record["gid"] == 0,
                f"public snapshot phone ownership differs from the reviewed root-owned export: {raw_path}")
        require(type(record.get("mode")) is int and 0 <= record["mode"] <= 0o7777,
                f"public snapshot phone mode record is malformed: {raw_path}")
        expected_hash = record.get("sha256")
        require(isinstance(expected_hash, str) and re.fullmatch(r"[0-9a-f]{64}", expected_hash),
                f"public snapshot hash record is malformed: {raw_path}")
        path = source_path(public_rootfs, relative, f"public snapshot metadata {raw_path}")
        info = path.stat()
        require(info.st_size == record["bytes"],
                f"public snapshot size differs from metadata: {raw_path}")
        require(stat.S_IMODE(info.st_mode) == record["mode"],
                f"public snapshot mode differs from phone metadata: {raw_path}")
        require(digest(path) == expected_hash,
                f"public snapshot hash differs from metadata: {raw_path}")
        expected_paths.add(raw_path)
    actual_paths = {
        "/" + path.relative_to(public_rootfs).as_posix()
        for path in public_rootfs.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    require(actual_paths == expected_paths | {"/snapshot-metadata.json"},
            "public snapshot whole path set differs from its metadata (metadata is the only extra file)")
    return {"schema": metadata["schema"], "files": len(entries),
            "sha256": EXPECTED_PUBLIC_METADATA_SHA256,
            "path_records": {path: entries[path] for path in sorted(entries)}}


def validate_initramfs_marker(marker: Path) -> dict[str, Any]:
    regular(marker, "retained-GPI initramfs marker")
    text = marker.read_text(encoding="utf-8", errors="strict")
    require(RELEASE in text,
            f"initramfs marker does not identify the new kernel release {RELEASE}")
    require(RETAINED_INITRAMFS_MARKER in text,
            "initramfs does not name the retained adapter handoff marker")
    for module in RETAINED_INITRAMFS_MODULES:
        require(module in text, f"initramfs does not retain {module}")
    for module in UNLOADED_INITRAMFS_MODULES:
        require(module in text, f"initramfs does not record disposable {module} teardown")
    require("rmmod gpi" not in text and "rmmod i2c_qcom_geni" not in text,
            "initramfs attempts to unload a retained adapter")
    return {
        "path": marker.as_posix(),
        "sha256": digest(marker),
        "marker": RETAINED_INITRAMFS_MARKER,
        "retained_modules": list(RETAINED_INITRAMFS_MODULES),
        "unloaded_modules": list(UNLOADED_INITRAMFS_MODULES),
    }


def find_current_module_order(public_rootfs: Path) -> tuple[str, list[str]]:
    modules_root = public_rootfs / "usr/lib/modules" / OLD_RELEASE
    directory(modules_root, "accepted module tree")
    order_file = modules_root / "modules.order"
    dep_file = modules_root / "modules.dep"
    regular(order_file, "accepted modules.order")
    regular(dep_file, "accepted modules.dep")
    entries = [line.strip() for line in order_file.read_text().splitlines() if line.strip()]
    require(entries, "accepted modules.order is empty")
    for relative in entries:
        safe_rel(relative, "accepted module path")
    return OLD_RELEASE, entries


def write_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


def stage_snapshot_file(public_rootfs: Path, output_root: Path, relative: str) -> None:
    source = source_path(public_rootfs, relative, f"public snapshot {relative}")
    destination = output_root / relative
    copy_file(source, destination)


def copy_tree_exact(public_rootfs: Path, output_root: Path, relative_root: str,
                    label: str) -> list[str]:
    """Copy a complete accepted tree without following or creating links."""
    source_root = public_rootfs / safe_rel(relative_root, label)
    directory(source_root, label)
    copied: list[str] = []
    for source in sorted(source_root.rglob("*")):
        relative = source.relative_to(public_rootfs).as_posix()
        if source.is_dir():
            directory(source, f"{label} directory {relative}")
            continue
        regular(source, f"{label} file {relative}")
        copy_file(source, output_root / relative)
        copied.append(relative)
    require(copied, f"{label} is empty")
    return copied


def profile_path(relative: str) -> str:
    return f"{PROFILE_REL}/{safe_rel(relative, 'profile')}"


def profile_absolute(relative: str) -> str:
    return "/" + profile_path(relative)


def profile_dispatch_text() -> str:
    """Return the fixed-action, fixed-release dispatch wrapper.

    The wrapper has no path argument and accepts only reviewed action names.
    Release selection is based on the running kernel's exact uname -r value,
    which keeps the accepted RTC2 helpers usable during an EFI-only rollback.
    """
    targets = {
        "route": (
            "/usr/local/sbin/r8q-usb-route-up.sh",
            profile_absolute("usr/local/sbin/r8q-usb-route-up.sh"),
        ),
        "battery": (
            "/usr/local/sbin/r8q-battery-up.sh",
            profile_absolute("usr/local/sbin/r8q-battery-up.sh"),
        ),
        "gadget": (
            "/usr/local/sbin/r8q-usb-gadget-up.sh",
            profile_absolute("usr/local/sbin/r8q-usb-gadget-up.sh"),
        ),
        "audio-load": (
            f"/opt/r8q-audio/{OLD_RELEASE}/load-r8q-audio.sh",
            profile_absolute(f"opt/r8q-audio/{RELEASE}/load-r8q-audio.sh"),
        ),
        "audio-init": (
            f"/opt/r8q-audio/{OLD_RELEASE}/init-r8q-audio.sh",
            profile_absolute(f"opt/r8q-audio/{RELEASE}/init-r8q-audio.sh"),
        ),
        "wifi-standby": (
            "/usr/local/sbin/r8q-wifi-standby.py",
            profile_absolute("usr/local/sbin/r8q-wifi-standby.py"),
        ),
    }
    lines = [
        "#!/bin/sh",
        "set -eu",
        "test \"$#\" -ge 1 || { echo 'r8q-kernel-profile-dispatch: missing action' >&2; exit 2; }",
        "ACTION=$1",
        "shift",
        "case \"$ACTION\" in",
    ]
    for action, (old_target, new_target) in targets.items():
        lines.extend([
            f"    {action}) OLD_TARGET={old_target}; NEW_TARGET={new_target} ;;",
        ])
    lines.extend([
        "    *) echo \"r8q-kernel-profile-dispatch: unknown action: $ACTION\" >&2; exit 2 ;;",
        "esac",
        'case "$(/usr/bin/uname -r)" in',
        f"    {OLD_RELEASE}) TARGET=$OLD_TARGET ;;",
        f"    {RELEASE}) TARGET=$NEW_TARGET ;;",
        "    *) echo 'r8q-kernel-profile-dispatch: unsupported kernel release' >&2; exit 1 ;;",
        "esac",
        'test -f "$TARGET" && test ! -L "$TARGET" || { echo "r8q-kernel-profile-dispatch: target unavailable: $TARGET" >&2; exit 1; }',
        'case "$ACTION" in',
        "    wifi-standby) exec /usr/bin/python3 \"$TARGET\" \"$@\" ;;",
        '    *) exec "$TARGET" "$@" ;;',
        "esac",
        "",
    ])
    return "\n".join(lines)


def dispatch_dropins() -> dict[str, str]:
    """Return only the service overrides needed to call the dispatch wrapper."""
    dispatch = PROFILE_DISPATCH
    return {
        "etc/systemd/system/r8q-hardware-prepare.service.d/90-r8q-waydroid2-dispatch.conf":
            f"[Service]\nExecStart=\nExecStart={dispatch} route\n",
        "etc/systemd/system/r8q-battery.service.d/90-r8q-waydroid2-dispatch.conf":
            f"[Service]\nExecStart=\nExecStart={dispatch} battery\n",
        "etc/systemd/system/r8q-usb-gadget.service.d/90-r8q-waydroid2-dispatch.conf":
            f"[Service]\nExecStart=\nExecStart={dispatch} gadget\n",
        "etc/systemd/system/r8q-audio-start.service.d/90-r8q-waydroid2-dispatch.conf":
            f"[Service]\nExecStart=\nExecStart={dispatch} audio-load\n"
            "ExecStartPost=\n"
            f"ExecStartPost={dispatch} audio-init\n",
        "etc/systemd/system/r8q-wifi-standby.service.d/90-r8q-waydroid2-dispatch.conf":
            f"[Service]\nExecStart=\nExecStart={dispatch} wifi-standby\n"
            "ExecStopPost=\n"
            f"ExecStopPost={dispatch} wifi-standby --restore-off\n",
    }


def parse_service_modules(public_rootfs: Path) -> set[str]:
    names: set[str] = set()
    for relative in PUBLIC_REQUIRED:
        if not relative.endswith((".service", ".conf", ".sh")):
            continue
        path = public_rootfs / relative
        if not path.is_file() or path.is_symlink():
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        # Read only command-shaped service entries.  Searching arbitrary prose
        # would mistake diagnostics such as ``modprobe failed`` for module
        # requests and could either widen or spuriously reject the closure.
        command_pattern = re.compile(
            r"^\s*(?:ExecStart(?:Pre|Post)?=)?(?:[^\s=]*/)?"
            r"(?:modprobe|insmod)\s+(?:--[^\s]+\s+)*([A-Za-z0-9_.-]+)"
        )
        for line in text.splitlines():
            line = line.split("#", 1)[0]
            match = command_pattern.match(line)
            if match:
                names.add(match.group(1).replace("-", "_"))
    # The parser only observes explicit command entries.  The fixed
    # DIRECT_NAMES allowlist below remains the authority for the curated
    # closure and rejects any unreviewed request.
    return names


def private_module_path(name: str) -> str:
    return dict(AUDIO_MODULES).get(name, name + ".ko")


def make_replacement_files(public_rootfs: Path, output_root: Path,
                           inventory: dict[str, dict[str, Any]],
                           boot_hash: str) -> dict[str, Any]:
    """Retain RTC2 globals and add an isolated Waydroid2 profile.

    The accepted global helpers, units, policy, and private namespaces are
    copied byte-for-byte.  Waydroid2 variants live below PROFILE_REL and are
    selected only through the fixed dispatch/drop-ins emitted here.
    """
    changes: dict[str, dict[str, Any]] = {}
    retained_paths: set[str] = set()
    for relative in PUBLIC_REQUIRED:
        stage_snapshot_file(public_rootfs, output_root, relative)
        retained_paths.add(relative)
    # Copy every module policy file exactly.  These are required to keep
    # alias-driven udev/systemd loading behind the reviewed service graph.
    for directory_name in ("etc/modprobe.d", "etc/modules-load.d", "etc/depmod.d"):
        policy_dir = public_rootfs / directory_name
        if not policy_dir.is_dir():
            continue
        directory(policy_dir, f"module policy directory {directory_name}")
        for source in sorted(policy_dir.rglob("*")):
            if source.is_dir():
                directory(source, f"module policy directory {source}")
                continue
            regular(source, f"module policy entry {source}")
            relative = source.relative_to(public_rootfs).as_posix()
            stage_snapshot_file(public_rootfs, output_root, relative)
            retained_paths.add(relative)

    # These namespaces are part of the rollback boundary and remain present
    # in the staged rootfs under their accepted release names.
    for relative_root, label in (
        (f"usr/lib/modules/{OLD_RELEASE}", "accepted RTC2 module namespace"),
        (f"opt/r8q-audio/{OLD_RELEASE}", "accepted RTC2 audio namespace"),
        (f"usr/local/lib/r8q-battery/{OLD_RELEASE}", "accepted RTC2 battery namespace"),
    ):
        retained_paths.update(copy_tree_exact(public_rootfs, output_root, relative_root, label))

    # Profile route environment and helper.  The raw BOOT partition remains
    # pinned to the accepted value because CACHE EFI is the replaced artifact.
    old_env_rel = "etc/r8q-usb-route.env"
    old_env = (public_rootfs / old_env_rel).read_text(encoding="utf-8")
    require(f"EXPECTED_BOOT_SHA256={boot_hash}" in old_env,
            "source route environment BOOT hash changed while reading snapshot")
    profile_env_rel = profile_path(old_env_rel)
    profile_env = old_env
    profile_env = replace_line_value(profile_env, "EXPECTED_KERNEL", RELEASE, profile_env_rel)
    profile_env = replace_line_value(profile_env, "EXPECTED_VERMAGIC", VERMAGIC, profile_env_rel, "'")
    profile_env = replace_line_value(profile_env, "EXPECTED_GPI_SHA256", inventory["gpi"]["sha256"], profile_env_rel)
    profile_env = replace_line_value(profile_env, "EXPECTED_GENI_SHA256", inventory["i2c_qcom_geni"]["sha256"], profile_env_rel)

    old_route = (public_rootfs / "usr/local/sbin/r8q-usb-route-up.sh").read_text(encoding="utf-8")
    profile_route = old_route
    profile_route = replace_once(profile_route, "ENV_FILE=/etc/r8q-usb-route.env",
                                 f"ENV_FILE={profile_absolute(old_env_rel)}", "profile route ENV_FILE")
    profile_route = replace_once(profile_route,
                                 "HELPER_PATH=/usr/local/sbin/r8q-usb-route-ensure.sh",
                                 f"HELPER_PATH={profile_absolute('usr/local/sbin/r8q-usb-route-ensure.sh')}",
                                 "profile route helper path")
    profile_route = replace_once(profile_route,
                                 "ROOT_DEVICE_HELPER=/usr/local/sbin/r8q-root-device",
                                 f"ROOT_DEVICE_HELPER={profile_absolute('usr/local/sbin/r8q-root-device')}",
                                 "profile route root-device path")
    profile_route = replace_once(profile_route,
                                 "PROTOCOL_PATH=/usr/local/lib/r8q-usb-route/protocol-binding.env",
                                 f"PROTOCOL_PATH={profile_absolute('usr/local/lib/r8q-usb-route/protocol-binding.env')}",
                                 "profile route protocol path")

    old_ensure = (public_rootfs / "usr/local/sbin/r8q-usb-route-ensure.sh").read_text(encoding="utf-8")
    profile_ensure = old_ensure
    profile_ensure = replace_once(profile_ensure, "PROTOCOL_DIR=/usr/local/lib/r8q-usb-route",
                                  f"PROTOCOL_DIR={profile_absolute('usr/local/lib/r8q-usb-route')}",
                                  "profile route protocol directory")
    profile_ensure = replace_once(profile_ensure, "CONFIG_FILE=/etc/r8q-usb-route.env",
                                  f"CONFIG_FILE={profile_absolute(old_env_rel)}",
                                  "profile route config path")
    profile_ensure = replace_once(profile_ensure,
                                  "ROOT_DEVICE_HELPER=/usr/local/sbin/r8q-root-device",
                                  f"ROOT_DEVICE_HELPER={profile_absolute('usr/local/sbin/r8q-root-device')}",
                                  "profile route root-device path")

    profile_protocol_rel = profile_path("usr/local/lib/r8q-usb-route/protocol-binding.env")
    copy_file(public_rootfs / "usr/local/lib/r8q-usb-route/protocol-binding.env",
              output_root / profile_protocol_rel)
    copy_file(public_rootfs / "usr/local/sbin/r8q-root-device",
              output_root / profile_path("usr/local/sbin/r8q-root-device"))
    write_text(output_root / profile_path("usr/local/sbin/r8q-usb-route-ensure.sh"),
               profile_ensure, stat.S_IMODE((public_rootfs / "usr/local/sbin/r8q-usb-route-ensure.sh").stat().st_mode))
    profile_helper_hash = digest(output_root / profile_path("usr/local/sbin/r8q-usb-route-ensure.sh"))
    profile_env = replace_line_value(profile_env, "EXPECTED_HELPER_SHA256", profile_helper_hash,
                                     profile_env_rel)
    write_text(output_root / profile_env_rel, profile_env,
               stat.S_IMODE((public_rootfs / old_env_rel).stat().st_mode))
    write_text(output_root / profile_path("usr/local/sbin/r8q-usb-route-up.sh"),
               profile_route, stat.S_IMODE((public_rootfs / "usr/local/sbin/r8q-usb-route-up.sh").stat().st_mode))

    # Battery, gadget, Wi-Fi, and audio helpers are copied into the same
    # profile.  Every substitution is an exact token/guard replacement.
    old_battery_rel = "usr/local/sbin/r8q-battery-up.sh"
    profile_battery_rel = profile_path(old_battery_rel)
    battery = (public_rootfs / old_battery_rel).read_text(encoding="utf-8")
    battery = replace_line_value(battery, "EXPECTED_KERNEL", RELEASE, profile_battery_rel)
    battery = replace_line_value(battery, "EXPECTED_VERMAGIC", VERMAGIC, profile_battery_rel, "'")
    battery = replace_line_value(battery, "PAYLOAD_DIR",
                                 profile_absolute(f"usr/local/lib/r8q-battery/{RELEASE}"), profile_battery_rel)
    for key, name in (("MAX17042_SHA256", "max17042_battery"),
                      ("MAX77705_SHA256", "max77705"),
                      ("MAX77705_CHARGER_SHA256", "max77705_charger")):
        battery = replace_line_value(battery, key, inventory[name]["sha256"], profile_battery_rel)
    battery = replace_exact(battery, "/etc/r8q-usb-route.env", profile_absolute(old_env_rel), 3,
                            "profile battery route environment")
    write_text(output_root / profile_battery_rel, battery,
               stat.S_IMODE((public_rootfs / old_battery_rel).stat().st_mode))

    old_gadget_rel = "usr/local/sbin/r8q-usb-gadget-up.sh"
    gadget = replace_once((public_rootfs / old_gadget_rel).read_text(encoding="utf-8"),
                          OLD_RELEASE, RELEASE, "profile gadget release guard")
    write_text(output_root / profile_path(old_gadget_rel), gadget,
               stat.S_IMODE((public_rootfs / old_gadget_rel).stat().st_mode))

    old_wifi_rel = "usr/local/sbin/r8q-wifi-standby.py"
    wifi = replace_once((public_rootfs / old_wifi_rel).read_text(encoding="utf-8"),
                        OLD_RELEASE, RELEASE, "profile Wi-Fi standby release guard")
    write_text(output_root / profile_path(old_wifi_rel), wifi,
               stat.S_IMODE((public_rootfs / old_wifi_rel).stat().st_mode))

    for name in ("load-r8q-audio.sh", "init-r8q-audio.sh"):
        source_rel = f"opt/r8q-audio/{OLD_RELEASE}/{name}"
        destination_rel = profile_path(f"opt/r8q-audio/{RELEASE}/{name}")
        audio = (public_rootfs / source_rel).read_text(encoding="utf-8")
        audio = replace_once(audio, f"/opt/r8q-audio/{OLD_RELEASE}",
                             profile_absolute(f"opt/r8q-audio/{RELEASE}"),
                             f"profile audio {name} root")
        if name == "load-r8q-audio.sh":
            audio = replace_line_value(audio, "EXPECTED_RELEASE", RELEASE, destination_rel)
            audio = replace_line_value(audio, "EXPECTED_VERMAGIC", VERMAGIC, destination_rel, "'")
        else:
            audio = replace_once(audio, " = " + OLD_RELEASE + " ||",
                                 " = " + RELEASE + " ||", f"profile audio {name} kernel guard")
        write_text(output_root / destination_rel, audio,
                   stat.S_IMODE((public_rootfs / source_rel).stat().st_mode))

    profile_dispatch_rel = profile_path("usr/local/sbin/r8q-kernel-profile-dispatch")
    write_text(output_root / profile_dispatch_rel, profile_dispatch_text(), 0o755)
    for relative, text in dispatch_dropins().items():
        write_text(output_root / relative, text, 0o644)

    # Record every profile addition and dispatch override with its source hash
    # where there is a source.  New generated files use null before-hashes.
    source_for_profile = {
        profile_env_rel: old_env_rel,
        profile_path("usr/local/sbin/r8q-usb-route-up.sh"): "usr/local/sbin/r8q-usb-route-up.sh",
        profile_path("usr/local/sbin/r8q-usb-route-ensure.sh"): "usr/local/sbin/r8q-usb-route-ensure.sh",
        profile_path("usr/local/sbin/r8q-root-device"): "usr/local/sbin/r8q-root-device",
        profile_protocol_rel: "usr/local/lib/r8q-usb-route/protocol-binding.env",
        profile_battery_rel: old_battery_rel,
        profile_path(old_gadget_rel): old_gadget_rel,
        profile_path(old_wifi_rel): old_wifi_rel,
        profile_path(f"opt/r8q-audio/{RELEASE}/load-r8q-audio.sh"):
            f"opt/r8q-audio/{OLD_RELEASE}/load-r8q-audio.sh",
        profile_path(f"opt/r8q-audio/{RELEASE}/init-r8q-audio.sh"):
            f"opt/r8q-audio/{OLD_RELEASE}/init-r8q-audio.sh",
    }
    for relative, source_relative in source_for_profile.items():
        destination = output_root / relative
        changes[relative] = {"before": digest(public_rootfs / source_relative),
                             "after": digest(destination), "action": "add-profile"}
    changes[profile_dispatch_rel] = {"before": None,
                                     "after": digest(output_root / profile_dispatch_rel),
                                     "action": "add-dispatch"}
    for relative in dispatch_dropins():
        changes[relative] = {"before": None, "after": digest(output_root / relative),
                             "action": "add-dispatch-dropin"}

    # The retained screen-lock manifest is copied into a clearly named proof
    # area; it remains a protected baseline and is never rewritten.
    lock_src = public_rootfs / "root/r8q-screen-lock-20261013.sha256"
    # Keep the proof copy beside rootfs/.  It is bundle evidence for the
    # deployment audit, not a phone rootfs path and must never enter the
    # deployable new_rootfs_paths inventory.
    lock_dst = output_root.parent / "protected-baseline/root/r8q-screen-lock-20261013.sha256"
    copy_file(lock_src, lock_dst)
    changes["protected-baseline/root/r8q-screen-lock-20261013.sha256"] = {
        "before": digest(lock_src), "after": digest(lock_dst), "action": "retain-exact"
    }

    retained: dict[str, dict[str, Any]] = {}
    for relative in sorted(retained_paths):
        source = public_rootfs / relative
        destination = output_root / relative
        before, after = digest(source), digest(destination)
        require(before == after, f"accepted global path changed while staging: {relative}")
        retained[relative] = {"sha256": before, "after_sha256": after, "action": "retain-exact"}
    return {"changes": changes, "retained": retained}


def module_index_records(module_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(module_root.iterdir()):
        if not path.is_file() or path.is_symlink() or not path.name.startswith("modules."):
            continue
        records.append({"path": path.name, "bytes": path.stat().st_size, "sha256": digest(path)})
    require(records, "depmod emitted no module index files")
    names = {row["path"] for row in records}
    for name in ("modules.order", "modules.dep", "modules.dep.bin", "modules.alias",
                 "modules.alias.bin", "modules.builtin", "modules.builtin.modinfo",
                 "modules.builtin.bin", "modules.builtin.alias.bin", "modules.symbols",
                 "modules.symbols.bin", "modules.softdep", "modules.weakdep", "modules.devname"):
        require(name in names, f"depmod did not emit required module index {name}")
    return records


def run_depmod(staged_rootfs: Path, module_root: Path) -> list[dict[str, Any]]:
    """Build indexes for the staged usr-merged tree, then bind their hashes."""
    depmod = shutil.which("depmod") or "/usr/sbin/depmod"
    regular(Path(depmod).resolve(), "depmod executable")
    command = [depmod, "-b", str(staged_rootfs), "-m", "/usr/lib/modules", RELEASE]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    diagnostics = (result.stdout + result.stderr).strip()
    require(result.returncode == 0,
            f"depmod failed for curated {RELEASE} tree: {diagnostics or 'no diagnostics'}")
    bad_lines = [line for line in diagnostics.splitlines()
                 if re.search(r"(?:ERROR|FATAL|WARNING|unknown symbol|not found|missing)", line, re.I)]
    require(not bad_lines, "depmod reported a missing curated dependency: " + " | ".join(bad_lines))
    return module_index_records(module_root)


def audit_modprobe_plans(staged_rootfs: Path, module_root: Path,
                         direct_names: Iterable[str]) -> list[dict[str, Any]]:
    """Resolve generic service requests against only the staged module tree."""
    modprobe = shutil.which("modprobe") or "/usr/sbin/modprobe"
    regular(Path(modprobe).resolve(), "modprobe executable")
    # kmod uses /lib/modules even on usr-merged systems.  This compatibility
    # link exists only while the read-only audit runs and is removed before the
    # bundle is hashed or returned.
    compatibility = staged_rootfs / "lib"
    require(not compatibility.exists() and not compatibility.is_symlink(),
            "staged rootfs unexpectedly already contains /lib for modprobe audit")
    compatibility.mkdir()
    modules_link = compatibility / "modules"
    modules_link.symlink_to(Path("../usr/lib/modules"))
    plans: list[dict[str, Any]] = []
    try:
        for name in sorted(set(direct_names)):
            command = [modprobe, "-d", str(staged_rootfs), "-S", RELEASE,
                       "--show-depends", name]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            diagnostics = (result.stdout + result.stderr).strip()
            require(result.returncode == 0,
                    f"modprobe plan failed for {name}: {diagnostics or 'no diagnostics'}")
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            require(lines, f"modprobe plan for {name} is empty; curated module is not loadable")
            resolved_paths: list[str] = []
            for line in lines:
                fields = shlex.split(line)
                require(fields and fields[0] == "insmod" and len(fields) >= 2,
                        f"modprobe plan for {name} contains an unreviewed command: {line!r}")
                candidate = Path(fields[1]).resolve()
                require(module_root.resolve() in candidate.parents,
                        f"modprobe plan for {name} escapes staged module tree: {candidate}")
                regular(candidate, f"modprobe plan module {name}")
                resolved_paths.append(candidate.relative_to(staged_rootfs.resolve()).as_posix())
            plans.append({"module": name, "command": ["modprobe", "-d", "<staged-rootfs>",
                                                        "-S", RELEASE, "--show-depends", name],
                          "modules": resolved_paths})
    finally:
        modules_link.unlink()
        compatibility.rmdir()
    return plans


def stage_modules(public_rootfs: Path, catalogue: Path, output_root: Path,
                  inventory: dict[str, dict[str, Any]], selected: list[str], order: list[str]) -> dict[str, Any]:
    module_root = output_root / "rootfs/usr/lib/modules" / RELEASE
    module_rows: list[dict[str, Any]] = []
    # Promote shared private dependencies to a fixed point.  The loop is
    # order-independent: a private A may depend on B even if B precedes A in
    # modules.order.  Route and battery objects remain private-managed.
    managed_private = {"gpi", "i2c_qcom_geni", "max17042_battery", "max77705",
                       "max77705_charger"}
    generic_names = set(order) - PRIVATE_NAMES
    promotion_rounds = 0
    while True:
        promoted = {
            name for name in ((set(order) & PRIVATE_NAMES) - managed_private)
            if name not in generic_names and
            any(name in inventory[owner]["depends"] for owner in generic_names)
        }
        if not promoted:
            break
        generic_names.update(promoted)
        promotion_rounds += 1
    for name in sorted(managed_private):
        require(not any(name in inventory[owner]["depends"] for owner in generic_names),
                f"generic closure depends on private-managed module {name}")
    generic_order = [name for name in order if name in generic_names]
    for name in generic_order:
        row = inventory[name]
        destination_relative = f"kernel/{row['path']}"
        source = catalogue / "kernel" / row["path"]
        destination = module_root / destination_relative
        copy_file(source, destination)
        module_rows.append({**row, "destination": destination_relative, "namespace": "generic"})
    # Route's wrapper deliberately uses this private path and audits the exact
    # two adapter files.  Keeping it separate from the generic kernel tree
    # prevents a generic alias from owning these drivers early.
    for name, relative in (("gpi", "updates/r8q-usb-route/gpi.ko"),
                           ("i2c_qcom_geni", "updates/r8q-usb-route/i2c-qcom-geni.ko")):
        copy_file(catalogue / "kernel" / inventory[name]["path"], module_root / relative)
        module_rows.append({**inventory[name], "destination": relative, "namespace": "route-private"})
    selected_order = [f"kernel/{inventory[name]['path']}" for name in generic_order]
    route_order = ["updates/r8q-usb-route/gpi.ko", "updates/r8q-usb-route/i2c-qcom-geni.ko"]
    write_text(module_root / "modules.order", "\n".join(selected_order + route_order) + "\n")

    # Built-in metadata comes from this exact candidate.  Never copy generated
    # modules.*.bin indexes from the full 1576-module catalogue: depmod below
    # must describe only the curated closure staged above.
    metadata_sources: list[str] = []
    for filename in REQUIRED_BUILTIN_METADATA:
        source = catalogue / filename
        regular(source, f"matching catalogue metadata {filename}")
        copy_file(source, module_root / filename)
        metadata_sources.append(filename)
    for filename in OPTIONAL_BUILTIN_METADATA:
        source = catalogue / filename
        if source.exists():
            regular(source, f"matching catalogue metadata {filename}")
            copy_file(source, module_root / filename)
            metadata_sources.append(filename)
    index_files = run_depmod(output_root / "rootfs", module_root)
    generic_direct = {
        name for names in SERVICE_LOAD_ORDERS.values() for name in names
        if name not in PRIVATE_NAMES
    }
    generic_direct.update(("gpi", "i2c_qcom_geni"))
    modprobe_plans = audit_modprobe_plans(output_root / "rootfs", module_root, generic_direct)

    # Private battery namespace is outside the generic modprobe search tree by
    # design.  It is under the release profile so the accepted RTC2 global
    # battery payload remains byte-identical and rollback-safe.
    battery_dir = output_root / "rootfs" / PROFILE_REL / "usr/local/lib/r8q-battery" / RELEASE
    for name in ("max17042_battery", "max77705", "max77705_charger"):
        copy_file(catalogue / "kernel" / inventory[name]["path"], battery_dir / (name + ".ko"))

    audio_dir = output_root / "rootfs" / PROFILE_REL / "opt/r8q-audio" / RELEASE
    audio_rows = []
    for index, (name, private) in enumerate(AUDIO_MODULES, 1):
        row = inventory[name]
        copy_file(catalogue / "kernel" / row["path"], audio_dir / private)
        audio_rows.append((index, name, row["path"], row["sha256"], private,
                           "reviewed exact-release audio closure"))
    import csv
    with (audio_dir / "module-load-order.tsv").open("w", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(("order", "module", "source_artifact", "sha256", "private_artifact", "why"))
        writer.writerows(audio_rows)
    with (audio_dir / "module-hashes.sha256").open("w") as stream:
        for _, _, _, sha, private, _ in audio_rows:
            stream.write(f"{sha}  {private}\n")

    return {
        "release": RELEASE,
        "vermagic": VERMAGIC,
        "selected_count": len(selected),
        "selected_names": selected,
        "load_order": order,
        "generic_names": generic_order,
        "private_only_names": sorted(set(selected) - generic_names),
        "promotion_policy": "fixed-point; route GPI/GENI and three MAX battery modules remain private-managed",
        "promotion_fixed_point": True,
        "promotion_rounds": promotion_rounds,
        "promoted_private_names": sorted(set(generic_order) & PRIVATE_NAMES),
        "route_order": ["gpi", "i2c_qcom_geni"],
        "battery_private_names": ["max17042_battery", "max77705", "max77705_charger"],
        "battery_private_root": f"/{PROFILE_REL}/usr/local/lib/r8q-battery/{RELEASE}",
        "audio_names": list(AUDIO_NAMES),
        "audio_private_root": f"/{PROFILE_REL}/opt/r8q-audio/{RELEASE}",
        "module_rows": module_rows,
        "builtin_metadata_sources": metadata_sources,
        "module_index_files": index_files,
        "modprobe_plans": modprobe_plans,
        "depmod_command": ["depmod", "-b", "<staged-rootfs>", "-m", "/usr/lib/modules", RELEASE],
    }


def stage_rollback(public_rootfs: Path, output_root: Path, old_release: str) -> dict[str, Any]:
    rollback_root = output_root / "rollback"
    rollback_paths = list(PUBLIC_REQUIRED)
    old_modules = public_rootfs / "usr/lib/modules" / old_release
    directory(old_modules, f"rollback module namespace {old_modules}")
    # Keep the accepted module namespace intact for the reboot rollback
    # boundary.  The new rootfs receives only the curated closure; this copy
    # is isolated under rollback/ and is never an autoload source.
    for path in sorted(old_modules.rglob("*")):
        if path.is_dir():
            continue
        regular(path, f"rollback module file {path}")
        rollback_paths.append(path.relative_to(public_rootfs).as_posix())
    for directory_name in ("etc/modprobe.d", "etc/modules-load.d", "etc/depmod.d"):
        policy_dir = public_rootfs / directory_name
        if not policy_dir.is_dir():
            continue
        for path in sorted(policy_dir.rglob("*")):
            if path.is_dir():
                continue
            regular(path, f"rollback policy file {path}")
            rollback_paths.append(path.relative_to(public_rootfs).as_posix())
    old_audio = public_rootfs / "opt/r8q-audio" / old_release
    old_battery = public_rootfs / "usr/local/lib/r8q-battery" / old_release
    for path in (old_audio, old_battery):
        directory(path, f"rollback private namespace {path}")
    for name in ("max17042_battery.ko", "max77705.ko", "max77705_charger.ko"):
        regular(old_battery / name, f"rollback battery module {name}")
    for path in sorted(old_audio.rglob("*")):
        if path.is_dir():
            continue
        regular(path, f"rollback audio file {path}")
        rollback_paths.append(path.relative_to(public_rootfs).as_posix())
    for path in sorted(old_battery.rglob("*")):
        if path.is_dir():
            continue
        regular(path, f"rollback battery file {path}")
        rollback_paths.append(path.relative_to(public_rootfs).as_posix())
    for relative in sorted(set(rollback_paths)):
        destination = rollback_root / "rootfs" / relative
        copy_file(public_rootfs / relative, destination)
    return {
        "release": old_release,
        "rootfs_files": sorted(set(rollback_paths)),
        "purpose": "accepted encrypted-root rollback helpers and private module bundles",
    }


def write_manifest(output: Path, payload: dict[str, Any]) -> None:
    files = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name not in {"bundle-manifest.json", "package-manifest.sha256"}:
            files.append({"path": path.relative_to(output).as_posix(), "bytes": path.stat().st_size, "sha256": digest(path)})
    payload["files"] = files
    (output / "bundle-manifest.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    with (output / "package-manifest.sha256").open("w") as stream:
        for row in files:
            stream.write(f"{row['sha256']}  {row['path']}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-rootfs", type=Path, required=True)
    parser.add_argument("--modules-catalogue", type=Path, required=True)
    parser.add_argument("--module-inventory", type=Path)
    parser.add_argument("--kernel-manifest", type=Path, required=True)
    parser.add_argument("--initramfs-marker", type=Path, required=True,
                        help="init script/manifest proving retained GPI/GENI handoff")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    public_rootfs = args.public_rootfs.expanduser().resolve()
    catalogue = args.modules_catalogue.expanduser().resolve()
    kernel_manifest_path = args.kernel_manifest.expanduser().resolve()
    marker = args.initramfs_marker.expanduser().resolve()
    output = args.output.expanduser().resolve()
    require(output == TARGET_PARENT / TARGET_NAME,
            f"output must be exactly {TARGET_PARENT / TARGET_NAME}")
    require(not output.exists(), f"output already exists; choose a fresh preparation: {output}")
    require(public_rootfs == EXPECTED_PUBLIC_SNAPSHOT,
            f"public rootfs must be the reviewed combined snapshot: {EXPECTED_PUBLIC_SNAPSHOT}")
    for label, path in (("public rootfs", public_rootfs), ("module catalogue", catalogue),
                        ("kernel manifest", kernel_manifest_path), ("initramfs marker", marker)):
        require(path != output and output not in path.parents and path not in output.parents,
                f"output overlaps {label}")
    kernel_manifest = read_json(kernel_manifest_path, "kernel candidate manifest")
    require(isinstance(kernel_manifest, dict), "kernel candidate manifest is not an object")
    require(kernel_manifest.get("kind") == "r8q-encrypted-waydroid-kernel-candidate",
            "kernel candidate manifest kind is not the completed encrypted Waydroid candidate")
    require(kernel_manifest.get("kernel_release") == RELEASE,
            "kernel candidate manifest release is not the requested encrypted Waydroid release")
    require(kernel_manifest.get("root_state") == "encrypted",
            "kernel candidate manifest root state is not encrypted")
    require(kernel_manifest.get("stage2_complete") is True,
            "kernel candidate manifest is not stage2_complete")
    source_value = kernel_manifest.get("source")
    require(isinstance(source_value, str) and Path(source_value).expanduser().resolve() == EXPECTED_SOURCE,
            "kernel candidate source is not the pinned complete source tree")
    directory(EXPECTED_SOURCE, "pinned complete kernel source")
    source_proof = kernel_manifest.get("complete_source_proof")
    require(isinstance(source_proof, dict) and
            source_proof.get("sha256") == EXPECTED_SOURCE_PROOF_SHA256,
            "kernel candidate complete-source proof is not the pinned proof")
    expected_catalogue = kernel_manifest_path.parent / "modules/lib/modules" / RELEASE
    require(catalogue == expected_catalogue,
            f"module catalogue must be the candidate's exact {expected_catalogue}")
    files = kernel_manifest.get("files", {})
    require(isinstance(files, dict) and files, "kernel candidate manifest file map is missing")
    boot_candidates = [key for key in files
                       if isinstance(key, str) and
                       (key == "payload/BOOTAA64.EFI" or key.endswith("/payload/BOOTAA64.EFI"))]
    require(len(boot_candidates) == 1 and boot_candidates[0] == "payload/BOOTAA64.EFI",
            "kernel candidate manifest must contain one relative payload/BOOTAA64.EFI entry")
    boot_entry = files["payload/BOOTAA64.EFI"]
    boot_hash = boot_entry.get("sha256") if isinstance(boot_entry, dict) else None
    require(isinstance(boot_hash, str) and re.fullmatch(r"[0-9a-f]{64}", boot_hash),
            "kernel candidate BOOTAA64.EFI hash is missing")
    boot_path = kernel_manifest_path.parent / "payload/BOOTAA64.EFI"
    regular(boot_path, "kernel candidate BOOTAA64.EFI")
    require(digest(boot_path) == boot_hash,
            "kernel candidate BOOTAA64.EFI hash is not bound to the actual payload")
    require(isinstance(boot_entry, dict) and type(boot_entry.get("bytes")) is int and
            boot_entry["bytes"] == boot_path.stat().st_size,
            "kernel candidate BOOTAA64.EFI size is not bound to the actual payload")
    inventory_path = (args.module_inventory.expanduser().resolve() if args.module_inventory
                      else kernel_manifest_path.parent / "module-inventory.json")
    inventory_entry = files.get("module-inventory.json")
    require(isinstance(inventory_entry, dict),
            "kernel candidate manifest lacks module-inventory.json binding")
    regular(inventory_path, "module inventory input")
    require(type(inventory_entry.get("bytes")) is int and
            inventory_entry["bytes"] == inventory_path.stat().st_size and
            inventory_entry.get("sha256") == digest(inventory_path),
            "supplied module inventory does not match the completed candidate manifest")
    public_metadata = validate_public_snapshot_metadata(public_rootfs)
    snapshot_hashes = validate_snapshot(public_rootfs)
    old_release, current_order = find_current_module_order(public_rootfs)
    initramfs = validate_initramfs_marker(marker)
    inventory = load_inventory(catalogue, inventory_path)
    service_names = parse_service_modules(public_rootfs)
    # Keep the direct set fixed.  Service parsing is diagnostic only and is
    # recorded below so a new unreviewed modprobe request cannot silently widen
    # the closure.
    unexpected = sorted(service_names - DIRECT_NAMES)
    require(not unexpected, "service requests modules outside reviewed closure: " + ", ".join(unexpected))
    load_order, selected = closure(inventory)
    service_orders = validate_service_orders(selected)

    output.mkdir(parents=True)
    try:
        rootfs = output / "rootfs"
        replacement = make_replacement_files(public_rootfs, rootfs, inventory, snapshot_hashes["boot_sha256"])
        changes = replacement["changes"]
        retained = replacement["retained"]
        generated_dropins = {path for path, row in changes.items()
                             if row["action"] == "add-dispatch-dropin"}
        require(generated_dropins == EXPECTED_DISPATCH_DROPINS,
                "dispatch drop-in set differs from the exact reviewed five-service boundary")
        module_selection = stage_modules(public_rootfs, catalogue, output, inventory, selected, load_order)
        rollback = stage_rollback(public_rootfs, output, old_release)
        write_text(output / "public-snapshot-paths.txt",
                   "\n".join(sorted(path for path in snapshot_hashes if path != "boot_sha256")) + "\n")
        write_text(output / "module-load-order.txt", "\n".join(load_order) + "\n")
        write_text(output / "module-load-orders.json",
                   json.dumps(service_orders, indent=2, sort_keys=True) + "\n")
        new_rootfs_paths = sorted(
            path.relative_to(output / "rootfs").as_posix()
            for path in (output / "rootfs").rglob("*")
            if path.is_file()
            and path.relative_to(output / "rootfs").as_posix() not in retained
        )
        allowed_changes = {
            "retained_global_paths": retained,
            "profile_paths": sorted(path for path in new_rootfs_paths
                                     if path.startswith(PROFILE_REL + "/")),
            "dispatch_dropin_paths": sorted(path for path, row in changes.items()
                                             if row["action"] == "add-dispatch-dropin"),
            "dispatch_dropin_paths_exact": sorted(EXPECTED_DISPATCH_DROPINS),
            "replacement_paths": sorted(changes),
            "new_rootfs_paths": new_rootfs_paths,
            "rollback_rootfs_paths": rollback["rootfs_files"],
            "policy": "Accepted RTC2 global paths are retained byte-for-byte. Only profile additions, dispatch drop-ins, curated new modules, and the isolated rollback tree may be consumed by deployment; raw BOOT hash and protected baseline remain exact.",
        }
        write_text(output / "allowed-change-inventory.json",
                   json.dumps(allowed_changes, indent=2, sort_keys=True) + "\n")
        payload = {
            "schema": "r8q-waydroid-hardware-preparation/v1",
            "release": RELEASE,
            "vermagic": VERMAGIC,
            "root_state": "encrypted",
            "phone_operations": False,
            "public_snapshot": str(public_rootfs),
            "public_snapshot_metadata": public_metadata,
            "public_snapshot_sha256": {key: value for key, value in sorted(snapshot_hashes.items())},
            "accepted_root_identity": {"machine_id": EXPECTED_MACHINE_ID, "root_uuid": EXPECTED_ROOT_UUID,
                                        "boot_partition_sha256": snapshot_hashes["boot_sha256"]},
            "kernel_manifest": {"path": str(kernel_manifest_path), "sha256": digest(kernel_manifest_path)},
            "module_inventory": {"path": str(inventory_path), "bytes": inventory_path.stat().st_size,
                                 "sha256": digest(inventory_path),
                                 "candidate_manifest_sha256": digest(kernel_manifest_path)},
            "candidate_source": {"path": str(EXPECTED_SOURCE),
                                  "complete_source_proof_sha256": EXPECTED_SOURCE_PROOF_SHA256},
            "boot_artifact": {"manifest_path": boot_candidates[0], "sha256": boot_entry["sha256"]},
            "initramfs_handoff": initramfs,
            "protected_baseline": {"path": "root/r8q-screen-lock-20261013.sha256",
                                    "sha256": EXPECTED_SCREENLOCK_MANIFEST_SHA256, "entries": 297,
                                    "policy": "retain exact; deployment must recheck all final 297 protected hashes"},
            "current_module_order": {"release": old_release, "entries": len(current_order),
                                     "sha256": digest(public_rootfs / "usr/lib/modules" / old_release / "modules.order")},
            "service_module_requests": sorted(DIRECT_NAMES),
            "service_load_orders": service_orders,
            "selected_module_count": len(selected),
            "module_selection": module_selection,
            "dispatch_dropins": sorted(EXPECTED_DISPATCH_DROPINS),
            "rollback": rollback,
            "change_inventory": changes,
            "retained_global_paths": retained,
            "allowed_change_inventory": allowed_changes,
            "guards": {
                "route": ["EXPECTED_KERNEL", "EXPECTED_VERMAGIC", "EXPECTED_GPI_SHA256", "EXPECTED_GENI_SHA256",
                           "EXPECTED_HELPER_SHA256", "EXPECTED_PROTOCOL_SHA256", "EXPECTED_BOOT_SHA256-preserved"],
                "battery": ["release", "vermagic", "three private module SHA256 values", "outside /usr/lib/modules"],
                "audio": ["release", "vermagic", "36-row module table/hash file", f"private /{PROFILE_REL}/opt namespace"],
                "dispatch": ["strict uname -r", OLD_RELEASE, RELEASE, "fixed action allowlist",
                              "exactly five reviewed service drop-ins", "no arbitrary target paths"],
                "standby": ["RTC2 guard/health helper retained exact", "no new-kernel dispatch", "embedded UTS/build proof fails closed"],
                "autoload": ["copied modprobe.d", "copied modules-load.d", "copied depmod.d",
                              "offline depmod indexes with bound SHA256", "generic direct modprobe plans audited",
                              "curated closure only"],
                "initramfs": [RETAINED_INITRAMFS_MARKER, *RETAINED_INITRAMFS_MODULES, *UNLOADED_INITRAMFS_MODULES],
                "protected_baseline": ["exact manifest hash", "no protected baseline rewrite"],
            },
        }
        write_manifest(output, payload)
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    print(json.dumps({"result": "PASS", "output": str(output), "release": RELEASE,
                      "selected_modules": len(selected), "rollback_files": len(rollback["rootfs_files"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreparationError as exc:
        print(f"prepare-waydroid-hardware-bundle: {exc}", file=sys.stderr)
        raise SystemExit(1)
