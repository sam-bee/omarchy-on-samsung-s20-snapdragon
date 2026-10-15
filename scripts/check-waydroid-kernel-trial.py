#!/usr/bin/env python3
"""Prepare an offline, read-only Waydroid2 post-boot acceptance probe.

``--prepare`` is intentionally refused until the final encrypted kernel
candidate and deployment plan exist.  It then emits one self-contained Python
probe that is safe to copy to the phone.  The probe only reads the installed
system, creates disposable objects below unique ``/run`` directories, and
cleans up its binderfs/network/overlay fixtures before returning.  It never
restarts a service, unloads a driver, writes CACHE/EFI, or touches userdata.

This file is an offline generator.  It does not connect to a phone and does
not run the generated probe on the laptop.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import tempfile
from typing import Any


REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"
TARGET = OUT / "waydroid-encrypted-20261015"
CANDIDATE = TARGET / "kernel"
HARDWARE = TARGET / "hardware-preparation"
DEPLOYMENT = TARGET / "deployment-preparation"
DEFAULT_OUTPUT = TARGET / "acceptance-preparation"
BINDER_HEADER = REPO / "out/waydroid-kernel-20261013/source/include/uapi/linux/android/binderfs.h"
BINDER_UAPI_HEADER = REPO / "out/waydroid-kernel-20261013/source/include/uapi/linux/android/binder.h"
BINDER_HEADER_SHA256 = "7c467a4a4c8d9b7a0946f670d68899e9ed31ba6ec2e26cb52a16cf4afbda3351"
BINDER_UAPI_HEADER_SHA256 = "4e6e262ea59bfdb5100cacc8d1014fc65979c4087cd0890e45d6156bdd3271a5"
PUBLIC_SNAPSHOT = TARGET / "phone-public-combined"
PROTECTED_MANIFEST = PUBLIC_SNAPSHOT / "root/r8q-screen-lock-20261013.sha256"
PROTECTED_METADATA = TARGET / "protected-baseline-metadata.json"

RELEASE = "7.1.2-r8q-waydroid2"
OLD_RELEASE = "7.1.2-r8q-rtc2"
OLD_BOOT_ID = "9296267e-edba-4c8f-8923-8f0395c52bfd"
MACHINE_ID = "1290f2212bd743569044571db21a6c96"
ROOT_DEVICE = "/dev/sda36"
ROOT_UUID = "217b9308-40c7-4eb0-90a9-09ed4e233173"
ROOT_PARTUUID = "1b81e7e6-f50d-419b-a739-2aeef8da3335"
LUKS_UUID = "b9081516-2446-4086-87c1-76d2127493ec"
OLD_EFI_SHA256 = "730627f49b8d41b9bdc6ef7931fe94911636003c61596c84d769d532ad27c49b"
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
OLD_MANIFEST_SHA256 = "c157dc72e80c64799ca4161a00f96784874c87323ce2fb0af0f2ff8a472e2ae5"
OLD_MANIFEST_ENTRIES = 297
PROTECTED_METADATA_SHA256 = "ada81d61b271b96f35681f07e42fb56907332ee4e93a04ccee0cc715cbbd3d1c"
COMPLETE_SOURCE_PROOF_SHA256 = "04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b"
BASELINE_WARNING_RECEIPT = TARGET / "baseline-kernel-warnings01.txt"
BASELINE_WARNING_RECEIPT_SHA256 = "ef4560474128f7461da5ffd7cbf8997a7222724ecdedc362681bdba4c93a9ffd"
KNOWN_BASELINE_WARNING = "rtc-pm8xxx c440000.spmi:pmic@0:rtc@6000: probe with driver rtc-pm8xxx failed with error -2"

EARLY_MODULES = {
    "gpi.ko": "gpi",
    "i2c-qcom-geni.ko": "i2c_qcom_geni",
    "fts5cu56a.ko": "fts5cu56a",
    "zinitix.ko": "zinitix",
}
REQUIRED_UNITS = (
    "r8q-hardware-prepare.service",
    "r8q-usb-gadget.service",
    "r8q-gpu.service",
    "r8q-touch.service",
    "r8q-wifi.service",
    "r8q-battery.service",
    "r8q-audio-start.service",
    "r8q-desktop.service",
    "r8q-wifi-standby.service",
)
DROPINS = {
    "etc/systemd/system/r8q-hardware-prepare.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-battery.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-usb-gadget.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-audio-start.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-wifi-standby.service.d/90-r8q-waydroid2-dispatch.conf",
}
TRANSIENT_PATHS = (
    "/run/r8q-encryption-passphrase",
    "/run/r8q-unl0kr.stderr",
    "/run/r8q-udevd.log",
    "/run/r8q-unl0kr.log",
    "/run/r8q-cryptsetup.log",
    "/run/r8q-unlock.fifo",
)
NETWORK_MODULES = ("bridge", "veth", "overlay", "nf_tables", "nf_nat", "nft_chain_nat", "nft_masq")
MODULE_ERROR_RE = re.compile(
    r"(?i)(unknown symbol|invalid module format|vermagic|module[^\n]*(?:fail|error)|"
    r"failed[^\n]*(?:module|firmware|probe)|probe[^\n]*failed)"
)
SENSITIVE_RE = re.compile(r"(?i)(passphrase|password|secret|token|private.?key|credential)[^\s]*")


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


def regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PreparationError(f"{label} is unavailable: {path}") from exc
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a regular non-symlink file: {path}")
    return info


def read_json(path: Path, label: str) -> dict[str, Any]:
    regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreparationError(f"{label} is not valid JSON: {path}") from exc
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def safe_relative(value: str, label: str) -> str:
    parsed = Path(value)
    require(value and not parsed.is_absolute() and "\\" not in value and
            all(part not in ("", ".", "..") for part in parsed.parts) and
            parsed.as_posix() == value, f"unsafe {label}: {value!r}")
    return value


def validate_hash_entry(root: Path, files: dict[str, Any], relative: str, label: str) -> dict[str, Any]:
    entry = files.get(relative)
    require(isinstance(entry, dict), f"{label} is absent from candidate manifest: {relative}")
    path = root / relative
    info = regular(path, label)
    expected = entry.get("sha256")
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
            f"{label} hash is malformed: {relative}")
    require(type(entry.get("bytes")) is int and entry["bytes"] == info.st_size,
            f"{label} size is not bound: {relative}")
    require(digest(path) == expected, f"{label} hash is not bound: {relative}")
    return entry


def binder_contract() -> dict[str, Any]:
    regular(BINDER_HEADER, "pinned binderfs header")
    text = BINDER_HEADER.read_text(encoding="utf-8")
    require(digest(BINDER_HEADER) == BINDER_HEADER_SHA256, "pinned binderfs header hash changed")
    require("#define BINDERFS_MAX_NAME 255" in text,
            "pinned binderfs header changed BINDERFS_MAX_NAME")
    require("char name[BINDERFS_MAX_NAME + 1];" in text and
            "__u32 major;" in text and "__u32 minor;" in text,
            "pinned binderfs_device layout is not recognised")
    require("#define BINDER_CTL_ADD _IOWR('b', 1, struct binderfs_device)" in text,
            "pinned binderfs ioctl definition changed")
    # Linux _IOC on arm64 uses DIRBITS=2, TYPEBITS=8, SIZEBITS=14 and
    # NRBITS=8.  binderfs_device is 256 bytes of name plus two u32 fields.
    struct_size = 256 + 4 + 4
    ioctl = (3 << 30) | (struct_size << 16) | (ord("b") << 8) | 1
    require(ioctl == 0xC1086201, "unexpected BINDER_CTL_ADD encoding")
    regular(BINDER_UAPI_HEADER, "pinned binder UAPI header")
    binder_text = BINDER_UAPI_HEADER.read_text(encoding="utf-8")
    require(digest(BINDER_UAPI_HEADER) == BINDER_UAPI_HEADER_SHA256,
            "pinned binder UAPI header hash changed")
    require("struct binder_version" in binder_text and "__s32       protocol_version;" in binder_text,
            "pinned binder_version layout is not recognised")
    require("#define BINDER_CURRENT_PROTOCOL_VERSION 8" in binder_text,
            "pinned binder UAPI is not the 64-bit protocol-8 contract")
    require("BINDER_VERSION" in binder_text and "_IOWR('b', 9, struct binder_version)" in binder_text,
            "pinned BINDER_VERSION definition changed")
    version_size = 4
    version_ioctl = (3 << 30) | (version_size << 16) | (ord("b") << 8) | 9
    require(version_ioctl == 0xC0046209, "unexpected BINDER_VERSION encoding")
    return {
        "path": str(BINDER_HEADER),
        "sha256": digest(BINDER_HEADER),
        "schema": "linux-uapi-binderfs/v1",
        "max_name": 255,
        "struct_size": struct_size,
        "name_offset": 0,
        "major_offset": 256,
        "minor_offset": 260,
        "binder_ctl_add": ioctl,
        "binder_header_path": str(BINDER_UAPI_HEADER),
        "binder_header_sha256": digest(BINDER_UAPI_HEADER),
        "binder_version": version_ioctl,
        "binder_version_size": version_size,
        "binder_protocol_version": 8,
    }


def protected_metadata_contract() -> dict[str, Any]:
    metadata = read_json(PROTECTED_METADATA, "protected baseline metadata")
    require(digest(PROTECTED_METADATA) == PROTECTED_METADATA_SHA256,
            "protected baseline metadata hash changed")
    require(metadata.get("schema") == "r8q-protected-baseline-metadata/v1" and
            metadata.get("boot_id") == OLD_BOOT_ID and
            metadata.get("manifest_sha256") == OLD_MANIFEST_SHA256,
            "protected baseline metadata identity changed")
    files = metadata.get("files")
    require(isinstance(files, dict) and len(files) == OLD_MANIFEST_ENTRIES,
            "protected baseline metadata does not contain all 297 entries")
    entries: dict[str, Any] = {}
    alarm_owned = 0
    for raw_path, row in sorted(files.items()):
        require(isinstance(raw_path, str) and raw_path.startswith("/") and
                "\\x00" not in raw_path and not Path(raw_path).is_symlink(),
                "protected baseline metadata path is malformed")
        require(isinstance(row, dict) and row.get("kind") == "file" and
                type(row.get("target_uid")) is int and type(row.get("target_gid")) is int and
                type(row.get("target_mode")) is int and 0 <= row["target_mode"] <= 0o777 and
                row["target_mode"] & 0o7000 == 0 and
                row.get("uid") == row.get("target_uid") and row.get("gid") == row.get("target_gid") and
                row.get("mode") == row.get("target_mode"),
                "protected baseline ownership/mode metadata is malformed: " + raw_path)
        if row["target_uid"] == 1000 and row["target_gid"] == 1000:
            alarm_owned += 1
        entries[raw_path] = {
            "kind": "file", "uid": row["target_uid"], "gid": row["target_gid"],
            "mode": row["target_mode"],
        }
    require(alarm_owned == 16, "protected baseline alarm-owned file count changed")
    return {
        "path": str(PROTECTED_METADATA), "sha256": PROTECTED_METADATA_SHA256,
        "schema": metadata["schema"], "boot_id": OLD_BOOT_ID,
        "manifest_sha256": OLD_MANIFEST_SHA256, "entries": entries,
        "entry_count": OLD_MANIFEST_ENTRIES, "alarm_owned_entries": alarm_owned,
    }


def protected_manifest_contract() -> dict[str, Any]:
    info = regular(PROTECTED_MANIFEST, "accepted protected manifest")
    data = PROTECTED_MANIFEST.read_bytes()
    require(digest(PROTECTED_MANIFEST) == OLD_MANIFEST_SHA256,
            "accepted protected manifest hash changed")
    require(len(data.splitlines()) == OLD_MANIFEST_ENTRIES,
            "accepted protected manifest does not contain the original 297 entries")
    metadata = protected_metadata_contract()
    return {
        "path": str(PROTECTED_MANIFEST),
        "sha256": OLD_MANIFEST_SHA256,
        "bytes": info.st_size,
        "entries": OLD_MANIFEST_ENTRIES,
        "prefix_sha256": hashlib.sha256(data).hexdigest(),
        "metadata": metadata,
    }


def baseline_warning_contract() -> dict[str, Any]:
    regular(BASELINE_WARNING_RECEIPT, "accepted kernel warning receipt")
    require(digest(BASELINE_WARNING_RECEIPT) == BASELINE_WARNING_RECEIPT_SHA256,
            "accepted kernel warning receipt hash changed")
    receipt = read_json(BASELINE_WARNING_RECEIPT, "accepted kernel warning receipt")
    require(receipt.get("boot_id") == OLD_BOOT_ID and receipt.get("kernel") == OLD_RELEASE and
            receipt.get("count") == 1 and receipt.get("warning_lines") == [KNOWN_BASELINE_WARNING],
            "accepted kernel warning receipt changed")
    return {"path": str(BASELINE_WARNING_RECEIPT), "sha256": BASELINE_WARNING_RECEIPT_SHA256,
            "line": KNOWN_BASELINE_WARNING, "boot_id": OLD_BOOT_ID, "kernel": OLD_RELEASE}


def candidate_contract() -> tuple[dict[str, Any], dict[str, Any]]:
    path = CANDIDATE / "candidate-manifest.json"
    manifest = read_json(path, "final encrypted Waydroid candidate manifest")
    require(manifest.get("kind") == "r8q-encrypted-waydroid-kernel-candidate",
            "candidate is not the final encrypted Waydroid candidate")
    require(manifest.get("kernel_release") == RELEASE and manifest.get("root_state") == "encrypted",
            "candidate release/root state is not Waydroid2 encrypted")
    require(manifest.get("stage2_complete") is True and manifest.get("installed") is False and
            manifest.get("boot_tested") is False and manifest.get("deployment_prepared") is False,
            "candidate is not an uninstalled stage2-complete artifact")
    require(manifest.get("source") == str(REPO / "out/waydroid-kernel-20261013/source"),
            "candidate source is not the pinned private source")
    source_proof = manifest.get("complete_source_proof")
    require(isinstance(source_proof, dict) and
            source_proof.get("sha256") == COMPLETE_SOURCE_PROOF_SHA256,
            "candidate complete-source proof is not the pinned proof")
    require(manifest.get("shared_source_references") == 0,
            "candidate contains shared source references")
    require(re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("source_sha256", ""))) is not None,
            "candidate source proof hash is missing")
    files = manifest.get("files")
    require(isinstance(files, dict), "candidate artifact map is missing")
    boot = validate_hash_entry(CANDIDATE, files, "payload/BOOTAA64.EFI", "candidate EFI")
    require(boot["sha256"] != OLD_EFI_SHA256, "candidate EFI still equals accepted RTC2 EFI")
    dtb = validate_hash_entry(CANDIDATE, files, "payload/R8Q-RTC.DTB", "candidate DTB")
    require(dtb["sha256"] == DTB_SHA256, "candidate DTB differs from the accepted active DTB")
    validate_hash_entry(CANDIDATE, files, "module-inventory.json", "candidate module inventory")
    validate_hash_entry(CANDIDATE, files, "embedded-initramfs-manifest.json", "candidate embedded manifest")
    early = manifest.get("early_modules", {}).get("modules")
    require(isinstance(early, dict), "candidate early module receipt is missing")
    early_receipt: dict[str, Any] = {}
    for filename, module_name in EARLY_MODULES.items():
        row = early.get(filename)
        require(isinstance(row, dict), f"candidate early module receipt is missing: {filename}")
        sha = row.get("sha256")
        require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha),
                f"candidate early module hash is malformed: {filename}")
        require(type(row.get("bytes")) is int and row["bytes"] > 0,
                f"candidate early module size is malformed: {filename}")
        require(str(row.get("vermagic", "")).startswith(RELEASE + " "),
                f"candidate early module vermagic is not Waydroid2: {filename}")
        early_receipt[filename] = {
            "module": module_name,
            "sha256": sha,
            "bytes": row["bytes"],
            "vermagic": row["vermagic"],
        }
    return manifest, {
        "path": str(path),
        "source_path": str(REPO / "out/waydroid-kernel-20261013/source"),
        "complete_source_proof_sha256": COMPLETE_SOURCE_PROOF_SHA256,
        "sha256": digest(path),
        "release": RELEASE,
        "efi": {"sha256": boot["sha256"], "bytes": boot["bytes"]},
        "dtb": {"sha256": dtb["sha256"], "bytes": dtb["bytes"]},
        "early_modules": early_receipt,
    }


def deployment_contract(candidate: dict[str, Any]) -> dict[str, Any]:
    plan_path = DEPLOYMENT / "deployment-plan.json"
    hardware_path = HARDWARE / "bundle-manifest.json"
    plan = read_json(plan_path, "Waydroid deployment plan")
    hardware = read_json(hardware_path, "Waydroid hardware bundle manifest")
    require(plan.get("schema") == "r8q-waydroid-kernel-trial-plan/v1" and
            plan.get("release") == RELEASE and plan.get("stage2_complete") is True,
            "deployment plan is not the final Waydroid2 plan")
    require(hardware.get("schema") == "r8q-waydroid-hardware-preparation/v1" and
            hardware.get("release") == RELEASE and hardware.get("root_state") == "encrypted" and
            hardware.get("phone_operations") is False,
            "hardware bundle is not the final offline Waydroid2 bundle")
    candidate_source = hardware.get("candidate_source", {})
    require(candidate_source.get("path") == str(REPO / "out/waydroid-kernel-20261013/source") and
            candidate_source.get("complete_source_proof_sha256") == COMPLETE_SOURCE_PROOF_SHA256,
            "hardware bundle source path/proof is not pinned")
    kernel_proof = hardware.get("kernel_manifest", {})
    require(Path(str(kernel_proof.get("path", ""))).resolve() == CANDIDATE / "candidate-manifest.json" and
            kernel_proof.get("sha256") == digest(CANDIDATE / "candidate-manifest.json"),
            "hardware bundle is not bound to the final candidate")
    baseline = hardware.get("protected_baseline", {})
    require(baseline.get("path") == "root/r8q-screen-lock-20261013.sha256" and
            baseline.get("entries") == OLD_MANIFEST_ENTRIES and
            baseline.get("sha256") == OLD_MANIFEST_SHA256,
            "hardware bundle protected baseline changed")
    require(plan.get("phone_operations") is False and plan.get("formatting") is False and
            plan.get("raw_userdata_writes") is False and plan.get("root_device_changed") is False and
            plan.get("luks_changed") is False and plan.get("service_restarts") is False and
            plan.get("gpu_unload") is False,
            "deployment plan contains a forbidden phone operation")
    require(plan.get("candidate_manifest_sha256") == digest(CANDIDATE / "candidate-manifest.json"),
            "deployment plan is not bound to the final candidate manifest")
    require(plan.get("hardware_manifest_sha256") == digest(hardware_path),
            "deployment plan is not bound to the hardware bundle manifest")
    candidate_files = candidate.get("files", {})
    require(plan.get("new_efi", {}).get("sha256") == candidate_files.get("payload/BOOTAA64.EFI", {}).get("sha256"),
            "deployment plan EFI hash differs from the final candidate")
    protected = plan.get("protected_manifest")
    require(isinstance(protected, dict) and protected.get("old_sha256") == OLD_MANIFEST_SHA256 and
            protected.get("old_entries") == OLD_MANIFEST_ENTRIES and protected.get("append_only") is True,
            "deployment plan protected-manifest contract changed")
    rows = plan.get("new_rootfs_files")
    require(isinstance(rows, list) and rows, "deployment plan has no rootfs additions")
    seen: set[str] = set()
    additions: list[dict[str, Any]] = []
    allowed_prefixes = (
        f"usr/local/lib/r8q-kernel-profiles/{RELEASE}/",
        f"usr/lib/modules/{RELEASE}/",
        "etc/systemd/system/",
    )
    for row in rows:
        require(isinstance(row, dict), "deployment rootfs row is not an object")
        relative = safe_relative(row.get("path", ""), "deployment rootfs path")
        require(relative not in seen, f"deployment rootfs path is duplicated: {relative}")
        seen.add(relative)
        require(relative.startswith(allowed_prefixes) and
                (relative.startswith(allowed_prefixes[0]) or relative.startswith(allowed_prefixes[1]) or
                 relative.endswith("90-r8q-waydroid2-dispatch.conf")),
                f"deployment rootfs path is outside the reviewed additions: {relative}")
        sha = row.get("sha256")
        require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha),
                f"deployment rootfs hash is malformed: {relative}")
        require(type(row.get("bytes")) is int and row["bytes"] >= 0 and
                type(row.get("mode")) is int and 0 <= row["mode"] <= 0o777 and
                row["mode"] & 0o7000 == 0,
                f"deployment rootfs metadata is malformed: {relative}")
        additions.append({"path": relative, "sha256": sha, "bytes": row["bytes"], "mode": row["mode"]})
    hardware_paths = hardware.get("allowed_change_inventory", {}).get("new_rootfs_paths")
    require(isinstance(hardware_paths, list) and set(hardware_paths) == seen,
            "deployment rows differ from hardware bundle path inventory")
    dispatch_paths = hardware.get("allowed_change_inventory", {}).get("dispatch_dropin_paths")
    require(isinstance(dispatch_paths, list) and set(dispatch_paths) == DROPINS,
            "hardware bundle dispatch drop-in inventory is not exactly the reviewed five")
    require({path for path in seen if path.startswith("etc/systemd/system/") and
             path.endswith("90-r8q-waydroid2-dispatch.conf")} == DROPINS,
            "deployment plan dispatch drop-in set is not exactly the reviewed five")
    archive = plan.get("archive", {})
    archive_path = Path(str(archive.get("path", "")))
    require(archive_path == DEPLOYMENT / "waydroid2-public-transaction.tar",
            "deployment archive path changed")
    archive_info = regular(archive_path, "deployment archive")
    require(type(archive.get("bytes")) is int and archive["bytes"] == archive_info.st_size and
            archive.get("sha256") == digest(archive_path),
            "deployment archive hash/size changed")
    hardware_boot = hardware.get("boot_artifact", {})
    require(hardware_boot.get("sha256") == candidate_files.get("payload/BOOTAA64.EFI", {}).get("sha256"),
            "hardware bundle EFI hash differs from the final candidate")
    old_prefix = PROTECTED_MANIFEST.read_bytes()
    require(digest(PROTECTED_MANIFEST) == OLD_MANIFEST_SHA256 and
            len(old_prefix.splitlines()) == OLD_MANIFEST_ENTRIES,
            "protected manifest source baseline changed")
    protected_metadata = protected_metadata_contract()
    return {
        "path": str(plan_path),
        "sha256": digest(plan_path),
        "hardware_manifest": {"path": str(hardware_path), "sha256": digest(hardware_path)},
        "archive": {"path": str(archive_path), "sha256": archive["sha256"], "bytes": archive_info.st_size},
        "protected_manifest": {
            "path": "/root/r8q-screen-lock-20261013.sha256",
            "old_sha256": OLD_MANIFEST_SHA256,
            "old_entries": OLD_MANIFEST_ENTRIES,
            "old_bytes": len(old_prefix),
            "old_prefix_sha256": hashlib.sha256(old_prefix).hexdigest(),
            "append_only": True,
            "metadata": protected_metadata,
            "additions": additions,
        },
        "rootfs_addition_count": len(additions),
    }


def probe_source(config: dict[str, Any]) -> str:
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return f'''#!/usr/bin/env python3
"""Read-only post-boot acceptance probe generated from final Waydroid2 pins."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

CONFIG = json.loads(r"""{encoded}""")
RELEASE = CONFIG["release"]
OLD_BOOT_ID = CONFIG["old_boot_id"]
MACHINE_ID = CONFIG["machine_id"]
ROOT_UUID = CONFIG["root_uuid"]
ROOT_PARTUUID = CONFIG["root_partuuid"]
ROOT_DEVICE = CONFIG["root_device"]
LUKS_UUID = CONFIG["luks_uuid"]
TRANSIENT_PATHS = CONFIG["transient_paths"]
REQUIRED_UNITS = CONFIG["required_units"]
MODULE_ERROR_RE = re.compile(r"(?i)(unknown symbol|invalid module format|vermagic|module[^\\n]*(?:fail|error)|failed[^\\n]*(?:module|firmware|probe)|probe[^\\n]*failed)")
SENSITIVE_RE = re.compile(r"(?i)(passphrase|password|secret|token|private.?key|credential)[^\\s]*")


class ProbeError(RuntimeError):
    pass


class ProbeInterrupted(BaseException):
    """Cancellation that must bypass per-check Exception handlers."""

    def __init__(self, signum):
        self.signum = signum
        super().__init__(signum)


def interrupt_handler(received, frame):
    raise ProbeInterrupted(received)


def install_signal_handlers():
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupt_handler)


def file_execution_guard():
    value = globals().get("__file__")
    if not value or not Path(value).is_file():
        print("This acceptance probe must run from its installed file path; stdin execution is unsupported.",
              file=sys.stderr)
        return False
    return True


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_text(path, limit=65536):
    data = path.read_bytes()
    require(len(data) <= limit, "file is unexpectedly large: " + str(path))
    return data.decode("utf-8", "strict")


def regular(path, label):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), label + " is not a regular file")
    return info


def command(argv, timeout=15, check=True, cwd=None):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=timeout, check=False,
                                cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("command unavailable or timed out: " + Path(argv[0]).name) from exc
    if check and result.returncode != 0:
        raise ProbeError("command failed: " + Path(argv[0]).name)
    return result


def safe_output(value, limit=320):
    value = SENSITIVE_RE.sub("<redacted>", value.replace("\\x00", ""))
    return value[-limit:]


def parse_kv(path):
    values = {{}}
    for line in read_text(path, 8192).splitlines():
        key, sep, value = line.partition("=")
        require(sep and key and key not in values, "malformed or duplicate key in " + str(path))
        values[key] = value
    return values


def check_kernel_and_root():
    require(os.geteuid() == 0, "probe must run as root")
    require(read_text(Path("/etc/machine-id"), 256).strip() == MACHINE_ID, "machine-id differs")
    release = command(["/usr/bin/uname", "-r"]).stdout.strip()
    require(release == RELEASE, "kernel release differs: " + release)
    boot_id = read_text(Path("/proc/sys/kernel/random/boot_id"), 256).strip()
    require(boot_id and boot_id != OLD_BOOT_ID, "boot ID is missing or equals accepted RTC2 boot")
    root = command(["/usr/bin/findmnt", "-n", "-o", "SOURCE,FSTYPE", "/"]).stdout.strip()
    require(root == "/dev/mapper/cryptroot ext4", "root source/fstype differs")
    require(command(["/usr/bin/findmnt", "-n", "-o", "UUID", "/"]).stdout.strip() == ROOT_UUID,
            "root UUID differs")
    env = Path("/etc/r8q-encrypted-root.env")
    info = regular(env, "encrypted-root identity")
    require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            "encrypted-root identity ownership/mode differs")
    require(read_text(env, 256).strip() == "LUKS_UUID=" + LUKS_UUID, "LUKS identity file differs")
    require(command(["/usr/local/sbin/r8q-root-device"]).stdout.strip() == "/dev/mapper/cryptroot",
            "root-device helper differs")
    require(command(["/usr/bin/cryptsetup", "luksUUID", ROOT_DEVICE]).stdout.strip().lower() == LUKS_UUID,
            "LUKS UUID differs")
    require(command(["/usr/bin/blkid", "-s", "TYPE", "-o", "value", ROOT_DEVICE]).stdout.strip() == "crypto_LUKS",
            "root block type is not LUKS")
    require(command(["/usr/bin/blkid", "-s", "PARTUUID", "-o", "value", ROOT_DEVICE]).stdout.strip().lower() == ROOT_PARTUUID,
            "root PARTUUID differs")
    status = command(["/usr/bin/cryptsetup", "status", "cryptroot"]).stdout
    require("is active" in status.lower() and ROOT_DEVICE in status, "cryptroot is not active")
    mappers = []
    for path in sorted(Path("/sys/class/block").glob("dm-*")):
        name = path / "dm/name"
        if name.is_file() and read_text(name, 256).strip() == "cryptroot":
            mappers.append(path)
    require(len(mappers) == 1, "cryptroot mapper is ambiguous")
    slaves = {{path.name for path in (mappers[0] / "slaves").iterdir()}}
    require(slaves == {{"sda36"}}, "cryptroot backing slave differs")
    device = Path(ROOT_DEVICE)
    info = device.stat()
    sysdev = read_text(Path("/sys/class/block/sda36/dev"), 64).strip()
    require(sysdev == f"{{os.major(info.st_rdev)}}:{{os.minor(info.st_rdev)}}", "root device numbers differ")
    return {{"kernel": release, "boot_id": boot_id, "root": root, "root_uuid": ROOT_UUID,
            "luks_uuid": LUKS_UUID, "cryptroot_slave": "sda36"}}


def check_runtime_safety():
    udev = Path("/run/udev")
    info = udev.stat()
    require(udev.is_dir() and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o755,
            "/run/udev ownership/mode differs")
    alarm = command(["/usr/bin/runuser", "-u", "alarm", "--", "test", "-r", "/run/udev/data/c226:0"], check=False)
    require(alarm.returncode == 0, "alarm cannot read the GPU udev record")
    render = Path("/dev/dri/renderD128")
    require(render.is_char_device() and os.access(render, os.R_OK), "GPU render node is unavailable")
    for value in TRANSIENT_PATHS:
        require(not Path(value).exists() and not Path(value).is_symlink(), "transient secret path remains: " + value)
    return {{"udev_mode": "0755", "udev_alarm_gpu_record_readable": True,
            "gpu_render_node": "/dev/dri/renderD128", "transient_secret_paths_absent": True}}


def check_handoff():
    marker = Path("/run/r8q-encryption-adapter-handoff")
    info = regular(marker, "adapter handoff marker")
    require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < 4096,
            "adapter handoff marker ownership/mode differs")
    values = parse_kv(marker)
    early = CONFIG["early_modules"]
    expected = {{
        "schema": "r8q-encryption-adapter-handoff/v1",
        "kernel": RELEASE,
        "gpi_module": f"lib/modules/{{RELEASE}}/r8q-encryption/gpi.ko",
        "geni_module": f"lib/modules/{{RELEASE}}/r8q-encryption/i2c-qcom-geni.ko",
        "fts_module": f"lib/modules/{{RELEASE}}/r8q-encryption/fts5cu56a.ko",
        "zinitix_module": f"lib/modules/{{RELEASE}}/r8q-encryption/zinitix.ko",
        "gpi_ownership": "inherited", "geni_ownership": "inherited",
        "touch_drivers": "absent", "touch_input_events": "absent",
        "gpi_sha256": early["gpi.ko"]["sha256"],
        "geni_sha256": early["i2c-qcom-geni.ko"]["sha256"],
        "fts_sha256": early["fts5cu56a.ko"]["sha256"],
        "zinitix_sha256": early["zinitix.ko"]["sha256"],
    }}
    require(set(values) == set(expected) | {{"boot_id", "i2c_adapters", "fifo"}},
            "adapter handoff marker keys differ")
    require(all(values[key] == value for key, value in expected.items()), "adapter handoff marker differs")
    current_boot = read_text(Path("/proc/sys/kernel/random/boot_id"), 256).strip()
    require(values["boot_id"] == current_boot and current_boot != OLD_BOOT_ID, "handoff boot ID differs")
    require(values["i2c_adapters"].isdigit() and int(values["i2c_adapters"]) > 0,
            "handoff has no I2C adapters")
    require(values["fifo"] in {{"1", "Y", "y"}}, "handoff FIFO parameter is disabled")
    fifo = Path("/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo")
    require(fifo.is_file() and read_text(fifo, 64).strip() in {{"1", "Y", "y"}},
            "live GENI FIFO parameter is disabled")
    require(Path("/sys/module/gpi").is_dir() and Path("/sys/module/i2c_qcom_geni").is_dir(),
            "retained adapter modules are absent")
    return {{"marker": "PASS", "boot_id": current_boot, "i2c_adapters": int(values["i2c_adapters"]),
            "fifo": values["fifo"], "retained_adapters": ["gpi", "i2c_qcom_geni"]}}


def validate_protected_manifest_bytes(data, expected):
    require(len(data) <= 4 * 1024 * 1024, "protected manifest is unexpectedly large")
    lines = data.splitlines(keepends=True)
    require(len(lines) == expected["old_entries"] + len(expected["additions"]),
            "protected manifest line count differs")
    prefix = b"".join(lines[:expected["old_entries"]])
    require(len(prefix) == expected["old_bytes"] and hashlib.sha256(prefix).hexdigest() == expected["old_prefix_sha256"],
            "original protected manifest prefix differs")
    append = b"".join((row["sha256"] + "  /" + row["path"] + "\\n").encode("ascii")
                       for row in expected["additions"])
    require(data == prefix + append, "protected manifest additions differ from deployment plan")
    return prefix


def check_protected_manifest():
    path = Path("/root/r8q-screen-lock-20261013.sha256")
    info = regular(path, "installed protected manifest")
    require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            "installed protected manifest ownership/mode differs")
    data = path.read_bytes()
    expected = CONFIG["protected_manifest"]
    prefix = validate_protected_manifest_bytes(data, expected)
    checksum = command(["/usr/bin/sha256sum", "--quiet", "-c", str(path)],
                       timeout=60, check=False, cwd="/")
    require(checksum.returncode == 0, "protected baseline sha256sum verification failed")
    metadata = expected["metadata"]
    require(metadata["sha256"] == "ada81d61b271b96f35681f07e42fb56907332ee4e93a04ccee0cc715cbbd3d1c" and
            metadata["entry_count"] == 297 and metadata["alarm_owned_entries"] == 16,
            "protected baseline metadata pin differs")
    metadata_checked = 0
    for raw_path, row in metadata["entries"].items():
        target = Path(raw_path)
        info = regular(target, "protected baseline file")
        require(row["kind"] == "file" and info.st_uid == row["uid"] and info.st_gid == row["gid"] and
                stat.S_IMODE(info.st_mode) == row["mode"],
                "protected baseline ownership/mode differs: " + raw_path)
        metadata_checked += 1
    return {{"old_entries": expected["old_entries"], "new_entries": len(expected["additions"]),
            "prefix_sha256": expected["old_prefix_sha256"], "append_only": True,
            "sha256sum_checked": True, "metadata_checked": metadata_checked,
            "alarm_owned_entries": metadata["alarm_owned_entries"]}}


def check_modules():
    checked = 0
    for row in CONFIG["module_files"]:
        path = Path("/") / row["path"]
        info = regular(path, "installed module")
        require(info.st_size == row["bytes"] and sha256(path) == row["sha256"],
                "installed module hash differs: " + row["path"])
        require(stat.S_IMODE(info.st_mode) & 0o7000 == 0, "installed module mode has special bits")
        checked += 1
    dep = Path("/usr/lib/modules") / RELEASE / "modules.dep"
    require(dep.is_file() and not dep.is_symlink(), "Waydroid modules.dep is missing")
    require(RELEASE in read_text(dep, 4 * 1024 * 1024) or "kernel/" in read_text(dep, 4 * 1024 * 1024),
            "Waydroid modules.dep is empty")
    return {{"module_files_checked": checked, "modules_dep": str(dep)}}


def check_rootfs_additions():
    checked = 0
    for row in CONFIG["rootfs_files"]:
        path = Path("/") / row["path"]
        info = regular(path, "installed Waydroid addition")
        require(info.st_uid == 0 and info.st_gid == 0 and
                stat.S_IMODE(info.st_mode) == row["mode"] and
                info.st_size == row["bytes"] and sha256(path) == row["sha256"],
                "installed Waydroid addition differs: " + row["path"])
        checked += 1
    return {{"rootfs_files_checked": checked}}


def check_psi_and_memfd():
    psi = {{}}
    for name in ("cpu", "memory", "io"):
        path = Path("/proc/pressure") / name
        text = read_text(path, 4096)
        require(any(line.startswith("some ") for line in text.splitlines()), "PSI some missing: " + name)
        psi[name] = True
    require(hasattr(os, "memfd_create"), "memfd_create is unavailable in Python")
    fd = os.memfd_create("r8q-waydroid-acceptance", os.MFD_CLOEXEC)
    try:
        payload = b"r8q-waydroid-memfd-v1"
        os.write(fd, payload)
        os.lseek(fd, 0, os.SEEK_SET)
        require(os.read(fd, len(payload)) == payload, "memfd readback differs")
        require(os.fstat(fd).st_size == len(payload), "memfd size differs")
    finally:
        os.close(fd)
    return {{"psi": psi, "memfd_create": True}}


def cleanup_binderfs(base, mountpoint, base_seed, mount_seed, mounted):
    errors = []
    base_owned = False
    mountpoint_owned = False
    try:
        current = base.lstat()
        base_owned = current.st_dev == base_seed.st_dev and current.st_ino == base_seed.st_ino
        if not base_owned:
            errors.append("binderfs cleanup base identity changed")
    except OSError as exc:
        errors.append("binderfs cleanup base unavailable: " + type(exc).__name__)
    try:
        mountpoint_owned = (mountpoint.parent == base and not mountpoint.is_symlink() and
                            mountpoint.is_dir())
        if not mountpoint_owned:
            errors.append("binderfs cleanup mountpoint identity changed")
    except OSError as exc:
        errors.append("binderfs cleanup mountpoint unavailable: " + type(exc).__name__)
    if mounted and base_owned and mountpoint_owned:
        try:
            result = command(["/usr/bin/umount", "--", str(mountpoint)], timeout=20, check=False)
            if result.returncode != 0:
                errors.append("binderfs cleanup umount failed")
        except Exception as exc:
            errors.append("binderfs cleanup umount error: " + type(exc).__name__)
    # A timeout or an exception above must not skip the second observation and
    # retry.  Keep the mountpoint until findmnt proves that it is gone.
    still_mounted = False
    try:
        probe = command(["/usr/bin/findmnt", "-n", "--target", str(mountpoint)],
                        timeout=15, check=False)
        still_mounted = probe.returncode == 0
    except Exception as exc:
        errors.append("binderfs cleanup mount observation error: " + type(exc).__name__)
        still_mounted = True
    if still_mounted and base_owned and mountpoint_owned:
        try:
            result = command(["/usr/bin/umount", "--", str(mountpoint)], timeout=20, check=False)
            if result.returncode != 0:
                errors.append("binderfs cleanup retry failed")
        except Exception as exc:
            errors.append("binderfs cleanup retry error: " + type(exc).__name__)
        try:
            probe = command(["/usr/bin/findmnt", "-n", "--target", str(mountpoint)],
                            timeout=15, check=False)
            still_mounted = probe.returncode == 0
        except Exception as exc:
            errors.append("binderfs cleanup retry observation error: " + type(exc).__name__)
            still_mounted = True
    if still_mounted:
        errors.append("binderfs mount remains mounted")
    elif mountpoint_owned:
        try:
            restored = mountpoint.lstat()
            if restored.st_dev != mount_seed.st_dev or restored.st_ino != mount_seed.st_ino:
                errors.append("binderfs mountpoint was not restored")
        except OSError as exc:
            errors.append("binderfs mountpoint restoration error: " + type(exc).__name__)
    if base_owned and not still_mounted:
        try:
            shutil.rmtree(base)
        except OSError as exc:
            errors.append("binderfs cleanup base removal error: " + type(exc).__name__)
        if base.exists():
            errors.append("binderfs cleanup base remains")
    elif not base_owned:
        errors.append("binderfs cleanup retained unowned base")
    if errors:
        raise ProbeError("; ".join(errors)[:320])


def check_binderfs():
    contract = CONFIG["binder_contract"]
    base = Path(tempfile.mkdtemp(prefix="r8q-waydroid-binder-", dir="/run"))
    base_seed = base.lstat()
    mountpoint = base / "binderfs"
    mountpoint.mkdir(mode=0o700)
    mount_seed = mountpoint.lstat()
    mounted = False
    devices = []
    try:
        command(["/usr/bin/mount", "-t", "binder", "-o", "nosuid,noexec", "binder", str(mountpoint)], timeout=20)
        mounted = True
        command(["/usr/bin/mount", "--make-private", str(mountpoint)], timeout=20)
        propagation = command(["/usr/bin/findmnt", "-n", "-o", "PROPAGATION",
                               "--target", str(mountpoint)], timeout=15).stdout.strip().lower()
        require(propagation == "private", "binderfs mount is not private")
        options = command(["/usr/bin/findmnt", "-n", "-o", "OPTIONS,FS-OPTIONS",
                           "--target", str(mountpoint)], timeout=15).stdout.lower()
        option_tokens = set(re.split(r"[,\\s]+", options.strip()))
        require("nodev" not in option_tokens and {{"nosuid", "noexec"}}.issubset(option_tokens),
                "binderfs mount options do not preserve usable character devices")
        control = mountpoint / "binder-control"
        require(control.is_char_device(), "binderfs control node is missing or not a character device")
        for name in ("binder", "hwbinder", "vndbinder"):
            raw = bytearray(contract["struct_size"])
            encoded = name.encode("ascii") + b"\\0"
            raw[:len(encoded)] = encoded
            fd = os.open(control, os.O_RDONLY | os.O_CLOEXEC)
            try:
                fcntl.ioctl(fd, contract["binder_ctl_add"], raw, True)
            finally:
                os.close(fd)
            major, minor = struct.unpack_from("<II", raw, contract["major_offset"])
            require(major > 0 and minor >= 0, "binderfs returned invalid device numbers")
            node = mountpoint / name
            require(node.is_char_device(), "binderfs did not create device node: " + name)
            info = node.stat()
            require(stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(major, minor),
                    "binderfs device node differs: " + name)
            test_fd = os.open(node, os.O_RDWR | os.O_CLOEXEC)
            try:
                version = bytearray(contract["binder_version_size"])
                fcntl.ioctl(test_fd, contract["binder_version"], version, True)
            finally:
                os.close(test_fd)
            protocol = struct.unpack_from("<i", version, 0)[0]
            require(protocol == contract["binder_protocol_version"],
                    "binder protocol version differs: " + name)
            devices.append({{"name": name, "major": major, "minor": minor, "protocol": protocol, "mode": 0o600}})
        return {{"mount": "binderfs", "mountpoint": str(mountpoint),
                "binder_ctl_add": contract["binder_ctl_add"], "struct_size": contract["struct_size"],
                "binder_version": contract["binder_version"], "devices": devices, "functional": True}}
    finally:
        cleanup_binderfs(base, mountpoint, base_seed, mount_seed, mounted)


def network_child():
    command(["/usr/bin/mount", "--make-rprivate", "/"], timeout=20)
    base = Path(tempfile.mkdtemp(prefix="r8q-waydroid-net-", dir="/run"))
    bridge = "r8qbr" + str(os.getpid() % 100000)
    veth_a = "r8qva" + str(os.getpid() % 100000)
    veth_b = "r8qvb" + str(os.getpid() % 100000)
    inet_table = "r8qaccf" + str(os.getpid() % 100000)
    ip_table = "r8qaccn" + str(os.getpid() % 100000)
    lower = base / "lower"
    upper = base / "upper"
    work = base / "work"
    merged = base / "merged"
    mounted = False
    bridge_created = False
    veth_created = False
    inet_created = False
    ip_created = False
    result = {{"isolated_mount_network_namespace": True, "persistent_configuration_changed": False,
              "runtime_resources_exercised": True, "module_dry_run": {{}}, "bridge": bridge,
              "veth": [veth_a, veth_b], "nft": {{}}, "overlay": False,
              "run_base": str(base)}}
    try:
        for name in CONFIG["network_modules"]:
            check = command(["/usr/bin/modprobe", "--dry-run", "--", name], timeout=15, check=False)
            require(check.returncode == 0, "network module is unavailable: " + name)
            result["module_dry_run"][name] = True
        command(["/usr/bin/ip", "link", "add", bridge, "type", "bridge"], timeout=15)
        bridge_created = True
        command(["/usr/bin/ip", "link", "set", bridge, "up"], timeout=15)
        command(["/usr/bin/ip", "link", "add", veth_a, "type", "veth", "peer", "name", veth_b], timeout=15)
        veth_created = True
        command(["/usr/bin/ip", "link", "set", veth_a, "master", bridge], timeout=15)
        command(["/usr/bin/ip", "link", "set", veth_a, "up"], timeout=15)
        command(["/usr/bin/ip", "link", "set", veth_b, "up"], timeout=15)
        links = command(["/usr/bin/ip", "-o", "link", "show"]).stdout
        require(bridge in links and veth_a in links and veth_b in links, "bridge/veth allocation is incomplete")
        result["bridge_allocated"] = True
        command(["/usr/bin/nft", "add", "table", "inet", inet_table], timeout=15)
        inet_created = True
        command(["/usr/bin/nft", "add", "chain", "inet", inet_table, "filter", "{{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "drop", ";", "}}"], timeout=15)
        command(["/usr/bin/nft", "add", "rule", "inet", inet_table, "filter", "counter"], timeout=15)
        inet_text = command(["/usr/bin/nft", "list", "table", "inet", inet_table]).stdout
        require("type filter" in inet_text and "hook forward" in inet_text, "inet filter chain is missing")
        result["nft"]["inet_filter"] = True
        command(["/usr/bin/nft", "add", "table", "ip", ip_table], timeout=15)
        ip_created = True
        command(["/usr/bin/nft", "add", "chain", "ip", ip_table, "postrouting", "{{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "policy", "accept", ";", "}}"], timeout=15)
        command(["/usr/bin/nft", "add", "rule", "ip", ip_table, "postrouting", "oifname", "lo", "masquerade"], timeout=15)
        ip_text = command(["/usr/bin/nft", "list", "table", "ip", ip_table]).stdout
        require("hook postrouting" in ip_text and "masquerade" in ip_text, "ip NAT masquerade is missing")
        result["nft"]["ip_nat_postrouting_masquerade"] = True
        lower.mkdir(mode=0o700); upper.mkdir(mode=0o700); work.mkdir(mode=0o700); merged.mkdir(mode=0o700)
        (lower / "r8q-lower-marker").write_text("r8q-overlay-v1\\n", encoding="ascii")
        command(["/usr/bin/mount", "-t", "overlay", "overlay", "-o",
                 "lowerdir=" + str(lower) + ",upperdir=" + str(upper) + ",workdir=" + str(work), str(merged)], timeout=20)
        mounted = True
        require((merged / "r8q-lower-marker").read_text(encoding="ascii") == "r8q-overlay-v1\\n", "overlay lower file missing")
        (merged / "r8q-upper-marker").write_text("r8q-overlay-upper-v1\\n", encoding="ascii")
        require((upper / "r8q-upper-marker").is_file(), "overlay upper write missing")
        result["overlay"] = True
        return result
    finally:
        cleanup_errors = []
        def cleanup_command(argv, label):
            try:
                cleanup_result = command(argv, timeout=20, check=False)
                if cleanup_result.returncode != 0:
                    cleanup_errors.append(label + " failed")
            except Exception as exc:
                cleanup_errors.append(label + " error: " + type(exc).__name__)
        if mounted:
            cleanup_command(["/usr/bin/umount", "--", str(merged)], "overlay umount")
        still_mounted = False
        for _ in range(2):
            try:
                mount_probe = command(["/usr/bin/findmnt", "-n", "--target", str(merged)],
                                      timeout=15, check=False)
                still_mounted = mount_probe.returncode == 0
            except Exception as exc:
                cleanup_errors.append("overlay mount observation error: " + type(exc).__name__)
                still_mounted = True
            if not still_mounted:
                break
            cleanup_command(["/usr/bin/umount", "--", str(merged)], "overlay umount retry")
        if still_mounted:
            cleanup_errors.append("overlay mount remains mounted")
        if ip_created:
            cleanup_command(["/usr/bin/nft", "delete", "table", "ip", ip_table], "ip nft cleanup")
        if inet_created:
            cleanup_command(["/usr/bin/nft", "delete", "table", "inet", inet_table], "inet nft cleanup")
        if veth_created:
            cleanup_command(["/usr/bin/ip", "link", "delete", veth_a], "veth cleanup")
        if bridge_created:
            cleanup_command(["/usr/bin/ip", "link", "delete", bridge], "bridge cleanup")
        for family, table, created in (("ip", ip_table, ip_created), ("inet", inet_table, inet_created)):
            if created:
                try:
                    probe = command(["/usr/bin/nft", "list", "table", family, table],
                                    timeout=15, check=False)
                    if probe.returncode == 0:
                        cleanup_errors.append(family + " nft table remains")
                except Exception as exc:
                    cleanup_errors.append(family + " nft observation error: " + type(exc).__name__)
        for name, created in ((veth_a, veth_created), (veth_b, veth_created), (bridge, bridge_created)):
            if created:
                try:
                    probe = command(["/usr/bin/ip", "link", "show", "dev", name],
                                    timeout=15, check=False)
                    if probe.returncode == 0:
                        cleanup_errors.append("network link remains: " + name)
                except Exception as exc:
                    cleanup_errors.append("network link observation error: " + type(exc).__name__)
        base_removed = False
        if not still_mounted:
            try:
                shutil.rmtree(base)
            except OSError as exc:
                cleanup_errors.append("network base removal error: " + type(exc).__name__)
            base_removed = not base.exists()
            if not base_removed:
                cleanup_errors.append("network base remains")
        else:
            cleanup_errors.append("network base retained while overlay mount remains")
        result["cleanup"] = {{"residual": cleanup_errors, "run_base_removed": base_removed}}
        if cleanup_errors:
            raise ProbeError("network cleanup residual: " + "; ".join(cleanup_errors)[:280])


def check_network():
    try:
        result = command(["/usr/bin/unshare", "--mount", "--net", "--fork", "--", sys.executable,
                          str(Path(__file__).resolve()), "--network-child"], timeout=90, check=False)
    except ProbeError:
        raise
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProbeError("isolated network probe did not return JSON") from exc
    if result.returncode != 0:
        raise ProbeError("isolated network child failed: " + str(value.get("error", "unknown"))[:280])
    require(value.get("isolated_mount_network_namespace") is True and
            value.get("bridge_allocated") is True and value.get("overlay") is True and
            value.get("nft", {{}}).get("inet_filter") is True and
            value.get("nft", {{}}).get("ip_nat_postrouting_masquerade") is True,
            "isolated Waydroid network/overlay probe is incomplete")
    cleanup = value.get("cleanup", {{}})
    require(cleanup.get("residual") == [] and cleanup.get("run_base_removed") is True,
            "isolated Waydroid network cleanup left residual resources")
    return value


def validate_power_state(charger, fuel):
    require(charger.get("status") in ("Charging", "Full") and
            charger.get("health") == "Good" and charger.get("online") == "1" and
            charger.get("input_current_limit") == "500000",
            "charger state/current limit differs")
    try:
        capacity = int(fuel.get("capacity", "-1"))
        temperature = int(fuel.get("temp", "-1"))
        voltage = int(fuel.get("voltage_now", "-1"))
    except (TypeError, ValueError) as exc:
        raise ProbeError("fuel gauge values are not numeric") from exc
    require(15 <= capacity <= 100 and 0 <= temperature <= 400 and
            2500000 <= voltage <= 4500000,
            "fuel gauge is outside the normal operating range")
    return {{"charger": charger, "fuel_gauge": {{"capacity": capacity, "temp": temperature,
                                                    "voltage_now": voltage}}}}


def check_audio_battery_wifi():
    card_id = Path("/proc/asound/card0/id")
    require(card_id.is_file() and read_text(card_id, 128).strip() == "CS35L41", "CS35L41 card0 is unavailable")
    cards = read_text(Path("/proc/asound/cards"), 8192)
    require("CS35L41" in cards, "CS35L41 ALSA card is not enumerated")
    charger = Path("/sys/class/power_supply/max77705-charger")
    values = {{name: read_text(charger / name, 128).strip() for name in ("status", "health", "online", "input_current_limit")}}
    fuel = Path("/sys/class/power_supply/max170xx_battery")
    fuel_values = {{name: read_text(fuel / name, 128).strip()
                    for name in ("capacity", "temp", "voltage_now")}}
    power = validate_power_state(values, fuel_values)
    standby = Path("/run/r8q-wifi-standby/status.json")
    status = json.loads(read_text(standby, 4096))
    boot_id = read_text(Path("/proc/sys/kernel/random/boot_id"), 256).strip()
    require(status.get("schema") == "r8q-wifi-standby/v1" and status.get("boot_id") == boot_id and
            status.get("power_save") in {{"on", "off"}} and isinstance(status.get("reason"), str),
            "Wi-Fi standby receipt is not healthy")
    iw = command(["/usr/bin/iw", "dev", "wlp1s0", "get", "power_save"]).stdout.strip().lower()
    require(iw in ("power save: on", "power save: off") and iw.endswith(status["power_save"]),
            "Wi-Fi standby readback differs")
    return {{"cs35l41_card0": True, "charger": power["charger"], "fuel_gauge": power["fuel_gauge"],
            "wifi_standby": status["power_save"], "wifi_standby_reason": status["reason"]}}


def check_hardware_runtime():
    udc = [path.name for path in Path("/sys/class/udc").glob("*") if path.exists()]
    require(udc, "USB gadget controller is unavailable")
    display = Path("/sys/class/drm/card0-DSI-1/status")
    require(display.is_file() and read_text(display, 128).strip() == "connected" and
            Path("/sys/class/drm/card0/device/driver").exists(),
            "GPU display connector or driver is unavailable")
    touch_names = []
    for path in Path("/sys/class/input").glob("input*/name"):
        value = read_text(path, 256).strip()
        if value:
            touch_names.append(value)
    require(any(re.search(r"touch|zinitix|fts5", value, re.I) for value in touch_names),
            "touch input device is unavailable")
    wifi = Path("/sys/class/net/wlp1s0")
    require(wifi.is_dir(), "Wi-Fi interface is unavailable")
    carrier = read_text(wifi / "carrier", 16).strip()
    require(carrier in ("0", "1"), "Wi-Fi carrier state is unreadable")
    return {{"usb_controllers": udc[:8], "gpu_display_connected": True,
            "touch_input": True, "wifi_interface": "wlp1s0", "wifi_carrier": carrier}}


def check_services():
    statuses = {{}}
    for unit in REQUIRED_UNITS:
        result = command(["/usr/bin/systemctl", "is-active", unit], timeout=15, check=False)
        statuses[unit] = result.stdout.strip() or "inactive"
        require(result.returncode == 0 and statuses[unit] == "active", "service is not active: " + unit)
    failed = command(["/usr/bin/systemctl", "--failed", "--no-legend", "--plain"], timeout=15, check=False)
    failed_names = []
    for line in failed.stdout.splitlines():
        fields = line.split()
        if fields and len(failed_names) < 32:
            failed_names.append(fields[0])
    require(not failed_names, "failed systemd units are present")
    return {{"required": statuses, "failed_units": failed_names}}


def check_kernel_logs():
    result = command(["/usr/bin/dmesg", "--level=err,warn", "--notime"], timeout=20, check=False)
    require(result.returncode == 0, "dmesg cannot be read")
    matched = [line.strip() for line in result.stdout.splitlines() if MODULE_ERROR_RE.search(line)]
    baseline = [line for line in matched if line == CONFIG["known_baseline_warning"]]
    lines = [safe_output(line) for line in matched if line != CONFIG["known_baseline_warning"]]
    lines = lines[-80:]
    require(not lines, "kernel/module error lines outside the accepted RTC warning are present")
    return {{"module_error_count": len(lines), "module_error_lines": lines,
            "accepted_baseline_warning": CONFIG["known_baseline_warning"],
            "accepted_baseline_warning_count": len(baseline)}}


def run_probe():
    result = {{"schema": "r8q-waydroid2-acceptance/v1", "release": RELEASE,
              "candidate_manifest_sha256": CONFIG["candidate_manifest_sha256"],
              "persistent_configuration_changed": False, "runtime_resources_exercised": True,
              "credentials_staged": False, "checks": {{}},
              "started_at_monotonic": time.monotonic()}}
    prerequisites = (
        ("kernel_root", check_kernel_and_root),
        ("runtime_safety", check_runtime_safety),
        ("handoff", check_handoff),
        ("protected_manifest", check_protected_manifest),
        ("rootfs_additions", check_rootfs_additions),
    )
    dependent_checks = (
        ("modules", check_modules),
        ("psi_memfd", check_psi_and_memfd),
        ("binderfs", check_binderfs),
        ("isolated_network_overlay", check_network),
        ("hardware_runtime", check_hardware_runtime),
        ("audio_battery_wifi", check_audio_battery_wifi),
        ("services", check_services),
        ("kernel_logs", check_kernel_logs),
    )
    failures = []
    prerequisite_failed = False
    for name, function in prerequisites:
        try:
            result["checks"][name] = {{"result": "PASS", "details": function()}}
        except Exception as exc:  # fail closed while preserving all bounded diagnostics
            failures.append(name)
            result["checks"][name] = {{"result": "FAIL", "error": str(exc)[:320]}}
            prerequisite_failed = True
    if prerequisite_failed:
        for name, function in dependent_checks:
            result["checks"][name] = {{"result": "SKIP", "reason": "prerequisite gate failed"}}
    else:
        for name, function in dependent_checks:
            try:
                result["checks"][name] = {{"result": "PASS", "details": function()}}
            except Exception as exc:  # fail closed while preserving all bounded diagnostics
                failures.append(name)
                result["checks"][name] = {{"result": "FAIL", "error": str(exc)[:320]}}
    result["failures"] = failures
    result["result"] = "PASS" if not failures else "FAIL"
    result["finished_at_monotonic"] = time.monotonic()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 1


def dispatch():
    if len(sys.argv) == 2 and sys.argv[1] == "--network-child":
        try:
            print(json.dumps(network_child(), sort_keys=True))
        except Exception as exc:
            print(json.dumps({{"result": "FAIL", "error": str(exc)[:320],
                              "persistent_configuration_changed": False,
                              "runtime_resources_exercised": True,
                              "credentials_staged": False}}))
            return 1
        return 0
    return run_probe()


def main():
    if not file_execution_guard():
        return 2
    install_signal_handlers()
    try:
        return dispatch()
    except ProbeInterrupted as exc:
        print(json.dumps({{"schema": "r8q-waydroid2-acceptance/v1",
                          "result": "FAIL", "failures": ["interrupted"],
                          "error": "probe interrupted by signal " + str(exc.signum)[:8],
                          "persistent_configuration_changed": False,
                          "runtime_resources_exercised": True,
                          "credentials_staged": False}}, sort_keys=True))
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
'''


def write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def self_test(output: Path) -> int:
    output = output.resolve()
    require(output == DEFAULT_OUTPUT.resolve(), f"output must be exactly {DEFAULT_OUTPUT}")
    contract = binder_contract()
    require(contract["struct_size"] == 264 and contract["binder_ctl_add"] == 0xC1086201 and
            contract["binder_version_size"] == 4 and contract["binder_version"] == 0xC0046209 and
            contract["binder_protocol_version"] == 8,
            "binderfs contract self-test failed")
    fixture = {
        "schema": "r8q-waydroid2-acceptance-probe-config/v1",
        "release": RELEASE,
        "old_release": OLD_RELEASE,
        "old_boot_id": OLD_BOOT_ID,
        "machine_id": MACHINE_ID,
        "root_device": ROOT_DEVICE,
        "root_uuid": ROOT_UUID,
        "root_partuuid": ROOT_PARTUUID,
        "luks_uuid": LUKS_UUID,
        "candidate_manifest_sha256": "0" * 64,
        "early_modules": {
            name: {"module": module, "sha256": "0" * 64, "bytes": 1,
                   "vermagic": RELEASE + " fixture"}
            for name, module in EARLY_MODULES.items()
        },
        "protected_manifest": {"old_entries": OLD_MANIFEST_ENTRIES, "old_bytes": 1,
                                "old_prefix_sha256": "0" * 64, "additions": []},
        "binder_contract": contract,
        "rootfs_files": [],
        "module_files": [],
        "network_modules": list(NETWORK_MODULES),
        "transient_paths": list(TRANSIENT_PATHS),
        "required_units": list(REQUIRED_UNITS),
        "known_baseline_warning": KNOWN_BASELINE_WARNING,
    }
    generated = probe_source(fixture)
    ast.parse(generated, filename="phone-acceptance-probe.py")
    compile(generated, "phone-acceptance-probe.py", "exec")
    namespace: dict[str, Any] = {"__name__": "phone_acceptance_fixture",
                                 "__file__": "phone-acceptance-probe.py"}
    exec(compile(generated, "phone-acceptance-probe.py", "exec"), namespace)
    dispatch_called = {"network": 0, "run": 0}

    def fake_network_child():
        dispatch_called["network"] += 1
        return {"fixture": "network-child"}

    def unexpected_run_probe():
        dispatch_called["run"] += 1
        raise AssertionError("network-child dispatch fell through to run_probe")

    original_run_probe = namespace["run_probe"]
    namespace["network_child"] = fake_network_child
    namespace["run_probe"] = unexpected_run_probe
    old_argv = sys.argv
    dispatch_stdout = io.StringIO()
    try:
        sys.argv = ["phone-acceptance-probe.py", "--network-child"]
        with contextlib.redirect_stdout(dispatch_stdout):
            dispatch_rc = namespace["dispatch"]()
    finally:
        sys.argv = old_argv
    dispatch_payload = json.loads(dispatch_stdout.getvalue())
    require(dispatch_rc == 0 and dispatch_payload == {"fixture": "network-child"} and
            dispatch_called == {"network": 1, "run": 0},
            "network-child dispatch fixture did not exit before run_probe")
    namespace["run_probe"] = original_run_probe
    gate_originals = {name: namespace[name] for name in (
        "check_kernel_and_root", "check_runtime_safety", "check_handoff",
        "check_protected_manifest", "check_rootfs_additions", "check_modules",
        "check_psi_and_memfd", "check_binderfs", "check_network",
        "check_hardware_runtime", "check_audio_battery_wifi", "check_services",
        "check_kernel_logs",
    )}
    gate_calls = {"binder": 0, "network": 0}

    def gate_kernel_failure():
        raise namespace["ProbeError"]("fixture kernel/profile mismatch")

    def forbidden_binder_call():
        gate_calls["binder"] += 1
        raise AssertionError("Binderfs ran after prerequisite failure")

    def forbidden_network_call():
        gate_calls["network"] += 1
        raise AssertionError("network fixture ran after prerequisite failure")

    namespace["check_kernel_and_root"] = gate_kernel_failure
    for name in ("check_runtime_safety", "check_handoff", "check_protected_manifest",
                 "check_rootfs_additions"):
        namespace[name] = lambda: {"fixture": "prerequisite-pass"}
    namespace["check_binderfs"] = forbidden_binder_call
    namespace["check_network"] = forbidden_network_call
    for name in ("check_modules", "check_psi_and_memfd", "check_hardware_runtime",
                 "check_audio_battery_wifi", "check_services", "check_kernel_logs"):
        namespace[name] = lambda: (_ for _ in ()).throw(
            AssertionError("dependent fixture ran after prerequisite failure"))
    gate_stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(gate_stdout):
            gate_rc = namespace["run_probe"]()
    finally:
        namespace.update(gate_originals)
    gate_payload = json.loads(gate_stdout.getvalue())
    require(gate_rc == 1 and gate_payload["checks"]["kernel_root"]["result"] == "FAIL" and
            gate_payload["checks"]["binderfs"]["result"] == "SKIP" and
            gate_payload["checks"]["isolated_network_overlay"]["result"] == "SKIP" and
            gate_calls == {"binder": 0, "network": 0},
            "prerequisite gate allowed functional fixture execution")
    power = namespace["validate_power_state"]
    for status in ("Charging", "Full"):
        power({"status": status, "health": "Good", "online": "1", "input_current_limit": "500000"},
              {"capacity": "75", "temp": "300", "voltage_now": "3800000"})
    for bad_charger, bad_fuel in (
        ({"status": "Discharging", "health": "Good", "online": "1", "input_current_limit": "500000"},
         {"capacity": "75", "temp": "300", "voltage_now": "3800000"}),
        ({"status": "Charging", "health": "Bad", "online": "1", "input_current_limit": "500000"},
         {"capacity": "75", "temp": "300", "voltage_now": "3800000"}),
        ({"status": "Full", "health": "Good", "online": "1", "input_current_limit": "500000"},
         {"capacity": "1", "temp": "300", "voltage_now": "3800000"}),
    ):
        try:
            power(bad_charger, bad_fuel)
        except namespace["ProbeError"]:
            pass
        else:
            raise PreparationError("power-state counterexample was accepted")
    manifest_prefix = b"old protected entry\\n"
    manifest_fixture = {
        "old_entries": 1, "old_bytes": len(manifest_prefix),
        "old_prefix_sha256": hashlib.sha256(manifest_prefix).hexdigest(), "additions": [],
    }
    namespace["validate_protected_manifest_bytes"](manifest_prefix, manifest_fixture)
    try:
        namespace["validate_protected_manifest_bytes"](b"mutated protected entry\\n", manifest_fixture)
    except namespace["ProbeError"]:
        pass
    else:
        raise PreparationError("protected-manifest counterexample was accepted")
    cleanup_base = Path(tempfile.mkdtemp(prefix="r8q-waydroid-cleanup-fixture-"))
    cleanup_mountpoint = cleanup_base / "binderfs"
    cleanup_mountpoint.mkdir()
    cleanup_base_seed = cleanup_base.lstat()
    cleanup_mount_seed = cleanup_mountpoint.lstat()
    cleanup_calls: list[list[str]] = []
    findmnt_calls = {"count": 0}

    class FixtureResult:
        def __init__(self, returncode: int):
            self.returncode = returncode
            self.stdout = ""
            self.stderr = ""

    def fixture_command(argv, timeout=15, check=True, cwd=None):
        cleanup_calls.append(list(argv))
        if Path(argv[0]).name == "findmnt":
            findmnt_calls["count"] += 1
            return FixtureResult(0 if findmnt_calls["count"] == 1 else 1)
        return FixtureResult(0)

    original_command = namespace["command"]
    namespace["command"] = fixture_command
    try:
        namespace["cleanup_binderfs"](cleanup_base, cleanup_mountpoint, cleanup_base_seed,
                                       cleanup_mount_seed, True)
    finally:
        namespace["command"] = original_command
    require(not cleanup_base.exists() and findmnt_calls["count"] == 2 and
            sum(Path(call[0]).name == "umount" for call in cleanup_calls) == 2,
            "binder cleanup retry fixture did not verify removal")
    interrupt_base = Path(tempfile.mkdtemp(prefix="r8q-waydroid-interrupt-fixture-"))
    interrupt_mountpoint = interrupt_base / "binderfs"
    interrupt_mountpoint.mkdir()
    interrupt_base_seed = interrupt_base.lstat()
    interrupt_mount_seed = interrupt_mountpoint.lstat()
    interrupt_calls: list[list[str]] = []
    interrupt_findmnt_calls = {"count": 0}

    def interrupt_fixture_command(argv, timeout=15, check=True, cwd=None):
        interrupt_calls.append(list(argv))
        if Path(argv[0]).name == "findmnt":
            interrupt_findmnt_calls["count"] += 1
            return FixtureResult(0 if interrupt_findmnt_calls["count"] == 1 else 1)
        return FixtureResult(0)

    saved_handlers = {signum: signal.getsignal(signum)
                      for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    interrupted = False
    namespace["command"] = interrupt_fixture_command
    try:
        namespace["install_signal_handlers"]()
        try:
            try:
                signal.raise_signal(signal.SIGTERM)
            finally:
                namespace["cleanup_binderfs"](interrupt_base, interrupt_mountpoint,
                                               interrupt_base_seed, interrupt_mount_seed, True)
        except namespace["ProbeInterrupted"]:
            interrupted = True
    finally:
        namespace["command"] = original_command
        for signum, handler in saved_handlers.items():
            signal.signal(signum, handler)
    require(interrupted and not interrupt_base.exists() and interrupt_findmnt_calls["count"] == 2 and
            sum(Path(call[0]).name == "umount" for call in interrupt_calls) == 2,
            "signal interrupt fixture did not run Binderfs cleanup")
    original_guard = namespace["file_execution_guard"]
    original_dispatch = namespace["dispatch"]
    namespace["file_execution_guard"] = lambda: True

    def interrupted_dispatch():
        raise namespace["ProbeInterrupted"](signal.SIGTERM)

    namespace["dispatch"] = interrupted_dispatch
    saved_handlers = {signum: signal.getsignal(signum)
                      for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    main_stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(main_stdout):
            main_rc = namespace["main"]()
    finally:
        namespace["file_execution_guard"] = original_guard
        namespace["dispatch"] = original_dispatch
        for signum, handler in saved_handlers.items():
            signal.signal(signum, handler)
    main_payload = json.loads(main_stdout.getvalue())
    require(main_rc == 130 and main_payload["result"] == "FAIL" and
            main_payload["failures"] == ["interrupted"] and
            main_payload["persistent_configuration_changed"] is False and
            main_payload["runtime_resources_exercised"] is True,
            "main interruption handler did not produce bounded FAIL")
    baseline = baseline_warning_contract()
    receipt = {
        "schema": "r8q-waydroid2-acceptance-preparation-self-test/v1",
        "status": "PASS",
        "phone_operations_performed": False,
        "binder_contract": contract,
        "generated_probe": {"written": False, "syntax": "PASS", "bytes": len(generated)},
        "dispatch_behavior_fixture": "PASS",
        "prerequisite_gate_fixture": "PASS",
        "power_state_counterexamples": "PASS",
        "protected_manifest_counterexample": "PASS",
        "binder_cleanup_retry_fixture": "PASS",
        "interrupt_cleanup_fixture": "PASS",
        "main_interrupt_fixture": "PASS",
        "baseline_warning": baseline,
        "candidate_required": True,
    }
    write_json(output / "offline-self-test.json", receipt)
    print(json.dumps(receipt, sort_keys=True))
    return 0


def prepare(output: Path) -> int:
    output = output.resolve()
    require(output == DEFAULT_OUTPUT.resolve(), f"output must be exactly {DEFAULT_OUTPUT}")
    output.mkdir(parents=True, exist_ok=True)
    try:
        manifest, candidate = candidate_contract()
        deployment = deployment_contract(manifest)
        binder = binder_contract()
        protected = protected_manifest_contract()
        baseline = baseline_warning_contract()
        deployment["protected_manifest"]["metadata"] = protected["metadata"]
        config = {
            "schema": "r8q-waydroid2-acceptance-probe-config/v1",
            "release": RELEASE,
            "old_release": OLD_RELEASE,
            "old_boot_id": OLD_BOOT_ID,
            "machine_id": MACHINE_ID,
            "root_device": ROOT_DEVICE,
            "root_uuid": ROOT_UUID,
            "root_partuuid": ROOT_PARTUUID,
            "luks_uuid": LUKS_UUID,
            "candidate_manifest_sha256": candidate["sha256"],
            "early_modules": candidate["early_modules"],
            "protected_manifest": deployment["protected_manifest"],
            "binder_contract": binder,
            "rootfs_files": deployment["protected_manifest"]["additions"],
            "module_files": [row for row in deployment["protected_manifest"]["additions"]
                             if row["path"].endswith(".ko")],
            "network_modules": list(NETWORK_MODULES),
            "transient_paths": list(TRANSIENT_PATHS),
            "required_units": list(REQUIRED_UNITS),
            "known_baseline_warning": baseline["line"],
        }
        # The deployment rows use rootfs-relative paths; the phone probe reads
        # those paths from /.  The receipt keeps the full input pins separately.
        source = probe_source(config)
        ast.parse(source, filename="phone-acceptance-probe.py")
        compile(source, "phone-acceptance-probe.py", "exec")
        probe_path = output / "phone-acceptance-probe.py"
        if probe_path.exists():
            raise PreparationError(f"refusing to overwrite existing probe: {probe_path}")
        temporary = output / ".phone-acceptance-probe.py.tmp"
        temporary.write_text(source, encoding="utf-8")
        os.chmod(temporary, 0o700)
        os.replace(temporary, probe_path)
        receipt = {
            "schema": "r8q-waydroid2-acceptance-preparation/v1",
            "status": "PASS",
            "phone_operations_performed": False,
            "credentials_or_secrets_staged": False,
            "probe": {"path": str(probe_path), "sha256": digest(probe_path), "mode": "0700"},
            "candidate": candidate,
            "deployment": deployment,
            "protected_manifest_source": protected,
            "binder_contract": binder,
            "baseline_warning": baseline,
            "checks": [
                "exact Waydroid2 kernel and new boot ID",
                "encrypted-root UUID/LUKS/sysfs identity and accepted root mode",
                "current-boot adapter handoff marker with four candidate module hashes and FIFO",
                "no transient unlock/credential paths",
                "root-owned 0755 /run/udev and alarm-readable GPU udev/render nodes",
                "original 297 protected-manifest prefix plus exact deployment additions",
                "hardware services, CS35L41 card, 500000-uA charger and Wi-Fi standby",
                "bounded kernel/module-error and failed-service report",
                "functional binderfs BINDER_CTL_ADD binder/hwbinder/vndbinder fixture",
                "PSI and actual memfd_create",
                "isolated mount/network namespace bridge/veth/nft/overlay fixture",
            ],
        }
        write_json(output / "preparation-receipt.json", receipt)
        print(json.dumps({"result": "PASS", "probe": str(probe_path), "sha256": receipt["probe"]["sha256"]}, sort_keys=True))
        return 0
    except Exception as exc:
        blocked = {
            "schema": "r8q-waydroid2-acceptance-preparation/v1",
            "status": "BLOCKED",
            "phone_operations_performed": False,
            "credentials_or_secrets_staged": False,
            "reason": str(exc)[:512],
            "required_before_prepare": [
                str(CANDIDATE / "candidate-manifest.json"),
                str(DEPLOYMENT / "deployment-plan.json"),
                str(HARDWARE / "bundle-manifest.json"),
            ],
        }
        write_json(output / "preparation-blocked.json", blocked)
        print(json.dumps(blocked, sort_keys=True), file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="generate the probe after final manifest/plan exist")
    parser.add_argument("--self-test", action="store_true", help="verify offline UAPI constants without a candidate")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    require(args.prepare ^ args.self_test, "choose exactly one of --prepare or --self-test")
    return prepare(args.output) if args.prepare else self_test(args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
