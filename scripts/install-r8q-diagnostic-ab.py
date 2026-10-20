#!/usr/bin/env python3
"""Package and arm one pseudo-NMI A/B EFI trial without changing rootfs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from typing import Any


SCRIPT = Path(__file__).resolve()
REPO = SCRIPT.parents[1]
OUT = REPO / "out"
DEFAULT_CANDIDATE = OUT / "diagnostic-ab-20261020" / "kernel"
DEFAULT_BASELINE = OUT / "diagnostic-ab-20261020" / "protected-baseline-523.json"
DEFAULT_PACKET = OUT / "diagnostic-ab-20261020" / "ab-arm-packet.json"
DEFAULT_OUTPUT = OUT / "diagnostic-ab-20261020" / "deployment-preparation"
SUPPORT = SCRIPT.with_name("install-r8q-diagnostic-trial.py")
SUPPORT_SHA256 = "021dc14bf8ae195664b94d22062b017fdc9edca63240f706cc4c189199884cc3"
RELEASE = "7.1.2-r8q-diag1"
ORIGINAL_RELEASE = "7.1.2-r8q-waydroid2"
EFI_SHA256 = "f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b"
EFI_BYTES = 67631616
ORIGINAL_CANDIDATE_SHA256 = "c4ca85a38870e1c230f1a63b21ac3faef8dd6347e2d50891e578d7a5c69fbaa3"
ORIGINAL_CANDIDATE_BYTES = 68160000
ORIGINAL_CANDIDATE_MANIFEST_SHA256 = "5b2109070962ed215b341cdd5e15b3c89cedc461d1b297012b87ff3611001204"
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
DTB_BYTES = 124302
CACHE_PARTUUID = "5594c694-c871-4b5f-90b1-690a6f68e0f7"
CACHE_PARTNAME = "cache"
CACHE_BYTES = 629145600
CACHE_BLOCK_SIZE = 4096
CACHE_FSTYPE = "vfat"
CACHE_BASELINE_SHA256 = "f62eb163fe645bf8fde135e20d3e2ee7636e39b446d2c32267e0987263ac59c8"
PROTECTED_MANIFEST = "/root/r8q-screen-lock-20261013.sha256"
PROTECTED_SCHEMA = "r8q-protected-baseline-metadata/v1"
BASELINE_SCHEMA = "r8q-diagnostic-ab-baseline/v1"
ARCHIVE_SCHEMA = "r8q-diagnostic-ab-archive/v1"
MARKER_SCHEMA = "r8q-diagnostic-fallback-marker/v1"
MARKER_FIELDS = frozenset({
    "schema", "state", "nonce", "tag", "candidate_sha256", "candidate_bytes",
    "accepted_sha256", "accepted_bytes", "cache_partuuid", "cache_partname",
    "cache_bytes", "cache_logical_block_size", "cache_fstype", "efi_rel", "dtb_rel",
    "backup_rel", "temp_rel", "candidate_copy_rel", "marker_rel",
})
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
REVISION = re.compile(r"^[A-Za-z0-9_-]{1,24}$")


class InstallError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InstallError(message)


def load_support(path: Path = SUPPORT, expected_sha256: str = SUPPORT_SHA256) -> Any:
    resolved = path.expanduser().resolve(strict=True)
    require(resolved.parent == SCRIPT.parent, "support module must be a sibling script")
    require(resolved == SUPPORT.resolve(), "support module path differs")
    require(resolved.is_file() and not resolved.is_symlink(), "support module is not a regular file")
    require(hashlib.sha256(resolved.read_bytes()).hexdigest() == expected_sha256,
            "support module hash differs from the pinned packet")
    spec = importlib.util.spec_from_file_location("r8q_diagnostic_trial_support", resolved)
    require(spec is not None and spec.loader is not None, "support module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPPORT_MODULE = load_support()


def digest(path: Path) -> str:
    try:
        with path.open("rb", buffering=0) as stream:
            value = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
            return value.hexdigest()
    except OSError as exc:
        raise InstallError(f"cannot read {path}") from exc


def regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError(f"{label} is unavailable: {path}") from exc
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a regular non-symlink file: {path}")
    return info


def directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError(f"{label} is unavailable: {path}") from exc
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a non-symlink directory: {path}")


def read_json(path: Path, label: str) -> dict[str, Any]:
    regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"{label} is malformed: {path}") from exc
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def safe_relative(value: str, label: str) -> str:
    require(isinstance(value, str) and value and not value.startswith("/"),
            f"{label} is not relative")
    parsed = PurePosixPath(value)
    require("\\" not in value and parsed.as_posix() == value and
            all(part not in ("", ".", "..") for part in parsed.parts),
            f"{label} contains unsafe components")
    return value


def target_path(target_root: Path, absolute: str, label: str) -> Path:
    require(isinstance(absolute, str) and absolute.startswith("/"),
            f"{label} is not absolute")
    relative = safe_relative(absolute[1:], label)
    return target_root / relative


def validate_path_pin(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.startswith("/"), f"{label} is not absolute")
    safe_relative(value[1:], label)
    return value


def validate_packet(packet_path: Path, baseline_path: Path) -> dict[str, Any]:
    packet = read_json(packet_path, "AB arm packet")
    require(packet.get("schema") == "r8q-diagnostic-ab-arm-packet/v1",
            "AB arm packet schema differs")
    require(packet.get("release") == RELEASE and packet.get("current_release") == RELEASE,
            "AB arm packet release differs")
    nonce = packet.get("nonce")
    tag = packet.get("tag")
    require(isinstance(nonce, str) and HEX32.fullmatch(nonce), "AB packet nonce differs")
    require(isinstance(tag, str) and re.fullmatch(r"[A-Za-z0-9._-]+", tag),
            "AB packet tag differs")
    revision = packet.get("rearm_revision")
    require(isinstance(revision, str) and REVISION.fullmatch(revision),
            "AB packet rearm revision differs")
    require(packet.get("support_sha256") == SUPPORT_SHA256,
            "AB packet support binding differs")
    baseline_sha256 = packet.get("baseline_sha256")
    require(isinstance(baseline_sha256, str) and HEX64.fullmatch(baseline_sha256) and
            digest(baseline_path) == baseline_sha256, "AB baseline hash differs from packet")
    original = packet.get("original_candidate")
    require(isinstance(original, dict), "AB original candidate binding is missing")
    require(original.get("nonce") == nonce and original.get("tag") == tag and
            original.get("candidate_sha256") == ORIGINAL_CANDIDATE_SHA256 and
            original.get("candidate_bytes") == ORIGINAL_CANDIDATE_BYTES and
            isinstance(original.get("dependency_sha256"), str) and
            original.get("dependency_sha256") == ORIGINAL_CANDIDATE_MANIFEST_SHA256,
            "AB original candidate binding differs")
    cache = packet.get("cache")
    require(cache == {"partuuid": CACHE_PARTUUID, "partname": CACHE_PARTNAME,
                      "bytes": CACHE_BYTES, "logical_block_size": CACHE_BLOCK_SIZE,
                      "fstype": CACHE_FSTYPE}, "AB CACHE identity differs")
    for key in ("source_journal_path", "source_plan_path", "old_manifest_backup_path"):
        validate_path_pin(packet.get(key), f"AB {key}")
    require(packet.get("manifest_path") == PROTECTED_MANIFEST,
            "AB protected manifest path differs")
    for key in ("source_journal_sha256", "source_plan_sha256", "old_manifest_sha256"):
        require(isinstance(packet.get(key), str) and HEX64.fullmatch(packet[key]),
                f"AB {key} hash differs")
    require(packet.get("old_manifest_sha256") == SUPPORT_MODULE.PROTECTED_MANIFEST_SHA256,
            "AB original 410-manifest pin differs")
    runtime = packet.get("runtime")
    require(isinstance(runtime, dict), "AB runtime binding is missing")
    for key in ("manifest_sha256", "provenance_sha256", "embedded_initramfs_sha256",
                "raw_initramfs_sha256", "compressed_initramfs_sha256"):
        require(isinstance(runtime.get(key), str) and HEX64.fullmatch(runtime[key]),
                f"AB runtime binding is malformed: {key}")
    require(packet.get("baseline_path") in (None, ""),
            "AB packet must not bind a host baseline path")
    validate_cache_baseline_packet(packet)
    return packet


def validate_cache_baseline_packet(packet: dict[str, Any]) -> dict[str, dict[str, int | str]]:
    value = packet.get("cache_baseline")
    require(isinstance(value, dict) and value.get("sha256") == CACHE_BASELINE_SHA256 and
            set(value) == {"sha256", "capture"},
            "AB CACHE baseline hash differs")
    capture = value.get("capture")
    require(isinstance(capture, dict) and capture.get("schema") == "r8q-diagnostic-ab-cache-baseline/v1" and
            hashlib.sha256((json.dumps(capture, indent=2, sort_keys=True) + "\n").encode()).hexdigest() ==
            value["sha256"], "AB CACHE baseline capture hash differs")
    files = capture.get("files")
    require(isinstance(files, dict) and len(files) == 18,
            "AB CACHE baseline must contain exactly 18 files")
    normalized: dict[str, dict[str, int | str]] = {}
    for relative, row in files.items():
        safe_relative(relative, "AB CACHE baseline path")
        require(isinstance(row, dict) and type(row.get("bytes")) is int and row["bytes"] >= 0 and
                isinstance(row.get("sha256"), str) and HEX64.fullmatch(row["sha256"]),
                f"AB CACHE baseline record is malformed: {relative}")
        normalized[relative] = {"bytes": row["bytes"], "sha256": row["sha256"]}
    return normalized


def validate_baseline(path: Path) -> dict[str, Any]:
    baseline = read_json(path, "523-entry AB baseline")
    require(baseline.get("schema") == BASELINE_SCHEMA and
            baseline.get("current_release") == RELEASE and
            baseline.get("manifest_path") == PROTECTED_MANIFEST,
            "AB baseline identity differs")
    records = baseline.get("files")
    require(isinstance(records, dict) and len(records) == 523,
            "AB baseline must contain exactly 523 files")
    normalized: dict[str, dict[str, Any]] = {}
    for absolute, row in records.items():
        require(isinstance(absolute, str) and absolute.startswith("/"),
                "AB baseline path is not absolute")
        safe_relative(absolute[1:], "AB baseline path")
        require(isinstance(row, dict) and row.get("kind") == "file" and
                type(row.get("bytes")) is int and row["bytes"] >= 0 and
                type(row.get("mode")) is int and 0 <= row["mode"] <= 0o777 and
                type(row.get("uid")) is int and row["uid"] >= 0 and
                type(row.get("gid")) is int and row["gid"] >= 0 and
                isinstance(row.get("sha256"), str) and HEX64.fullmatch(row["sha256"]),
                f"AB baseline record is malformed: {absolute}")
        normalized[absolute] = dict(row)
    for key in ("manifest_mode", "manifest_uid", "manifest_gid"):
        require(type(baseline.get(key)) is int and baseline[key] >= 0 and
                (key != "manifest_mode" or baseline[key] <= 0o777),
                f"AB baseline {key} is missing or malformed")
    boot_id = baseline.get("boot_id")
    receipt_hash = baseline.get("guard_receipt_sha256")
    require(isinstance(boot_id, str) and boot_id and
            isinstance(receipt_hash, str) and HEX64.fullmatch(receipt_hash),
            "AB baseline boot or guard receipt binding is missing")
    manifest_text = baseline.get("manifest_text")
    require(isinstance(manifest_text, str), "AB baseline manifest text is missing")
    manifest_bytes = manifest_text.encode("utf-8")
    require(hashlib.sha256(manifest_bytes).hexdigest() == baseline.get("manifest_sha256"),
            "AB baseline manifest binding differs")
    manifest_rows = SUPPORT_MODULE.parse_manifest_lines(manifest_bytes)
    expected_rows = {(row["sha256"], absolute) for absolute, row in normalized.items()}
    require(len(manifest_rows) == 523 and len(set(manifest_rows)) == 523 and
            set(manifest_rows) == expected_rows,
            "AB baseline manifest line count differs")
    require(isinstance(baseline.get("old_manifest_backup_path"), str) and
            isinstance(baseline.get("old_manifest_sha256"), str) and
            baseline["old_manifest_sha256"] == SUPPORT_MODULE.PROTECTED_MANIFEST_SHA256,
            "AB original manifest backup binding is missing")
    for key in ("source_journal_path", "source_plan_path", "old_manifest_backup_path"):
        validate_path_pin(baseline.get(key), f"AB baseline {key}")
    for key in ("source_journal_sha256", "source_plan_sha256", "old_manifest_sha256"):
        require(isinstance(baseline.get(key), str) and HEX64.fullmatch(baseline[key]),
                f"AB baseline {key} is malformed")
    return {"metadata": baseline, "records": dict(sorted(normalized.items())),
            "manifest_bytes": manifest_bytes, "metadata_sha256": digest(path)}


def validate_candidate(candidate: Path, packet: dict[str, Any]) -> dict[str, Any]:
    directory(candidate, "AB candidate")
    manifest = read_json(candidate / "ab-candidate-manifest.json", "AB candidate manifest")
    require(manifest.get("kind") == "r8q-diagnostic-ab-candidate" and
            manifest.get("kernel_release") == RELEASE and
            manifest.get("deployable") is True and manifest.get("boot_tested") is False and
            manifest.get("accepted") is False and manifest.get("installed") is False and
            manifest.get("phone_install_performed") is False,
            "AB candidate state is unsafe")
    require(manifest.get("guard_nonce") == packet["nonce"] and
            manifest.get("guard_tag") == packet["tag"] and
            manifest.get("base_efi_sha256") == EFI_SHA256 and
            manifest.get("dtb_sha256") == DTB_SHA256,
            "AB candidate guard or accepted pins differ")
    runtime = packet["runtime"]
    require(manifest.get("runtime_guard_manifest_sha256") == runtime["manifest_sha256"] and
            manifest.get("runtime_provenance_sha256") == runtime["provenance_sha256"] and
            manifest.get("embedded_initramfs_sha256") == runtime["embedded_initramfs_sha256"] and
            manifest.get("raw_initramfs_sha256") == runtime["raw_initramfs_sha256"] and
            manifest.get("compressed_initramfs_sha256") == runtime["compressed_initramfs_sha256"],
            "AB runtime or initramfs binding differs")
    require(manifest.get("canonical_candidate_sha256") ==
            packet["original_candidate"]["dependency_sha256"],
            "AB canonical candidate dependency binding differs")
    delta = manifest.get("config_delta")
    require(isinstance(delta, dict) and set(delta) == {"CONFIG_CMDLINE"},
            "AB candidate config delta is not minimal")
    cmdline_delta = delta["CONFIG_CMDLINE"]
    require(isinstance(cmdline_delta, dict) and isinstance(cmdline_delta.get("before"), str) and
            isinstance(cmdline_delta.get("after"), str) and
            "irqchip.gicv3_pseudo_nmi=1" in cmdline_delta["before"] and
            "irqchip.gicv3_pseudo_nmi=0" in cmdline_delta["after"] and
            cmdline_delta["before"].replace("irqchip.gicv3_pseudo_nmi=1",
                                               "irqchip.gicv3_pseudo_nmi=0") == cmdline_delta["after"],
            "AB candidate pseudo-NMI change is not exactly one token")
    efi = candidate / "payload/BOOTAA64.EFI"
    dtb = candidate / "payload/R8Q-RTC.DTB"
    efi_info = regular(efi, "AB candidate EFI")
    dtb_info = regular(dtb, "AB candidate DTB")
    require(efi_info.st_size > 0 and digest(dtb) == DTB_SHA256 and dtb_info.st_size == DTB_BYTES,
            "AB candidate DTB differs")
    require(not (digest(efi) == packet["original_candidate"]["candidate_sha256"] and
                 efi_info.st_size == packet["original_candidate"]["candidate_bytes"]),
            "AB candidate is the original candidate")
    files = manifest.get("files")
    require(isinstance(files, dict), "AB candidate file inventory is missing")
    for relative, path in (("payload/BOOTAA64.EFI", efi), ("payload/R8Q-RTC.DTB", dtb)):
        row = files.get(relative)
        info = path.stat()
        require(isinstance(row, dict) and row.get("bytes") == info.st_size and
                row.get("sha256") == digest(path), f"AB candidate inventory differs: {relative}")
    if "dependency_sha256" in manifest:
        require(manifest["dependency_sha256"] == packet["original_candidate"]["dependency_sha256"],
                "AB candidate dependency binding differs")
    return {"manifest": manifest, "manifest_sha256": digest(candidate / "ab-candidate-manifest.json"),
            "efi": efi, "efi_sha256": digest(efi), "efi_bytes": efi_info.st_size,
            "dtb_sha256": DTB_SHA256, "dtb_bytes": DTB_BYTES}


def marker_paths(cache_mount: Path, nonce: str) -> dict[str, Path]:
    boot = cache_mount / "EFI/BOOT"
    return {
        "efi": boot / "BOOTAA64.EFI",
        "dtb": boot / "R8Q-RTC.DTB",
        "backup": boot / f"BOOTAA64.EFI.R8Q-DIAG1-SAVED-{nonce}",
        "candidate": boot / f"BOOTAA64.EFI.R8Q-DIAG1-CANDIDATE-{nonce}",
        "temp": boot / f"BOOTAA64.EFI.R8Q-DIAG1-RECOVERY-{nonce}",
        "marker": boot / f"R8Q-DIAG1-GUARD-{nonce}.marker",
        "marker_temp": boot / f"R8Q-DIAG1-GUARD-{nonce}.marker.tmp",
    }


def archived_paths(cache_mount: Path, nonce: str, revision: str) -> dict[str, Path]:
    boot = cache_mount / "EFI/BOOT"
    return {
        "candidate": boot / f"BOOTAA64.EFI.R8Q-DIAG1-AB-ARCHIVE-{revision}-{nonce}-CANDIDATE",
        "marker": boot / f"R8Q-DIAG1-GUARD-{nonce}.marker.AB-ARCHIVE-{revision}",
    }


def marker_text(fields: dict[str, str]) -> str:
    require(set(fields) == MARKER_FIELDS, "marker field set differs")
    return "".join(f"{name}={fields[name]}\n" for name in (
        "schema", "state", "nonce", "tag", "candidate_sha256", "candidate_bytes",
        "accepted_sha256", "accepted_bytes", "cache_partuuid", "cache_partname",
        "cache_bytes", "cache_logical_block_size", "cache_fstype", "efi_rel", "dtb_rel",
        "backup_rel", "temp_rel", "candidate_copy_rel", "marker_rel"))


def parse_marker(path: Path, packet: dict[str, Any], expected_state: str = "consumed",
                 candidate_sha256: str | None = None, candidate_bytes: int | None = None) -> dict[str, str]:
    regular(path, "CACHE guard marker")
    lines = path.read_text(encoding="ascii").splitlines()
    require(len(lines) == 19, "CACHE guard marker line count differs")
    fields: dict[str, str] = {}
    for line in lines:
        require(line.count("=") == 1, "CACHE guard marker contains malformed line")
        key, value = line.split("=", 1)
        require(key not in fields, "CACHE guard marker contains duplicate field")
        fields[key] = value
    require(set(fields) == MARKER_FIELDS and fields["schema"] == MARKER_SCHEMA,
            "CACHE guard marker schema differs")
    require(fields["state"] == expected_state and fields["nonce"] == packet["nonce"] and
            fields["tag"] == packet["tag"], "CACHE guard marker state or packet differs")
    original = packet["original_candidate"]
    expected_candidate_sha256 = candidate_sha256 or original["candidate_sha256"]
    expected_candidate_bytes = candidate_bytes if candidate_bytes is not None else original["candidate_bytes"]
    require(fields["candidate_sha256"] == expected_candidate_sha256 and
            fields["candidate_bytes"] == str(expected_candidate_bytes),
            "CACHE guard marker candidate differs")
    require(fields["accepted_sha256"] == EFI_SHA256 and fields["accepted_bytes"] == str(EFI_BYTES) and
            fields["cache_partuuid"] == CACHE_PARTUUID and fields["cache_partname"] == CACHE_PARTNAME and
            fields["cache_bytes"] == str(CACHE_BYTES) and
            fields["cache_logical_block_size"] == str(CACHE_BLOCK_SIZE) and
            fields["cache_fstype"] == CACHE_FSTYPE,
            "CACHE guard marker identity differs")
    expected = marker_paths(path.parents[2], packet["nonce"])
    expected_relative = {
        "efi_rel": "EFI/BOOT/BOOTAA64.EFI", "dtb_rel": "EFI/BOOT/R8Q-RTC.DTB",
        "backup_rel": expected["backup"].relative_to(path.parents[2]).as_posix(),
        "temp_rel": expected["temp"].relative_to(path.parents[2]).as_posix(),
        "candidate_copy_rel": expected["candidate"].relative_to(path.parents[2]).as_posix(),
        "marker_rel": expected["marker"].relative_to(path.parents[2]).as_posix(),
    }
    for key, value in expected_relative.items():
        require(fields[key] == value, f"CACHE guard marker {key} differs")
    return fields


def validate_baseline_target(target_root: Path, baseline: dict[str, Any]) -> None:
    manifest_path = target_path(target_root, PROTECTED_MANIFEST, "protected manifest")
    regular(manifest_path, "current protected manifest")
    manifest_info = manifest_path.stat()
    metadata = baseline["metadata"]
    require(stat.S_IMODE(manifest_info.st_mode) == metadata["manifest_mode"] and
            manifest_info.st_uid == metadata["manifest_uid"] and
            manifest_info.st_gid == metadata["manifest_gid"] and
            manifest_path.read_bytes() == baseline["manifest_bytes"] and
            digest(manifest_path) == baseline["metadata"]["manifest_sha256"] and
            len(SUPPORT_MODULE.parse_manifest_lines(manifest_path.read_bytes())) == 523,
            "current 523-entry manifest differs")
    SUPPORT_MODULE.verify_protected_files(target_root, baseline["records"])


def validate_original_transaction(target_root: Path, baseline: dict[str, Any], packet: dict[str, Any]) -> None:
    metadata = baseline["metadata"]
    for key, expected in (("source_journal_path", packet["source_journal_path"]),
                          ("source_plan_path", packet["source_plan_path"]),
                          ("old_manifest_backup_path", packet["old_manifest_backup_path"])):
        require(metadata.get(key) == expected, f"AB baseline {key} differs")
    journal_path = target_path(target_root, packet["source_journal_path"], "source journal")
    plan_path = target_path(target_root, packet["source_plan_path"], "source plan")
    backup_path = target_path(target_root, packet["old_manifest_backup_path"], "old manifest backup")
    require(digest(journal_path) == packet["source_journal_sha256"] and
            digest(plan_path) == packet["source_plan_sha256"] and
            digest(backup_path) == packet["old_manifest_sha256"],
            "original transaction or 410 backup hash differs")
    journal = read_json(journal_path, "original transaction journal")
    plan = read_json(plan_path, "original transaction plan")
    require(journal.get("schema") == "r8q-diagnostic-root-transaction/v1" and
            journal.get("state") == "committed" and journal.get("release") == RELEASE and
            journal.get("current_release") == ORIGINAL_RELEASE and
            journal.get("nonce") == packet["nonce"] and journal.get("tag") == packet["tag"] and
            journal.get("journal_path") == packet["source_journal_path"] and
            journal.get("plan_path") == packet["source_plan_path"],
            "original transaction journal identity differs")
    require(plan.get("schema") == "r8q-diagnostic-root-transaction-plan/v1" and
            plan.get("state") == "prepared" and plan.get("nonce") == packet["nonce"] and
            plan.get("tag") == packet["tag"] and
            plan.get("journal_path") == packet["source_journal_path"] and
            plan.get("plan_path") == packet["source_plan_path"],
            "original transaction plan identity differs")
    backup_info = regular(backup_path, "original 410 manifest backup")
    require(backup_info.st_size > 0 and digest(backup_path) == packet["old_manifest_sha256"],
            "original 410 manifest backup readback differs")


def validate_lxc_stopped() -> None:
    output = SUPPORT_MODULE.run_command(
        ["/usr/bin/lxc-info", "-P", "/var/lib/waydroid/lxc", "-n", "waydroid", "-s", "-p"],
        "LXC STOPPED check")
    states = [line.split(":", 1)[1].strip() for line in output.splitlines()
              if line.startswith("State:")]
    require(states == ["STOPPED"], "LXC waydroid is not explicitly STOPPED")


def validate_cache_state(cache_mount: Path, packet: dict[str, Any]) -> dict[str, Path]:
    paths = marker_paths(cache_mount, packet["nonce"])
    boot_directory = cache_mount / "EFI/BOOT"
    for entry in boot_directory.iterdir():
        require(not entry.name.endswith(".tmp") and "RECOVERY" not in entry.name and
                "AB-RESTORE" not in entry.name and "AB-STAGE" not in entry.name,
                f"stale CACHE temporary artifact exists: {entry.name}")
    parse_marker(paths["marker"], packet)
    require(paths["marker_temp"].exists() is False and not paths["marker_temp"].is_symlink(),
            "CACHE guard marker temporary exists")
    for name in ("efi", "dtb", "backup", "candidate"):
        regular(paths[name], f"CACHE {name}")
    require(digest(paths["efi"]) == EFI_SHA256 and paths["efi"].stat().st_size == EFI_BYTES and
            digest(paths["dtb"]) == DTB_SHA256 and paths["dtb"].stat().st_size == DTB_BYTES,
            "CACHE current accepted EFI/DTB differs")
    original = packet["original_candidate"]
    require(digest(paths["backup"]) == EFI_SHA256 and paths["backup"].stat().st_size == EFI_BYTES and
            digest(paths["candidate"]) == original["candidate_sha256"] and
            paths["candidate"].stat().st_size == original["candidate_bytes"],
            "CACHE original candidate or accepted backup differs")
    require(not paths["temp"].exists() and not paths["temp"].is_symlink(),
            "CACHE recovery temporary exists")
    validate_cache_inventory(cache_mount, validate_cache_baseline_packet(packet), set())
    return paths


def cache_relative(path: Path, cache_mount: Path) -> str:
    return path.relative_to(cache_mount).as_posix()


def validate_cache_inventory(cache_mount: Path, baseline_files: dict[str, dict[str, int | str]],
                             owned_paths: set[Path]) -> None:
    observed: dict[str, dict[str, int | str]] = {}
    for path in cache_mount.rglob("*"):
        if path.is_symlink():
            raise InstallError(f"CACHE inventory contains a symlink: {path}")
        if path.is_file():
            info = regular(path, "CACHE inventory file")
            observed[cache_relative(path, cache_mount)] = {
                "bytes": info.st_size, "sha256": digest(path)}
    owned_relative = {cache_relative(path, cache_mount) for path in owned_paths}
    require(set(observed) <= set(baseline_files) | owned_relative,
            "CACHE inventory contains an unknown file")
    for relative, expected in baseline_files.items():
        if relative in owned_relative:
            continue
        actual = observed.get(relative)
        require(actual == expected, f"non-owned CACHE file changed: {relative}")


def validate_armed_cache_state(cache_mount: Path, packet: dict[str, Any],
                               transaction: dict[str, Any], baseline_files: dict[str, dict[str, int | str]],
                               archive_paths: dict[str, Path],
                               allow_accepted_efi: bool = False) -> dict[str, Path]:
    paths = marker_paths(cache_mount, packet["nonce"])
    for name in ("efi", "dtb", "backup", "candidate", "marker"):
        regular(paths[name], f"armed CACHE {name}")
    parse_marker(paths["marker"], packet, "armed",
                 transaction["candidate_efi_sha256"], transaction["candidate_efi_bytes"])
    efi_hash = digest(paths["efi"])
    efi_bytes = paths["efi"].stat().st_size
    require(((efi_hash == transaction["candidate_efi_sha256"] and
              efi_bytes == transaction["candidate_efi_bytes"]) or
             (allow_accepted_efi and efi_hash == EFI_SHA256 and efi_bytes == EFI_BYTES)) and
            digest(paths["candidate"]) == transaction["candidate_efi_sha256"] and
            paths["candidate"].stat().st_size == transaction["candidate_efi_bytes"] and
            digest(paths["dtb"]) == DTB_SHA256 and paths["dtb"].stat().st_size == DTB_BYTES and
            digest(paths["backup"]) == EFI_SHA256 and paths["backup"].stat().st_size == EFI_BYTES,
            "armed CACHE identity differs")
    original = packet["original_candidate"]
    marker_relative = cache_relative(paths["marker"], cache_mount)
    require(marker_relative in baseline_files, "AB marker is absent from CACHE baseline")
    require(regular(archive_paths["candidate"], "AB candidate archive").st_size == original["candidate_bytes"] and
            digest(archive_paths["candidate"]) == original["candidate_sha256"] and
            regular(archive_paths["marker"], "AB marker archive").st_size == baseline_files[marker_relative]["bytes"] and
            digest(archive_paths["marker"]) == baseline_files[marker_relative]["sha256"],
            "AB archived old state differs")
    owned_paths = {paths["efi"], paths["candidate"], paths["marker"], paths["marker_temp"],
                   paths["temp"], archive_paths["candidate"], archive_paths["marker"]}
    validate_cache_inventory(cache_mount, baseline_files, owned_paths)
    return paths


def unmount_cache_for_mode(cache_mount: Path, mounted: bool, fixture: bool) -> None:
    if fixture:
        return
    SUPPORT_MODULE.unmount_cache(cache_mount, mounted, fixture)


def write_bytes_exclusive(path: Path, data: bytes, mode: int, support: Any) -> None:
    require(not path.exists() and not path.is_symlink(), f"refusing to overwrite {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(path, mode)
    info = regular(path, "new CACHE artifact")
    require(info.st_size == len(data) and digest(path) == hashlib.sha256(data).hexdigest(),
            f"CACHE artifact readback differs: {path}")
    support.fsync_path(path.parent)


def publish_bytes(destination: Path, data: bytes, mode: int, stage: Path, support: Any) -> None:
    require(not destination.exists() and not destination.is_symlink(),
            f"refusing to overwrite {destination}")
    write_bytes_exclusive(stage, data, mode, support)
    require(digest(stage) == hashlib.sha256(data).hexdigest() and stage.stat().st_size == len(data),
            f"staged CACHE artifact readback differs: {stage}")
    os.replace(stage, destination)
    support.fsync_path(destination.parent)
    require(digest(destination) == hashlib.sha256(data).hexdigest() and
            destination.stat().st_size == len(data),
            f"published CACHE artifact readback differs: {destination}")


def rename_owned(source: Path, destination: Path, support: Any) -> None:
    regular(source, "CACHE archive source")
    require(not destination.exists() and not destination.is_symlink(),
            f"CACHE archive destination already exists: {destination}")
    os.replace(source, destination)
    support.fsync_path(destination.parent)
    regular(destination, "CACHE archive destination")


def reconcile_rename(source: Path, destination: Path, expected_sha256: str,
                     expected_bytes: int, label: str) -> bool:
    source_exists = source.exists() or source.is_symlink()
    destination_exists = destination.exists() or destination.is_symlink()
    if source_exists and destination_exists:
        raise InstallError(f"{label} rename has both source and destination")
    if source_exists:
        require(not source.is_symlink(), f"{label} source became a symlink")
        info = regular(source, f"{label} source")
        require(info.st_size == expected_bytes and digest(source) == expected_sha256,
                f"{label} source identity differs")
        return False
    require(destination_exists and not destination.is_symlink(),
            f"{label} rename has neither source nor destination")
    info = regular(destination, f"{label} destination")
    require(info.st_size == expected_bytes and digest(destination) == expected_sha256,
            f"{label} destination identity differs")
    return True


def archive_transaction(archive: Path) -> tuple[dict[str, Any], bytes]:
    regular(archive, "AB archive")
    try:
        bundle = tarfile.open(archive, "r")
    except (OSError, tarfile.TarError) as exc:
        raise InstallError("AB archive is unreadable") from exc
    with bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        require(names == ["transaction.json", "efi/BOOTAA64.EFI"],
                "AB archive member inventory differs")
        require(all(member.isfile() and not member.issym() and not member.islnk() and
                    member.uid == 0 and member.gid == 0 and stat.S_IMODE(member.mode) & 0o7000 == 0
                    for member in members), "AB archive member is unsafe")
        transaction_stream = bundle.extractfile("transaction.json")
        efi_stream = bundle.extractfile("efi/BOOTAA64.EFI")
        require(transaction_stream is not None and efi_stream is not None,
                "AB archive payload is missing")
        try:
            transaction = json.loads(transaction_stream.read().decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise InstallError("AB archive transaction is malformed") from exc
        require(isinstance(transaction, dict), "AB archive transaction is not an object")
        efi = efi_stream.read()
        require(len(efi) == transaction.get("candidate_efi_bytes") and
                hashlib.sha256(efi).hexdigest() == transaction.get("candidate_efi_sha256"),
                "AB archive EFI hash differs")
        return transaction, efi


def build_archive(candidate: Path, baseline_path: Path, packet_path: Path,
                  output: Path) -> dict[str, Any]:
    baseline = validate_baseline(baseline_path)
    packet = validate_packet(packet_path, baseline_path)
    cache_baseline_files = validate_cache_baseline_packet(packet)
    candidate_info = validate_candidate(candidate, packet)
    transaction = {
        "schema": ARCHIVE_SCHEMA,
        "release": RELEASE,
        "current_release": RELEASE,
        "rearm_revision": packet["rearm_revision"],
        "nonce": packet["nonce"],
        "tag": packet["tag"],
        "candidate_manifest_sha256": candidate_info["manifest_sha256"],
        "candidate_efi_sha256": candidate_info["efi_sha256"],
        "candidate_efi_bytes": candidate_info["efi_bytes"],
        "accepted_efi_sha256": EFI_SHA256,
        "accepted_efi_bytes": EFI_BYTES,
        "accepted_dtb_sha256": DTB_SHA256,
        "accepted_dtb_bytes": DTB_BYTES,
        "cache": packet["cache"],
        "cache_baseline": packet["cache_baseline"],
        "original_candidate": packet["original_candidate"],
        "baseline": {"sha256": baseline["metadata_sha256"],
                      "manifest_sha256": baseline["metadata"]["manifest_sha256"], "entries": 523},
        "source_journal_path": packet["source_journal_path"],
        "source_journal_sha256": packet["source_journal_sha256"],
        "source_plan_path": packet["source_plan_path"],
        "source_plan_sha256": packet["source_plan_sha256"],
        "old_manifest_backup_path": packet["old_manifest_backup_path"],
        "old_manifest_sha256": packet["old_manifest_sha256"],
        "phone_operations": False,
        "rootfs_changes": False,
        "raw_boot_writes": False,
        "raw_uefi_writes": False,
        "raw_userdata_writes": False,
        "hotload_hardware": False,
    }
    output = output.expanduser().resolve(strict=False)
    archive = output / "r8q-diagnostic-ab.tar"
    require(not archive.exists() and not output.is_symlink(), f"AB output already exists: {output}")
    output.mkdir(parents=True, exist_ok=False)
    metadata = (json.dumps(transaction, indent=2, sort_keys=True) + "\n").encode()
    with tarfile.open(archive, "w") as bundle:
        for name, data, mode in (("transaction.json", metadata, 0o600),
                                 ("efi/BOOTAA64.EFI", candidate_info["efi"].read_bytes(), 0o600)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            bundle.addfile(info, __import__("io").BytesIO(data))
    os.chmod(archive, 0o600)
    plan = {"schema": "r8q-diagnostic-ab-installation-plan/v1", **transaction,
            "archive": {"path": str(archive), "bytes": archive.stat().st_size,
                        "sha256": digest(archive)},
            "candidate": {"manifest_sha256": candidate_info["manifest_sha256"],
                          "efi_sha256": candidate_info["efi_sha256"],
                          "efi_bytes": candidate_info["efi_bytes"]}}
    plan_path = output / "installation-plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(plan_path, 0o600)
    return {"archive": plan["archive"], "plan_path": str(plan_path), "transaction": transaction}


def run_builder_check() -> None:
    builder = REPO / "scripts/build-r8q-diagnostic-ab.py"
    regular(builder, "AB candidate builder")
    try:
        result = subprocess.run(
            [sys.executable, str(builder), "--check-final"], cwd=REPO,
            capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("AB candidate builder check failed") from exc
    require(result.returncode == 0,
            "AB candidate builder --check-final failed: " +
            (result.stderr.strip()[-2000:] or result.stdout.strip()[-2000:]))


def validate_archive(archive: Path, baseline_path: Path, packet_path: Path) -> tuple[dict[str, Any], bytes]:
    baseline = validate_baseline(baseline_path)
    packet = validate_packet(packet_path, baseline_path)
    cache_baseline_files = validate_cache_baseline_packet(packet)
    transaction, efi = archive_transaction(archive)
    require(transaction.get("schema") == ARCHIVE_SCHEMA and
            transaction.get("release") == RELEASE and transaction.get("current_release") == RELEASE and
            transaction.get("nonce") == packet["nonce"] and transaction.get("tag") == packet["tag"] and
            transaction.get("rearm_revision") == packet["rearm_revision"] and
            transaction.get("baseline", {}).get("sha256") == baseline["metadata_sha256"] and
            transaction.get("baseline", {}).get("manifest_sha256") == baseline["metadata"]["manifest_sha256"] and
            transaction.get("baseline", {}).get("entries") == 523,
            "AB archive transaction binding differs")
    require(transaction.get("cache_baseline") == packet["cache_baseline"] and
            validate_cache_baseline_packet({"cache_baseline": transaction["cache_baseline"]}) ==
            cache_baseline_files,
            "AB archive CACHE baseline binding differs")
    require(transaction.get("original_candidate") == packet["original_candidate"] and
            transaction.get("source_journal_path") == packet["source_journal_path"] and
            transaction.get("source_journal_sha256") == packet["source_journal_sha256"] and
            transaction.get("source_plan_path") == packet["source_plan_path"] and
            transaction.get("source_plan_sha256") == packet["source_plan_sha256"] and
            transaction.get("old_manifest_backup_path") == packet["old_manifest_backup_path"] and
            transaction.get("old_manifest_sha256") == packet["old_manifest_sha256"],
            "AB archive source identity differs")
    candidate_hash = hashlib.sha256(efi).hexdigest()
    require(transaction.get("candidate_efi_sha256") == candidate_hash and
            transaction.get("candidate_efi_bytes") == len(efi) and candidate_hash != packet["original_candidate"]["candidate_sha256"],
            "AB archive candidate binding differs")
    require(transaction.get("accepted_efi_sha256") == EFI_SHA256 and
            transaction.get("accepted_efi_bytes") == EFI_BYTES and
            transaction.get("accepted_dtb_sha256") == DTB_SHA256 and
            transaction.get("accepted_dtb_bytes") == DTB_BYTES and
            transaction.get("raw_boot_writes") is False and transaction.get("raw_uefi_writes") is False and
            transaction.get("raw_userdata_writes") is False and transaction.get("rootfs_changes") is False,
            "AB archive safety binding differs")
    return transaction, efi


def validate_target(target_root: Path, baseline: dict[str, Any], packet: dict[str, Any],
                    require_lxc: bool) -> None:
    target_root = SUPPORT_MODULE.ensure_root(target_root, "phone target root")
    SUPPORT_MODULE.validate_phone_identity(target_root, False, expected_release=RELEASE)
    if require_lxc:
        validate_lxc_stopped()
    boot_id_path = target_root / "proc/sys/kernel/random/boot_id"
    receipt_path = target_root / "run/r8q-diagnostic-fallback"
    regular(boot_id_path, "current boot id")
    require(boot_id_path.read_text(encoding="ascii").strip() == baseline["metadata"]["boot_id"],
            "current boot id differs from protected baseline")
    regular(receipt_path, "diagnostic guard receipt")
    require(digest(receipt_path) == baseline["metadata"]["guard_receipt_sha256"],
            "diagnostic guard receipt differs from protected baseline")
    validate_baseline_target(target_root, baseline)
    validate_original_transaction(target_root, baseline, packet)


def validate_fixture_target(target_root: Path, baseline: dict[str, Any], packet: dict[str, Any]) -> None:
    target_root = SUPPORT_MODULE.ensure_root(target_root, "fixture target root")
    validate_baseline_target(target_root, baseline)
    validate_original_transaction(target_root, baseline, packet)


def phone_preflight(archive: Path, baseline_path: Path, packet_path: Path, target_root: Path,
                    cache_mount: Path, cache_device: Path | None = None,
                    fixture: bool = False) -> dict[str, Any]:
    try:
        SUPPORT_MODULE.validate_fixture_scope(target_root, cache_mount, fixture)
        transaction, _efi = validate_archive(archive, baseline_path, packet_path)
        baseline = validate_baseline(baseline_path)
        packet = validate_packet(packet_path, baseline_path)
        if fixture:
            validate_fixture_target(target_root, baseline, packet)
        else:
            validate_target(target_root, baseline, packet, True)
        cache_device = SUPPORT_MODULE.resolve_cache_device(cache_device, fixture)
        mounted = SUPPORT_MODULE.mount_cache(cache_device, cache_mount, fixture)
        try:
            validate_cache_state(cache_mount, packet)
        finally:
            SUPPORT_MODULE.unmount_cache(cache_mount, mounted, fixture)
        return {"result": "PASS", "mode": "phone-preflight", "release": RELEASE,
                "rearm_revision": transaction["rearm_revision"], "baseline_entries": 523,
                "rootfs_changes": False, "raw_boot_writes": False, "raw_uefi_writes": False,
                "raw_userdata_writes": False, "hotload_hardware": False}
    except BaseException as exc:
        return {"result": "FAIL", "mode": "phone-preflight", "error": str(exc),
                "rootfs_changes": False, "raw_boot_writes": False, "raw_uefi_writes": False,
                "raw_userdata_writes": False, "hotload_hardware": False}


def phone_arm(archive: Path, baseline_path: Path, packet_path: Path, target_root: Path,
              cache_mount: Path, cache_device: Path | None = None,
              fixture: bool = False) -> dict[str, Any]:
    mounted = False
    cache_ready = False
    cache_paths: dict[str, Path] | None = None
    archive_paths: dict[str, Path] | None = None
    moved_candidate = False
    moved_marker = False
    candidate_move_intent = False
    marker_move_intent = False
    candidate_owned = False
    marker_temp_owned = False
    marker_published = False
    temp_owned = False
    candidate_stage: Path | None = None
    candidate_stage_owned = False
    candidate_stage_complete = False
    marker_temp_complete = False
    temp_complete = False
    efi_replaced = False
    cache_unmounted = False
    cache_identity_checked = False
    journal_path: Path | None = None
    receipt_path: Path | None = None
    transaction_owned: set[Path] = set()
    transaction: dict[str, Any] | None = None
    packet: dict[str, Any] | None = None
    marker_bytes: bytes | None = None
    baseline_cache_files: dict[str, dict[str, int | str]] = {}
    try:
        SUPPORT_MODULE.validate_fixture_scope(target_root, cache_mount, fixture)
        transaction, efi_data = validate_archive(archive, baseline_path, packet_path)
        baseline = validate_baseline(baseline_path)
        packet = validate_packet(packet_path, baseline_path)
        target_root = SUPPORT_MODULE.ensure_root(target_root, "phone target root")
        if fixture:
            validate_fixture_target(target_root, baseline, packet)
        else:
            validate_target(target_root, baseline, packet, True)
        nonce = packet["nonce"]
        revision = packet["rearm_revision"]
        journal_path = target_path(target_root, f"/root/r8q-diagnostic-ab-transaction-{revision}-{nonce}.json",
                                   "AB journal")
        receipt_path = target_path(target_root, f"/root/r8q-diagnostic-ab-receipt-{revision}-{nonce}.json",
                                   "AB receipt")
        require(not journal_path.exists() and not journal_path.is_symlink() and
                not receipt_path.exists() and not receipt_path.is_symlink(),
                "AB journal or receipt already exists")
        journal = {
            "schema": "r8q-diagnostic-ab-transaction/v1", "state": "prepared",
            "release": RELEASE, "nonce": nonce, "tag": packet["tag"],
            "rearm_revision": revision, "archive_sha256": digest(archive),
            "candidate_efi_sha256": transaction["candidate_efi_sha256"],
            "original_candidate_sha256": packet["original_candidate"]["candidate_sha256"],
            "raw_boot_writes": False, "raw_uefi_writes": False,
            "raw_userdata_writes": False, "rootfs_changes": False,
            "recovery": "preserve journal and CACHE artifacts on rollback failure",
        }
        SUPPORT_MODULE.write_transaction_json(journal_path, journal, transaction_owned)
        cache_device = SUPPORT_MODULE.resolve_cache_device(cache_device, fixture)
        mounted = SUPPORT_MODULE.mount_cache(cache_device, cache_mount, fixture)
        cache_ready = True
        cache_paths = validate_cache_state(cache_mount, packet)
        baseline_cache_files = validate_cache_baseline_packet(packet)
        cache_identity_checked = True
        archive_paths = archived_paths(cache_mount, nonce, revision)
        for path in archive_paths.values():
            require(not path.exists() and not path.is_symlink(),
                    f"AB archive path already exists: {path.name}")
        required_bytes = transaction["candidate_efi_bytes"] * 2 + 16 * 1024 * 1024
        require(shutil.disk_usage(cache_mount).free >= required_bytes,
                "CACHE free space is insufficient for candidate and recovery staging")
        SUPPORT_MODULE.remount_cache(cache_device, cache_mount, fixture)
        candidate_move_intent = True
        rename_owned(cache_paths["candidate"], archive_paths["candidate"], SUPPORT_MODULE)
        moved_candidate = True
        marker_move_intent = True
        rename_owned(cache_paths["marker"], archive_paths["marker"], SUPPORT_MODULE)
        moved_marker = True
        SUPPORT_MODULE.update_transaction_json(journal_path, {**journal, "state": "old-state-archived"})
        candidate_stage = cache_paths["candidate"].with_name(
            cache_paths["candidate"].name + f".AB-STAGE-{revision}")
        require(not candidate_stage.exists() and not candidate_stage.is_symlink(),
                "CACHE candidate staging path already exists")
        candidate_stage_owned = True
        publish_bytes(cache_paths["candidate"], efi_data, 0o600, candidate_stage, SUPPORT_MODULE)
        candidate_stage_owned = False
        candidate_stage_complete = True
        candidate_owned = True
        require(digest(cache_paths["candidate"]) == transaction["candidate_efi_sha256"] and
                cache_paths["candidate"].stat().st_size == transaction["candidate_efi_bytes"],
                "new CACHE candidate copy differs")
        fields = {
            "schema": MARKER_SCHEMA, "state": "armed", "nonce": nonce, "tag": packet["tag"],
            "candidate_sha256": transaction["candidate_efi_sha256"],
            "candidate_bytes": str(transaction["candidate_efi_bytes"]),
            "accepted_sha256": EFI_SHA256, "accepted_bytes": str(EFI_BYTES),
            "cache_partuuid": CACHE_PARTUUID, "cache_partname": CACHE_PARTNAME,
            "cache_bytes": str(CACHE_BYTES), "cache_logical_block_size": str(CACHE_BLOCK_SIZE),
            "cache_fstype": CACHE_FSTYPE, "efi_rel": "EFI/BOOT/BOOTAA64.EFI",
            "dtb_rel": "EFI/BOOT/R8Q-RTC.DTB",
            "backup_rel": cache_paths["backup"].relative_to(cache_mount).as_posix(),
            "temp_rel": cache_paths["temp"].relative_to(cache_mount).as_posix(),
            "candidate_copy_rel": cache_paths["candidate"].relative_to(cache_mount).as_posix(),
            "marker_rel": cache_paths["marker"].relative_to(cache_mount).as_posix(),
        }
        marker_bytes = marker_text(fields).encode("ascii")
        marker_temp_owned = True
        write_bytes_exclusive(cache_paths["marker_temp"], marker_bytes, 0o600, SUPPORT_MODULE)
        marker_temp_complete = True
        marker_published = True
        os.replace(cache_paths["marker_temp"], cache_paths["marker"])
        SUPPORT_MODULE.fsync_path(cache_paths["marker"].parent)
        require(cache_paths["marker"].read_bytes() == marker_bytes and
                stat.S_IMODE(cache_paths["marker"].stat().st_mode) == 0o600,
                "armed CACHE marker readback differs")
        SUPPORT_MODULE.update_transaction_json(journal_path, {**journal, "state": "armed-durable"})
        require(not cache_paths["temp"].exists() and not cache_paths["temp"].is_symlink(),
                "CACHE recovery temporary already exists")
        temp_owned = True
        write_bytes_exclusive(cache_paths["temp"], efi_data, 0o600, SUPPORT_MODULE)
        temp_complete = True
        require(digest(cache_paths["temp"]) == transaction["candidate_efi_sha256"],
                "new CACHE EFI temporary differs")
        efi_replaced = True
        os.replace(cache_paths["temp"], cache_paths["efi"])
        SUPPORT_MODULE.fsync_path(cache_paths["efi"].parent)
        os.sync()
        require(digest(cache_paths["efi"]) == transaction["candidate_efi_sha256"] and
                cache_paths["efi"].stat().st_size == transaction["candidate_efi_bytes"],
                "new CACHE EFI readback differs")
        require(digest(cache_paths["backup"]) == EFI_SHA256 and
                cache_paths["backup"].stat().st_size == EFI_BYTES,
                "accepted CACHE backup changed")
        validate_cache_inventory(
            cache_mount, baseline_cache_files,
            {cache_paths["efi"], cache_paths["candidate"], cache_paths["marker"],
             cache_paths["marker_temp"], cache_paths["temp"],
             archive_paths["candidate"], archive_paths["marker"]})
        SUPPORT_MODULE.update_transaction_json(journal_path, {**journal, "state": "efi-candidate-installed"})
        unmount_cache_for_mode(cache_mount, mounted, fixture)
        cache_unmounted = True
        cache_ready = False
        mounted = False
        journal = {**journal, "state": "committed", "cache_archives": {
            "candidate": str(archive_paths["candidate"].relative_to(cache_mount)),
            "marker": str(archive_paths["marker"].relative_to(cache_mount)),
        }}
        SUPPORT_MODULE.update_transaction_json(journal_path, journal)
        receipt = {"schema": "r8q-diagnostic-ab-receipt/v1", "result": "PASS",
                   "state": "armed", "action": "armed", "release": RELEASE,
                   "rearm_revision": revision, "nonce": nonce, "tag": packet["tag"],
                   "candidate_sha256": transaction["candidate_efi_sha256"],
                   "candidate_bytes": transaction["candidate_efi_bytes"],
                   "accepted_sha256": EFI_SHA256, "accepted_bytes": EFI_BYTES,
                   "raw_boot_writes": False, "raw_uefi_writes": False,
                   "raw_userdata_writes": False, "rootfs_changes": False,
                   "hotload_hardware": False}
        SUPPORT_MODULE.write_transaction_json(receipt_path, receipt, transaction_owned)
        return receipt
    except BaseException as exc:
        rollback_errors: list[str] = []
        rename_reconciliation_failed = False
        if cache_paths is not None and archive_paths is not None and baseline_cache_files:
            if candidate_move_intent and not moved_candidate:
                try:
                    moved_candidate = reconcile_rename(
                        cache_paths["candidate"], archive_paths["candidate"],
                        packet["original_candidate"]["candidate_sha256"],
                        packet["original_candidate"]["candidate_bytes"], "AB candidate")
                except BaseException as reconcile_error:
                    rollback_errors.append("AB candidate rename reconciliation: " + str(reconcile_error))
                    rename_reconciliation_failed = True
            if marker_move_intent and not moved_marker:
                try:
                    marker_relative = cache_relative(cache_paths["marker"], cache_mount)
                    require(marker_relative in baseline_cache_files,
                            "AB marker is absent from CACHE baseline")
                    marker_record = baseline_cache_files[marker_relative]
                    moved_marker = reconcile_rename(
                        cache_paths["marker"], archive_paths["marker"],
                        marker_record["sha256"], marker_record["bytes"], "AB marker")
                except BaseException as reconcile_error:
                    rollback_errors.append("AB marker rename reconciliation: " + str(reconcile_error))
                    rename_reconciliation_failed = True
        if rename_reconciliation_failed:
            cache_identity_checked = False
        if isinstance(exc, SUPPORT_MODULE.CacheUnmountError) and exc.unmounted:
            cache_unmounted = True
            cache_ready = False
        if cache_unmounted and not cache_ready and cache_paths is not None and packet is not None and transaction is not None:
            try:
                cache_identity_checked = False
                if not fixture and not cache_mount.exists():
                    cache_mount.mkdir(mode=0o700)
                mounted = SUPPORT_MODULE.remount_cache_for_rollback(cache_device, cache_mount, fixture)
                cache_ready = True
                validate_armed_cache_state(
                    cache_mount, packet, transaction, baseline_cache_files,
                    archive_paths or archived_paths(cache_mount, packet["nonce"], packet["rearm_revision"]))
                cache_identity_checked = True
            except BaseException as remount_error:
                rollback_errors.append("CACHE rollback remount or identity: " + str(remount_error))
        efi_rollback_failed = False
        if cache_ready and cache_paths is not None and cache_identity_checked:
            if efi_replaced:
                try:
                    validate_armed_cache_state(
                        cache_mount, packet, transaction, baseline_cache_files,
                        archive_paths or archived_paths(cache_mount, packet["nonce"], packet["rearm_revision"]),
                        allow_accepted_efi=True)
                except BaseException as identity_error:
                    rollback_errors.append("CACHE armed identity: " + str(identity_error))
                    cache_identity_checked = False
            if efi_replaced:
                if not cache_identity_checked:
                    efi_rollback_failed = True
                else:
                    try:
                        restore_path = cache_paths["efi"].with_name(
                            f"BOOTAA64.EFI.R8Q-DIAG1-AB-RESTORE-{packet['rearm_revision']}-{packet['nonce']}")
                        require(not restore_path.exists() and not restore_path.is_symlink(),
                                "AB restore path already exists")
                        SUPPORT_MODULE.copy_exclusive(cache_paths["backup"], restore_path, 0o600, set())
                        require(digest(restore_path) == EFI_SHA256, "AB accepted restore copy differs")
                        os.replace(restore_path, cache_paths["efi"])
                        SUPPORT_MODULE.fsync_path(cache_paths["efi"].parent)
                        require(digest(cache_paths["efi"]) == EFI_SHA256, "AB accepted EFI rollback differs")
                    except BaseException as rollback_error:
                        rollback_errors.append("EFI rollback: " + str(rollback_error))
                        efi_rollback_failed = True
            if not efi_rollback_failed:
                try:
                    owned_entries = []
                    if marker_published:
                        owned_entries.append((cache_paths["marker"], marker_bytes, marker_bytes is not None))
                    if marker_temp_owned:
                        owned_entries.append((cache_paths["marker_temp"], marker_bytes, marker_temp_complete))
                    if candidate_owned:
                        owned_entries.append((cache_paths["candidate"], efi_data, True))
                    if candidate_stage_owned and candidate_stage is not None:
                        owned_entries.append((candidate_stage, efi_data, candidate_stage_complete))
                    if temp_owned:
                        owned_entries.append((cache_paths["temp"], efi_data, temp_complete))
                    for path, expected_data, complete in owned_entries:
                        if not (path.exists() or path.is_symlink()):
                            continue
                        require(not path.is_symlink(), f"AB rollback path became symlink: {path}")
                        if complete and expected_data is not None:
                            require(path.stat().st_size == len(expected_data) and
                                    digest(path) == hashlib.sha256(expected_data).hexdigest(),
                                    f"owned AB artifact changed: {path}")
                        else:
                            regular(path, "owned partial AB artifact")
                    for path, _expected_data, _complete in owned_entries:
                        if path.exists() or path.is_symlink():
                            path.unlink()
                            require(not path.exists() and not path.is_symlink(),
                                    f"owned AB artifact removal was not confirmed: {path}")
                    if archive_paths is not None and moved_candidate:
                        rename_owned(archive_paths["candidate"], cache_paths["candidate"], SUPPORT_MODULE)
                    if archive_paths is not None and moved_marker:
                        rename_owned(archive_paths["marker"], cache_paths["marker"], SUPPORT_MODULE)
                except BaseException as rollback_error:
                    rollback_errors.append("CACHE state rollback: " + str(rollback_error))
        if cache_ready:
            try:
                unmount_cache_for_mode(cache_mount, mounted, fixture)
                cache_ready = False
                mounted = False
            except BaseException as unmount_error:
                rollback_errors.append("CACHE unmount: " + str(unmount_error))
        if journal_path is not None and journal_path.exists():
            try:
                state = {"state": "rolled-back" if not rollback_errors else "recovery-required",
                         "error": str(exc), "rollback_errors": rollback_errors}
                prior = read_json(journal_path, "AB journal")
                SUPPORT_MODULE.update_transaction_json(journal_path, {**prior, **state})
            except BaseException as journal_error:
                rollback_errors.append("AB journal update: " + str(journal_error))
        return {"result": "FAIL", "mode": "phone-arm", "error": str(exc),
                "rollback_errors": rollback_errors, "recovery_required": bool(rollback_errors),
                "raw_boot_writes": False, "raw_uefi_writes": False,
                "raw_userdata_writes": False, "rootfs_changes": False,
                "hotload_hardware": False}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--package", action="store_true")
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--phone-preflight", action="store_true")
    modes.add_argument("--phone-arm", action="store_true")
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--target-root", type=Path, default=Path("/"))
    parser.add_argument("--cache-mount", type=Path, default=Path("/run/r8q-diagnostic-cache"))
    parser.add_argument("--cache-device", type=Path)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--support", type=Path, default=SUPPORT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        options = parse_args(argv or sys.argv[1:])
        require(options.support.resolve() == SUPPORT.resolve(), "unsupported support path")
        if options.package:
            require(not options.fixture, "--package cannot use fixture mode")
            require(options.candidate.resolve() == DEFAULT_CANDIDATE.resolve(),
                    "--package only supports the canonical AB candidate")
            run_builder_check()
            result = build_archive(options.candidate.resolve(), options.baseline.resolve(),
                                   options.packet.resolve(), options.output)
            print(json.dumps({"result": "PASS", **result}, sort_keys=True))
            return 0
        require(options.archive is not None, "--archive is required")
        if options.check:
            transaction, _efi = validate_archive(options.archive.resolve(), options.baseline.resolve(),
                                                 options.packet.resolve())
            print(json.dumps({"result": "PASS", "mode": "check", "rearm_revision": transaction["rearm_revision"],
                              "candidate_efi_sha256": transaction["candidate_efi_sha256"],
                              "raw_boot_writes": False, "raw_uefi_writes": False,
                              "raw_userdata_writes": False, "rootfs_changes": False}, sort_keys=True))
            return 0
        if options.phone_preflight:
            result = phone_preflight(options.archive.resolve(), options.baseline.resolve(),
                                     options.packet.resolve(), options.target_root, options.cache_mount,
                                     options.cache_device, options.fixture)
        else:
            result = phone_arm(options.archive.resolve(), options.baseline.resolve(), options.packet.resolve(),
                               options.target_root, options.cache_mount, options.cache_device, options.fixture)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("result") == "PASS" else 1
    except (InstallError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"install-r8q-diagnostic-ab: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
