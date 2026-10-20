#!/usr/bin/env python3
"""Package and transactionally install the r8q diagnostic trial.

Packaging is offline and never contacts a phone.  The phone-side routine is
explicitly invoked with ``--phone-install`` and only writes the encrypted
root's reviewed diagnostic paths plus CACHE EFI transaction artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, BinaryIO


SCRIPT = Path(__file__).resolve()
REPO = SCRIPT.parents[1]
OUT = REPO / "out"
DEFAULT_CANDIDATE = OUT / "diagnostic-kernel-20261020" / "kernel"
DEFAULT_RUNTIME = OUT / "diagnostic-kernel-20261020" / "runtime-preparation"
DEFAULT_INITRAMFS = OUT / "diagnostic-kernel-20261020" / "initramfs"
DEFAULT_BASELINE = OUT / "diagnostic-kernel-20261020" / "protected-baseline-metadata.json"
DEFAULT_OUTPUT = OUT / "diagnostic-kernel-20261020" / "deployment-preparation"
RELEASE = "7.1.2-r8q-diag1"
CURRENT_RELEASE = "7.1.2-r8q-waydroid2"
VERMAGIC = f"{RELEASE} SMP preempt mod_unload aarch64"
EFI_SHA256 = "f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b"
EFI_BYTES = 67631616
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
DTB_BYTES = 124302
MACHINE_ID = "1290f2212bd743569044571db21a6c96"
ROOT_UUID = "217b9308-40c7-4eb0-90a9-09ed4e233173"
ROOT_SOURCE = "/dev/mapper/cryptroot"
ROOT_PARTUUID = "1b81e7e6-f50d-419b-a739-2aeef8da3335"
ROOT_LUKS_UUID = "b9081516-2446-4086-87c1-76d2127493ec"
ROOT_DEVICE_BYTES = 115107409920
CACHE_PARTUUID = "5594c694-c871-4b5f-90b1-690a6f68e0f7"
CACHE_PARTNAME = "cache"
CACHE_BYTES = 629145600
CACHE_SECTORS = 1228800
CACHE_BLOCK_SIZE = 4096
CACHE_FSTYPE = "vfat"
DISK_GUID = "98101b32-bbe2-4bf2-a06e-2bb33d000c20"
PROTECTED_MANIFEST = "/root/r8q-screen-lock-20261013.sha256"
PROTECTED_MANIFEST_SHA256 = "1b63409d3e1cb9662d8f97bdbe59b53d06b967979967d18218ddd7280251922b"
PROTECTED_ENTRY_COUNT = 410
PROTECTED_SCHEMA = "r8q-protected-baseline-metadata/v1"
PROFILE_PREFIX = f"usr/local/lib/r8q-kernel-profiles/{RELEASE}/rootfs/"
MODULE_PREFIX = f"usr/lib/modules/{RELEASE}/"
DROPINS = frozenset({
    "etc/systemd/system/r8q-hardware-prepare.service.d/95-r8q-diag1-dispatch.conf",
    "etc/systemd/system/r8q-battery.service.d/95-r8q-diag1-dispatch.conf",
    "etc/systemd/system/r8q-usb-gadget.service.d/95-r8q-diag1-dispatch.conf",
    "etc/systemd/system/r8q-audio-start.service.d/95-r8q-diag1-dispatch.conf",
    "etc/systemd/system/r8q-wifi-standby.service.d/95-r8q-diag1-dispatch.conf",
})
GUARD_HELPER_PATH = "bin/r8q-diagnostic-busybox"
GUARD_HELPER_LINKS = frozenset({"cp", "mv", "readlink", "sha256sum", "stat"})
MARGIN_BYTES = 16 * 1024 * 1024
ARCHIVE_NAME = "r8q-diagnostic-trial.tar"
PLAN_NAME = "installation-plan.json"
RECEIPT_NAME = "installation-receipt.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")


class InstallError(RuntimeError):
    """Raised when a package or phone transaction fails closed."""


class CacheUnmountError(InstallError):
    def __init__(self, message: str, unmounted: bool):
        super().__init__(message)
        self.unmounted = unmounted


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InstallError(message)


def digest(path: Path, label: str = "file") -> str:
    regular(path, label)
    result = hashlib.sha256()
    try:
        with path.open("rb", buffering=0) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(block)
    except OSError as exc:
        raise InstallError(f"cannot read {label}: {path}") from exc
    return result.hexdigest()


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
        raise InstallError(f"{label} is not valid JSON: {path}") from exc
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def safe_relative(value: str, label: str) -> str:
    require(isinstance(value, str) and value and not value.startswith("/"),
            f"{label} is not relative")
    parsed = PurePosixPath(value)
    require("\\" not in value and parsed.as_posix() == value and
            all(part not in ("", ".", "..") for part in parsed.parts),
            f"{label} contains unsafe components: {value!r}")
    return value


def ensure_root(root: Path, label: str) -> Path:
    root = root.expanduser()
    require(not root.is_symlink(), f"{label} is a symlink")
    root = root.resolve(strict=False)
    directory(root, label)
    require(root != Path("/") or label == "phone target root",
            f"{label} is unsafe")
    return root


def ensure_parent(root: Path, relative: str, created: list[Path]) -> Path:
    safe_relative(relative, "transaction path")
    parent = root
    parts = PurePosixPath(relative).parts[:-1]
    missing: list[Path] = []
    for part in parts:
        parent = parent / part
        if parent.exists() or parent.is_symlink():
            require(parent.is_dir() and not parent.is_symlink(),
                    f"transaction parent is unsafe: {parent}")
        else:
            missing.append(parent)
    for path in missing:
        path.mkdir(mode=0o755)
        os.chmod(path, 0o755)
        created.append(path)
        fsync_path(path)
        fsync_path(path.parent)
    return root / relative


def validate_existing_parent(root: Path, relative: str, label: str) -> None:
    safe_relative(relative, label)
    parent = root
    for part in PurePosixPath(relative).parts[:-1]:
        parent = parent / part
        require(parent.exists() and parent.is_dir() and not parent.is_symlink(),
                f"{label} parent is unsafe: {parent}")


def file_row(path: Path, relative: str) -> dict[str, Any]:
    info = regular(path, relative)
    mode = stat.S_IMODE(info.st_mode)
    require(mode & 0o7000 == 0, f"{relative} has special mode bits")
    return {"path": relative, "bytes": info.st_size, "mode": mode,
            "sha256": digest(path, relative)}


def allowed_runtime_path(relative: str) -> bool:
    return relative.startswith(PROFILE_PREFIX) or relative.startswith(MODULE_PREFIX) or relative in DROPINS


def allowed_runtime_tree_path(relative: str) -> bool:
    if allowed_runtime_path(relative):
        return True
    prefix = relative.rstrip("/") + "/"
    return any(candidate.startswith(prefix) for candidate in (PROFILE_PREFIX, MODULE_PREFIX, *DROPINS))


def runtime_tree_records(rootfs: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for current, directory_names, file_names in os.walk(rootfs, topdown=True,
                                                         followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        kept_directories: list[str] = []
        for name in directory_names:
            path = current_path / name
            relative = path.relative_to(rootfs).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                records[relative] = {"type": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                     "target": os.readlink(path)}
                continue
            require(stat.S_ISDIR(info.st_mode), f"runtime tree contains special directory: {relative}")
            records[relative] = {"type": "directory", "mode": stat.S_IMODE(info.st_mode)}
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(rootfs).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                records[relative] = {"type": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                     "target": os.readlink(path)}
                continue
            require(stat.S_ISREG(info.st_mode), f"runtime tree contains special file: {relative}")
            records[relative] = {"type": "file", "mode": stat.S_IMODE(info.st_mode),
                                 "bytes": info.st_size, "sha256": digest(path, relative)}
    return records


def validate_runtime_guard(value: Any, label: str) -> tuple[str, str]:
    require(isinstance(value, dict) and value.get("accepted_efi_sha256") == EFI_SHA256 and
            value.get("accepted_dtb_sha256") == DTB_SHA256 and
            isinstance(value.get("nonce"), str) and HEX32.fullmatch(value["nonce"]) and
            isinstance(value.get("tag"), str) and
            re.fullmatch(r"[A-Za-z0-9._-]+", value["tag"]),
            f"{label} guard binding differs")
    return value["nonce"], value["tag"]


def validate_candidate(candidate: Path) -> dict[str, Any]:
    directory(candidate, "diagnostic final candidate")
    manifest = read_json(candidate / "candidate-manifest.json", "diagnostic candidate manifest")
    require(manifest.get("kind") == "r8q-diagnostic-kernel-candidate",
            "candidate manifest kind is not the deployable diagnostic candidate")
    require(manifest.get("kernel_release") == RELEASE and manifest.get("deployable") is True and
            manifest.get("stage2_complete") is True and manifest.get("stage2_required") is False,
            "candidate is not the completed deployable diag1 candidate")
    require(manifest.get("installed") is False and manifest.get("boot_tested") is False and
            manifest.get("deployment_prepared") is False,
            "candidate manifest has already been installed or tested")
    files = manifest.get("files")
    require(isinstance(files, dict), "candidate file inventory is missing")
    efi = candidate / "payload/BOOTAA64.EFI"
    dtb = candidate / "payload/R8Q-RTC.DTB"
    efi_info = regular(efi, "candidate EFI")
    dtb_info = regular(dtb, "candidate DTB")
    efi_row = files.get("payload/BOOTAA64.EFI")
    dtb_row = files.get("payload/R8Q-RTC.DTB")
    require(isinstance(efi_row, dict) and efi_row.get("sha256") == digest(efi) and
            efi_row.get("bytes") == efi_info.st_size,
            "candidate EFI inventory differs")
    require(isinstance(dtb_row, dict) and dtb_row.get("sha256") == DTB_SHA256 and
            dtb_row.get("bytes") == DTB_BYTES and digest(dtb) == DTB_SHA256,
            "candidate DTB does not match the accepted pin")
    require(manifest.get("base_efi_sha256") == EFI_SHA256 and
            manifest.get("dtb_sha256") == DTB_SHA256,
            "candidate accepted artifact pins differ")
    guard = manifest.get("runtime_guard")
    validate_runtime_guard(guard, "candidate")
    helper = manifest.get("guard_helper")
    require(isinstance(helper, dict) and helper.get("path") == GUARD_HELPER_PATH and
            isinstance(helper.get("sha256"), str) and HEX64.fullmatch(helper["sha256"]) and
            type(helper.get("bytes")) is int and helper["bytes"] > 0,
            "candidate guard helper binding is missing")
    symlinks = helper.get("symlinks")
    require(isinstance(symlinks, dict) and set(symlinks) == GUARD_HELPER_LINKS and
            all(value == GUARD_HELPER_PATH for value in symlinks.values()),
            "candidate guard helper symlink binding differs")
    return {"manifest": manifest, "manifest_sha256": digest(candidate / "candidate-manifest.json"),
            "runtime_guard": guard,
            "efi": file_row(efi, "payload/BOOTAA64.EFI"), "efi_path": efi,
            "dtb": file_row(dtb, "payload/R8Q-RTC.DTB")}


def validate_baseline(path: Path, expected_entries: int = PROTECTED_ENTRY_COUNT,
                      expected_manifest_sha256: str = PROTECTED_MANIFEST_SHA256) -> dict[str, Any]:
    baseline = read_json(path, "protected baseline metadata")
    require(baseline.get("schema") == PROTECTED_SCHEMA,
            "protected baseline metadata schema differs")
    require(baseline.get("manifest_sha256") == expected_manifest_sha256,
            "protected manifest pin differs")
    records = baseline.get("files")
    require(isinstance(records, dict) and len(records) == expected_entries,
            f"protected baseline must contain exactly {expected_entries} files")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_path, row in records.items():
        require(isinstance(raw_path, str) and raw_path.startswith("/"),
                "protected baseline path is not absolute")
        relative = safe_relative(raw_path[1:], "protected baseline path")
        require("/" + relative == raw_path, f"protected baseline path is not canonical: {raw_path}")
        require(isinstance(row, dict) and row.get("kind", "file") == "file",
                f"protected baseline entry is not a file: {raw_path}")
        require(type(row.get("bytes")) is int and row["bytes"] >= 0 and
                type(row.get("mode")) is int and 0 <= row["mode"] <= 0o777 and
                isinstance(row.get("sha256"), str) and HEX64.fullmatch(row["sha256"]),
                f"protected baseline entry is malformed: {raw_path}")
        for identity in ("uid", "gid"):
            if identity in row:
                require(type(row[identity]) is int and row[identity] >= 0,
                        f"protected baseline {identity} is malformed: {raw_path}")
        normalized[raw_path] = dict(row)
    return {"schema": baseline["schema"], "manifest_sha256": expected_manifest_sha256,
            "entries": expected_entries, "path_records": dict(sorted(normalized.items())),
            "source": str(path), "source_sha256": digest(path)}


def validate_runtime(runtime: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    runtime = runtime.expanduser().resolve(strict=False)
    nested_rootfs = runtime / "rootfs"
    require(not nested_rootfs.is_symlink(), "diagnostic runtime rootfs is a symlink")
    rootfs = nested_rootfs if nested_rootfs.is_dir() else runtime
    directory(rootfs, "diagnostic runtime rootfs")
    manifest_path = rootfs.parent / "runtime-manifest.json"
    manifest = read_json(manifest_path, "diagnostic hardware runtime manifest")
    require(manifest.get("kind") == "r8q-diagnostic-hardware-preparation" and
            manifest.get("kernel_release") == RELEASE and manifest.get("phone_operations") is False,
            "diagnostic hardware runtime manifest differs")
    require(manifest.get("accepted_efi_sha256") == EFI_SHA256 and
            manifest.get("accepted_dtb_sha256") == DTB_SHA256,
            "diagnostic hardware accepted artifact pins differ")
    stage_binding = manifest.get("stage1_manifest")
    require(isinstance(stage_binding, dict) and isinstance(stage_binding.get("path"), str) and
            isinstance(stage_binding.get("sha256"), str) and HEX64.fullmatch(stage_binding["sha256"]),
            "diagnostic hardware stage1 provenance is missing")
    stage_path = Path(stage_binding["path"]).expanduser().resolve(strict=False)
    regular(stage_path, "diagnostic hardware stage1 manifest")
    require(digest(stage_path) == stage_binding["sha256"],
            "diagnostic hardware stage1 manifest hash differs")
    records = manifest.get("files")
    require(isinstance(records, list), "diagnostic hardware runtime file inventory is missing")
    indexed: dict[str, dict[str, Any]] = {}
    for row in records:
        require(isinstance(row, dict) and isinstance(row.get("path"), str),
                "diagnostic runtime file row is malformed")
        safe_relative(row["path"], "diagnostic runtime inventory path")
        require(row["path"] not in indexed,
                "diagnostic runtime file inventory contains duplicate paths")
        indexed[row["path"]] = row
    observed_tree = runtime_tree_records(rootfs)
    require(set(indexed) == set(observed_tree),
            "diagnostic runtime inventory does not match the complete rootfs tree")
    provenance_path = rootfs.parent / "provenance.json"
    provenance = read_json(provenance_path, "diagnostic hardware provenance")
    require(provenance.get("schema") == "r8q-diagnostic-runtime-provenance/v1" and
            provenance.get("mode") == "hardware" and
            provenance.get("accepted_efi_sha256") == EFI_SHA256 and
            provenance.get("accepted_dtb_sha256") == DTB_SHA256,
            "diagnostic hardware provenance differs")
    accepted_rootfs_value = provenance.get("accepted_rootfs")
    accepted_bundle_value = provenance.get("accepted_bundle_manifest")
    require(isinstance(accepted_rootfs_value, str) and isinstance(accepted_bundle_value, str),
            "diagnostic hardware accepted provenance paths are missing")
    accepted_rootfs = Path(accepted_rootfs_value).expanduser().resolve(strict=False)
    accepted_bundle = Path(accepted_bundle_value).expanduser().resolve(strict=False)
    directory(accepted_rootfs, "accepted hardware rootfs provenance")
    accepted_tree = runtime_tree_records(accepted_rootfs)
    regular(accepted_bundle, "accepted hardware bundle manifest provenance")
    require(provenance.get("accepted_bundle_manifest_sha256") == digest(accepted_bundle),
            "accepted hardware bundle manifest hash differs")
    require(provenance.get("stage1_manifest") == str(stage_path) and
            provenance.get("stage1_manifest_sha256") == digest(stage_path),
            "diagnostic hardware stage1 provenance differs")
    module_selection = manifest.get("module_selection")
    require(isinstance(module_selection, dict) and module_selection.get("accepted_count") == 78 and
            isinstance(module_selection.get("accepted_names"), list) and
            len(module_selection["accepted_names"]) == 78 and
            len(set(module_selection["accepted_names"])) == 78 and
            isinstance(module_selection.get("global_rows"), list) and
            len(module_selection["global_rows"]) == 42,
            "diagnostic hardware module selection provenance differs")
    require(provenance.get("module_selection_count") == 78 and
            isinstance(provenance.get("modules"), dict) and
            set(provenance["modules"]) == set(module_selection["accepted_names"]),
            "diagnostic hardware module provenance differs")
    source_module_root_value = provenance.get("source_module_root")
    require(isinstance(source_module_root_value, str),
            "diagnostic hardware source module root is missing")
    source_module_root = Path(source_module_root_value).expanduser().resolve(strict=False)
    directory(source_module_root, "diagnostic hardware source module root")
    for name, module_row in provenance["modules"].items():
        require(isinstance(module_row, dict) and isinstance(module_row.get("path"), str) and
                module_row.get("module_name") == name and module_row.get("vermagic") == VERMAGIC and
                isinstance(module_row.get("sha256"), str) and HEX64.fullmatch(module_row["sha256"]) and
                type(module_row.get("bytes")) is int,
                f"diagnostic hardware module provenance row is malformed: {name}")
        source_module = Path(module_row["path"]).expanduser().resolve(strict=False)
        require(source_module_root in source_module.parents,
                f"diagnostic hardware module escaped source root: {name}")
        source_info = regular(source_module, f"diagnostic hardware source module {name}")
        require(source_info.st_size == module_row["bytes"] and
                digest(source_module) == module_row["sha256"],
                f"diagnostic hardware source module hash differs: {name}")
    for relative, expected in observed_tree.items():
        row = indexed[relative]
        require(row.get("type") == expected["type"] and
                type(row.get("mode")) is int and row["mode"] == expected["mode"],
                f"diagnostic runtime inventory metadata differs for {relative}")
        if expected["type"] == "file":
            require(type(row.get("bytes")) is int and row["bytes"] == expected["bytes"] and
                    row.get("sha256") == expected["sha256"],
                    f"diagnostic runtime inventory content differs for {relative}")
        elif expected["type"] == "symlink":
            require(row.get("target") == expected["target"],
                    f"diagnostic runtime inventory symlink differs for {relative}")
        source = row.get("source")
        require(isinstance(source, str), f"diagnostic runtime source provenance is missing for {relative}")
        if source == "generated":
            require(allowed_runtime_tree_path(relative),
                    f"generated runtime path is outside the diagnostic namespace: {relative}")
            if expected["type"] == "file":
                require(allowed_runtime_path(relative),
                        f"generated runtime file is outside the package namespace: {relative}")
            else:
                require(expected["type"] == "directory",
                        f"generated runtime namespace contains a symlink: {relative}")
        else:
            source_path = Path(source).expanduser().resolve(strict=False)
            require(source_path == (accepted_rootfs / relative).resolve(strict=False),
                    f"accepted runtime source path differs for {relative}")
            source_row = accepted_tree.get(relative)
            require(source_row == expected,
                    f"accepted runtime source content differs for {relative}")
    selected: list[dict[str, Any]] = []
    observed: set[str] = set()
    for relative, row in sorted(observed_tree.items()):
        if row["type"] != "file" or not allowed_runtime_path(relative):
            continue
        selected.append({"path": relative, "bytes": row["bytes"], "mode": row["mode"],
                         "sha256": row["sha256"]})
        observed.add(relative)
    require(DROPINS <= observed, "diagnostic runtime is missing one of the five dispatch drop-ins")
    require(selected, "diagnostic runtime has no packageable files")
    require(all(allowed_runtime_path(row["path"]) for row in selected),
            "diagnostic runtime contains a path outside the package allowlist")
    return sorted(selected, key=lambda row: row["path"]), manifest


def transaction_metadata(candidate_info: dict[str, Any], runtime_manifest: dict[str, Any],
                         runtime_rows: list[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "r8q-diagnostic-trial-archive/v1",
        "release": RELEASE,
        "current_release": CURRENT_RELEASE,
        "rootfs": runtime_rows,
        "efi": candidate_info["efi"],
        "manifest_path": PROTECTED_MANIFEST,
        "protected_baseline": baseline,
        "machine_id": MACHINE_ID,
        "root_uuid": ROOT_UUID,
        "current_uname": CURRENT_RELEASE,
        "cache": {"partuuid": CACHE_PARTUUID, "partname": CACHE_PARTNAME,
                   "bytes": CACHE_BYTES, "sectors": CACHE_SECTORS, "logical_block_size": CACHE_BLOCK_SIZE,
                   "fstype": CACHE_FSTYPE, "dtb_sha256": DTB_SHA256, "dtb_bytes": DTB_BYTES},
        "candidate_manifest_sha256": candidate_info["manifest_sha256"],
        "runtime_guard": candidate_info["runtime_guard"],
        "runtime_manifest_sha256": None,
        "phone_operations": False,
        "raw_boot_writes": False,
        "raw_uefi_writes": False,
        "raw_userdata_writes": False,
        "hotload_hardware": False,
    }


def add_tar_file(bundle: tarfile.TarFile, name: str, data: bytes, mode: int = 0o600) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    bundle.addfile(info, __import__("io").BytesIO(data))


def run_finalizer_check(initramfs: Path) -> None:
    finalizer = REPO / "scripts/finalize-r8q-diagnostic-candidate.py"
    regular(finalizer, "diagnostic candidate finalizer")
    command = [sys.executable, str(finalizer), "--check-final-existing",
               "--runtime-initramfs", str(initramfs)]
    provenance = initramfs.parent / "provenance.json"
    if provenance.is_file():
        command.extend(["--runtime-provenance", str(provenance)])
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, check=False, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("diagnostic candidate finalizer check failed to run") from exc
    require(result.returncode == 0,
            "diagnostic candidate finalizer check failed: " + result.stderr.strip())


def build_archive(candidate: Path, runtime: Path, baseline_path: Path, output: Path,
                  expected_entries: int = PROTECTED_ENTRY_COUNT,
                  expected_manifest_sha256: str = PROTECTED_MANIFEST_SHA256,
                  finalizer_check: bool = True,
                  initramfs: Path | None = None) -> dict[str, Any]:
    candidate_info = validate_candidate(candidate)
    if finalizer_check:
        require(candidate.resolve() == DEFAULT_CANDIDATE.resolve(),
                "finalizer check only supports the canonical diagnostic candidate")
        run_finalizer_check((initramfs or DEFAULT_INITRAMFS).resolve())
    runtime_rows, runtime_manifest = validate_runtime(runtime)
    baseline = validate_baseline(baseline_path, expected_entries, expected_manifest_sha256)
    output = output.expanduser().resolve(strict=False)
    require(not output.exists() and not output.is_symlink(), f"archive already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata = transaction_metadata(candidate_info, runtime_manifest, runtime_rows, baseline)
    metadata["runtime_manifest_sha256"] = digest((runtime / "runtime-manifest.json") if (runtime / "runtime-manifest.json").is_file()
                                                 else runtime.parent / "runtime-manifest.json")
    metadata_bytes = json.dumps(metadata, indent=2, sort_keys=True).encode() + b"\n"
    with tarfile.open(output, "w") as bundle:
        add_tar_file(bundle, "transaction.json", metadata_bytes)
        for row in runtime_rows:
            source = (runtime / "rootfs" / row["path"]) if (runtime / "rootfs").is_dir() else runtime / row["path"]
            add_tar_file(bundle, "rootfs/" + row["path"], source.read_bytes(), row["mode"])
        add_tar_file(bundle, "efi/BOOTAA64.EFI", candidate_info["efi_path"].read_bytes(), 0o600)
    os.chmod(output, 0o600)
    archive_row = {"path": str(output), "bytes": output.stat().st_size,
                   "sha256": digest(output), "mode": stat.S_IMODE(output.stat().st_mode)}
    plan = {"schema": "r8q-diagnostic-trial-installation-plan/v1", "release": RELEASE,
            "archive": archive_row, "rootfs_files": runtime_rows,
            "candidate_manifest_sha256": candidate_info["manifest_sha256"],
            "runtime_manifest_sha256": metadata["runtime_manifest_sha256"],
            "protected_manifest": {"path": PROTECTED_MANIFEST,
                                    "sha256": expected_manifest_sha256,
                                    "entries": expected_entries, "append_only": True},
            "new_efi": candidate_info["efi"],
            "cache": metadata["cache"], "phone_operations": False,
            "raw_boot_writes": False, "raw_uefi_writes": False,
            "raw_userdata_writes": False, "hotload_hardware": False,
            "service_restarts": False}
    plan_path = output.parent / PLAN_NAME
    require(not plan_path.exists() and not plan_path.is_symlink(), f"plan already exists: {plan_path}")
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(plan_path, 0o600)
    return {"archive": archive_row, "plan": plan, "plan_path": str(plan_path)}


def archive_transaction(archive: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    regular(archive, "diagnostic trial archive")
    try:
        bundle = tarfile.open(archive, "r")
    except (OSError, tarfile.TarError) as exc:
        raise InstallError("diagnostic trial archive is unreadable") from exc
    with bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)), "archive contains duplicate members")
        require(all(member.isfile() and not member.issym() and not member.islnk() and
                    member.uid == 0 and member.gid == 0 and stat.S_IMODE(member.mode) & 0o7000 == 0
                    for member in members), "archive contains an unsafe member")
        try:
            transaction_member = bundle.getmember("transaction.json")
        except KeyError as exc:
            raise InstallError("archive transaction metadata is absent") from exc
        stream = bundle.extractfile(transaction_member)
        require(stream is not None, "archive transaction metadata is absent")
        try:
            transaction = json.loads(stream.read().decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise InstallError("archive transaction metadata is malformed") from exc
        require(isinstance(transaction, dict) and transaction.get("schema") == "r8q-diagnostic-trial-archive/v1" and
                transaction.get("release") == RELEASE and transaction.get("current_release") == CURRENT_RELEASE,
                "archive transaction binding differs")
        validate_runtime_guard(transaction.get("runtime_guard"), "archive")
        rows = transaction.get("rootfs")
        require(isinstance(rows, list) and rows and all(isinstance(row, dict) for row in rows),
                "archive rootfs inventory is malformed")
        require(len({row.get("path") for row in rows}) == len(rows),
                "archive rootfs inventory contains duplicate paths")
        require(all(isinstance(row.get("path"), str) for row in rows),
                "archive rootfs inventory contains an invalid path")
        expected_names = {"transaction.json", "efi/BOOTAA64.EFI"} | {"rootfs/" + row["path"] for row in rows}
        require(set(names) == expected_names, "archive member inventory differs from transaction")
        payloads: dict[str, bytes] = {}
        for row in rows:
            require(isinstance(row, dict) and safe_relative(row.get("path", ""), "archive rootfs path") and
                    allowed_runtime_path(row["path"]) and isinstance(row.get("bytes"), int) and
                    isinstance(row.get("mode"), int) and row["mode"] & 0o7000 == 0 and
                    isinstance(row.get("sha256"), str) and HEX64.fullmatch(row["sha256"]),
                    "archive rootfs row is malformed")
            member = bundle.getmember("rootfs/" + row["path"])
            stream = bundle.extractfile(member)
            require(stream is not None, "archive rootfs member is absent")
            data = stream.read()
            require(len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"],
                    "archive rootfs member hash differs")
            payloads[row["path"]] = data
        efi = bundle.extractfile("efi/BOOTAA64.EFI")
        require(efi is not None, "archive EFI member is absent")
        efi_data = efi.read()
        efi_row = transaction.get("efi")
        require(isinstance(efi_row, dict) and len(efi_data) == efi_row.get("bytes") and
                hashlib.sha256(efi_data).hexdigest() == efi_row.get("sha256"),
                "archive EFI member hash differs")
        return transaction, {"efi/BOOTAA64.EFI": efi_data, **payloads}


def fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def preserve_owner(path: Path, uid: int, gid: int, label: str) -> None:
    regular(path, label)
    try:
        os.chown(path, uid, gid)
    except OSError as exc:
        raise InstallError(f"cannot preserve owner for {label}: {path}") from exc
    info = regular(path, label)
    require(info.st_uid == uid and info.st_gid == gid,
            f"owner readback differs for {label}: {path}")


def record_owned(owned: list[Path] | set[Path], path: Path) -> None:
    if isinstance(owned, set):
        owned.add(path)
    else:
        owned.append(path)


def copy_exclusive(source: Path, destination: Path, mode: int,
                   owned: list[Path] | set[Path]) -> None:
    regular(source, "transaction copy source")
    source_info = source.stat()
    source_digest = digest(source, "transaction copy source")
    require(not destination.exists() and not destination.is_symlink(),
            f"refusing to overwrite existing transaction artifact: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), mode)
    record_owned(owned, destination)
    try:
        with source.open("rb", buffering=0) as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            descriptor = -1
            for block in iter(lambda: input_stream.read(1024 * 1024), b""):
                output_stream.write(block)
            output_stream.flush()
            os.fsync(output_stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(destination, mode)
    destination_info = regular(destination, "transaction copy destination")
    require(destination_info.st_size == source_info.st_size and
            digest(destination, "transaction copy destination") == source_digest,
            f"transaction copy readback differs: {destination}")
    fsync_path(destination.parent)


def write_exclusive(destination: Path, data: bytes, mode: int,
                    owned: list[Path] | set[Path]) -> None:
    require(not destination.exists() and not destination.is_symlink(),
            f"refusing to overwrite existing transaction artifact: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), mode)
    record_owned(owned, destination)
    try:
        with os.fdopen(descriptor, "wb") as output_stream:
            descriptor = -1
            output_stream.write(data)
            output_stream.flush()
            os.fsync(output_stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(destination, mode)
    destination_info = regular(destination, "transaction write destination")
    require(destination_info.st_size == len(data) and
            digest(destination, "transaction write destination") == hashlib.sha256(data).hexdigest(),
            f"transaction write readback differs: {destination}")
    fsync_path(destination.parent)


def write_atomic_new(destination: Path, data: bytes, mode: int,
                     owned: list[Path] | set[Path], nonce: str) -> None:
    require(not destination.exists() and not destination.is_symlink(),
            f"refusing to overwrite phone path: {destination}")
    stage = destination.with_name(destination.name + f".R8Q-DIAG1-STAGE-{nonce}")
    require(not stage.exists() and not stage.is_symlink(),
            f"transaction staging path already exists: {stage}")
    stage_owned: list[Path] = []
    try:
        write_exclusive(stage, data, mode, stage_owned)
        os.link(stage, destination, follow_symlinks=False)
        record_owned(owned, destination)
        stage.unlink()
        fsync_path(destination.parent)
    except BaseException:
        if stage.exists() and not stage.is_symlink():
            stage.unlink()
        raise


def parse_manifest_lines(data: bytes) -> list[tuple[str, str]]:
    rows = []
    for raw in data.splitlines():
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InstallError("protected manifest is not UTF-8") from exc
        fields = line.split(None, 1)
        require(len(fields) == 2 and HEX64.fullmatch(fields[0]) and fields[1].startswith("/"),
                "protected manifest contains a malformed row")
        safe_relative(fields[1][1:], "protected manifest path")
        rows.append((fields[0], fields[1]))
    return rows


def verify_baseline_on_target(target_root: Path, transaction: dict[str, Any]) -> tuple[Path, bytes, int, int, int]:
    validate_existing_parent(target_root, PROTECTED_MANIFEST.lstrip("/"),
                             "phone protected manifest")
    manifest_path = target_root / PROTECTED_MANIFEST.lstrip("/")
    info = regular(manifest_path, "phone protected manifest")
    baseline = transaction.get("protected_baseline")
    require(isinstance(baseline, dict) and baseline.get("schema") == PROTECTED_SCHEMA and
            baseline.get("manifest_sha256") == PROTECTED_MANIFEST_SHA256 and
            baseline.get("entries") == PROTECTED_ENTRY_COUNT,
            "archive protected baseline binding differs")
    original = manifest_path.read_bytes()
    require(digest(manifest_path) == PROTECTED_MANIFEST_SHA256 and
            len(parse_manifest_lines(original)) == PROTECTED_ENTRY_COUNT,
            "phone protected manifest differs from the accepted 410-entry baseline")
    records = baseline.get("path_records")
    require(isinstance(records, dict) and len(records) == PROTECTED_ENTRY_COUNT,
            "archive protected baseline records are incomplete")
    require(all(isinstance(row, dict) and isinstance(row.get("sha256"), str) and
                HEX64.fullmatch(row["sha256"]) for row in records.values()),
            "archive protected baseline records are malformed")
    manifest_rows = parse_manifest_lines(original)
    expected_rows = [(row.get("sha256"), absolute) for absolute, row in records.items()]
    require(len(set(manifest_rows)) == PROTECTED_ENTRY_COUNT and
            set(manifest_rows) == set(expected_rows),
            "phone protected manifest does not match the accepted baseline records")
    verify_protected_files(target_root, records)
    manifest_mode = stat.S_IMODE(info.st_mode)
    return manifest_path, original, manifest_mode, info.st_uid, info.st_gid


def verify_protected_files(target_root: Path, records: dict[str, Any]) -> None:
    for absolute, row in records.items():
        relative = safe_relative(absolute[1:], "protected baseline target")
        path = target_root / relative
        target_info = regular(path, "protected baseline file")
        require(digest(path) == row.get("sha256") and target_info.st_size == row.get("bytes") and
                stat.S_IMODE(target_info.st_mode) == row.get("mode"),
                f"protected baseline file changed: {absolute}")
        if "uid" in row:
            require(target_info.st_uid == row["uid"], f"protected baseline owner changed: {absolute}")
        if "gid" in row:
            require(target_info.st_gid == row["gid"], f"protected baseline group changed: {absolute}")


def run_command(command: list[str], label: str) -> str:
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError(f"{label} failed to run") from exc
    require(result.returncode == 0, f"{label} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def validate_phone_identity(target_root: Path, fixture: bool,
                            expected_release: str = CURRENT_RELEASE) -> None:
    if fixture:
        return
    require(os.geteuid() == 0 and target_root == Path("/"),
            "phone installation requires root target /")
    machine_path = target_root / "etc/machine-id"
    regular(machine_path, "phone machine-id")
    require(machine_path.read_text(encoding="ascii").strip() == MACHINE_ID,
            "phone machine identity differs")
    require(os.uname().release == expected_release,
            f"current kernel is not {expected_release}")
    require(run_command(["/usr/bin/findmnt", "-rn", "-o", "SOURCE", "/"],
                        "root source") == ROOT_SOURCE,
            "encrypted root source differs")
    require(run_command(["/usr/bin/findmnt", "-rn", "-o", "UUID", "/"], "root UUID") == ROOT_UUID,
            "encrypted root UUID differs")
    crypt_status = run_command(["/usr/sbin/cryptsetup", "status", "cryptroot"],
                               "cryptroot status")
    crypt_fields = {}
    for line in crypt_status.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            crypt_fields[key.strip().lower()] = value.strip()
    backing = crypt_fields.get("device")
    require(backing and backing.startswith("/dev/"), "cryptroot backing device is unavailable")
    backing_path = Path(backing)
    backing_info = backing_path.resolve(strict=True).lstat()
    require(stat.S_ISBLK(backing_info.st_mode), "cryptroot backing device is not a block device")
    require(run_command(["/usr/bin/blkid", "-s", "PARTUUID", "-o", "value", backing],
                        "root backing PARTUUID").lower() == ROOT_PARTUUID,
            "encrypted root backing PARTUUID differs")
    require(run_command(["/usr/sbin/cryptsetup", "luksUUID", backing],
                        "LUKS UUID").lower() == ROOT_LUKS_UUID,
            "LUKS UUID differs")
    require(run_command(["/usr/bin/blockdev", "--getsize64", backing],
                        "root backing size") == str(ROOT_DEVICE_BYTES),
            "encrypted root backing size differs")
    validate_quiescent_phone()


def process_command_lines() -> list[tuple[int, str]]:
    processes = []
    for process_path in sorted(Path("/proc").glob("[0-9]*")):
        try:
            process_id = int(process_path.name)
            raw = (process_path / "cmdline").read_bytes()
        except (OSError, ValueError):
            continue
        if not raw:
            continue
        command_line = " ".join(part.decode("utf-8", "replace") for part in raw.split(b"\0") if part)
        if command_line:
            processes.append((process_id, command_line))
    return processes


def validate_quiescent_phone() -> None:
    for service in ("waydroid-container.service", "r8q-noidle.service"):
        try:
            result = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", service],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallError(f"cannot verify inactive service: {service}") from exc
        require(result.returncode in (3, 4), f"service is active or indeterminate: {service}")
    process_patterns = {
        "Android/container": re.compile(r"(?:^|/)(?:waydroid|waydroid-container|lxc-start|surfaceflinger|app_process(?:64)?|zygote(?:64)?)(?:$|\s)|android\.hardware", re.I),
        "recorder": re.compile(r"(?:^|/)(?:wf-recorder|ffmpeg|gst-launch(?:-1\.0)?|scrcpy|arecord|grim)(?:$|\s)", re.I),
        "diagnostic spinner": re.compile(r"r8q-noidle|noidle\.sh|SCHED_IDLE|while\s+:;\s*do\s+:;\s*done", re.I),
    }
    for process_id, command_line in process_command_lines():
        for label, pattern in process_patterns.items():
            require(not pattern.search(command_line),
                    f"{label} process is active: {process_id}")


def mountinfo_rows(path: Path = Path("/proc/self/mountinfo")) -> list[dict[str, Any]]:
    regular(path, "mountinfo")
    rows = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if " - " not in raw_line:
            continue
        left, right = raw_line.split(" - ", 1)
        left_fields = left.split()
        right_fields = right.split()
        require(len(left_fields) >= 6 and len(right_fields) >= 3,
                "mountinfo row is malformed")
        mountpoint = left_fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        rows.append({"device": left_fields[2], "mountpoint": mountpoint,
                     "options": set(left_fields[5].split(",")),
                     "fstype": right_fields[0], "source": right_fields[1],
                     "super_options": set(right_fields[2].split(","))})
    return rows


def device_major_minor(path: Path, label: str) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError(f"{label} is unavailable: {path}") from exc
    require(stat.S_ISBLK(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a block device: {path}")
    return f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"


def verify_cache_mount(cache_mount: Path, cache_device: Path, writable: bool) -> None:
    device_id = device_major_minor(cache_device, "CACHE device")
    rows = [row for row in mountinfo_rows()
            if row["mountpoint"] == str(cache_mount.resolve(strict=False))]
    require(len(rows) == 1, "CACHE mount is not uniquely present in mountinfo")
    row = rows[0]
    require(row["device"] == device_id and row["fstype"] == CACHE_FSTYPE,
            "CACHE mounted device or filesystem differs")
    required_options = {"nosuid", "nodev", "noexec"}
    require(required_options <= row["options"] | row["super_options"],
            "CACHE mount safety options differ")
    require(("rw" in row["options"]) if writable else ("ro" in row["options"]),
            "CACHE mount write mode differs")


def locate_cache_device(sysfs_root: Path = Path("/sys/class/block")) -> Path:
    directory(sysfs_root, "block sysfs root")
    matches = []
    for entry in sorted(sysfs_root.iterdir()):
        if not entry.is_dir():
            continue
        real_entry = entry.resolve(strict=True)
        uevent = real_entry / "uevent"
        if not uevent.is_file():
            continue
        fields = {}
        for line in uevent.read_text(encoding="ascii").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value
        if fields.get("PARTUUID", "").lower() != CACHE_PARTUUID:
            continue
        require(fields.get("PARTNAME") == CACHE_PARTNAME and
                (real_entry / "size").read_text().strip() == str(CACHE_SECTORS) and
                (real_entry.parent / "queue/logical_block_size").read_text().strip() == str(CACHE_BLOCK_SIZE),
                "CACHE sysfs identity differs")
        require(fields.get("MAJOR", "").isdigit() and fields.get("MINOR", "").isdigit(),
                "CACHE sysfs major/minor is unavailable")
        holders = real_entry / "holders"
        require(holders.is_dir() and not any(holders.iterdir()), "CACHE has active holders")
        device = Path("/dev") / fields.get("DEVNAME", entry.name)
        require(device_major_minor(device, "CACHE device") ==
                f"{fields['MAJOR']}:{fields['MINOR']}",
                "CACHE device major/minor differs from sysfs")
        parent_disk = real_entry.parent
        parent_uevent = parent_disk / "uevent"
        require(parent_disk.name != real_entry.name and parent_uevent.is_file(),
                "CACHE parent disk identity is unavailable")
        parent_fields = {}
        for line in parent_uevent.read_text(encoding="ascii").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                parent_fields[key] = value
        parent_device = Path("/dev") / parent_fields.get("DEVNAME", parent_disk.name)
        require(run_command(["/usr/bin/blkid", "-s", "PTUUID", "-o", "value", str(parent_device)],
                            "parent disk identity").lower() == DISK_GUID,
                "parent disk GUID differs")
        matches.append(device)
    require(len(matches) == 1, "CACHE is not uniquely identified")
    require(run_command(["/usr/bin/blkid", "-s", "TYPE", "-o", "value", str(matches[0])],
                        "CACHE filesystem identity") == CACHE_FSTYPE,
            "CACHE filesystem type differs")
    require(not any(row["device"] == device_major_minor(matches[0], "CACHE device")
                    for row in mountinfo_rows()),
            "CACHE device is already mounted")
    return matches[0]


def mount_cache(cache_device: Path, cache_mount: Path, fixture: bool) -> bool:
    if fixture:
        directory(cache_mount, "fixture CACHE mount")
        return False
    require(not cache_mount.exists() and not cache_mount.is_symlink(),
            "CACHE mountpoint already exists")
    device_id = device_major_minor(cache_device, "CACHE device")
    require(not any(row["device"] == device_id for row in mountinfo_rows()),
            "CACHE device is already mounted")
    cache_mount.mkdir(mode=0o700)
    try:
        run_command(["/usr/bin/mount", "-t", "vfat", "-o", "ro,nosuid,nodev,noexec,uid=0,gid=0,fmask=0177,dmask=0077",
                     "--", str(cache_device), str(cache_mount)], "CACHE mount")
        verify_cache_mount(cache_mount, cache_device, False)
    except BaseException:
        try:
            run_command(["/usr/bin/umount", "--", str(cache_mount)], "CACHE mount cleanup")
        except BaseException:
            pass
        try:
            cache_mount.rmdir()
        except OSError:
            pass
        raise
    return True


def remount_cache(cache_device: Path, cache_mount: Path, fixture: bool) -> None:
    if fixture:
        return
    run_command(["/usr/bin/mount", "-o", "remount,rw,nosuid,nodev,noexec,uid=0,gid=0,fmask=0177,dmask=0077",
                 "--", str(cache_device), str(cache_mount)], "CACHE remount")
    verify_cache_mount(cache_mount, cache_device, True)


def remount_cache_for_rollback(cache_device: Path, cache_mount: Path, fixture: bool) -> bool:
    if fixture:
        return False
    require(cache_mount.exists() and not cache_mount.is_symlink(),
            "CACHE mountpoint is unavailable for rollback remount")
    run_command(["/usr/bin/mount", "-t", "vfat", "-o", "ro,nosuid,nodev,noexec,uid=0,gid=0,fmask=0177,dmask=0077",
                 "--", str(cache_device), str(cache_mount)], "CACHE rollback remount")
    verify_cache_mount(cache_mount, cache_device, False)
    run_command(["/usr/bin/mount", "-o", "remount,rw,nosuid,nodev,noexec,uid=0,gid=0,fmask=0177,dmask=0077",
                 "--", str(cache_device), str(cache_mount)], "CACHE rollback writable remount")
    verify_cache_mount(cache_mount, cache_device, True)
    return True


def unmount_cache(cache_mount: Path, mounted: bool, fixture: bool) -> None:
    if not mounted:
        return
    run_command(["/usr/bin/umount", "--", str(cache_mount)], "CACHE unmount")
    try:
        rows = mountinfo_rows()
    except BaseException as exc:
        raise CacheUnmountError(f"CACHE mount state could not be verified: {exc}", False) from exc
    if any(row["mountpoint"] == str(cache_mount.resolve(strict=False)) for row in rows):
        raise CacheUnmountError("CACHE remains mounted after unmount", False)
    if cache_mount.exists() and not cache_mount.is_symlink():
        try:
            cache_mount.rmdir()
        except BaseException as exc:
            raise CacheUnmountError(f"CACHE mountpoint cleanup failed: {exc}", True) from exc


def verify_cache_current(cache_mount: Path) -> tuple[Path, Path]:
    directory(cache_mount / "EFI", "CACHE EFI directory")
    directory(cache_mount / "EFI/BOOT", "CACHE EFI boot directory")
    efi = cache_mount / "EFI/BOOT/BOOTAA64.EFI"
    dtb = cache_mount / "EFI/BOOT/R8Q-RTC.DTB"
    efi_info = regular(efi, "current CACHE EFI")
    dtb_info = regular(dtb, "current CACHE DTB")
    require(efi_info.st_size == EFI_BYTES and digest(efi) == EFI_SHA256,
            "current CACHE EFI differs from accepted pin")
    require(dtb_info.st_size == DTB_BYTES and digest(dtb) == DTB_SHA256,
            "current CACHE DTB differs from accepted pin")
    return efi, dtb


def validate_fixture_scope(target_root: Path, cache_mount: Path, fixture: bool) -> None:
    if not fixture:
        return
    require(target_root.expanduser().resolve(strict=False) != Path("/"),
            "fixture mode cannot target the live root filesystem")
    mountpoint = str(cache_mount.expanduser().resolve(strict=False))
    require(not any(row["mountpoint"] == mountpoint for row in mountinfo_rows()),
            "fixture CACHE mountpoint is already mounted")


def resolve_cache_device(cache_device: Path | None, fixture: bool) -> Path:
    if fixture:
        if cache_device is not None and cache_device.exists() and cache_device.is_block_device():
            raise InstallError("fixture CACHE device cannot be a real block device")
        return cache_device or Path("fixture-cache")
    discovered_cache = locate_cache_device()
    if cache_device is not None:
        require(cache_device.resolve(strict=True) == discovered_cache.resolve(strict=True),
                "requested CACHE device differs from pinned sysfs CACHE")
    return discovered_cache


def remove_owned(path: Path, expected_sha256: str | None, expected_bytes: int | None,
                 owned: set[Path]) -> None:
    if path not in owned or not path.exists():
        return
    info = regular(path, "owned transaction artifact")
    if expected_sha256 is not None:
        require(digest(path) == expected_sha256, f"owned artifact changed: {path}")
    if expected_bytes is not None:
        require(info.st_size == expected_bytes, f"owned artifact size changed: {path}")
    path.unlink()


def write_transaction_json(path: Path, value: dict[str, Any], owned: set[Path]) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    write_exclusive(path, data, 0o600, owned)


def update_transaction_json(path: Path, value: dict[str, Any]) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists() and not temporary.is_symlink(),
            f"transaction journal temporary path already exists: {temporary}")
    temporary_owned: list[Path] = []
    try:
        write_exclusive(temporary, data, 0o600, temporary_owned)
        os.replace(temporary, path)
        fsync_path(path.parent)
        require(path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == 0o600,
                f"transaction journal readback differs: {path}")
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
        raise


def phone_install(archive: Path, target_root: Path, cache_mount: Path,
                  cache_device: Path | None = None, fixture: bool = False) -> dict[str, Any]:
    validate_fixture_scope(target_root, cache_mount, fixture)
    transaction, payloads = archive_transaction(archive)
    target_root = ensure_root(target_root, "phone target root")
    validate_phone_identity(target_root, fixture)
    manifest_path, manifest_before, manifest_mode, manifest_uid, manifest_gid = verify_baseline_on_target(
        target_root, transaction)
    rows = transaction["rootfs"]
    require(all(allowed_runtime_path(row["path"]) and row["path"] not in {"boot", "efi"} for row in rows),
            "archive rootfs path is outside the diagnostic allowlist")
    total_bytes = sum(row["bytes"] for row in rows) + len(manifest_before) + transaction["efi"]["bytes"] * 3 + MARGIN_BYTES
    usage = shutil.disk_usage(target_root)
    require(usage.free >= total_bytes, "encrypted root free space is insufficient")
    cache_device = resolve_cache_device(cache_device, fixture)
    mounted = False
    created_files: list[Path] = []
    created_dirs: list[Path] = []
    cache_owned: set[Path] = set()
    manifest_owned: set[Path] = set()
    transaction_owned: set[Path] = set()
    efi_replaced = False
    manifest_changed = False
    manifest_backup: Path | None = None
    manifest_temp: Path | None = None
    cache_saved: Path | None = None
    cache_candidate: Path | None = None
    cache_temp: Path | None = None
    cache_marker: Path | None = None
    nonce, tag = validate_runtime_guard(transaction["runtime_guard"], "archive")
    validate_existing_parent(target_root, "root", "transaction journal parent")
    manifest_backup = manifest_path.with_name(manifest_path.name + f".R8Q-DIAG1-SAVED-{nonce}")
    manifest_temp = manifest_path.with_name(manifest_path.name + f".R8Q-DIAG1-NEW-{nonce}")
    journal_path = manifest_path.with_name(f"r8q-diagnostic-transaction-{nonce}.json")
    plan_path = manifest_path.with_name(f"r8q-diagnostic-transaction-{nonce}.plan.json")
    for path in (manifest_backup, manifest_temp, journal_path, plan_path):
        require(not path.exists() and not path.is_symlink(),
                f"transaction artifact already exists: {path}")
    journal_value = {
        "schema": "r8q-diagnostic-root-transaction/v1",
        "state": "prepared",
        "release": RELEASE,
        "current_release": CURRENT_RELEASE,
        "nonce": nonce,
        "tag": tag,
        "manifest_path": PROTECTED_MANIFEST,
        "manifest_backup": "/" + manifest_backup.relative_to(target_root).as_posix(),
        "plan_path": "/" + plan_path.relative_to(target_root).as_posix(),
        "journal_path": "/" + journal_path.relative_to(target_root).as_posix(),
        "rootfs_paths": [row["path"] for row in rows],
        "dropin_paths": sorted(path for path in (row["path"] for row in rows) if path in DROPINS),
        "expected_efi_sha256": transaction["efi"]["sha256"],
        "expected_efi_bytes": transaction["efi"]["bytes"],
        "accepted_efi_sha256": EFI_SHA256,
        "accepted_efi_bytes": EFI_BYTES,
        "accepted_dtb_sha256": DTB_SHA256,
        "accepted_dtb_bytes": DTB_BYTES,
        "cache": transaction["cache"],
        "protected_manifest_sha256": PROTECTED_MANIFEST_SHA256,
        "protected_manifest_mode": manifest_mode,
        "protected_manifest_uid": manifest_uid,
        "protected_manifest_gid": manifest_gid,
        "recovery_api": "r8q-diagnostic-root-transaction/v1; inspect this journal before retrying",
        "recovery_steps": [
            "retain journal, plan, manifest backup, and CACHE artifacts",
            "verify accepted CACHE EFI and restore the manifest backup with readback",
            "remove nonce-owned artifacts only after both restorations are verified",
        ],
    }
    plan_value = {**journal_value, "schema": "r8q-diagnostic-root-transaction-plan/v1",
                  "rootfs": rows, "protected_baseline": transaction["protected_baseline"]}
    result: dict[str, Any] = {"result": "FAIL", "error": "transaction did not complete"}
    try:
        copy_exclusive(manifest_path, manifest_backup, manifest_mode, manifest_owned)
        preserve_owner(manifest_backup, manifest_uid, manifest_gid, "protected manifest backup")
        write_transaction_json(plan_path, plan_value, transaction_owned)
        write_transaction_json(journal_path, journal_value, transaction_owned)
        mounted = mount_cache(cache_device, cache_mount, fixture)
        cache_efi, _cache_dtb = verify_cache_current(cache_mount)
        cache_usage = shutil.disk_usage(cache_mount)
        require(cache_usage.free >= transaction["efi"]["bytes"] * 3 + MARGIN_BYTES,
                "CACHE free space is insufficient")
        remount_cache(cache_device, cache_mount, fixture)
        cache_saved = cache_efi.with_name(cache_efi.name + f".R8Q-DIAG1-SAVED-{nonce}")
        cache_candidate = cache_efi.with_name(cache_efi.name + f".R8Q-DIAG1-CANDIDATE-{nonce}")
        cache_temp = cache_efi.with_name(cache_efi.name + f".R8Q-DIAG1-RECOVERY-{nonce}")
        cache_marker = cache_efi.with_name(f"R8Q-DIAG1-GUARD-{nonce}.marker")
        cache_marker_temp = cache_efi.with_name(f"R8Q-DIAG1-GUARD-{nonce}.marker.tmp")
        for path in (cache_saved, cache_candidate, cache_temp, cache_marker, cache_marker_temp):
            require(not path.exists() and not path.is_symlink(), f"CACHE transaction artifact already exists: {path.name}")
        rootfs_rows = [row for row in rows if row["path"] not in DROPINS]
        dropin_rows = [row for row in rows if row["path"] in DROPINS]
        for row in rootfs_rows + dropin_rows:
            relative = safe_relative(row["path"], "archive rootfs path")
            target = ensure_parent(target_root, relative, created_dirs)
            write_atomic_new(target, payloads[relative], row["mode"], created_files, nonce)
            info = target.lstat()
            require(info.st_size == row["bytes"] and stat.S_IMODE(info.st_mode) == row["mode"] and
                    digest(target) == row["sha256"], f"installed path readback differs: {relative}")
        journal_value["state"] = "rootfs-complete"
        update_transaction_json(journal_path, journal_value)
        existing_paths = {path for _, path in parse_manifest_lines(manifest_before)}
        append_rows = []
        for row in rows:
            absolute = "/" + row["path"]
            require(absolute not in existing_paths, f"protected manifest already contains new path: {absolute}")
            append_rows.append(f"{row['sha256']}  {absolute}\n".encode())
        write_exclusive(manifest_temp, manifest_before + b"".join(append_rows), manifest_mode,
                        manifest_owned)
        preserve_owner(manifest_temp, manifest_uid, manifest_gid, "new protected manifest")
        manifest_changed = True
        os.replace(manifest_temp, manifest_path)
        fsync_path(manifest_path.parent)
        new_manifest = manifest_path.read_bytes()
        require(new_manifest.startswith(manifest_before) and
                len(parse_manifest_lines(new_manifest)) == PROTECTED_ENTRY_COUNT + len(rows) and
                stat.S_IMODE(manifest_path.stat().st_mode) == manifest_mode and
                manifest_path.stat().st_uid == manifest_uid and
                manifest_path.stat().st_gid == manifest_gid,
                "protected manifest append readback differs")
        journal_value["state"] = "manifest-appended"
        update_transaction_json(journal_path, journal_value)
        verify_protected_files(target_root, transaction["protected_baseline"]["path_records"])
        copy_exclusive(cache_efi, cache_saved, 0o600, cache_owned)
        require(cache_saved.stat().st_size == EFI_BYTES and digest(cache_saved) == EFI_SHA256,
                "accepted CACHE EFI backup readback differs")
        candidate_path = cache_mount / "EFI/BOOT" / cache_candidate.name
        write_exclusive(candidate_path, payloads["efi/BOOTAA64.EFI"], 0o600, cache_owned)
        require(candidate_path.stat().st_size == transaction["efi"]["bytes"] and
                digest(candidate_path) == transaction["efi"]["sha256"],
                "candidate CACHE EFI copy readback differs")
        marker_data = ("schema=r8q-diagnostic-fallback-marker/v1\n"
                       f"state=armed\nnonce={nonce}\ntag={tag}\n"
                       f"candidate_sha256={transaction['efi']['sha256']}\n"
                       f"candidate_bytes={transaction['efi']['bytes']}\n"
                       f"accepted_sha256={EFI_SHA256}\naccepted_bytes={EFI_BYTES}\n"
                       f"cache_partuuid={CACHE_PARTUUID}\ncache_partname={CACHE_PARTNAME}\n"
                       f"cache_bytes={CACHE_BYTES}\n"
                       f"cache_logical_block_size={CACHE_BLOCK_SIZE}\n"
                       f"cache_fstype={CACHE_FSTYPE}\n"
                       f"efi_rel=EFI/BOOT/BOOTAA64.EFI\ndtb_rel=EFI/BOOT/R8Q-RTC.DTB\n"
                       f"backup_rel={cache_saved.relative_to(cache_mount).as_posix()}\n"
                       f"temp_rel={cache_temp.relative_to(cache_mount).as_posix()}\n"
                       f"candidate_copy_rel={candidate_path.relative_to(cache_mount).as_posix()}\n"
                       f"marker_rel={cache_marker.relative_to(cache_mount).as_posix()}\n")
        write_exclusive(cache_marker_temp, marker_data.encode(), 0o600, cache_owned)
        os.replace(cache_marker_temp, cache_marker)
        cache_owned.add(cache_marker)
        fsync_path(cache_marker.parent)
        require(cache_marker.read_bytes() == marker_data.encode() and
                stat.S_IMODE(cache_marker.stat().st_mode) == 0o600,
                "diagnostic guard marker readback differs")
        copy_exclusive(Path(cache_candidate), cache_temp, 0o600, cache_owned)
        require(cache_temp.stat().st_size == transaction["efi"]["bytes"] and
                digest(cache_temp) == transaction["efi"]["sha256"],
                "recovery EFI temporary readback differs")
        efi_replaced = True
        os.replace(cache_temp, cache_efi)
        fsync_path(cache_efi.parent)
        os.sync()
        require(cache_efi.stat().st_size == transaction["efi"]["bytes"] and
                digest(cache_efi) == transaction["efi"]["sha256"],
                "new CACHE EFI readback differs")
        journal_value["state"] = "efi-candidate-installed"
        update_transaction_json(journal_path, journal_value)
        try:
            unmount_cache(cache_mount, mounted, fixture)
        except CacheUnmountError as unmount_exc:
            if unmount_exc.unmounted:
                mounted = False
            raise
        mounted = False
        journal_value["state"] = "committed"
        update_transaction_json(journal_path, journal_value)
        result = {"result": "PASS", "release": RELEASE, "nonce": nonce, "tag": tag,
                  "rootfs_files_changed": [row["path"] for row in rows],
                  "protected_manifest_appended": len(rows),
                  "efi_before_sha256": EFI_SHA256, "efi_after_sha256": transaction["efi"]["sha256"],
                  "journal_path": str(journal_path), "plan_path": str(plan_path),
                  "raw_boot_writes": False, "raw_uefi_writes": False,
                  "raw_userdata_writes": False, "hotload_hardware": False}
    except BaseException as exc:
        rollback_errors: list[str] = []
        efi_rollback_ok = not efi_replaced
        manifest_rollback_ok = not manifest_changed
        if isinstance(exc, CacheUnmountError) and exc.unmounted and not fixture:
            try:
                mounted = remount_cache_for_rollback(cache_device, cache_mount, fixture)
            except BaseException as remount_exc:
                rollback_errors.append("CACHE rollback remount: " + str(remount_exc))
        if efi_replaced and cache_saved is not None:
            try:
                restore_temp = cache_efi.with_name(cache_efi.name + f".R8Q-DIAG1-RESTORE-{nonce}")
                require(not restore_temp.exists() and not restore_temp.is_symlink(), "EFI restore target exists")
                copy_exclusive(cache_saved, restore_temp, 0o600, cache_owned)
                require(restore_temp.stat().st_size == EFI_BYTES and
                        digest(restore_temp) == EFI_SHA256,
                        "accepted EFI restore temporary readback differs")
                os.replace(restore_temp, cache_efi)
                fsync_path(cache_efi.parent)
                require(digest(cache_efi) == EFI_SHA256 and cache_efi.stat().st_size == EFI_BYTES,
                        "accepted EFI rollback readback differs")
                efi_rollback_ok = True
            except BaseException as rollback_exc:
                rollback_errors.append("EFI rollback: " + str(rollback_exc))
        if manifest_changed and manifest_backup is not None and efi_rollback_ok:
            try:
                restore_manifest = manifest_path.with_name(manifest_path.name + f".R8Q-DIAG1-RESTORE-{nonce}")
                copy_exclusive(manifest_backup, restore_manifest, manifest_mode, manifest_owned)
                preserve_owner(restore_manifest, manifest_uid, manifest_gid, "restored protected manifest")
                require(restore_manifest.stat().st_size == len(manifest_before) and
                        digest(restore_manifest) == PROTECTED_MANIFEST_SHA256 and
                        restore_manifest.read_bytes() == manifest_before,
                        "protected manifest restore temporary differs before replace")
                os.replace(restore_manifest, manifest_path)
                fsync_path(manifest_path.parent)
                require(digest(manifest_path) == PROTECTED_MANIFEST_SHA256 and
                        manifest_path.read_bytes() == manifest_before and
                        stat.S_IMODE(manifest_path.stat().st_mode) == manifest_mode and
                        manifest_path.stat().st_uid == manifest_uid and
                        manifest_path.stat().st_gid == manifest_gid,
                        "protected manifest rollback readback differs")
                manifest_rollback_ok = True
            except BaseException as rollback_exc:
                rollback_errors.append("manifest rollback: " + str(rollback_exc))
        elif manifest_changed and not efi_rollback_ok:
            rollback_errors.append("manifest rollback deferred because EFI rollback failed")
        if efi_rollback_ok and manifest_rollback_ok:
            cleanup_complete = True
            for path in reversed(created_files):
                try:
                    if path.is_symlink():
                        raise InstallError(f"rootfs rollback path became a symlink: {path}")
                    if path.exists():
                        path.unlink()
                except (OSError, InstallError) as rollback_exc:
                    rollback_errors.append(f"rootfs rollback {path}: {rollback_exc}")
                    cleanup_complete = False
            for path in reversed(created_dirs):
                try:
                    path.rmdir()
                except OSError as rollback_exc:
                    rollback_errors.append(f"rootfs directory rollback {path}: {rollback_exc}")
                    cleanup_complete = False
            owned_to_remove = cache_owned | manifest_owned
            for path in sorted(owned_to_remove, key=lambda value: len(value.parts), reverse=True):
                try:
                    if path.is_symlink():
                        raise InstallError(f"artifact rollback path became a symlink: {path}")
                    if path.exists():
                        path.unlink()
                except (OSError, InstallError) as rollback_exc:
                    rollback_errors.append(f"artifact rollback {path}: {rollback_exc}")
                    cleanup_complete = False
            if cleanup_complete:
                for path in sorted(transaction_owned - {journal_path},
                                   key=lambda value: len(value.parts), reverse=True):
                    try:
                        if path.is_symlink():
                            raise InstallError(f"transaction rollback path became a symlink: {path}")
                        if path.exists():
                            path.unlink()
                    except (OSError, InstallError) as rollback_exc:
                        rollback_errors.append(f"transaction artifact rollback {path}: {rollback_exc}")
                        cleanup_complete = False
            if cleanup_complete and journal_path.exists():
                try:
                    if journal_path.is_symlink():
                        raise InstallError(f"transaction journal became a symlink: {journal_path}")
                    journal_path.unlink()
                except (OSError, InstallError) as rollback_exc:
                    rollback_errors.append(f"transaction journal rollback {journal_path}: {rollback_exc}")
                    cleanup_complete = False
            if not cleanup_complete:
                rollback_errors.append("recovery artifacts preserved because cleanup was incomplete")
        else:
            rollback_errors.append("recovery artifacts preserved because rollback was incomplete")
        result = {"result": "FAIL", "error": str(exc), "rollback_errors": rollback_errors,
                  "rollback_attempted": True, "raw_boot_writes": False,
                  "raw_uefi_writes": False, "raw_userdata_writes": False}
    finally:
        if mounted:
            try:
                unmount_cache(cache_mount, mounted, fixture)
                mounted = False
            except CacheUnmountError as unmount_exc:
                if unmount_exc.unmounted:
                    mounted = False
                result.setdefault("rollback_errors", []).append("CACHE unmount: " + str(unmount_exc))
            except BaseException as unmount_exc:
                result.setdefault("rollback_errors", []).append("CACHE unmount: " + str(unmount_exc))
    return result


def phone_preflight(archive: Path, target_root: Path, cache_mount: Path,
                    cache_device: Path | None = None, fixture: bool = False) -> dict[str, Any]:
    validate_fixture_scope(target_root, cache_mount, fixture)
    transaction, _payloads = archive_transaction(archive)
    target_root = ensure_root(target_root, "phone target root")
    validate_phone_identity(target_root, fixture)
    _manifest_path, _manifest_before, _manifest_mode, _manifest_uid, _manifest_gid = verify_baseline_on_target(
        target_root, transaction)
    require(all(allowed_runtime_path(row["path"]) for row in transaction["rootfs"]),
            "archive rootfs path is outside the diagnostic allowlist")
    cache_device = resolve_cache_device(cache_device, fixture)
    mounted = False
    result: dict[str, Any] = {"result": "FAIL", "error": "preflight did not complete"}
    try:
        mounted = mount_cache(cache_device, cache_mount, fixture)
        cache_efi, cache_dtb = verify_cache_current(cache_mount)
        cache_identity = {
            "current_efi_sha256": digest(cache_efi),
            "current_efi_bytes": cache_efi.stat().st_size,
            "current_dtb_sha256": digest(cache_dtb),
            "current_dtb_bytes": cache_dtb.stat().st_size,
        }
        try:
            unmount_cache(cache_mount, mounted, fixture)
        except CacheUnmountError as unmount_exc:
            if unmount_exc.unmounted:
                mounted = False
            raise
        mounted = False
        result = {
            "result": "PASS",
            "mode": "phone-preflight",
            "release": RELEASE,
            "cache_device": str(cache_device),
            **cache_identity,
            "baseline_entries": PROTECTED_ENTRY_COUNT,
            "quiescence_checked": not fixture,
            "raw_boot_writes": False,
            "raw_uefi_writes": False,
            "raw_userdata_writes": False,
            "hotload_hardware": False,
        }
    except BaseException as exc:
        result = {"result": "FAIL", "mode": "phone-preflight", "error": str(exc),
                  "raw_boot_writes": False, "raw_uefi_writes": False,
                  "raw_userdata_writes": False, "hotload_hardware": False}
    finally:
        if mounted:
            try:
                unmount_cache(cache_mount, mounted, fixture)
            except CacheUnmountError as unmount_exc:
                if unmount_exc.unmounted:
                    mounted = False
                result.setdefault("error", "CACHE unmount failed")
                result["unmount_error"] = str(unmount_exc)
                result["result"] = "FAIL"
            except BaseException as unmount_exc:
                result.setdefault("error", "CACHE unmount failed")
                result["unmount_error"] = str(unmount_exc)
                result["result"] = "FAIL"
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--package", action="store_true")
    modes.add_argument("--phone-install", action="store_true")
    modes.add_argument("--phone-preflight", action="store_true")
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--runtime-initramfs", type=Path, default=DEFAULT_INITRAMFS)
    parser.add_argument("--protected-baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--target-root", type=Path, default=Path("/"))
    parser.add_argument("--cache-mount", type=Path, default=Path("/run/r8q-diagnostic-cache"))
    parser.add_argument("--cache-device", type=Path)
    parser.add_argument("--fixture", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        options = parse_args(argv or sys.argv[1:])
        if options.package:
            require(not options.fixture, "--package cannot bypass final candidate verification with --fixture")
            archive = options.output / ARCHIVE_NAME
            receipt = options.output / RECEIPT_NAME
            require(not receipt.exists() and not receipt.is_symlink(),
                    f"receipt already exists: {receipt}")
            result = build_archive(options.candidate.resolve(), options.runtime.resolve(),
                                   options.protected_baseline.resolve(), archive,
                                   finalizer_check=True,
                                   initramfs=options.runtime_initramfs.resolve())
            receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
            os.chmod(receipt, 0o600)
            print(json.dumps({"result": "PASS", "archive": result["archive"],
                              "plan": result["plan_path"]}, sort_keys=True))
            return 0
        require(options.archive is not None,
                "--archive is required with --phone-install or --phone-preflight")
        if options.phone_preflight:
            result = phone_preflight(options.archive.resolve(), options.target_root,
                                     options.cache_mount, options.cache_device, options.fixture)
            print(json.dumps(result, sort_keys=True))
            return 0 if result.get("result") == "PASS" else 1
        result = phone_install(options.archive.resolve(), options.target_root, options.cache_mount,
                               options.cache_device, options.fixture)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("result") == "PASS" else 1
    except (InstallError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"install-r8q-diagnostic-trial: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
