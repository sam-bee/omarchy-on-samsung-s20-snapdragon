#!/usr/bin/env python3
"""Prepare, audit, and (only with --execute) deploy the Waydroid2 trial.

The normal path is deliberately offline.  It validates the completed encrypted
candidate and the hardware bundle, then creates a small public archive and a
transaction plan.  The device path is explicitly gated by ``--execute`` and
uses only the pinned SSH command from ``out/waydroid-encrypted-20261015/phone.py``.
The remote transaction writes new rootfs paths first and replaces CACHE EFI
last; every failure restores files created by this transaction.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


os.umask(0o077)
os.environ["LC_ALL"] = "C"

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
OUT = REPO / "out"
DEPLOY = OUT / "waydroid-encrypted-20261015" / "deployment-preparation"
CANDIDATE = OUT / "waydroid-encrypted-20261015" / "kernel"
HARDWARE = OUT / "waydroid-encrypted-20261015" / "hardware-preparation"
PHONE_HELPER = OUT / "waydroid-encrypted-20261015" / "phone.py"
PHONE_HELPER_SHA256 = "dc3618c0557308ed5143ee26336fb76196810d7436face8eb6cfc589bbb2f350"
OLD_EFI = OUT / "encryption-implementation-20261013" / "production-kernel04" / "payload" / "BOOTAA64.EFI"
RELEASE = "7.1.2-r8q-waydroid2"
OLD_RELEASE = "7.1.2-r8q-rtc2"
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
OLD_EFI_SHA256 = "730627f49b8d41b9bdc6ef7931fe94911636003c61596c84d769d532ad27c49b"
OLD_MANIFEST_SHA256 = "c157dc72e80c64799ca4161a00f96784874c87323ce2fb0af0f2ff8a472e2ae5"
PROTECTED_BASELINE_METADATA = OUT / "waydroid-encrypted-20261015" / "protected-baseline-metadata.json"
PROTECTED_BASELINE_METADATA_SHA256 = "ada81d61b271b96f35681f07e42fb56907332ee4e93a04ccee0cc715cbbd3d1c"
PROTECTED_BASELINE_METADATA_SCHEMA = "r8q-protected-baseline-metadata/v1"
PUBLIC_SNAPSHOT_METADATA_SHA256 = "c9f06e873f9f35396b4c63ea3b3a32ae169d76eb195ab6eb94d257af03d80fe7"
PUBLIC_SNAPSHOT_METADATA_SCHEMA = "r8q-public-rootfs-snapshot/v1"
PUBLIC_SNAPSHOT_METADATA_FILES = 147
COMPLETE_SOURCE_PROOF_SHA256 = "04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b"
MANIFEST_REL = "root/r8q-screen-lock-20261013.sha256"
PROFILE_PREFIX = f"usr/local/lib/r8q-kernel-profiles/{RELEASE}/"
MODULE_PREFIX = f"usr/lib/modules/{RELEASE}/"
DROPINS = {
    "etc/systemd/system/r8q-hardware-prepare.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-battery.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-usb-gadget.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-audio-start.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-wifi-standby.service.d/90-r8q-waydroid2-dispatch.conf",
}
FINAL_INITRAMFS_SOURCE = '"' + str(OUT / "waydroid-encrypted-20261015/initramfs-preparation/initramfs") + " " + str(REPO / "initramfs/irfs.devnodes") + '"'
ARCHIVE_NAME = "waydroid2-public-transaction.tar"
PLAN_NAME = "deployment-plan.json"
RECEIPT_NAME = "deployment-receipt.json"
REMOTE_ARCHIVE = "/run/r8q-waydroid2-deploy.tar"


class InstallError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InstallError(message)


def regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError(f"{label} is unavailable: {path}") from exc
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a regular non-symlink file: {path}")
    return info


def digest(path: Path, label: str = "file") -> str:
    regular(path, label)
    result = hashlib.sha256()
    try:
        with path.open("rb", buffering=0) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(block)
    except OSError as exc:
        raise InstallError(f"{label} could not be read: {path}") from exc
    return result.hexdigest()


def json_object(path: Path, label: str) -> dict[str, Any]:
    regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"{label} is not valid JSON: {path}") from exc
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def validate_metadata_records(payload: dict[str, Any], label: str, schema: str,
                              metadata_sha256: str, count: int) -> dict[str, Any]:
    require(payload.get("schema") == schema, f"{label} schema is not reviewed")
    require(payload.get("sha256") == metadata_sha256,
            f"{label} hash is not pinned")
    records = payload.get("path_records")
    require(isinstance(records, dict) and len(records) == count,
            f"{label} must contain exactly {count} path records")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_path, record in records.items():
        require(isinstance(raw_path, str) and raw_path.startswith("/"),
                f"{label} path is not absolute: {raw_path!r}")
        relative = safe_relative(raw_path[1:], f"{label} path")
        require("/" + relative == raw_path, f"{label} path is not canonical: {raw_path!r}")
        require(isinstance(record, dict), f"{label} record is not an object: {raw_path}")
        require(record.get("kind", "file") == "file",
                f"{label} record is not a regular file: {raw_path}")
        require(type(record.get("bytes")) is int and record["bytes"] >= 0,
                f"{label} byte count is malformed: {raw_path}")
        for field in ("uid", "gid", "mode"):
            require(type(record.get(field)) is int and record[field] >= 0,
                    f"{label} {field} is malformed: {raw_path}")
        require(record["mode"] <= 0o7777,
                f"{label} mode is malformed: {raw_path}")
        expected_hash = record.get("sha256")
        require(isinstance(expected_hash, str) and re.fullmatch(r"[0-9a-f]{64}", expected_hash),
                f"{label} hash is malformed: {raw_path}")
        for field in ("target_uid", "target_gid", "target_mode"):
            if field in record:
                require(type(record[field]) is int and record[field] >= 0,
                        f"{label} target metadata is malformed: {raw_path}")
        if "target_uid" in record:
            require(record["target_uid"] == record["uid"] and
                    record["target_gid"] == record["gid"] and
                    record["target_mode"] == record["mode"],
                    f"{label} target metadata differs from recorded metadata: {raw_path}")
        normalized[raw_path] = dict(record)
    return {**payload, "files": count, "path_records": dict(sorted(normalized.items()))}


def load_metadata_bindings(hardware: dict[str, Any]) -> dict[str, Any]:
    protected_raw = json_object(PROTECTED_BASELINE_METADATA,
                                "protected baseline metadata")
    require(digest(PROTECTED_BASELINE_METADATA, "protected baseline metadata") ==
            PROTECTED_BASELINE_METADATA_SHA256,
            "protected baseline metadata hash changed")
    require(protected_raw.get("schema") == PROTECTED_BASELINE_METADATA_SCHEMA and
            protected_raw.get("manifest_sha256") == OLD_MANIFEST_SHA256,
            "protected baseline metadata is not bound to the accepted manifest")
    protected_payload = validate_metadata_records(
        {"schema": protected_raw["schema"], "sha256": PROTECTED_BASELINE_METADATA_SHA256,
         "manifest_sha256": protected_raw["manifest_sha256"],
         "files": len(protected_raw.get("files", {})),
         "path_records": protected_raw.get("files")},
        "protected baseline metadata", PROTECTED_BASELINE_METADATA_SCHEMA,
        PROTECTED_BASELINE_METADATA_SHA256, 297)
    public_raw = hardware.get("public_snapshot_metadata")
    require(isinstance(public_raw, dict), "hardware public snapshot metadata is missing")
    public_payload = validate_metadata_records(
        public_raw, "hardware public snapshot metadata", PUBLIC_SNAPSHOT_METADATA_SCHEMA,
        PUBLIC_SNAPSHOT_METADATA_SHA256, PUBLIC_SNAPSHOT_METADATA_FILES)
    public_source = OUT / "waydroid-encrypted-20261015" / "phone-public-combined" / "snapshot-metadata.json"
    require(digest(public_source, "public snapshot metadata") == PUBLIC_SNAPSHOT_METADATA_SHA256,
            "public snapshot metadata source hash changed")
    source_raw = json_object(public_source, "public snapshot metadata")
    require(source_raw.get("schema") == PUBLIC_SNAPSHOT_METADATA_SCHEMA and
            source_raw.get("files") == public_payload["path_records"],
            "hardware public snapshot path records differ from pinned metadata")
    manifest_source = OUT / "waydroid-encrypted-20261015" / "phone-public-combined" / MANIFEST_REL
    regular(manifest_source, "protected manifest snapshot")
    require(digest(manifest_source, "protected manifest snapshot") == OLD_MANIFEST_SHA256,
            "protected manifest snapshot hash changed")
    protected_manifest = {
        "path": "/" + MANIFEST_REL, "bytes": manifest_source.stat().st_size,
        "uid": 0, "gid": 0, "mode": 0o600, "sha256": OLD_MANIFEST_SHA256,
    }
    return {
        "protected_baseline_metadata": protected_payload,
        "public_snapshot_metadata": public_payload,
        "protected_manifest_metadata": protected_manifest,
    }


def safe_relative(value: str, label: str) -> str:
    require(isinstance(value, str) and value and not value.startswith("/"),
            f"{label} is not a relative path")
    parsed = PurePosixPath(value)
    require("\\" not in value and all(part not in ("", ".", "..") for part in parsed.parts),
            f"{label} contains unsafe path components: {value!r}")
    require(parsed.as_posix() == value, f"{label} is not canonical: {value!r}")
    return value


def validate_candidate() -> dict[str, Any]:
    manifest = json_object(CANDIDATE / "candidate-manifest.json", "encrypted candidate manifest")
    require(manifest.get("kind") == "r8q-encrypted-waydroid-kernel-candidate",
            "candidate kind is not the reviewed encrypted kernel candidate")
    require(manifest.get("stage2_complete") is True, "candidate is not stage2_complete")
    require(manifest.get("kernel_release") == RELEASE, "candidate release is not Waydroid2")
    require(manifest.get("root_state") == "encrypted", "candidate root state is not encrypted")
    require(manifest.get("shared_source_references") == 0, "candidate references shared source")
    require(manifest.get("installed") is False and manifest.get("boot_tested") is False,
            "candidate manifest is already marked installed or boot-tested")
    require(manifest.get("deployment_prepared") is False,
            "candidate manifest is already marked deployment-prepared")
    source = (REPO / "out/waydroid-kernel-20261013/source").resolve()
    require(Path(str(manifest.get("source", ""))).resolve() == source,
            "candidate source is not the pinned complete source")
    require(manifest.get("complete_source_proof", {}).get("sha256") == COMPLETE_SOURCE_PROOF_SHA256 and
            re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("source_sha256", ""))) is not None,
            "candidate complete-source proof is not the pinned proof")
    files = manifest.get("files")
    require(isinstance(files, dict), "candidate artifact map is missing")
    for relative, entry in files.items():
        safe_relative(relative, "candidate artifact path")
        require(isinstance(entry, dict) and re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))) is not None,
                f"candidate artifact metadata is malformed: {relative}")
        path = CANDIDATE / relative
        info = regular(path, f"candidate artifact {relative}")
        require(info.st_size == entry.get("bytes") and digest(path, relative) == entry["sha256"],
                f"candidate artifact hash/size differs: {relative}")
    required = {"payload/BOOTAA64.EFI", "payload/R8Q-RTC.DTB", ".config",
                "module-inventory.json", "embedded-initramfs-manifest.json",
                "usr/initramfs_data.cpio", "usr/initramfs_inc_data"}
    for relative in sorted(required):
        entry = files.get(relative)
        require(isinstance(entry, dict), f"candidate artifact is absent: {relative}")
        path = CANDIDATE / relative
        safe_relative(relative, "candidate artifact path")
        expected = entry.get("sha256")
        require(re.fullmatch(r"[0-9a-f]{64}", str(expected)) is not None,
                f"candidate artifact hash is malformed: {relative}")
    require(files["payload/R8Q-RTC.DTB"]["sha256"] == DTB_SHA256,
            "candidate DTB hash differs from accepted DTB")
    require(isinstance(manifest.get("module_count"), int) and manifest["module_count"] > 0,
            "candidate module inventory is empty")
    config: dict[str, str] = {}
    for line in (CANDIDATE / ".config").read_text(encoding="utf-8").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            config[key] = value
    for key in ("CONFIG_BLK_DEV_DM", "CONFIG_DM_CRYPT", "CONFIG_CRYPTO_AES", "CONFIG_CRYPTO_AUTHENC",
                "CONFIG_CRYPTO_CBC", "CONFIG_CRYPTO_ESSIV", "CONFIG_CRYPTO_LIB_MD5", "CONFIG_CRYPTO_XTS",
                "CONFIG_PNFS_BLOCK"):
        require(config.get(key) == "y", f"candidate encrypted config gate is not built-in: {key}")
    require(config.get("CONFIG_LOCALVERSION") == '"-r8q-waydroid2"',
            "candidate local version differs from Waydroid2")
    require(config.get("CONFIG_INITRAMFS_SOURCE") == FINAL_INITRAMFS_SOURCE,
            "candidate initramfs source is not the final encrypted archive")
    delta = manifest.get("config_delta")
    require(isinstance(delta, dict), "candidate configuration delta is missing")
    require(set(delta) == {"CONFIG_BLK_DEV_DM", "CONFIG_DM_CRYPT", "CONFIG_CRYPTO_AES",
                           "CONFIG_CRYPTO_AUTHENC", "CONFIG_CRYPTO_CBC", "CONFIG_CRYPTO_ESSIV",
                           "CONFIG_CRYPTO_LIB_MD5", "CONFIG_CRYPTO_XTS", "CONFIG_PNFS_BLOCK",
                           "CONFIG_INITRAMFS_SOURCE", "CONFIG_LOCALVERSION"},
            "candidate configuration delta is outside reviewed encryption gates")
    return manifest


def validate_hardware(candidate: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    manifest = json_object(HARDWARE / "bundle-manifest.json", "hardware bundle manifest")
    require(manifest.get("schema") == "r8q-waydroid-hardware-preparation/v1",
            "hardware bundle schema is not reviewed")
    require(manifest.get("release") == RELEASE and manifest.get("root_state") == "encrypted",
            "hardware bundle release/root state is wrong")
    require(manifest.get("phone_operations") is False, "hardware bundle records phone operations")
    kernel_proof = manifest.get("kernel_manifest", {})
    require(Path(str(kernel_proof.get("path", ""))).resolve() == CANDIDATE / "candidate-manifest.json" and
            kernel_proof.get("sha256") == digest(CANDIDATE / "candidate-manifest.json", "candidate manifest"),
            "hardware bundle was not built from this final candidate manifest")
    identity = manifest.get("accepted_root_identity", {})
    require(identity.get("machine_id") == "1290f2212bd743569044571db21a6c96" and
            identity.get("root_uuid") == "217b9308-40c7-4eb0-90a9-09ed4e233173",
            "hardware bundle root identity is not the accepted identity")
    protected = manifest.get("protected_baseline", {})
    require(protected.get("path") == MANIFEST_REL and protected.get("entries") == 297 and
            protected.get("sha256") == OLD_MANIFEST_SHA256,
            "hardware bundle protected baseline is not the accepted 297-line manifest")
    source_binding = manifest.get("candidate_source", {})
    require(Path(str(source_binding.get("path", ""))).resolve() ==
            (REPO / "out/waydroid-kernel-20261013/source").resolve() and
            source_binding.get("complete_source_proof_sha256") == COMPLETE_SOURCE_PROOF_SHA256,
            "hardware candidate source binding is not the pinned complete source proof")
    inventory_binding = manifest.get("module_inventory", {})
    inventory_path = CANDIDATE / "module-inventory.json"
    catalogue_path = CANDIDATE / "modules/lib/modules" / RELEASE
    inventory_entry = candidate["files"].get("module-inventory.json")
    require(isinstance(inventory_entry, dict) and
            Path(str(inventory_binding.get("path", ""))).resolve() == inventory_path.resolve() and
            catalogue_path.is_dir() and not catalogue_path.is_symlink() and
            inventory_binding.get("bytes") == inventory_entry.get("bytes") and
            inventory_binding.get("sha256") == inventory_entry.get("sha256") and
            inventory_binding.get("candidate_manifest_sha256") ==
            digest(CANDIDATE / "candidate-manifest.json", "candidate manifest"),
            "hardware module inventory is not bound to the final candidate")
    require(manifest.get("boot_artifact", {}).get("sha256") ==
            candidate["files"]["payload/BOOTAA64.EFI"]["sha256"],
            "hardware bundle BOOT hash does not match final candidate")
    changes = manifest.get("allowed_change_inventory")
    require(isinstance(changes, dict), "hardware bundle change inventory is missing")
    paths = changes.get("new_rootfs_paths")
    require(isinstance(paths, list) and paths, "hardware bundle has no new rootfs paths")
    require(DROPINS <= set(paths), "hardware bundle new paths omit a reviewed dispatch drop-in")
    retained = set(changes.get("retained_global_paths", []))
    dropins = set(changes.get("dispatch_dropin_paths", []))
    require(dropins == DROPINS, "hardware bundle dispatch drop-ins do not match the exact five-file allowlist")
    rows: list[dict[str, Any]] = []
    file_rows = {row.get("path"): row for row in manifest.get("files", [])
                 if isinstance(row, dict) and isinstance(row.get("path"), str)}
    for relative in sorted(set(paths)):
        safe_relative(relative, "new rootfs path")
        require(relative not in retained, f"new path is also a retained global: {relative}")
        allowed = relative.startswith(PROFILE_PREFIX) or relative.startswith(MODULE_PREFIX) or relative in DROPINS
        require(allowed, f"new rootfs path is outside exact reviewed prefixes: {relative}")
        source = HARDWARE / "rootfs" / relative
        info = regular(source, f"new rootfs file {relative}")
        require(stat.S_IMODE(info.st_mode) & 0o7000 == 0,
                f"new rootfs file has special mode bits: {relative}")
        row = file_rows.get("rootfs/" + relative)
        require(isinstance(row, dict) and row.get("sha256") == digest(source, relative) and
                row.get("bytes") == info.st_size, f"bundle inventory differs: {relative}")
        changes_row = manifest.get("change_inventory", {}).get(relative)
        if relative in dropins:
            require(isinstance(changes_row, dict) and changes_row.get("after") == row["sha256"],
                    f"bundle change proof is missing: {relative}")
        rows.append({"path": relative, "sha256": row["sha256"], "bytes": info.st_size,
                     "mode": stat.S_IMODE(info.st_mode)})
    return manifest, rows, load_metadata_bindings(manifest)


def build_archive(rows: list[dict[str, Any]], candidate: dict[str, Any], hardware: dict[str, Any],
                  metadata_binding: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    DEPLOY.mkdir(parents=True, exist_ok=True)
    archive = DEPLOY / ARCHIVE_NAME
    require(not archive.exists() and not archive.is_symlink(), f"archive already exists: {archive}")
    boot = CANDIDATE / "payload/BOOTAA64.EFI"
    boot_row = candidate["files"]["payload/BOOTAA64.EFI"]
    metadata = {"schema": "r8q-waydroid-kernel-trial-archive/v1", "release": RELEASE,
                "manifest_path": "/" + MANIFEST_REL, "old_manifest_sha256": OLD_MANIFEST_SHA256,
                "rootfs": rows, "efi": {"path": "efi/BOOTAA64.EFI", "sha256": boot_row["sha256"],
                                          "bytes": boot_row["bytes"]},
                **metadata_binding}
    with tarfile.open(archive, "x") as bundle:
        payload = json.dumps(metadata, indent=2, sort_keys=True).encode() + b"\n"
        info = tarfile.TarInfo("transaction.json")
        info.size, info.mode, info.uid, info.gid = len(payload), 0o600, 0, 0
        bundle.addfile(info, __import__("io").BytesIO(payload))
        for row in rows:
            source = HARDWARE / "rootfs" / row["path"]
            member = tarfile.TarInfo("rootfs/" + row["path"])
            member.size, member.mode, member.uid, member.gid = row["bytes"], row["mode"], 0, 0
            with source.open("rb") as stream:
                bundle.addfile(member, stream)
        member = tarfile.TarInfo("efi/BOOTAA64.EFI")
        member.size, member.mode, member.uid, member.gid = boot_row["bytes"], 0o600, 0, 0
        with boot.open("rb") as stream:
            bundle.addfile(member, stream)
    archive_hash = digest(archive, "deployment archive")
    saved = DEPLOY / "rollback"
    saved.mkdir(exist_ok=True)
    saved_efi = saved / "BOOTAA64.EFI.ENCRYPTED04-SAVED"
    if not saved_efi.exists():
        shutil.copyfile(OLD_EFI, saved_efi)
        saved_efi.chmod(0o600)
    require(digest(saved_efi, "local EFI rollback copy") == OLD_EFI_SHA256,
            "local EFI rollback copy hash differs")
    plan = {"schema": "r8q-waydroid-kernel-trial-plan/v1", "release": RELEASE,
            "stage2_complete": True, "archive": {"path": str(archive), "bytes": archive.stat().st_size,
            "sha256": archive_hash}, "new_rootfs_files": rows,
            "candidate_manifest_sha256": digest(CANDIDATE / "candidate-manifest.json", "candidate manifest"),
            "hardware_manifest_sha256": digest(HARDWARE / "bundle-manifest.json", "hardware bundle manifest"),
            "new_efi": {"sha256": boot_row["sha256"], "bytes": boot_row["bytes"]},
            "old_efi": {"sha256": OLD_EFI_SHA256, "bytes": OLD_EFI.stat().st_size,
                        "local_rollback": str(saved_efi)},
            "protected_manifest": {"path": "/" + MANIFEST_REL, "old_sha256": OLD_MANIFEST_SHA256,
                                   "old_entries": 297, "append_only": True},
            "metadata_binding": metadata_binding,
            "phone_operations": False, "formatting": False, "raw_userdata_writes": False,
            "root_device_changed": False, "luks_changed": False,
            "service_restarts": False, "gpu_unload": False, "daemon_reload_only": True}
    plan_path = DEPLOY / PLAN_NAME
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    plan_path.chmod(0o600)
    return archive, plan


def verify_existing_plan(plan: dict[str, Any], rows: list[dict[str, Any]], candidate: dict[str, Any],
                         hardware: dict[str, Any], metadata_binding: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    require(plan.get("schema") == "r8q-waydroid-kernel-trial-plan/v1" and
            plan.get("release") == RELEASE and plan.get("stage2_complete") is True,
            "deployment plan is not the reviewed Waydroid2 plan")
    require(plan.get("candidate_manifest_sha256") == digest(CANDIDATE / "candidate-manifest.json", "candidate manifest") and
            plan.get("hardware_manifest_sha256") == digest(HARDWARE / "bundle-manifest.json", "hardware bundle manifest"),
            "deployment plan inputs changed")
    require(plan.get("new_rootfs_files") == rows, "deployment plan rootfs inventory changed")
    require(plan.get("metadata_binding") == metadata_binding,
            "deployment plan metadata binding changed")
    require(stat.S_IMODE((DEPLOY / PLAN_NAME).stat().st_mode) == 0o600,
            "deployment plan mode changed")
    boot = candidate["files"]["payload/BOOTAA64.EFI"]
    require(plan.get("new_efi") == {"sha256": boot["sha256"], "bytes": boot["bytes"]},
            "deployment plan EFI inventory changed")
    archive_info = plan.get("archive", {})
    archive = DEPLOY / ARCHIVE_NAME
    info = regular(archive, "deployment archive")
    require(archive_info.get("path") == str(archive) and archive_info.get("bytes") == info.st_size and
            archive_info.get("sha256") == digest(archive, "deployment archive") and
            stat.S_IMODE(info.st_mode) == 0o600,
            "deployment archive bytes or metadata changed")
    try:
        with tarfile.open(archive, "r") as bundle:
            stream = bundle.extractfile("transaction.json")
            require(stream is not None, "deployment archive transaction metadata is absent")
            transaction = json.loads(stream.read())
    except (OSError, KeyError, TypeError, json.JSONDecodeError, tarfile.TarError) as exc:
        raise InstallError("deployment archive transaction metadata is unreadable") from exc
    for key, expected in metadata_binding.items():
        require(transaction.get(key) == expected,
                "deployment archive metadata binding changed: " + key)
    return archive, plan





def run_fixture() -> int:
    """Execute the embedded remote implementation against its real fixtures."""
    DEPLOY.mkdir(parents=True, exist_ok=True)
    upload_fixture()
    snapshot = OUT / "waydroid-encrypted-20261015/phone-public-rootfs"
    old_efi = OLD_EFI
    dtb = OUT / "encryption-implementation-20261013/production-kernel04/payload/R8Q-RTC.DTB"
    require(snapshot.is_dir() and old_efi.is_file() and dtb.is_file(),
            "remote transaction fixture inputs are unavailable")
    with tempfile.TemporaryDirectory(prefix="remote-fixture-", dir=DEPLOY) as temporary:
        temporary_path = Path(temporary)
        source = REMOTE_TEMPLATE.replace("__ARCHIVE_BYTES__", "1").replace("__ARCHIVE_SHA256__", "0" * 64)
        source = source.replace("__NEW_EFI_SHA256__", "1" * 64).replace("__NEW_EFI_BYTES__", "1")
        remote_script = temporary_path / "remote-transaction-fixture.py"
        remote_script.write_text(source, encoding="utf-8")
        remote_script.chmod(0o700)
        environment = os.environ.copy()
        environment.update({"R8Q_FIXTURE_SNAPSHOT": str(snapshot),
                            "R8Q_FIXTURE_OLD_EFI": str(old_efi),
                            "R8Q_FIXTURE_DTB": str(dtb),
                            "R8Q_FIXTURE_DIR": str(temporary_path / "sandbox")})
        completed = subprocess.run([sys.executable, str(remote_script), "--fixture"],
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, timeout=180, check=False)
        output_lines = completed.stdout.splitlines()
        record: dict[str, Any] = {}
        if output_lines:
            try:
                record = json.loads(output_lines[-1])
            except json.JSONDecodeError:
                pass
        require(completed.returncode == 0 and record.get("result") == "PASS",
                "embedded remote fixture failed: " + (completed.stderr or completed.stdout)[-4096:])
    record["upload_fixture"] = "PASS"
    receipt = DEPLOY / "fixture-transaction-receipt.json"
    receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt.chmod(0o600)
    print(json.dumps({"result": "PASS", "fixture": str(receipt), "cases": len(record.get("cases", []))}, sort_keys=True))
    return 0


REMOTE_TEMPLATE = r'''#!/usr/bin/env python3
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

os.umask(0o077)
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
os.environ["LC_ALL"] = "C"

ARCHIVE = Path("/run/r8q-waydroid2-deploy.tar")
ARCHIVE_BYTES = __ARCHIVE_BYTES__
ARCHIVE_SHA256 = "__ARCHIVE_SHA256__"
NEW_RELEASE = "7.1.2-r8q-waydroid2"
CURRENT_RELEASE = "7.1.2-r8q-rtc2"
NEW_EFI_SHA256 = "__NEW_EFI_SHA256__"
NEW_EFI_BYTES = __NEW_EFI_BYTES__
OLD_EFI_SHA256 = "730627f49b8d41b9bdc6ef7931fe94911636003c61596c84d769d532ad27c49b"
OLD_EFI_BYTES = 67484160
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
OLD_MANIFEST_SHA256 = "c157dc72e80c64799ca4161a00f96784874c87323ce2fb0af0f2ff8a472e2ae5"
PROTECTED_BASELINE_METADATA_SHA256 = "ada81d61b271b96f35681f07e42fb56907332ee4e93a04ccee0cc715cbbd3d1c"
PROTECTED_BASELINE_METADATA_SCHEMA = "r8q-protected-baseline-metadata/v1"
PUBLIC_SNAPSHOT_METADATA_SHA256 = "c9f06e873f9f35396b4c63ea3b3a32ae169d76eb195ab6eb94d257af03d80fe7"
PUBLIC_SNAPSHOT_METADATA_SCHEMA = "r8q-public-rootfs-snapshot/v1"
PUBLIC_SNAPSHOT_METADATA_FILES = 147
MACHINE_ID = "1290f2212bd743569044571db21a6c96"
ROOT_DEVICE = "/dev/sda36"
ROOT_PARTUUID = "1b81e7e6-f50d-419b-a739-2aeef8da3335"
ROOT_BYTES = 115107409920
LUKS_UUID = "b9081516-2446-4086-87c1-76d2127493ec"
MAPPER_NAME = "cryptroot"
CACHE_DEVICE = "/dev/sda32"
CACHE_NAME = "sda32"
CACHE_PARTUUID = "5594c694-c871-4b5f-90b1-690a6f68e0f7"
CACHE_BYTES = 629145600
CACHE_PARTNAME = "cache"
DISK_DEVICE = "/dev/sda"
DISK_GUID = "98101b32-bbe2-4bf2-a06e-2bb33d000c20"
STAGE = Path("/run/r8q-waydroid2-stage")
MOUNT = Path("/run/r8q-waydroid2-cache")
TARGET_ROOT = Path("/")
MANIFEST = Path("/root/r8q-screen-lock-20261013.sha256")
EFI = Path("EFI/BOOT/BOOTAA64.EFI")
DTB = Path("EFI/BOOT/R8Q-RTC.DTB")
SAVED = EFI.with_name("BOOTAA64.EFI.WAYDROID2-SAVED-FOR-ROLLBACK")
NEW = EFI.with_name("BOOTAA64.EFI.WAYDROID2-NEW")
RECOVERY = EFI.with_name("BOOTAA64.EFI.WAYDROID2-RECOVERY")
MARGIN_BYTES = 16 * 1024 * 1024
DROPINS = {
    "etc/systemd/system/r8q-hardware-prepare.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-battery.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-usb-gadget.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-audio-start.service.d/90-r8q-waydroid2-dispatch.conf",
    "etc/systemd/system/r8q-wifi-standby.service.d/90-r8q-waydroid2-dispatch.conf",
}

FIXTURE = False
OWNER_UID = 0
OWNER_GID = 0
INJECT_FAILURE = ""
fixture_mount_active = False
fixture_mount_fail_once = False
fixture_after_unmount_fired = False
fixture_no_mount_failures = 0
cache_rdev = None
cache_mounted = False
cache_active = None
cache_saved = None
cache_recovery = None
efi_replaced = False
manifest_changed = False
manifest_before = b""
manifest_new_sha256 = None
manifest_new_bytes = None
protected_baseline_metadata = {}
public_snapshot_metadata = {}
protected_manifest_metadata = {}
cleanup_failures = []
rollback_phase = False
owned_artifacts = set()
stage_owned = False
archive_owned = False
created_files = []
created_dirs = []
stage_dirs = []


class Failure(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Failure(message)


def regular(path, label):
    try:
        info = path.lstat()
    except OSError as exc:
        raise Failure(label + ": unavailable") from exc
    need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), label + ": not regular")
    return info


def sha(path, label):
    regular(path, label)
    value = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def output(argv, timeout=60):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Failure("command failed to run: " + argv[0]) from exc
    need(result.returncode == 0, "command failed: " + Path(argv[0]).name)
    return result.stdout.strip()


def run(argv, timeout=60):
    global fixture_mount_active, fixture_mount_fail_once
    if FIXTURE:
        name = Path(argv[0]).name
        if name == "mount":
            fixture_mount_active = True
            if INJECT_FAILURE == "mount-before-mounted" and not fixture_mount_fail_once:
                fixture_mount_fail_once = True
                raise Failure("fixture mount subprocess failure after mount")
        elif name == "umount":
            fixture_mount_active = False
        return ""
    return output(argv, timeout)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        need(count > 0, "short write")
        view = view[count:]


def fsync_directories(paths):
    seen = set()
    for directory in paths:
        for candidate in (directory, directory.parent):
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                directory_fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                raise Failure("cannot fsync created parent directory: " + str(candidate)) from exc


def copy_exclusive(source, destination, mode=0o600):
    global owned_artifacts
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                  getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with source.open("rb", buffering=0) as original, os.fdopen(fd, "wb") as target:
            fd = -1
            for block in iter(lambda: original.read(1024 * 1024), b""):
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(destination, mode)
        os.chown(destination, OWNER_UID, OWNER_GID)
        owned_artifacts.add(Path(destination))
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            Path(destination).unlink()
        except OSError:
            pass
        raise


def safe_relative(value):
    path = Path(value)
    need(value and not value.startswith("/") and "\\" not in value and
         all(part not in ("", ".", "..") for part in path.parts) and path.as_posix() == value,
         "unsafe archive path")
    return value


def ensure_parent(path, stop, tracking):
    need(path.is_absolute() and stop.is_absolute(), "transaction paths must be absolute")
    try:
        relative = path.relative_to(stop)
    except ValueError as exc:
        raise Failure("path escaped transaction root: " + str(path) + " stop=" + str(stop)) from exc
    need(stop.is_dir() and not stop.is_symlink(), "transaction root is unsafe: " + str(stop))
    missing = []
    current = stop
    for component in relative.parts[:-1]:
        current /= component
        if current.exists() or current.is_symlink():
            need(current.is_dir() and not current.is_symlink(),
                 "symlink/non-directory parent: " + str(current))
        else:
            missing.append(current)
    for directory in missing:
        directory.mkdir(mode=0o755)
        os.chmod(directory, 0o755)
        os.chown(directory, OWNER_UID, OWNER_GID)
        tracking.append(directory)


def target_absolute(path):
    need(path.startswith("/") and ".." not in Path(path).parts, "manifest path is unsafe")
    return TARGET_ROOT / path.lstrip("/")


def verify_metadata_binding(payload, schema, metadata_sha256, count, label,
                            allow_manifest_append=False, manifest_bytes=None,
                            manifest_sha256=None):
    need(isinstance(payload, dict) and payload.get("schema") == schema and
         payload.get("sha256") == metadata_sha256 and payload.get("files") == count,
         label + " binding changed")
    records = payload.get("path_records")
    need(isinstance(records, dict) and len(records) == count,
         label + " record count changed")
    for path, expected in sorted(records.items()):
        need(isinstance(path, str) and path.startswith("/") and
             "\\" not in path and path == "/" + path.lstrip("/") and
             all(part not in ("", ".", "..") for part in Path(path).parts[1:]),
             label + " path is unsafe: " + repr(path))
        need(isinstance(expected, dict) and expected.get("kind", "file") == "file",
             label + " record is not a regular file: " + path)
        need(type(expected.get("bytes")) is int and expected["bytes"] >= 0 and
             type(expected.get("uid")) is int and expected["uid"] >= 0 and
             type(expected.get("gid")) is int and expected["gid"] >= 0 and
             type(expected.get("mode")) is int and 0 <= expected["mode"] <= 0o7777 and
             isinstance(expected.get("sha256"), str) and
             re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]),
             label + " record is malformed: " + path)
        target = target_absolute(path)
        info = regular(target, path)
        need(info.st_uid == expected["uid"] and info.st_gid == expected["gid"] and
             stat.S_IMODE(info.st_mode) == expected["mode"],
             label + " ownership or mode differs: " + path)
        manifest_path = "/" + MANIFEST.relative_to(TARGET_ROOT).as_posix()
        if allow_manifest_append and path == manifest_path:
            need(type(manifest_bytes) is int and isinstance(manifest_sha256, str),
                 label + " post-append manifest binding is missing")
            need(info.st_size == manifest_bytes and sha(target, path) == manifest_sha256,
                 label + " post-append manifest bytes/hash differ: " + path)
        else:
            need(info.st_size == expected["bytes"] and sha(target, path) == expected["sha256"],
                 label + " metadata differs: " + path)
    return records


def verify_protected_manifest_metadata(label, baseline=True):
    need(isinstance(protected_manifest_metadata, dict) and
         protected_manifest_metadata.get("path") == str(MANIFEST) and
         protected_manifest_metadata.get("sha256") == OLD_MANIFEST_SHA256 and
         type(protected_manifest_metadata.get("bytes")) is int and
         type(protected_manifest_metadata.get("uid")) is int and
         type(protected_manifest_metadata.get("gid")) is int and
         type(protected_manifest_metadata.get("mode")) is int,
         label + " binding changed")
    info = MANIFEST.lstat()
    need(info.st_uid == protected_manifest_metadata["uid"] and
         info.st_gid == protected_manifest_metadata["gid"] and
         stat.S_IMODE(info.st_mode) == protected_manifest_metadata["mode"],
         label + " ownership or mode changed")
    if baseline:
        need(info.st_size == protected_manifest_metadata["bytes"],
             label + " size changed")


def mount_records():
    if FIXTURE:
        if fixture_mount_active:
            return [{"mountpoint": str(MOUNT), "rdev": cache_rdev, "source": CACHE_DEVICE,
                     "fstype": "vfat", "options": {"rw", "nosuid", "nodev", "noexec"}}]
        return []
    records = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        fields, tail = left.split(), right.split()
        if len(fields) >= 6 and len(tail) >= 2:
            records.append({"mountpoint": fields[4], "rdev": fields[2], "source": tail[1],
                            "fstype": tail[0], "options": set(fields[5].split(","))})
    return records


def device_numbers(path):
    info = path.lstat()
    need(stat.S_ISBLK(info.st_mode) and not stat.S_ISLNK(info.st_mode), str(path) + " is not block")
    return f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"


def no_mount(device, rdev):
    global fixture_no_mount_failures
    if FIXTURE:
        if INJECT_FAILURE == "no-mount" and fixture_no_mount_failures < 2:
            fixture_no_mount_failures += 1
            raise Failure("fixture no_mount verification failure")
        need(not fixture_mount_active, device + " remains mounted")
        return
    try:
        result = subprocess.run(["/usr/bin/findmnt", "-rn", "-S", device],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Failure("cannot inspect device mounts") from exc
    need(result.returncode == 1 and not result.stdout.strip(), device + " is mounted")
    need(not any(record["rdev"] == rdev for record in mount_records()),
         device + " remains in mountinfo")


def no_holders(name):
    if FIXTURE:
        return
    holders = Path("/sys/class/block") / name / "holders"
    need(holders.is_dir() and not any(holders.iterdir()), name + " has an active holder")


def root_identity():
    if FIXTURE:
        return
    need(os.geteuid() == 0, "transaction must run as root")
    need(Path("/etc/machine-id").read_text(encoding="ascii").strip() == MACHINE_ID,
         "machine identity changed")
    need(output(["/usr/bin/uname", "-r"]) == CURRENT_RELEASE, "current kernel changed")
    need(output(["/usr/bin/findmnt", "-rn", "-o", "SOURCE,FSTYPE", "/"]) ==
         "/dev/mapper/cryptroot ext4", "encrypted root identity changed")
    status = output(["/usr/bin/cryptsetup", "status", MAPPER_NAME])
    need("is active" in status.lower() and ROOT_DEVICE in status, "cryptroot is not active")
    need(output(["/usr/bin/cryptsetup", "luksUUID", ROOT_DEVICE]).lower() == LUKS_UUID,
         "LUKS UUID changed")
    need(output(["/usr/bin/blkid", "-s", "TYPE", "-o", "value", ROOT_DEVICE]) == "crypto_LUKS",
         "root is not LUKS")
    need(output(["/usr/bin/blkid", "-s", "PARTUUID", "-o", "value", ROOT_DEVICE]).lower() ==
         ROOT_PARTUUID, "root PARTUUID changed")
    need(output(["/usr/bin/blockdev", "--getsize64", ROOT_DEVICE]) == str(ROOT_BYTES),
         "root size changed")
    no_holders(CACHE_NAME)
    no_mount(ROOT_DEVICE, device_numbers(Path(ROOT_DEVICE)))
    mappers = []
    for device in sorted(Path("/sys/class/block").glob("dm-*")):
        if (device / "dm/name").is_file() and (device / "dm/name").read_text().strip() == MAPPER_NAME:
            mappers.append(device)
    need(len(mappers) == 1, "cryptroot mapper is ambiguous")
    need({path.name for path in (mappers[0] / "slaves").iterdir()} == {"sda36"},
         "cryptroot slave changed")


def cache_identity():
    global cache_rdev
    if FIXTURE:
        cache_rdev = "fixture-rdev"
        return cache_rdev
    device = Path(CACHE_DEVICE)
    need(device.is_block_device() and not device.is_symlink(), "CACHE block unavailable")
    cache_rdev = device_numbers(device)
    need(output(["/usr/bin/blockdev", "--getsize64", CACHE_DEVICE]) == str(CACHE_BYTES),
         "CACHE size changed")
    need(output(["/usr/bin/blkid", "-s", "PARTUUID", "-o", "value", CACHE_DEVICE]).lower() ==
         CACHE_PARTUUID, "CACHE PARTUUID changed")
    need(output(["/usr/bin/blkid", "-s", "TYPE", "-o", "value", CACHE_DEVICE]) == "vfat",
         "CACHE type changed")
    need(output(["/usr/bin/blkid", "-s", "PTUUID", "-o", "value", DISK_DEVICE]).lower() == DISK_GUID,
         "disk GUID changed")
    uevent = Path("/sys/class/block") / CACHE_NAME / "uevent"
    values = dict(line.split("=", 1) for line in uevent.read_text(encoding="ascii").splitlines() if "=" in line)
    need(values.get("PARTNAME") == CACHE_PARTNAME and values.get("PARTUUID", "").lower() == CACHE_PARTUUID,
         "CACHE uevent identity changed")
    no_holders(CACHE_NAME)
    no_mount(CACHE_DEVICE, cache_rdev)
    return cache_rdev


def verify_manifest(label, expected_prefix=None, expected_append=None):
    data = MANIFEST.read_bytes()
    verify_protected_manifest_metadata(label, baseline=expected_prefix is None)
    verify_metadata_binding(protected_baseline_metadata, PROTECTED_BASELINE_METADATA_SCHEMA,
                            PROTECTED_BASELINE_METADATA_SHA256, 297,
                            "protected baseline metadata")
    if expected_prefix is None:
        need(sha(MANIFEST, label) == OLD_MANIFEST_SHA256 and len(data.splitlines()) == 297,
             label + " baseline changed")
    else:
        need(data.startswith(expected_prefix), label + " changed its protected prefix")
    rows = data.splitlines()
    failures = []
    parsed = []
    for raw_line in rows:
        line = raw_line.decode("utf-8", "strict")
        fields = line.split(None, 1)
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]) or not fields[1].startswith("/"):
            failures.append("malformed manifest row")
            continue
        path = fields[1]
        try:
            target = target_absolute(path)
            info = regular(target, path)
            protected_record = protected_baseline_metadata["path_records"].get(path)
            if protected_record is None and (info.st_uid != OWNER_UID or info.st_gid != OWNER_GID):
                failures.append(path + ": owner")
            elif sha(target, path) != fields[0]:
                failures.append(path + ": hash")
            parsed.append((fields[0], path))
        except (Failure, OSError) as exc:
            failures.append(path + ": " + str(exc))
        if len(failures) >= 8:
            break
    if not FIXTURE:
        result = subprocess.run(["/usr/bin/sha256sum", "--quiet", "-c", str(MANIFEST)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, check=False, timeout=120,
                                cwd=str(TARGET_ROOT))
        if result.returncode != 0:
            detail = (result.stdout + result.stderr)[:4096]
            failures.append("sha256sum -c failed: " + detail)
    if expected_prefix is None:
        need({path for _, path in parsed} == set(protected_baseline_metadata["path_records"]),
             label + " does not cover the pinned protected metadata paths")
    if expected_append is not None:
        expected_tail = [(row["sha256"], "/" + row["path"]) for row in expected_append]
        prefix_rows = len(expected_prefix.splitlines()) if expected_prefix is not None else 0
        need(parsed[prefix_rows:] == expected_tail,
             label + " appended rows differ from the requested new files")
    need(not failures, label + " verification failed: " + "; ".join(failures[:8]))
    return parsed


def stage_archive():
    global protected_baseline_metadata, public_snapshot_metadata, protected_manifest_metadata
    global stage_owned, archive_owned
    info = regular(ARCHIVE, "deployment archive")
    need(info.st_uid == OWNER_UID and info.st_gid == OWNER_GID and stat.S_IMODE(info.st_mode) == 0o600 and
         info.st_size == ARCHIVE_BYTES, "deployment archive metadata changed")
    need(sha(ARCHIVE, "deployment archive") == ARCHIVE_SHA256, "deployment archive hash changed")
    archive_owned = True
    need(not STAGE.exists() and not STAGE.is_symlink(), "transaction stage already exists")
    STAGE.mkdir(mode=0o700)
    stage_owned = True
    os.chmod(STAGE, 0o700)
    os.chown(STAGE, OWNER_UID, OWNER_GID)
    with tarfile.open(ARCHIVE, "r") as bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        need(len(names) == len(set(names)), "duplicate archive member")
        transaction = json.loads(bundle.extractfile("transaction.json").read())
        need(transaction.get("schema") == "r8q-waydroid-kernel-trial-archive/v1" and
             transaction.get("release") == NEW_RELEASE and
             transaction.get("manifest_path") == "/root/r8q-screen-lock-20261013.sha256" and
             transaction.get("old_manifest_sha256") == OLD_MANIFEST_SHA256,
             "archive transaction metadata changed")
        need(transaction.get("efi", {}).get("sha256") == NEW_EFI_SHA256 and
             transaction.get("efi", {}).get("bytes") == NEW_EFI_BYTES,
             "archive EFI metadata changed")
        protected_baseline_metadata = transaction.get("protected_baseline_metadata")
        public_snapshot_metadata = transaction.get("public_snapshot_metadata")
        protected_manifest_metadata = transaction.get("protected_manifest_metadata")
        verify_metadata_binding(protected_baseline_metadata, PROTECTED_BASELINE_METADATA_SCHEMA,
                                PROTECTED_BASELINE_METADATA_SHA256, 297,
                                "protected baseline metadata")
        need(protected_baseline_metadata.get("manifest_sha256") == OLD_MANIFEST_SHA256,
             "protected baseline metadata manifest binding changed")
        verify_metadata_binding(public_snapshot_metadata, PUBLIC_SNAPSHOT_METADATA_SCHEMA,
                                PUBLIC_SNAPSHOT_METADATA_SHA256, PUBLIC_SNAPSHOT_METADATA_FILES,
                                "public snapshot metadata")
        need(isinstance(protected_manifest_metadata, dict) and
             protected_manifest_metadata.get("path") == str(MANIFEST) and
             protected_manifest_metadata.get("sha256") == OLD_MANIFEST_SHA256,
             "protected manifest metadata binding changed")
        rows = transaction.get("rootfs")
        need(isinstance(rows, list) and len({row.get("path") for row in rows}) == len(rows),
             "archive rootfs inventory is empty or duplicated")
        expected_names = {"transaction.json", "efi/BOOTAA64.EFI"} | {
            "rootfs/" + row["path"] for row in rows
        }
        need(set(names) == expected_names, "archive member inventory changed")
        for member in members:
            need(member.isfile() and not member.issym() and not member.islnk() and member.uid == 0 and
                 member.gid == 0 and stat.S_IMODE(member.mode) & 0o7000 == 0,
                 "archive member is unsafe")
            if member.name.startswith("rootfs/"):
                safe_relative(member.name[7:])
        efi_stream = bundle.extractfile("efi/BOOTAA64.EFI")
        need(efi_stream is not None, "archive EFI is absent")
        efi_data = efi_stream.read()
        need(len(efi_data) == NEW_EFI_BYTES and hashlib.sha256(efi_data).hexdigest() == NEW_EFI_SHA256,
             "archive EFI bytes changed")
        efi_stage = STAGE / "BOOTAA64.EFI"
        efi_stage.write_bytes(efi_data)
        os.chmod(efi_stage, 0o600)
        os.chown(efi_stage, OWNER_UID, OWNER_GID)
        return transaction


def install_rootfs(transaction):
    global manifest_changed, manifest_before, manifest_new_sha256, manifest_new_bytes
    rows = transaction["rootfs"]
    for row in rows:
        path = safe_relative(row["path"])
        need(path.startswith("usr/local/lib/r8q-kernel-profiles/7.1.2-r8q-waydroid2/") or
             path.startswith("usr/lib/modules/7.1.2-r8q-waydroid2/") or path in DROPINS,
             "rootfs path outside exact allowlist")
        need(isinstance(row.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) and
             isinstance(row.get("bytes"), int) and row["bytes"] >= 0 and isinstance(row.get("mode"), int) and
             0 <= row["mode"] <= 0o777 and row["mode"] & 0o7000 == 0, "malformed rootfs row")
        with tarfile.open(ARCHIVE, "r") as bundle:
            member = bundle.getmember("rootfs/" + path)
            source = STAGE / "rootfs" / path
            ensure_parent(source, STAGE, stage_dirs)
            stream = bundle.extractfile(member)
            need(stream is not None, "archive rootfs file is absent")
            fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(fd, "wb") as output:
                    fd = -1
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)
            source.chmod(0o600)
            os.chown(source, OWNER_UID, OWNER_GID)
            need(source.stat().st_size == row["bytes"] and sha(source, "staged rootfs") == row["sha256"],
                 "staged rootfs hash changed")
        target = TARGET_ROOT / path
        ensure_parent(target, TARGET_ROOT, created_dirs)
        need(not target.exists() and not target.is_symlink(), "refusing to overwrite rootfs path")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                     getattr(os, "O_NOFOLLOW", 0), row["mode"])
        try:
            with source.open("rb", buffering=0) as original, os.fdopen(fd, "wb") as output:
                fd = -1
                for block in iter(lambda: original.read(1024 * 1024), b""):
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            if fd >= 0:
                os.close(fd)
            try:
                target.unlink()
            except OSError:
                pass
            raise
        os.chmod(target, row["mode"])
        os.chown(target, OWNER_UID, OWNER_GID)
        created_files.append(target)
        info = target.lstat()
        need(info.st_uid == OWNER_UID and info.st_gid == OWNER_GID and stat.S_IMODE(info.st_mode) == row["mode"] and
             info.st_size == row["bytes"] and sha(target, path) == row["sha256"],
             "installed rootfs metadata or hash changed")
    if INJECT_FAILURE == "after-rootfs":
        raise Failure("fixture failure after rootfs files")
    manifest_before = MANIFEST.read_bytes()
    verify_manifest("protected manifest before append")
    fsync_directories(created_dirs)
    backup = MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-SAVED-FOR-ROLLBACK")
    temporary = MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-NEW")
    need(not backup.exists() and not backup.is_symlink() and not temporary.exists() and not temporary.is_symlink(),
         "manifest rollback name already exists")
    copy_exclusive(MANIFEST, backup, 0o600)
    append = b"".join((row["sha256"] + "  /" + row["path"] + "\n").encode() for row in rows)
    need(all(line not in manifest_before.splitlines() for line in append.splitlines()),
         "protected manifest already contains a new path")
    existing_paths = {line.decode("utf-8", "strict").split(None, 1)[1]
                      for line in manifest_before.splitlines() if b"  /" in line}
    need(all("/" + row["path"] not in existing_paths for row in rows),
         "protected manifest already contains a requested path")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    owned_artifacts.add(temporary)
    try:
        write_all(fd, manifest_before + append)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(temporary, 0o600)
    os.chown(temporary, OWNER_UID, OWNER_GID)
    manifest_new_bytes = temporary.stat().st_size
    manifest_new_sha256 = sha(temporary, "new manifest")
    # Set this before os.replace so a signal in the replace window restores the
    # old manifest from the exclusive backup.
    manifest_changed = True
    os.replace(temporary, MANIFEST)
    directory_fd = os.open(MANIFEST.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if INJECT_FAILURE == "after-manifest":
        raise Failure("fixture failure after manifest replace")


def rollback_rootfs():
    global manifest_changed
    errors = []
    for path in reversed(created_files):
        try:
            if path.exists() and not path.is_symlink():
                path.unlink()
        except OSError as exc:
            errors.append(str(path) + ": " + str(exc))
    for directory in reversed(created_dirs):
        try:
            directory.rmdir()
        except OSError:
            pass
    backup = MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-SAVED-FOR-ROLLBACK")
    if manifest_changed:
        try:
            need(backup.exists() and not backup.is_symlink(), "manifest rollback backup is missing")
            temporary = MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-RESTORE")
            need(not temporary.exists() and not temporary.is_symlink(), "manifest restore name exists")
            copy_exclusive(backup, temporary, 0o600)
            os.replace(temporary, MANIFEST)
            directory_fd = os.open(MANIFEST.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            need(MANIFEST.read_bytes() == manifest_before and sha(MANIFEST, "restored manifest") == OLD_MANIFEST_SHA256,
                 "manifest rollback readback failed")
            manifest_changed = False
        except BaseException as exc:
            errors.append("manifest: " + str(exc))
    if errors:
        raise Failure("rootfs rollback failed: " + "; ".join(errors[:8]))


def mount_cache():
    global cache_mounted, fixture_mount_active
    if FIXTURE:
        need(MOUNT.is_dir() and not MOUNT.is_symlink(), "fixture CACHE mountpoint is unsafe")
        try:
            run(["/usr/bin/mount", "--", CACHE_DEVICE, str(MOUNT)])
            cache_mounted = True
        except BaseException:
            cache_mounted = fixture_mount_active
            raise
        return
    need(not MOUNT.exists() and not MOUNT.is_symlink(), "CACHE mountpoint already exists")
    MOUNT.mkdir(mode=0o700)
    os.chmod(MOUNT, 0o700)
    os.chown(MOUNT, OWNER_UID, OWNER_GID)
    mount_started = True
    try:
        run(["/usr/bin/mount", "--types", "vfat", "--options",
             "rw,nosuid,nodev,noexec,uid=0,gid=0,umask=0077", "--", CACHE_DEVICE, str(MOUNT)])
        cache_mounted = True
    except BaseException:
        cache_mounted = any(record["mountpoint"] == str(MOUNT) for record in mount_records())
        raise
    need(any(record["mountpoint"] == str(MOUNT) and record["rdev"] == cache_rdev and
             record["source"] == CACHE_DEVICE and record["fstype"] == "vfat" and
             "rw" in record["options"] and not {"ro", "suid", "dev", "exec"} & record["options"]
             for record in mount_records()), "CACHE mount identity changed")


def unmount_cache():
    global cache_mounted, fixture_mount_active, fixture_after_unmount_fired
    if not cache_mounted and not fixture_mount_active:
        return
    if INJECT_FAILURE == "rollback-cleanup-failure" and rollback_phase:
        raise Failure("fixture rollback cleanup failure")
    errors = []
    detached = False
    for _ in range(2):
        try:
            run(["/usr/bin/umount", "--", str(MOUNT)])
        except BaseException as exc:
            errors.append("umount: " + str(exc))
            try:
                no_mount(CACHE_DEVICE, cache_rdev)
            except BaseException as verify_exc:
                errors.append("detach verification: " + str(verify_exc))
                continue
            detached = True
            break
        try:
            no_mount(CACHE_DEVICE, cache_rdev)
        except BaseException as exc:
            errors.append("detach verification: " + str(exc))
            continue
        detached = True
        break
    need(detached, "CACHE detach could not be verified: " + "; ".join(errors[-4:]))
    cache_mounted = False
    fixture_mount_active = False
    if INJECT_FAILURE == "after-unmount" and not fixture_after_unmount_fired:
        fixture_after_unmount_fired = True
        raise Failure("fixture failure after unmount")


def record_cleanup_failure(label, exc):
    cleanup_failures.append(label + ": " + str(exc))


def remove_verified_artifact(path, expected_sha256, expected_bytes, label):
    if not path.exists() and not path.is_symlink():
        return
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
         label + " is not a regular file")
    need(info.st_uid == OWNER_UID and info.st_gid == OWNER_GID and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == expected_bytes and
         sha(path, label) == expected_sha256,
         label + " metadata or hash is not this transaction's artifact")
    path.unlink()
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def cleanup_transaction_artifacts(manifest=True, cache=True):
    errors = []
    if manifest:
        manifest_paths = []
        if manifest_new_sha256 is not None and manifest_new_bytes is not None:
            manifest_paths.append((
                MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-NEW"),
                manifest_new_sha256, manifest_new_bytes, "manifest new"))
        manifest_paths.extend([
            (MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-SAVED-FOR-ROLLBACK"),
             OLD_MANIFEST_SHA256, protected_manifest_metadata["bytes"], "manifest rollback backup"),
            (MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-RESTORE"),
             OLD_MANIFEST_SHA256, protected_manifest_metadata["bytes"], "manifest restore"),
        ])
        for path, expected_sha256, expected_bytes, label in manifest_paths:
            if path not in owned_artifacts:
                continue
            try:
                remove_verified_artifact(path, expected_sha256, expected_bytes, label)
            except BaseException as exc:
                errors.append(label + ": " + str(exc))
    if cache and (cache_mounted or fixture_mount_active):
        cache_paths = [
            (MOUNT / NEW, NEW_EFI_SHA256, NEW_EFI_BYTES, "CACHE new EFI"),
            (MOUNT / RECOVERY, OLD_EFI_SHA256, OLD_EFI_BYTES, "CACHE recovery EFI"),
            (MOUNT / SAVED, OLD_EFI_SHA256, OLD_EFI_BYTES, "CACHE saved EFI"),
        ]
        for path, expected_sha256, expected_bytes, label in cache_paths:
            if path not in owned_artifacts:
                continue
            try:
                remove_verified_artifact(path, expected_sha256, expected_bytes, label)
            except BaseException as exc:
                errors.append(label + ": " + str(exc))
    if errors:
        raise Failure("transaction artifact cleanup failed: " + "; ".join(errors[:8]))


def refresh_cache_attachment():
    global cache_mounted, fixture_mount_active
    if not cache_mounted and not fixture_mount_active:
        return False
    if FIXTURE:
        attached = fixture_mount_active
    else:
        attached = any(record["mountpoint"] == str(MOUNT) and
                       record["source"] == CACHE_DEVICE for record in mount_records())
    if not attached:
        cache_mounted = False
        fixture_mount_active = False
    return attached


def cleanup_mount_state(label):
    before = len(cleanup_failures)
    refresh_cache_attachment()
    if cache_mounted or fixture_mount_active:
        try:
            unmount_cache()
        except BaseException as exc:
            record_cleanup_failure(label + " unmount", exc)
    if (not FIXTURE and not cache_mounted and not fixture_mount_active and
            MOUNT.exists() and not MOUNT.is_symlink()):
        try:
            MOUNT.rmdir()
        except OSError as exc:
            record_cleanup_failure(label + " mountpoint removal", exc)
    if len(cleanup_failures) > before:
        raise Failure("; ".join(cleanup_failures[before:]))


def cache_update():
    global cache_active, cache_saved, cache_recovery, efi_replaced
    try:
        # Keep mount_cache inside the guarded region: a mount subprocess may
        # throw after the kernel has attached CACHE but before it returns.
        mount_cache()
        cache_active = MOUNT / EFI
        cache_saved = MOUNT / SAVED
        cache_recovery = MOUNT / RECOVERY
        dtb = MOUNT / DTB
        need(cache_active.is_file() and not cache_active.is_symlink() and dtb.is_file() and not dtb.is_symlink(),
             "CACHE EFI or DTB is unavailable")
        need(sha(cache_active, "current EFI") == OLD_EFI_SHA256 and cache_active.stat().st_size == OLD_EFI_BYTES,
             "current CACHE EFI is not the accepted EFI04")
        need(sha(dtb, "current DTB") == DTB_SHA256, "CACHE DTB changed")
        root_identity()
        for path in (cache_saved, MOUNT / NEW, cache_recovery):
            need(not path.exists() and not path.is_symlink(), "CACHE rollback name already exists")
        free = os.statvfs(MOUNT).f_bavail * os.statvfs(MOUNT).f_frsize
        need(free >= OLD_EFI_BYTES + NEW_EFI_BYTES + MARGIN_BYTES, "CACHE free space is insufficient")
        copy_exclusive(cache_active, cache_saved, 0o600)
        need(sha(cache_saved, "saved EFI04") == OLD_EFI_SHA256, "saved EFI04 hash changed")
        staged = MOUNT / NEW
        copy_exclusive(STAGE / "BOOTAA64.EFI", staged, 0o600)
        os.sync()
        # Conservative flag before os.replace covers a signal in either half
        # of the atomic replacement window.
        efi_replaced = True
        os.replace(staged, cache_active)
        if INJECT_FAILURE == "after-efi-replace":
            raise Failure("fixture failure after EFI replace")
        os.sync()
        if INJECT_FAILURE == "efi-readback":
            raise Failure("fixture EFI readback failure")
        need(sha(cache_active, "new EFI") == NEW_EFI_SHA256 and cache_active.stat().st_size == NEW_EFI_BYTES,
             "new EFI readback failed")
        if INJECT_FAILURE in ("rollback-failure", "rollback-cleanup-failure"):
            raise Failure("fixture trigger before injected EFI rollback failure")
    finally:
        cleanup_mount_state("CACHE update")


def rollback_efi_if_needed():
    global efi_replaced, cache_mounted, fixture_mount_active, rollback_phase

    def restore_active(source, expected_sha256, expected_bytes, label):
        need(cache_active is not None and cache_recovery is not None,
             "EFI rollback state is incomplete")
        need(source.exists() and not source.is_symlink() and
             sha(source, label + " source") == expected_sha256 and
             source.stat().st_size == expected_bytes,
             label + " source is unavailable")
        need(not cache_recovery.exists() and not cache_recovery.is_symlink(),
             "EFI recovery name already exists")
        copy_exclusive(source, cache_recovery, 0o600)
        need(sha(cache_recovery, label + " copy") == expected_sha256 and
             cache_recovery.stat().st_size == expected_bytes,
             label + " copy changed")
        os.replace(cache_recovery, cache_active)
        os.sync()
        need(sha(cache_active, label + " readback") == expected_sha256 and
             cache_active.stat().st_size == expected_bytes,
             label + " readback failed")

    def ensure_cache_for_restore():
        refresh_cache_attachment()
        if cache_mounted or fixture_mount_active:
            return
        if not FIXTURE and MOUNT.exists() and not MOUNT.is_symlink():
            need(not any(MOUNT.iterdir()), "detached CACHE mountpoint is not empty")
            MOUNT.rmdir()
        mount_cache()

    if not efi_replaced:
        rollback_phase = True
        try:
            cleanup_mount_state("rollback cleanup")
        except BaseException as exc:
            return False, "EFI was not replaced; CACHE cleanup failed: " + str(exc)
        finally:
            rollback_phase = False
        return True, "EFI was not replaced"
    if INJECT_FAILURE == "rollback-failure":
        rollback_phase = True
        try:
            cleanup_mount_state("EFI rollback skipped")
        except BaseException as exc:
            return False, "fixture injected EFI rollback failure; CACHE cleanup failed: " + str(exc)
        finally:
            rollback_phase = False
        return False, "fixture injected EFI rollback failure"

    restored = False
    rollback_error = None
    try:
        ensure_cache_for_restore()
        need(cache_saved is not None and cache_saved.exists() and not cache_saved.is_symlink() and
             sha(cache_saved, "EFI rollback copy") == OLD_EFI_SHA256 and
             cache_saved.stat().st_size == OLD_EFI_BYTES,
             "EFI rollback copy is unavailable")
        restore_active(cache_saved, OLD_EFI_SHA256, OLD_EFI_BYTES, "restored EFI04")
        restored = True
    except BaseException as exc:
        rollback_error = exc

    # Keep the phase flag around the detach attempt: the fixture and the real
    # transaction use it to inject and report failures in the cleanup window.
    rollback_phase = True
    try:
        cleanup_mount_state("EFI rollback")
    except BaseException as exc:
        if rollback_error is None:
            rollback_error = exc
    finally:
        rollback_phase = False

    if rollback_error is not None:
        if restored:
            return False, "EFI04 active and verified; rollback cleanup failed: " + str(rollback_error)
        return False, "EFI active state unknown; EFI rollback failed: " + str(rollback_error)
    need(restored, "EFI rollback did not restore EFI04")

    artifact_error = None
    try:
        mount_cache()
        cleanup_transaction_artifacts(manifest=False, cache=True)
    except BaseException as exc:
        artifact_error = exc
    finally:
        try:
            cleanup_mount_state("EFI rollback artifact cleanup")
        except BaseException as exc:
            if artifact_error is None:
                artifact_error = exc
    if artifact_error is not None:
        return False, "EFI04 active and verified; rollback cleanup failed: " + str(artifact_error)
    efi_replaced = False
    return True, "EFI04 restored and verified"


def transaction():
    global created_files, created_dirs, stage_dirs, cache_mounted
    global manifest_new_sha256, manifest_new_bytes, cleanup_failures, rollback_phase
    global owned_artifacts, stage_owned, archive_owned
    created_files = []
    created_dirs = []
    stage_dirs = []
    cache_mounted = False
    manifest_new_sha256 = None
    manifest_new_bytes = None
    cleanup_failures = []
    rollback_phase = False
    owned_artifacts = set()
    stage_owned = False
    archive_owned = False
    daemon_reloaded = False
    metadata = None
    try:
        root_identity()
        cache_identity()
        metadata = stage_archive()
        verify_manifest("protected manifest before rootfs transaction")
        verify_metadata_binding(public_snapshot_metadata, PUBLIC_SNAPSHOT_METADATA_SCHEMA,
                                PUBLIC_SNAPSHOT_METADATA_SHA256, PUBLIC_SNAPSHOT_METADATA_FILES,
                                "public snapshot metadata before rootfs transaction")
        install_rootfs(metadata)
        verify_manifest("protected manifest after rootfs transaction", manifest_before,
                        metadata["rootfs"])
        verify_metadata_binding(public_snapshot_metadata, PUBLIC_SNAPSHOT_METADATA_SCHEMA,
                                PUBLIC_SNAPSHOT_METADATA_SHA256, PUBLIC_SNAPSHOT_METADATA_FILES,
                                "public snapshot metadata after rootfs transaction",
                                allow_manifest_append=True, manifest_bytes=manifest_new_bytes,
                                manifest_sha256=manifest_new_sha256)
        run(["/usr/bin/systemctl", "daemon-reload"])
        daemon_reloaded = True
        cache_update()
        return {"result": "PASS", "recovery": "new EFI active; EFI04 saved for rollback",
                "rootfs_files_changed": [row["path"] for row in metadata["rootfs"]],
                "protected_manifest_appended": len(metadata["rootfs"]),
                "efi_before_sha256": OLD_EFI_SHA256, "efi_after_sha256": NEW_EFI_SHA256,
                "saved_efi_rollback": True, "daemon_reload": daemon_reloaded,
                "service_restarts": False, "gpu_unload": False, "formatting": False,
                "raw_userdata_writes": False, "root_device_changed": False, "luks_changed": False}
    except BaseException as exc:
        efi_ok, efi_state = rollback_efi_if_needed()
        if efi_ok:
            try:
                rollback_rootfs()
                rootfs_state = "new rootfs and manifest rolled back"
                try:
                    cleanup_transaction_artifacts(manifest=True, cache=False)
                except BaseException as cleanup_exc:
                    record_cleanup_failure("manifest artifact cleanup", cleanup_exc)
            except BaseException as rollback_exc:
                rootfs_state = "rootfs rollback failed: " + str(rollback_exc)
        else:
            rootfs_state = "new rootfs and manifest preserved because EFI rollback failed"
        try:
            cleanup_mount_state("transaction")
        except BaseException as cleanup_exc:
            record_cleanup_failure("transaction cleanup", cleanup_exc)
        if daemon_reloaded:
            try:
                run(["/usr/bin/systemctl", "daemon-reload"])
            except BaseException:
                pass
        if cleanup_failures:
            efi_state += "; cleanup failures: " + "; ".join(cleanup_failures[:8])
        return {"result": "FAIL", "error": str(exc), "recovery": efi_state + "; " + rootfs_state,
                "rollback_attempted": True, "efi_rollback_verified": efi_ok,
                "rootfs_preserved": not efi_ok,
                "rootfs_files_changed": [str(path) for path in created_files],
                "formatting": False, "raw_userdata_writes": False,
                "root_device_changed": False, "luks_changed": False}


def cleanup():
    if stage_owned and STAGE.exists() and not STAGE.is_symlink():
        shutil.rmtree(STAGE)
    if archive_owned and ARCHIVE.exists() and not ARCHIVE.is_symlink():
        try:
            info = ARCHIVE.lstat()
            if (stat.S_ISREG(info.st_mode) and info.st_uid == OWNER_UID and
                    info.st_gid == OWNER_GID and stat.S_IMODE(info.st_mode) == 0o600 and
                    info.st_size == ARCHIVE_BYTES and sha(ARCHIVE, "deployment archive cleanup") == ARCHIVE_SHA256):
                ARCHIVE.unlink()
        except OSError:
            pass


def fixture_main():
    global FIXTURE, OWNER_UID, OWNER_GID, INJECT_FAILURE, ARCHIVE, STAGE, MOUNT, TARGET_ROOT, MANIFEST
    global NEW_EFI_SHA256, NEW_EFI_BYTES, ARCHIVE_BYTES, ARCHIVE_SHA256, OLD_MANIFEST_SHA256
    global PROTECTED_BASELINE_METADATA_SHA256, PUBLIC_SNAPSHOT_METADATA_SHA256
    global cache_active, cache_saved, cache_recovery
    global efi_replaced, manifest_changed, fixture_mount_active, fixture_mount_fail_once
    global fixture_after_unmount_fired, fixture_no_mount_failures
    global cleanup_failures, rollback_phase, manifest_new_sha256, manifest_new_bytes
    global owned_artifacts, stage_owned, archive_owned
    fixture_directory = os.environ.get("R8Q_FIXTURE_DIR")
    if fixture_directory is None:
        fixture_directory = tempfile.mkdtemp(prefix="waydroid2-remote-fixture-")
    sandbox = Path(fixture_directory)
    snapshot = Path(os.environ["R8Q_FIXTURE_SNAPSHOT"])
    # The exported public snapshot intentionally contains only the reviewed
    # file inventory, so the isolated fixture synthesizes 297 known files and
    # pins a fixture-only manifest hash.  Production keeps the accepted hash.
    baseline_files = {}
    baseline_lines = []
    for index in range(297):
        absolute = "/fixture/baseline/%03d" % index
        content = ("fixture baseline %03d\n" % index).encode()
        baseline_files[absolute] = content
        baseline_lines.append(hashlib.sha256(content).hexdigest() + "  " + absolute + "\n")
    baseline = "".join(baseline_lines).encode()
    OLD_MANIFEST_SHA256 = hashlib.sha256(baseline).hexdigest()
    old_efi = Path(os.environ["R8Q_FIXTURE_OLD_EFI"])
    dtb_source = Path(os.environ["R8Q_FIXTURE_DTB"])
    cases = ["success", "after-rootfs", "after-manifest", "after-efi-replace", "efi-readback",
             "after-unmount", "mount-before-mounted", "no-mount", "rollback-failure",
             "rollback-cleanup-failure", "rollback-retry"]
    results = []
    try:
        for case in cases:
            case_root = sandbox / case
            TARGET_ROOT = case_root / "root"
            TARGET_ROOT.mkdir(parents=True)
            MANIFEST = TARGET_ROOT / "root/r8q-screen-lock-20261013.sha256"
            MANIFEST.parent.mkdir(parents=True)
            MANIFEST.write_bytes(baseline)
            MANIFEST.chmod(0o600)
            for line in baseline.splitlines():
                value, absolute = line.decode().split("  ", 1)
                destination = TARGET_ROOT / absolute.lstrip("/")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(baseline_files[absolute])
                destination.chmod(0o644)
            protected_records = {}
            for absolute in sorted(baseline_files):
                destination = TARGET_ROOT / absolute.lstrip("/")
                info = destination.lstat()
                protected_records[absolute] = {
                    "bytes": info.st_size, "gid": info.st_gid, "kind": "file",
                    "mode": stat.S_IMODE(info.st_mode),
                    "sha256": sha(destination, "fixture protected file"),
                    "uid": info.st_uid,
                }
            manifest_info = MANIFEST.lstat()
            protected_manifest = {
                "path": str(MANIFEST), "bytes": manifest_info.st_size,
                "gid": manifest_info.st_gid, "mode": stat.S_IMODE(manifest_info.st_mode),
                "sha256": OLD_MANIFEST_SHA256, "uid": manifest_info.st_uid,
            }
            protected_payload = {
                "schema": PROTECTED_BASELINE_METADATA_SCHEMA,
                "manifest_sha256": OLD_MANIFEST_SHA256, "files": len(protected_records),
                "path_records": protected_records,
            }
            public_payload = {
                "schema": PUBLIC_SNAPSHOT_METADATA_SCHEMA, "files": PUBLIC_SNAPSHOT_METADATA_FILES,
                "path_records": {
                    "/root/r8q-screen-lock-20261013.sha256": {
                        key: value for key, value in protected_manifest.items() if key != "path"
                    },
                    **dict(list(sorted(protected_records.items()))[:PUBLIC_SNAPSHOT_METADATA_FILES - 1]),
                },
            }
            protected_payload["sha256"] = hashlib.sha256(
                (json.dumps(protected_payload, sort_keys=True) + "\n").encode()).hexdigest()
            public_payload["sha256"] = hashlib.sha256(
                (json.dumps(public_payload, sort_keys=True) + "\n").encode()).hexdigest()
            PROTECTED_BASELINE_METADATA_SHA256 = protected_payload["sha256"]
            PUBLIC_SNAPSHOT_METADATA_SHA256 = public_payload["sha256"]
            helper = TARGET_ROOT / "usr/local/lib/r8q-kernel-profiles/7.1.2-r8q-waydroid2/fixture/helper"
            helper_data = b"fixture Waydroid2 helper\n"
            row = {"path": "usr/local/lib/r8q-kernel-profiles/7.1.2-r8q-waydroid2/fixture/helper",
                   "sha256": hashlib.sha256(helper_data).hexdigest(), "bytes": len(helper_data), "mode": 0o755}
            ARCHIVE = case_root / "upload.tar"
            STAGE = case_root / "stage"
            MOUNT = case_root / "cache"
            cache_dir = MOUNT / EFI.parent
            cache_dir.mkdir(parents=True)
            os.link(old_efi, cache_dir / EFI.name)
            shutil.copyfile(dtb_source, MOUNT / DTB)
            new_efi = b"fixture new EFI\n"
            NEW_EFI_BYTES = len(new_efi)
            NEW_EFI_SHA256 = hashlib.sha256(new_efi).hexdigest()
            transaction_metadata = {"schema": "r8q-waydroid-kernel-trial-archive/v1", "release": NEW_RELEASE,
                           "manifest_path": "/root/r8q-screen-lock-20261013.sha256",
                           "old_manifest_sha256": OLD_MANIFEST_SHA256, "rootfs": [row],
                           "efi": {"path": "efi/BOOTAA64.EFI", "sha256": NEW_EFI_SHA256, "bytes": NEW_EFI_BYTES},
                           "protected_baseline_metadata": protected_payload,
                           "public_snapshot_metadata": public_payload,
                           "protected_manifest_metadata": protected_manifest}
            with tarfile.open(ARCHIVE, "w") as bundle:
                data = (json.dumps(transaction_metadata, sort_keys=True) + "\n").encode()
                info = tarfile.TarInfo("transaction.json"); info.size = len(data); info.mode = 0o600; info.uid = 0; info.gid = 0
                bundle.addfile(info, io.BytesIO(data))
                info = tarfile.TarInfo("rootfs/" + row["path"]); info.size = len(helper_data); info.mode = row["mode"]; info.uid = 0; info.gid = 0
                bundle.addfile(info, io.BytesIO(helper_data))
                info = tarfile.TarInfo("efi/BOOTAA64.EFI"); info.size = len(new_efi); info.mode = 0o600; info.uid = 0; info.gid = 0
                bundle.addfile(info, io.BytesIO(new_efi))
            ARCHIVE.chmod(0o600)
            ARCHIVE_BYTES = ARCHIVE.stat().st_size
            ARCHIVE_SHA256 = sha(ARCHIVE, "fixture archive")
            injection = "after-efi-replace" if case == "rollback-retry" else case
            FIXTURE = True; OWNER_UID = os.getuid(); OWNER_GID = os.getgid(); INJECT_FAILURE = "" if case == "success" else injection
            cache_rdev = "fixture-rdev"; cache_active = None; cache_saved = None; cache_recovery = None
            efi_replaced = False; manifest_changed = False; fixture_mount_active = False
            fixture_mount_fail_once = False; fixture_after_unmount_fired = False
            fixture_no_mount_failures = 0
            cleanup_failures = []; rollback_phase = False
            manifest_new_sha256 = None; manifest_new_bytes = None
            result = transaction()
            active = MOUNT / EFI
            helper_exists = helper.exists()
            manifest_after = MANIFEST.read_bytes()
            efi_after = sha(active, "fixture active EFI") if active.exists() else "missing"
            if case == "success":
                public_manifest = public_snapshot_metadata["path_records"][
                    "/root/r8q-screen-lock-20261013.sha256"]
                need(result["result"] == "PASS" and helper_exists and efi_after == NEW_EFI_SHA256 and
                     manifest_after.startswith(baseline) and len(manifest_after.splitlines()) == 298,
                     "fixture success failed: " + repr((result, helper_exists, efi_after, len(manifest_after.splitlines()))))
                need(public_manifest["bytes"] == len(baseline) and
                     public_manifest["sha256"] == OLD_MANIFEST_SHA256 and
                     manifest_new_bytes == len(manifest_after) and
                     manifest_new_sha256 == sha(MANIFEST, "fixture post-append manifest"),
                     "fixture public manifest row did not bind baseline and post-append bytes/hash")
            elif case == "rollback-failure":
                need(result["result"] == "FAIL" and result["rootfs_preserved"] and helper_exists and
                     efi_after == NEW_EFI_SHA256,
                     "fixture preserved-state failure failed: " + repr((result, helper_exists, efi_after)))
            elif case == "rollback-cleanup-failure":
                need(result["result"] == "FAIL" and result["rootfs_preserved"] and helper_exists and
                     manifest_after != baseline and efi_after == OLD_EFI_SHA256 and
                     "cleanup failures" in result["recovery"] and
                     (MOUNT / SAVED).exists() and
                     MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-SAVED-FOR-ROLLBACK").exists(),
                     "fixture rollback cleanup failure was not preserved: " + repr(result))
            elif case == "no-mount":
                need(result["result"] == "FAIL" and not helper_exists and manifest_after == baseline and
                     efi_after == OLD_EFI_SHA256 and not cache_mounted and not fixture_mount_active,
                     "fixture no_mount cleanup retry failed: " + repr(result))
            elif case == "rollback-retry":
                need(result["result"] == "FAIL" and not helper_exists and manifest_after == baseline and
                     efi_after == OLD_EFI_SHA256 and
                     not (MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-SAVED-FOR-ROLLBACK")).exists() and
                     not (MOUNT / SAVED).exists(),
                     "fixture verified rollback left retry artifacts: " + repr(result))
                shutil.rmtree(STAGE)
                INJECT_FAILURE = ""
                cleanup_failures = []
                rollback_phase = False
                retry = transaction()
                retry_active = MOUNT / EFI
                need(retry["result"] == "PASS" and helper.exists() and
                     sha(retry_active, "fixture retry EFI") == NEW_EFI_SHA256 and
                     len(MANIFEST.read_bytes().splitlines()) == 298 and
                     (MOUNT / SAVED).exists(),
                     "fixture retry after verified rollback failed: " + repr(retry))
            else:
                need(result["result"] == "FAIL" and not helper_exists and manifest_after == baseline and
                     efi_after == OLD_EFI_SHA256,
                     "fixture rollback failed: " + case + ": " + repr((result, helper_exists, efi_after, len(manifest_after))))
            results.append({"case": case, "result": result["result"], "recovery": result["recovery"]})
            FIXTURE = False

        # A prerequisite refusal must leave a same-hash artifact from an
        # earlier invocation untouched.  The stage sentinel exercises the
        # stage-owned cleanup guard; the manifest backup exercises the
        # transaction-artifact ownership guard.
        ownership_root = sandbox / "ownership"
        TARGET_ROOT = ownership_root / "root"
        TARGET_ROOT.mkdir(parents=True)
        MANIFEST = TARGET_ROOT / "root/r8q-screen-lock-20261013.sha256"
        MANIFEST.parent.mkdir(parents=True)
        MANIFEST.write_bytes(baseline)
        MANIFEST.chmod(0o600)
        previous_backup = MANIFEST.with_name(MANIFEST.name + ".WAYDROID2-SAVED-FOR-ROLLBACK")
        previous_backup.write_bytes(baseline)
        previous_backup.chmod(0o600)
        STAGE = ownership_root / "stage"
        STAGE.mkdir(mode=0o700)
        stage_sentinel = STAGE / "previous-transaction-sentinel"
        stage_sentinel.write_bytes(b"previous transaction stage\n")
        ARCHIVE = ownership_root / "upload.tar"
        shutil.copyfile(sandbox / "rollback-retry/upload.tar", ARCHIVE)
        ARCHIVE.chmod(0o600)
        ARCHIVE_BYTES = ARCHIVE.stat().st_size
        ARCHIVE_SHA256 = sha(ARCHIVE, "ownership fixture archive")
        MOUNT = ownership_root / "cache"
        FIXTURE = True; OWNER_UID = os.getuid(); OWNER_GID = os.getgid(); INJECT_FAILURE = ""
        cache_active = None; cache_saved = None; cache_recovery = None
        efi_replaced = False; manifest_changed = False; fixture_mount_active = False
        fixture_mount_fail_once = False; fixture_after_unmount_fired = False
        fixture_no_mount_failures = 0; cleanup_failures = []; rollback_phase = False
        manifest_new_sha256 = None; manifest_new_bytes = None
        ownership_result = transaction()
        need(ownership_result["result"] == "FAIL" and stage_sentinel.read_bytes() ==
             b"previous transaction stage\n" and previous_backup.read_bytes() == baseline,
             "ownership refusal removed a preexisting sentinel or rollback backup")
        cleanup_transaction_artifacts(manifest=True, cache=False)
        need(previous_backup.read_bytes() == baseline,
             "ownership cleanup removed a preexisting rollback backup")
        cleanup()
        need(STAGE.is_dir() and stage_sentinel.read_bytes() == b"previous transaction stage\n" and
             previous_backup.read_bytes() == baseline,
             "cleanup removed preexisting stage or rollback backup")
        ownership_result = "PASS"
        FIXTURE = False
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    print(json.dumps({"schema": "r8q-waydroid-kernel-trial/v3", "result": "PASS",
                      "cases": results, "ownership_fixture": ownership_result}, sort_keys=True))
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture":
        return fixture_main()
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, lambda received, frame: (_ for _ in ()).throw(Failure("transaction interrupted")))
    result = transaction()
    print(json.dumps({"schema": "r8q-waydroid-kernel-trial/v1", **result}, sort_keys=True), flush=True)
    cleanup()
    return 0 if result["result"] == "PASS" else 1


raise SystemExit(main())
'''


def build_upload_command(remote_archive: str, archive_bytes: int, archive_sha256: str) -> str:
    partial = remote_archive + ".partial"
    archive_q = shlex.quote(remote_archive)
    partial_q = shlex.quote(partial)
    return (
        "set -eu -C; umask 077; "
        "partial=" + partial_q + "; archive=" + archive_q + "; "
        "cleanup() { rm -f -- \"$partial\"; }; "
        "trap cleanup EXIT HUP INT TERM; "
        "test ! -e \"$archive\" && test ! -L \"$archive\"; "
        "test ! -e \"$partial\" && test ! -L \"$partial\"; "
        "cat > \"$partial\"; "
        "test -f \"$partial\" && test ! -L \"$partial\"; "
        "test \"$(stat -c '%a' \"$partial\")\" = '600'; "
        "test \"$(wc -c < \"$partial\")\" -eq " + str(archive_bytes) + "; "
        "test \"$(sha256sum \"$partial\" | cut -d' ' -f1)\" = " + shlex.quote(archive_sha256) + "; "
        "mv -n -- \"$partial\" \"$archive\"; "
        "test ! -e \"$partial\" && test ! -L \"$partial\"; "
        "test -f \"$archive\" && test ! -L \"$archive\"; "
        "test \"$(stat -c '%a' \"$archive\")\" = '600'; "
        "test \"$(wc -c < \"$archive\")\" -eq " + str(archive_bytes) + "; "
        "test \"$(sha256sum \"$archive\" | cut -d' ' -f1)\" = " + shlex.quote(archive_sha256)
    )


def upload_fixture():
    data = b"offline upload archive with spaces in its scoped path\n"
    archive_sha256 = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(prefix="upload-fixture-", dir=DEPLOY) as temporary:
        root = Path(temporary)
        archive = root / "official archive.tar"
        command = build_upload_command(str(archive), len(data), archive_sha256)
        # Model OpenSSH's remote-command join: the actual SSH argv contains
        # one argument whose contents are ``sh -c <quoted script>``.
        remote_command = "sh -c " + shlex.quote(command)
        completed = subprocess.run(["/bin/sh", "-c", remote_command], input=data,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(completed.returncode == 0 and digest(archive, "upload fixture archive") == archive_sha256 and
                not archive.with_name(archive.name + ".partial").exists(),
                "offline upload fixture success failed")
        archive.write_bytes(b"unrelated existing archive\n")
        partial = archive.with_name(archive.name + ".partial")
        completed = subprocess.run(["/bin/sh", "-c", remote_command], input=data,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(completed.returncode != 0 and archive.read_bytes() == b"unrelated existing archive\n" and
                not partial.exists(), "offline upload fixture exclusivity failed")
        second = root / "failed archive.tar"
        bad_command = build_upload_command(str(second), len(data), "0" * 64)
        bad_remote_command = "sh -c " + shlex.quote(bad_command)
        completed = subprocess.run(["/bin/sh", "-c", bad_remote_command], input=data,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(completed.returncode != 0 and not second.exists() and
                not second.with_name(second.name + ".partial").exists(),
                "offline upload fixture cleanup failed")


def execute(archive: Path, plan: dict[str, Any]) -> int:
    require(PHONE_HELPER.is_file(), f"pinned phone helper is unavailable: {PHONE_HELPER}")
    require(digest(PHONE_HELPER, "pinned phone helper") == PHONE_HELPER_SHA256,
            "pinned phone helper hash changed")
    namespace: dict[str, Any] = {"__name__": "r8q_phone_helper", "__file__": str(PHONE_HELPER)}
    exec(compile(PHONE_HELPER.read_text(encoding="utf-8"), str(PHONE_HELPER), "exec"), namespace)
    ssh = namespace.get("SSH")
    expected_ssh = [
        "ssh", "-F", "/dev/null", "-T", "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=yes",
        "-o", "HostKeyAlias=172.16.42.1",
        "-o", "UserKnownHostsFile=" + str(REPO / "out/arch-preparation-20261009/first-arch-boot-01/ssh-known-hosts"),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-i",
        str(REPO / "out/unattended-boot-20261009/private-phone-access/id_ed25519"),
        "root@172.16.42.1",
    ]
    require(ssh == expected_ssh, "phone helper is not the exact pinned SSH identity")
    archive_bytes = archive.stat().st_size; archive_hash = digest(archive, "deployment archive")
    remote = REMOTE_TEMPLATE.replace("__ARCHIVE_BYTES__", str(archive_bytes)).replace("__ARCHIVE_SHA256__", archive_hash)
    remote = remote.replace("__NEW_EFI_SHA256__", plan["new_efi"]["sha256"]).replace("__NEW_EFI_BYTES__", str(plan["new_efi"]["bytes"]))
    upload_command = build_upload_command(REMOTE_ARCHIVE, archive_bytes, archive_hash)
    # OpenSSH joins its remaining arguments into one remote command.  Pass one
    # shell-quoted command argument so the remote shell receives exactly
    # ``sh -c <script>``; passing separate ``sh``, ``-c``, and quoted script
    # arguments can add a second layer of quoting and change the script bytes.
    remote_upload = "sh -c " + shlex.quote(upload_command)
    upload = subprocess.run(ssh + [remote_upload], input=archive.read_bytes(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    require(upload.returncode == 0, "pinned SSH archive transfer failed")
    result = subprocess.run(ssh + ["python3", "-c", shlex.quote(remote)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=300, check=False)
    lines = result.stdout.decode("utf-8", "strict").splitlines(); record: dict[str, Any] = {}
    if lines:
        try: record = json.loads(lines[-1])
        except json.JSONDecodeError: pass
    record.update({"ssh_exit_code": result.returncode, "archive_sha256": archive_hash, "archive_bytes": archive_bytes})
    receipt = DEPLOY / RECEIPT_NAME; receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"); receipt.chmod(0o600)
    print(json.dumps(record, sort_keys=True)); return 0 if result.returncode == 0 and record.get("result") == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan", action="store_true", help="validate and prepare the public archive offline")
    modes.add_argument("--execute", action="store_true", help="perform the guarded transaction over pinned SSH")
    modes.add_argument("--fixture", action="store_true", help="run local success and rollback transaction fixtures")
    args = parser.parse_args()
    if args.fixture: return run_fixture()
    candidate = validate_candidate(); hardware, rows, metadata_binding = validate_hardware(candidate)
    plan_path = DEPLOY / PLAN_NAME
    archive_path = DEPLOY / ARCHIVE_NAME
    if plan_path.exists() or archive_path.exists():
        require(plan_path.is_file() and archive_path.is_file(),
                "deployment plan and archive must be present together")
        plan = json_object(plan_path, "deployment plan")
        archive, plan = verify_existing_plan(plan, rows, candidate, hardware, metadata_binding)
    else:
        require(args.plan, "--execute requires a previously verified --plan archive")
        archive, plan = build_archive(rows, candidate, hardware, metadata_binding)
    if args.plan:
        print(json.dumps({"result": "PASS", "plan": str(DEPLOY / PLAN_NAME), "archive": str(archive), "rootfs_files": len(rows)}, sort_keys=True)); return 0
    return execute(archive, plan)


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (InstallError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"install-waydroid-kernel-trial: FAIL: {exc}", file=sys.stderr); raise SystemExit(1)
