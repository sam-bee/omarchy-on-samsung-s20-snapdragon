#!/usr/bin/env python3
"""Prepare the encrypted initramfs for the Waydroid kernel release.

The accepted production initramfs is deliberately cloned instead of being
regenerated from a mutable runtime staging tree.  Only the four early touch
modules, their release/hash metadata, and the public root profile are allowed
to change.  The command has an audit-only mode so it can be run before the
new kernel has been built; preparation mode refuses until a matching kernel
output and module staging tree are present.

No phone access, key material, recovery material, or credentials are needed.
All source and old-artifact paths are pinned to this repository's accepted
receipts.  A failed run leaves no candidate output behind.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tempfile
from typing import Any


REPO = Path(__file__).resolve().parents[1]
OLD_RELEASE = "7.1.2-r8q-rtc2"
NEW_RELEASE = "7.1.2-r8q-waydroid2"
MODULES = ("gpi.ko", "i2c-qcom-geni.ko", "fts5cu56a.ko", "zinitix.ko")
MODULE_NAMES = {
    "gpi.ko": "gpi",
    "i2c-qcom-geni.ko": "i2c_qcom_geni",
    "fts5cu56a.ko": "fts5cu56a",
    "zinitix.ko": "zinitix",
}
MODULE_OLD_HASHES = {
    "gpi.ko": "285f155bad523b79317d57371f0903c1e4db21f77c7bb7d6f5c9e460e4869f3f",
    "i2c-qcom-geni.ko": "e1db5d320d80ad07aaafb22f33971dca453c562f697491dd67407440631d7d4a",
    "fts5cu56a.ko": "a25f4396f020397ef7aecb47390156e06325c45f7d04a96cae1e3efa95e75c98",
    "zinitix.ko": "2a6ca89c453fa7722397d04dc859093d216a8693664570fc67b376163a8e0223",
}

OLD_PRODUCTION_MANIFEST_SHA256 = "cc8cc6b65a4acfebdf4613d6160dab350f5185cbabeaf1f48c5601ee50f74e73"
OLD_RUNTIME_AUDIT_SHA256 = "f8b187e8068e8f2e230796ef53cb09cfa0e95f14678330f53ebbd41988adf3b2"
OLD_ROOT_ACCEPTANCE_SHA256 = "44dc5e6825cbc2ef62b79a100024d27f7c9416bc2e386e7c1f43785e2ed2ed63"
OLD_INIT_MANIFEST_SHA256 = "cdf774b8074883a3faafad0ce86c9d85ed50d9eff3c7bffbc4cb52a43148b033"
OLD_INIT_SHA256 = "f44cfcf409da1a780f014ecdffa6fdea1ca94eac2d543ead9df20ebcbac61c88"
OLD_BUSYBOX_SHA256 = "5390b3622a9dd6c5ef440377a62faddca7a03effec64471c16ab362e91505424"
OLD_DEVNODES_SHA256 = "f2ab0e694b2267616f2b52dcf1b5b5a6d012cf630cf2ea0aab505178702c8f14"
OLD_EFI_SHA256 = "730627f49b8d41b9bdc6ef7931fe94911636003c61596c84d769d532ad27c49b"
OLD_DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
OLD_GENERATOR_SHA256 = "140e8e4d25b035e3e2a117b3fbad7448f3e146eae8fb6afe7e772a9975afbbf4"
SOURCE_MANIFEST_SHA256 = "aca2ca580368e8529967e7f5a88c632580aee569aec565a795bab3def3767e29"

DEFAULT_ACCEPTED_INIT = REPO / "out/encryption-implementation-20261013/production-init04"
DEFAULT_PRODUCTION_MANIFEST = REPO / "out/encryption-implementation-20261013/production-final-manifest04.json"
DEFAULT_RUNTIME_AUDIT = REPO / "out/encryption-implementation-20261013/runtime-command-audit04.json"
DEFAULT_ROOT_ACCEPTANCE = REPO / "out/encryption-implementation-20261013/encrypted-root-final-acceptance04.json"
DEFAULT_PRIVATE_SOURCE = REPO / "out/waydroid-kernel-20261013/source"
DEFAULT_SOURCE_MANIFEST = REPO / "out/waydroid-kernel-20261013/kernel/kernel-source-manifest.jsonl"
DEFAULT_KERNEL_OUTPUT = REPO / "out/waydroid-encrypted-20261015/kernel"
DEFAULT_RECEIPT_DIR = DEFAULT_KERNEL_OUTPUT.parent / "initramfs-preparation"
DEFAULT_INITRAMFS_OUTPUT = DEFAULT_RECEIPT_DIR / "initramfs"

SENSITIVE_NAMES = {
    "authorized_keys",
    "known_hosts",
    "passwd",
    "shadow",
    "gshadow",
    "crypttab",
    "credentials",
    "credential",
    "secrets",
    "secret",
    "private",
    "recovery-key",
    "recovery_key",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".asc", ".gpg", ".token")
VERMAGIC = re.compile(rb"(?:^|\x00)vermagic=([^\x00]+)")
MODULE_DEPENDS = re.compile(rb"(?:^|\x00)depends=([^\x00]*)")
MODULE_NAME = re.compile(rb"(?:^|\x00)name=([^\x00]+)")
MODULE_PARM = re.compile(rb"(?:^|\x00)parm=([^\x00]+)")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class PrepareError(RuntimeError):
    """A fail-closed input or output error."""


def fail(message: str) -> None:
    raise PrepareError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_file(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} must be a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value


def resolved(path: Path, label: str) -> Path:
    value = Path(os.path.realpath(path))
    if not value.exists():
        fail(f"{label} does not exist: {path}")
    return value


def under(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} must be a regular non-symlink file: {path}")
    return path


def safe_name(name: str) -> bool:
    lower = name.lower()
    return (
        lower not in SENSITIVE_NAMES
        and not lower.startswith("id_")
        and "private" not in lower
        and "secret" not in lower
        and not lower.endswith(SENSITIVE_SUFFIXES)
    )


def safe_relative(relative: Path) -> bool:
    return all(part not in ("", ".", "..") and safe_name(part) for part in relative.parts)


def reject_sensitive_tree(root: Path, label: str) -> None:
    if root.is_symlink():
        fail(f"{label} must not be a symlink: {root}")
    if not root.exists():
        fail(f"{label} does not exist: {root}")
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if not safe_relative(relative):
            fail(f"{label} contains a sensitive path: {relative}")
        if path.is_symlink():
            fail(f"{label} contains a symlink: {relative}")


def assert_hash(path: Path, expected: str, label: str) -> None:
    regular(path, label)
    actual = sha256(path)
    if actual != expected:
        fail(f"{label} hash mismatch: expected {expected}, got {actual}")


def elf_identity(path: Path, label: str) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        fail(f"{label} is not little-endian ELF64: {path}")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 183:
        fail(f"{label} is not AArch64 (machine {machine}): {path}")
    return {"class": 2, "data": "little-endian", "machine": "AArch64", "bytes": len(data)}


def module_info(path: Path, label: str) -> dict[str, Any]:
    regular(path, label)
    identity = elf_identity(path, label)
    data = path.read_bytes()
    vermagic = VERMAGIC.findall(data)
    if len(vermagic) != 1:
        fail(f"{label} does not have unique vermagic metadata: {path}")
    names = MODULE_NAME.findall(data)
    if len(names) != 1:
        fail(f"{label} does not have unique module name metadata: {path}")
    depends = MODULE_DEPENDS.findall(data)
    if len(depends) != 1:
        fail(f"{label} does not have unique dependency metadata: {path}")
    if depends[0] not in (b"", b"-"):
        fail(f"{label} has a dependency that the early initramfs does not stage: {depends[0]!r}")
    return {
        **identity,
        "module_name": names[0].decode("utf-8", "strict"),
        "vermagic": vermagic[0].decode("utf-8", "strict"),
        "depends": depends[0].decode("utf-8", "strict"),
        "sha256": sha256(path),
        "bytes": path.stat().st_size,
    }


def public_root_profile(path: Path) -> dict[str, Any]:
    data = json_file(path, "accepted encrypted-root manifest")
    if data.get("schema") != "r8q-encryption-acceptance/v1" or data.get("status") != "PASS":
        fail("accepted encrypted-root manifest is not a PASS receipt")
    expected = {
        "root_source": "/dev/mapper/cryptroot",
        "backing": "/dev/sda36",
        "luks_uuid": "b9081516-2446-4086-87c1-76d2127493ec",
        "type": "LUKS2",
        "cipher": "aes-xts-plain64",
        "key_bits": 512,
        "sector_bytes": 4096,
        "data_offset_bytes": 16777216,
    }
    for key, expected_value in expected.items():
        if data.get(key) != expected_value:
            fail(f"accepted root profile {key} changed: expected {expected_value!r}, got {data.get(key)!r}")
    if not UUID.fullmatch(str(data["luks_uuid"])):
        fail("accepted root profile LUKS UUID is malformed")
    mode_and_runtime_guards = {
        "runtime_udev_mode": "0755",
        "handoff_marker_mode": "0600",
        "new_boot_without_runtime_repair": True,
        "early_credential_paths_removed": True,
        "no_failed_system_services": True,
    }
    for key, expected_value in mode_and_runtime_guards.items():
        if data.get(key) != expected_value:
            fail(f"accepted root profile {key} changed: expected {expected_value!r}, got {data.get(key)!r}")
    # Keep only public, stable profile identities.  Do not copy boot IDs,
    # machine IDs, receipt payloads, or any credential-bearing field.
    return {"schema": "r8q-encryption-public-profile/v1", **expected, **mode_and_runtime_guards}


def manifest_file_records(initramfs: Path, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = manifest.get("files")
    if not isinstance(records, dict):
        fail("accepted initramfs manifest has no files object")
    for name, record in records.items():
        if not isinstance(name, str) or not safe_relative(Path(name)):
            fail(f"accepted initramfs manifest has unsafe file path: {name!r}")
        if not isinstance(record, dict) or not isinstance(record.get("sha256"), str):
            fail(f"accepted initramfs manifest has malformed record: {name!r}")
        target = initramfs / name
        regular(target, f"accepted initramfs file {name}")
        if target.stat().st_size != record.get("size"):
            fail(f"accepted initramfs size mismatch: {name}")
        if sha256(target) != record["sha256"]:
            fail(f"accepted initramfs hash mismatch: {name}")
    return records


def actual_files(root: Path) -> set[str]:
    files: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_symlink():
            fail(f"initramfs contains a symlink: {relative}")
        if path.is_file():
            files.add(relative.as_posix())
    return files


def inspect_old_artifacts(
    accepted_init: Path,
    production_manifest_path: Path,
    runtime_audit_path: Path,
    root_acceptance_path: Path,
    private_source: Path,
    source_manifest_path: Path,
) -> dict[str, Any]:
    """Audit the accepted inputs without creating a candidate initramfs."""

    accepted_init = resolved(accepted_init, "accepted initramfs")
    if not accepted_init.is_dir():
        fail("accepted initramfs must be a directory")
    reject_sensitive_tree(accepted_init, "accepted initramfs")

    production_manifest_path = resolved(production_manifest_path, "accepted production manifest")
    assert_hash(production_manifest_path, OLD_PRODUCTION_MANIFEST_SHA256, "accepted production manifest")
    production = json_file(production_manifest_path, "accepted production manifest")
    if production.get("schema") != 1 or production.get("kind") != "r8q-encryption-production-candidate":
        fail("accepted production manifest schema/kind changed")
    if production.get("kernel_release") != OLD_RELEASE:
        fail("accepted production manifest does not describe the accepted kernel release")
    if Path(os.path.realpath(production.get("initramfs", ""))) != accepted_init:
        fail("accepted production manifest points at a different initramfs")
    artifacts = production.get("artifacts")
    if not isinstance(artifacts, list):
        fail("accepted production manifest has no artifact list")
    efi_records = [item for item in artifacts if isinstance(item, dict) and str(item.get("path", "")).endswith("/payload/BOOTAA64.EFI")]
    dtb_records = [item for item in artifacts if isinstance(item, dict) and str(item.get("path", "")).endswith("/payload/R8Q-RTC.DTB")]
    if len(efi_records) != 1 or efi_records[0].get("sha256") != OLD_EFI_SHA256:
        fail("accepted production manifest EFI pin changed")
    if len(dtb_records) != 1 or dtb_records[0].get("sha256") != OLD_DTB_SHA256:
        fail("accepted production manifest DTB pin changed")

    runtime_audit_path = resolved(runtime_audit_path, "accepted runtime audit")
    assert_hash(runtime_audit_path, OLD_RUNTIME_AUDIT_SHA256, "accepted runtime audit")
    runtime_audit = json_file(runtime_audit_path, "accepted runtime audit")
    if runtime_audit.get("schema") != "r8q-runtime-command-audit/v1" or runtime_audit.get("result") != "PASS":
        fail("accepted runtime audit is not the expected PASS receipt")
    generator = runtime_audit.get("generator", {})
    if generator.get("sha256") != OLD_GENERATOR_SHA256 or not str(generator.get("path", "")).endswith("/scripts/prepare-encryption-initramfs.py"):
        fail("accepted runtime audit generator pin changed")
    closure = runtime_audit.get("elf_closure", {})
    if closure.get("missing") != []:
        fail("accepted runtime audit reports missing ELF dependencies")
    if set(closure.get("start", [])) != {
        "usr/bin/cryptsetup",
        "usr/bin/dmsetup",
        "usr/bin/udevadm",
        "usr/lib/systemd/systemd-udevd",
        "usr/lib/r8q-encryption/unl0kr",
    }:
        fail("accepted runtime audit ELF start set changed")
    if runtime_audit.get("init", {}).get("run_udev_command") != "mkdir -m 0755 -p /run/udev":
        fail("accepted runtime audit lost the public /run/udev mode guard")
    if runtime_audit.get("init", {}).get("chmod_command_present") is not False:
        fail("accepted runtime audit unexpectedly uses chmod in generated init")
    expected_external = {
        "/usr/bin/cryptsetup": "6377ef0fcea20f79408b5cb1354eea8a7b6388c6dfe4415fb91de50b987335cf",
        "/usr/bin/dmsetup": "f16fb9b0176cbb2c6a295a809ae32d1bcd34858972be229e6457da89960b0ea4",
        "/usr/bin/udevadm": "8bb2e967409da6ac106f8fa9b5ea55166fbbb49c3f996ef59b654b7524c27c64",
        "/usr/lib/systemd/systemd-udevd": "8bb2e967409da6ac106f8fa9b5ea55166fbbb49c3f996ef59b654b7524c27c64",
        "/usr/lib/r8q-encryption/unl0kr": "e24d7f2d7fbb68ef2506fb635b38ddb8598174506a217c5a6627026110563e7e",
    }
    external = {item.get("path"): item.get("sha256") for item in runtime_audit.get("external_commands", []) if isinstance(item, dict)}
    if external != expected_external:
        fail("accepted helper/native UI external hash set changed")

    root_acceptance_path = resolved(root_acceptance_path, "accepted encrypted-root manifest")
    assert_hash(root_acceptance_path, OLD_ROOT_ACCEPTANCE_SHA256, "accepted encrypted-root manifest")
    root_profile = public_root_profile(root_acceptance_path)

    init_manifest_path = accepted_init / "etc/r8q-encryption-manifest.json"
    assert_hash(init_manifest_path, OLD_INIT_MANIFEST_SHA256, "accepted initramfs manifest")
    init_manifest = json_file(init_manifest_path, "accepted initramfs manifest")
    if init_manifest.get("schema") != 1 or init_manifest.get("kind") != "r8q-encryption-initramfs-candidate":
        fail("accepted initramfs manifest schema/kind changed")
    if init_manifest.get("kernel_release") != OLD_RELEASE or init_manifest.get("fail_closed") is not True:
        fail("accepted initramfs release/fail-closed pin changed")
    if init_manifest.get("cryptsetup") != "usr/bin/cryptsetup":
        fail("accepted cryptsetup path guard changed")
    if init_manifest.get("dmsetup") != "usr/bin/dmsetup":
        fail("accepted dmsetup path guard changed")
    if init_manifest.get("udevadm") != "usr/bin/udevadm":
        fail("accepted udevadm path guard changed")
    if init_manifest.get("udevd") != "usr/lib/systemd/systemd-udevd" or not init_manifest.get("udevd_alias_from_udevadm"):
        fail("accepted udevd alias/path guard changed")
    if init_manifest.get("unl0kr") != "usr/lib/r8q-encryption/unl0kr":
        fail("accepted native unlock UI path guard changed")
    if init_manifest.get("ui_contract") != "stdout-raw-passphrase-no-newline":
        fail("accepted native unlock UI stdout contract changed")
    if init_manifest.get("ui_args") != ["-d", "400", "-m", "Unlock encrypted phone storage"]:
        fail("accepted native unlock UI arguments changed")
    if init_manifest.get("adapter_handoff") != {
        "schema": "r8q-encryption-adapter-handoff/v1",
        "marker": "/run/r8q-encryption-adapter-handoff",
        "retained_modules": ["gpi.ko", "i2c-qcom-geni.ko"],
        "unloaded_modules": ["fts5cu56a.ko", "zinitix.ko"],
        "fifo": "r8q_force_fifo=1",
        "touch_drivers": "absent",
    }:
        fail("accepted adapter handoff contract changed")
    records = manifest_file_records(accepted_init, init_manifest)

    init_path = accepted_init / "init"
    assert_hash(init_path, OLD_INIT_SHA256, "accepted generated init")
    init_text = init_path.read_text(encoding="utf-8")
    required_fragments = (
        "No plaintext-init fallback is embedded.",
        "umask 077",
        "mkdir -m 0755 -p /run/udev",
        "HANDOFF_MARKER=/run/r8q-encryption-adapter-handoff",
        "BOOT_ID=$(cat /proc/sys/kernel/random/boot_id",
        "printf 'boot_id=%s",
        "printf 'kernel=%s",
        "printf 'gpi_module=lib/modules/",
        "printf 'gpi_sha256=%s",
        "printf 'geni_module=lib/modules/",
        "printf 'geni_sha256=%s",
        "printf 'gpi_ownership=inherited",
        "printf 'geni_ownership=inherited",
        "printf 'touch_drivers=absent",
        "printf 'touch_input_events=absent",
        "mount -o move /run /newroot/run",
        "exec switch_root /newroot /usr/lib/systemd/systemd",
    )
    for fragment in required_fragments:
        if fragment not in init_text:
            fail(f"accepted generated init is missing required guard: {fragment}")
    if "mount \"$ROOT\" /newroot" in init_text or "exec /bin/sh" in init_text:
        fail("accepted generated init contains a plaintext/debug fallback")
    if any("chmod" in line and not line.lstrip().startswith("#") for line in init_text.splitlines()):
        fail("accepted generated init must preserve the tested no-chmod marker contract")

    expected_old_module_paths = {f"lib/modules/{OLD_RELEASE}/r8q-encryption/{name}" for name in MODULES}
    record_module_paths = {name for name, record in records.items() if record.get("kind") == "kernel-module"}
    if record_module_paths != expected_old_module_paths:
        fail("accepted initramfs module path set changed")
    for name in MODULES:
        record = records[f"lib/modules/{OLD_RELEASE}/r8q-encryption/{name}"]
        if record.get("sha256") != MODULE_OLD_HASHES[name] or not str(record.get("vermagic", "")).startswith(OLD_RELEASE + " "):
            fail(f"accepted initramfs module pin changed: {name}")

    # BusyBox and the generated devnode list are inherited base files and are
    # intentionally outside the generic preparer's closure manifest.
    listed = set(records)
    actual = actual_files(accepted_init)
    allowed_unlisted = {"bin/busybox", "irfs.devnodes", "etc/r8q-encryption-manifest.json"}
    if actual - listed != allowed_unlisted:
        fail(f"accepted initramfs unlisted files changed: {sorted(actual - listed)}")
    if listed - actual:
        fail(f"accepted initramfs manifest references missing files: {sorted(listed - actual)}")
    busybox = accepted_init / "bin/busybox"
    elf_identity(busybox, "accepted BusyBox")
    if b"/lib/ld-linux" in busybox.read_bytes() or b"DT_NEEDED" in busybox.read_bytes():
        fail("accepted BusyBox is not the expected static base")
    if runtime_audit.get("busybox", {}).get("sha256") != OLD_BUSYBOX_SHA256 or sha256(busybox) != OLD_BUSYBOX_SHA256:
        fail("accepted BusyBox hash pin changed")
    devnodes = accepted_init / "irfs.devnodes"
    regular(devnodes, "accepted initramfs devnode list")
    if sha256(devnodes) != OLD_DEVNODES_SHA256:
        fail("accepted initramfs devnode list hash pin changed")

    ui_path = accepted_init / str(init_manifest["unl0kr"])
    ui_elf = elf_identity(ui_path, "accepted native unlock UI")
    ui_data = ui_path.read_bytes()
    if b".ko\x00" in ui_data or OLD_RELEASE.encode() in ui_data or NEW_RELEASE.encode() in ui_data:
        fail("accepted native unlock UI unexpectedly carries kernel/module release coupling")

    # Ensure all runtime assets and command dependencies are regular staged
    # files and that only the four module records are kernel-specific.
    for name, record in records.items():
        if record.get("kind") in {"elf", "elf-alias", "runtime-alias", "runtime-asset"}:
            regular(accepted_init / name, f"accepted runtime closure file {name}")
    old_runtime_files = {name: sha256(accepted_init / name) for name, record in records.items() if record.get("kind") not in {"kernel-module", "generated-encrypted-init"}}

    source_manifest_path = resolved(source_manifest_path, "pinned Waydroid source manifest")
    assert_hash(source_manifest_path, SOURCE_MANIFEST_SHA256, "pinned Waydroid source manifest")
    private_source = resolved(private_source, "pinned private Waydroid source")
    if not private_source.is_dir() or private_source.is_symlink():
        fail("pinned private Waydroid source must be a directory")
    if Path(os.path.realpath(source_manifest_path)).parent != private_source.parent / "kernel":
        # The source manifest is intentionally the manifest emitted by the
        # pinned build output, not an arbitrary manifest imported elsewhere.
        fail("pinned source manifest is not the retained Waydroid build manifest")
    if Path(os.path.realpath(private_source)) != DEFAULT_PRIVATE_SOURCE:
        fail(f"private source path changed: expected {DEFAULT_PRIVATE_SOURCE}, got {private_source}")

    return {
        "accepted_production_manifest": {"path": str(production_manifest_path), "sha256": sha256(production_manifest_path)},
        "accepted_runtime_audit": {"path": str(runtime_audit_path), "sha256": sha256(runtime_audit_path)},
        "accepted_root_profile_manifest": {"path": str(root_acceptance_path), "sha256": sha256(root_acceptance_path)},
        "accepted_initramfs": {
            "path": str(accepted_init),
            "init_sha256": sha256(init_path),
            "manifest_sha256": sha256(init_manifest_path),
            "files": len(actual),
            "manifest_records": len(records),
            "runtime_closure_files": len(old_runtime_files),
        },
        "native_unlock_ui": {
            "path": init_manifest["unl0kr"],
            "sha256": records[init_manifest["unl0kr"]]["sha256"],
            "elf": ui_elf,
            "kernel_abi": "userspace ELF; no staged kernel/module release references",
        },
        "root_profile": root_profile,
        "source_pin": {
            "path": str(private_source),
            "manifest": str(source_manifest_path),
            "manifest_sha256": SOURCE_MANIFEST_SHA256,
        },
        "old_artifact_pins": {
            "kernel_release": OLD_RELEASE,
            "efi_sha256": OLD_EFI_SHA256,
            "dtb_sha256": OLD_DTB_SHA256,
            "generator_sha256": OLD_GENERATOR_SHA256,
            "module_sha256": MODULE_OLD_HASHES,
        },
        "old_runtime_file_hashes": old_runtime_files,
        "old_base_file_hashes": {
            "bin/busybox": OLD_BUSYBOX_SHA256,
            "irfs.devnodes": OLD_DEVNODES_SHA256,
        },
    }


def module_inputs(kernel_output: Path) -> tuple[dict[str, Path], dict[str, Any]]:
    kernel_output = resolved(kernel_output, "Waydroid kernel output")
    if not kernel_output.is_dir() or kernel_output.is_symlink():
        fail("Waydroid kernel output must be a directory")
    expected_kernel_release = kernel_output / "include/config/kernel.release"
    regular(expected_kernel_release, "Waydroid kernel release file")
    release = expected_kernel_release.read_text(encoding="utf-8").strip()
    if release != NEW_RELEASE:
        fail(f"Waydroid kernel output release mismatch: expected {NEW_RELEASE}, got {release!r}")
    image = kernel_output / "arch/arm64/boot/Image"
    regular(image, "Waydroid kernel Image")
    module_roots = [kernel_output / "modules/lib/modules" / NEW_RELEASE]
    # Permit a caller to pass a modules_install root while still constraining
    # it to the primary kernel output. The default path is the build's normal
    # modules staging path.
    candidates: dict[str, list[Path]] = {name: [] for name in MODULES}
    for root in module_roots:
        if root.is_dir() and not root.is_symlink():
            for path in root.rglob("*.ko"):
                if path.name in candidates and not path.is_symlink():
                    candidates[path.name].append(path)
    missing = [name for name, paths in candidates.items() if not paths]
    duplicate = [name for name, paths in candidates.items() if len(paths) != 1]
    if missing:
        fail(f"Waydroid kernel output has not staged required modules: {', '.join(missing)}")
    if duplicate:
        fail(f"Waydroid kernel output has ambiguous required modules: {', '.join(duplicate)}")
    modules = {name: paths[0] for name, paths in candidates.items()}
    module_receipts: dict[str, Any] = {}
    for name, path in modules.items():
        info = module_info(path, f"Waydroid module {name}")
        if info["module_name"] != MODULE_NAMES[name]:
            fail(f"Waydroid module {name} name mismatch: {info['module_name']!r}")
        if not info["vermagic"].startswith(NEW_RELEASE + " "):
            fail(f"Waydroid module {name} vermagic mismatch: {info['vermagic']!r}")
        module_receipts[name] = {"path": str(path), **info}
    geni_data = modules["i2c-qcom-geni.ko"].read_bytes()
    if not any(b"r8q_force_fifo:" in value for value in MODULE_PARM.findall(geni_data)):
        fail("Waydroid i2c-qcom-geni module lacks the required r8q_force_fifo parameter")

    candidate_manifest = kernel_output / "candidate-manifest.json"
    candidate_receipt = None
    if candidate_manifest.exists():
        candidate = json_file(candidate_manifest, "Waydroid kernel candidate manifest")
        if candidate.get("kernel_release") != NEW_RELEASE:
            fail("Waydroid kernel candidate manifest release mismatch")
        if candidate.get("source") != str(DEFAULT_PRIVATE_SOURCE):
            fail("Waydroid kernel candidate manifest source pin mismatch")
        candidate_receipt = {"path": str(candidate_manifest), "sha256": sha256(candidate_manifest)}
    return modules, {
        "kernel_output": str(kernel_output),
        "kernel_release": release,
        "image": {"path": str(image), "bytes": image.stat().st_size, "sha256": sha256(image)},
        "modules": module_receipts,
        "candidate_manifest": candidate_receipt,
    }


def rewrite_manifest(
    old_manifest: dict[str, Any],
    module_info_by_name: dict[str, dict[str, Any]],
    root_profile: dict[str, Any],
) -> dict[str, Any]:
    manifest = copy.deepcopy(old_manifest)
    manifest["kernel_release"] = NEW_RELEASE
    manifest["root_profile"] = root_profile
    records = dict(manifest["files"])
    for name in MODULES:
        old_path = f"lib/modules/{OLD_RELEASE}/r8q-encryption/{name}"
        if old_path not in records:
            fail(f"accepted manifest lacks module record: {old_path}")
        del records[old_path]
        new_path = f"lib/modules/{NEW_RELEASE}/r8q-encryption/{name}"
        records[new_path] = {
            "kind": "kernel-module",
            "source": name,
            "sha256": module_info_by_name[name]["sha256"],
            "size": module_info_by_name[name]["bytes"],
            "vermagic": module_info_by_name[name]["vermagic"],
        }
    manifest["touch_modules"] = {name: f"lib/modules/{NEW_RELEASE}/r8q-encryption/{name}" for name in MODULES}
    manifest["files"] = dict(sorted(records.items()))
    return manifest


def prepare_candidate(
    accepted_init: Path,
    output: Path,
    old_manifest: dict[str, Any],
    audit: dict[str, Any],
    modules: dict[str, Path],
    module_receipt: dict[str, Any],
) -> dict[str, Any]:
    output = Path(os.path.realpath(output))
    receipt_dir = output.parent
    if output == Path("/") or output == accepted_init or under(output, accepted_init) or under(accepted_init, output):
        fail("new initramfs output must be separate from accepted initramfs")
    if not under(receipt_dir, DEFAULT_RECEIPT_DIR) or receipt_dir == DEFAULT_RECEIPT_DIR.parent:
        fail(f"new output must remain under {DEFAULT_RECEIPT_DIR}")
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            fail(f"new initramfs output must be absent or empty: {output}")
        output.rmdir()
    receipt_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".initramfs-stage-", dir=str(receipt_dir)))
    try:
        shutil.rmtree(staging)
        shutil.copytree(accepted_init, staging, symlinks=False)
        reject_sensitive_tree(staging, "cloned initramfs")
        old_init = staging / "init"
        old_init_text = old_init.read_text(encoding="utf-8")
        if sha256(old_init) != OLD_INIT_SHA256:
            fail("accepted generated init changed during clone")
        if old_init_text.count(OLD_RELEASE) < 6:
            fail("accepted generated init has fewer release guards than expected")
        for name in MODULES:
            count = old_init_text.count(MODULE_OLD_HASHES[name])
            if count != 1:
                fail(f"accepted generated init has unexpected {name} hash count: {count}")
        new_text = old_init_text.replace(OLD_RELEASE, NEW_RELEASE)
        for name in MODULES:
            new_text = new_text.replace(MODULE_OLD_HASHES[name], module_receipt[name]["sha256"])
        if OLD_RELEASE in new_text:
            fail("generated init retained the old kernel release")
        if any(value in new_text for value in MODULE_OLD_HASHES.values()):
            fail("generated init retained an old module hash")
        old_init.write_text(new_text, encoding="utf-8")
        os.chmod(old_init, 0o755)

        old_module_root = staging / f"lib/modules/{OLD_RELEASE}/r8q-encryption"
        if not old_module_root.is_dir():
            fail("accepted initramfs old module directory is missing")
        old_module_files = {path.name for path in old_module_root.iterdir() if path.is_file()}
        if old_module_files != set(MODULES):
            fail("accepted initramfs old module directory contains unexpected files")
        shutil.rmtree(staging / f"lib/modules/{OLD_RELEASE}")
        new_module_root = staging / f"lib/modules/{NEW_RELEASE}/r8q-encryption"
        new_module_root.mkdir(parents=True)
        for name, source in modules.items():
            target = new_module_root / name
            shutil.copy2(source, target)
            # Match accepted early-boot permissions independently of the
            # build host's umask or staged module group-write permission.
            os.chmod(target, 0o744)

        old_manifest_path = staging / "etc/r8q-encryption-manifest.json"
        old_manifest_mode = stat.S_IMODE(old_manifest_path.stat().st_mode)
        new_manifest = rewrite_manifest(old_manifest, module_receipt, audit["root_profile"])
        # Update the generated-init record only after the transformed file is
        # final. The manifest itself is intentionally outside the runtime
        # closure comparison because its release/module records must change.
        new_manifest["files"]["init"] = {
            "kind": "generated-encrypted-init",
            "sha256": sha256(old_init),
            "size": old_init.stat().st_size,
            "source": "generated",
        }
        old_manifest_path.write_text(json.dumps(new_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(old_manifest_path, old_manifest_mode)

        # Every inherited base/runtime file must be byte-identical. This is
        # the central reason this tool clones production04 rather than
        # rerunning the generic preparer.
        transformed_records = new_manifest["files"]
        old_runtime_hashes = audit["old_runtime_file_hashes"]
        for name, expected_hash in old_runtime_hashes.items():
            target = staging / name
            regular(target, f"transformed runtime closure file {name}")
            if sha256(target) != expected_hash:
                fail(f"runtime closure changed during Waydroid preparation: {name}")
        for name, expected_hash in audit["old_base_file_hashes"].items():
            target = staging / name
            regular(target, f"transformed base file {name}")
            if sha256(target) != expected_hash:
                fail(f"base initramfs file changed during Waydroid preparation: {name}")
        actual = actual_files(staging)
        expected_old_actual = actual_files(accepted_init)
        expected_new_actual = (expected_old_actual - {f"lib/modules/{OLD_RELEASE}/r8q-encryption/{name}" for name in MODULES}) | {f"lib/modules/{NEW_RELEASE}/r8q-encryption/{name}" for name in MODULES}
        if actual != expected_new_actual:
            fail("transformed initramfs file set differs from accepted closure plus new modules")
        if any(OLD_RELEASE in path for path in actual):
            fail("transformed initramfs retains an old release path")
        if any(OLD_RELEASE.encode() in (staging / path).read_bytes() for path in actual if path not in {"bin/busybox"}):
            fail("transformed initramfs retains the old release in file contents")
        reject_sensitive_tree(staging, "transformed initramfs")

        # Reopen and verify the public manifest before publishing the staging
        # directory. This also proves all new module records point at the
        # transformed files rather than merely recording hashes.
        published_manifest = json_file(old_manifest_path, "transformed initramfs manifest")
        if published_manifest.get("kernel_release") != NEW_RELEASE:
            fail("transformed manifest release mismatch")
        for name in MODULES:
            rel = f"lib/modules/{NEW_RELEASE}/r8q-encryption/{name}"
            record = published_manifest["files"].get(rel)
            target = staging / rel
            if not record or record.get("sha256") != sha256(target) or record.get("size") != target.stat().st_size:
                fail(f"transformed module manifest mismatch: {name}")
        if published_manifest["files"]["init"]["sha256"] != sha256(old_init):
            fail("transformed init manifest hash mismatch")
        os.replace(staging, output)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {
        "path": str(output),
        "kernel_release": NEW_RELEASE,
        "files": len(actual_files(output)),
        "manifest_sha256": sha256(output / "etc/r8q-encryption-manifest.json"),
        "init_sha256": sha256(output / "init"),
        "module_sha256": {name: sha256(output / f"lib/modules/{NEW_RELEASE}/r8q-encryption/{name}") for name in MODULES},
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def build_interface(audit: dict[str, Any], script_hash: str) -> dict[str, Any]:
    output = DEFAULT_INITRAMFS_OUTPUT
    return {
        "schema": "r8q-waydroid-encrypted-initramfs-interface/v1",
        "status": "awaiting-waydroid2-kernel-modules",
        "generator": {"path": str(Path(__file__).resolve()), "sha256": script_hash},
        "command": [
            "/usr/bin/python3",
            str(Path(__file__).resolve()),
            "--prepare",
            "--kernel-output",
            str(DEFAULT_KERNEL_OUTPUT),
            "--output",
            str(output),
        ],
        "expected_kernel_release": NEW_RELEASE,
        "module_staging_contract": {
            "root": str(DEFAULT_KERNEL_OUTPUT / "modules/lib/modules" / NEW_RELEASE),
            "required": list(MODULES),
            "vermagic_prefix": NEW_RELEASE + " ",
            "dependencies": "empty; initramfs loads the four modules explicitly",
            "required_geni_parameter": "r8q_force_fifo",
        },
        "source_pin": audit["source_pin"],
        "old_artifact_pins": audit["old_artifact_pins"],
        "root_profile": audit["root_profile"],
        "accepted_runtime_closure": {
            "strategy": "clone accepted production04 and guardedly transform release/module records",
            "files": audit["accepted_initramfs"]["files"],
            "runtime_closure_files": audit["accepted_initramfs"]["runtime_closure_files"],
            "native_unlock_ui": audit["native_unlock_ui"],
        },
        "outstanding": [
            "Build and independently validate the 7.1.2-r8q-waydroid2 kernel and matching modules.",
            "Run this command with --prepare after kernel Image, kernel.release, and all four modules exist.",
            "Carry the resulting initramfs into the new kernel's embedded cpio and audit the final EFI/hash binding.",
            "Physical boot, unlock, Waydroid, and rollback acceptance remain outside this offline tool.",
        ],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-only", action="store_true", help="audit accepted inputs and emit receipts (default)")
    parser.add_argument("--prepare", action="store_true", help="clone and transform the accepted initramfs after module checks")
    parser.add_argument("--accepted-initramfs", type=Path, default=DEFAULT_ACCEPTED_INIT)
    parser.add_argument("--production-manifest", type=Path, default=DEFAULT_PRODUCTION_MANIFEST)
    parser.add_argument("--runtime-audit", type=Path, default=DEFAULT_RUNTIME_AUDIT)
    parser.add_argument("--root-acceptance", type=Path, default=DEFAULT_ROOT_ACCEPTANCE)
    parser.add_argument("--private-source", type=Path, default=DEFAULT_PRIVATE_SOURCE)
    parser.add_argument("--source-manifest", type=Path, default=DEFAULT_SOURCE_MANIFEST)
    parser.add_argument("--kernel-output", type=Path, default=DEFAULT_KERNEL_OUTPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_INITRAMFS_OUTPUT)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    options = parse_args(argv or sys.argv[1:])
    if options.audit_only and options.prepare:
        print("prepare-waydroid-encrypted-initramfs: error: --audit-only and --prepare are mutually exclusive", file=sys.stderr)
        return 2
    prepare = options.prepare
    if not options.audit_only and not options.prepare:
        prepare = False
    try:
        audit = inspect_old_artifacts(
            options.accepted_initramfs,
            options.production_manifest,
            options.runtime_audit,
            options.root_acceptance,
            options.private_source,
            options.source_manifest,
        )
        script_hash = sha256(Path(__file__).resolve())
        receipt_dir = Path(os.path.realpath(options.receipt_dir))
        if receipt_dir != DEFAULT_RECEIPT_DIR:
            fail(f"receipt directory is pinned to {DEFAULT_RECEIPT_DIR}")
        if not under(receipt_dir, REPO / "out"):
            fail("receipt directory must remain under repository out/")
        interface = build_interface(audit, script_hash)
        write_json(receipt_dir / "preparation-interface.json", interface)
        audit_receipt = {
            "schema": "r8q-waydroid-encrypted-initramfs-audit/v1",
            "status": "PASS",
            "mode": "prepare" if prepare else "audit-only",
            "generator": {"path": str(Path(__file__).resolve()), "sha256": script_hash},
            "strategy": "guarded-clone-production04",
            "checks": audit,
        }
        if prepare:
            kernel_output = Path(os.path.realpath(options.kernel_output))
            if kernel_output != DEFAULT_KERNEL_OUTPUT:
                fail(f"kernel output is pinned to {DEFAULT_KERNEL_OUTPUT}")
            modules, kernel_receipt = module_inputs(kernel_output)
            audit_receipt["kernel_input"] = kernel_receipt
            candidate = prepare_candidate(
                Path(os.path.realpath(options.accepted_initramfs)),
                options.output,
                json_file(Path(os.path.realpath(options.accepted_initramfs)) / "etc/r8q-encryption-manifest.json", "accepted initramfs manifest"),
                audit,
                modules,
                kernel_receipt["modules"],
            )
            audit_receipt["candidate"] = candidate
            interface["status"] = "prepared"
            interface["candidate"] = candidate
            write_json(receipt_dir / "preparation-interface.json", interface)
        write_json(receipt_dir / "acceptance-audit.json", audit_receipt)
        print(options.output if prepare else receipt_dir / "acceptance-audit.json")
        return 0
    except (PrepareError, OSError, UnicodeError, json.JSONDecodeError, ValueError, struct.error) as exc:
        print(f"prepare-waydroid-encrypted-initramfs: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
