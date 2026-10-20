#!/usr/bin/env python3
"""Prepare the offline r8q diagnostic initramfs and runtime bundle.

The preparer has two explicit modes.  Both require a completed diagnostic
stage1 catalogue and write to a new preparation directory.  Accepted v2
inputs are read-only and are copied only as provenance for the new candidate.
No phone, package manager, network, or live root is touched.
"""

from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid
from typing import Any


SCRIPT = Path(__file__).resolve()
REPO = SCRIPT.parents[1]
OLD_RELEASE = "7.1.2-r8q-waydroid2"
RELEASE = "7.1.2-r8q-diag1"
VERMAGIC = f"{RELEASE} SMP preempt mod_unload aarch64"
ACCEPTED_EFI_SHA256 = "f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b"
ACCEPTED_DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
OLD_HARDWARE = REPO / "out/waydroid-encrypted-20261015/hardware-preparation"
OLD_INITRAMFS = OLD_HARDWARE / "../initramfs-preparation/initramfs"
DEFAULT_KERNEL = REPO / "out/diagnostic-kernel-20261020/kernel"
DEFAULT_GENERATED = REPO / "out/diagnostic-kernel-20261020"
MODULE_NAMES = ("gpi", "i2c_qcom_geni", "fts5cu56a", "zinitix")
PRIVATE_PROFILE_ROOT = "usr/local/lib/r8q-kernel-profiles"
OLD_PROFILE_REL = f"{PRIVATE_PROFILE_ROOT}/{OLD_RELEASE}/rootfs"
NEW_PROFILE_RELEASE_REL = f"{PRIVATE_PROFILE_ROOT}/{RELEASE}"
NEW_PROFILE_REL = f"{PRIVATE_PROFILE_ROOT}/{RELEASE}/rootfs"
MODULE_ROOT_REL = f"usr/lib/modules/{RELEASE}"
GUARD_NAME = "r8q-diagnostic-fallback.sh"
GUARD_DESTINATION = GUARD_NAME
GUARD_HELPER_BINARY = "r8q-diagnostic-busybox"
GUARD_HELPER_LINKS = ("cp", "mv", "readlink", "sha256sum", "stat")
DEFAULT_GUARD_HELPER = DEFAULT_GENERATED / "guard-tools"
MANIFEST_NAME = "runtime-manifest.json"
PROVENANCE_NAME = "provenance.json"
CONFIG_DELTA_NAME = "config-delta.json"
PACKAGE_HASHES_NAME = "package-manifest.sha256"


class PreparationError(RuntimeError):
    """Raised for a fail-closed preparation rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


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


def absolute(path: Path, label: str) -> Path:
    value = path.expanduser().resolve(strict=False)
    require(value.is_absolute(), f"{label} must be absolute")
    return value


def reject_system_path(path: Path, label: str) -> None:
    roots = (Path("/bin"), Path("/etc"), Path("/lib"), Path("/lib64"),
             Path("/opt"), Path("/proc"), Path("/run"), Path("/sbin"),
             Path("/sys"), Path("/usr"), Path("/var"))
    require(path != Path("/") and
            all(path != root and root not in path.parents for root in roots),
            f"{label} resolves to a live/system path: {path}")


def safe_output(path: Path) -> Path:
    output = absolute(path, "output")
    reject_system_path(output, "output")
    require(not output.exists() and not output.is_symlink(),
            f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    require(output.parent.is_dir() and not output.parent.is_symlink(),
            f"output parent must be a non-symlink directory: {output.parent}")
    return output


def safe_relative(raw: str, label: str) -> str:
    value = Path(raw)
    require(not value.is_absolute() and ".." not in value.parts and
            "" not in value.parts and "." not in value.parts,
            f"unsafe {label} path: {raw!r}")
    return value.as_posix()


def copy_file(source: Path, destination: Path) -> None:
    regular(source, "copy source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def write_text(path: Path, value: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.exists() and not path.is_symlink(),
            f"refusing to overwrite staged path: {path}")
    path.write_text(value, encoding="utf-8")
    os.chmod(path, mode)


def write_json(path: Path, value: Any, mode: int = 0o644) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode)


def tree_records(root: Path) -> dict[str, dict[str, Any]]:
    directory(root, "tree root")
    records: dict[str, dict[str, Any]] = {}
    for current, directory_names, file_names in os.walk(root, topdown=True,
                                                         followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        kept_directories = []
        for name in directory_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                records[relative] = {"type": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                     "target": os.readlink(path)}
                continue
            require(stat.S_ISDIR(info.st_mode), f"tree contains non-directory: {path}")
            records[relative] = {"type": "directory", "mode": stat.S_IMODE(info.st_mode)}
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                records[relative] = {"type": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                     "target": os.readlink(path)}
            else:
                require(stat.S_ISREG(info.st_mode), f"tree contains special file: {path}")
                records[relative] = {"type": "file", "mode": stat.S_IMODE(info.st_mode),
                                     "bytes": info.st_size, "sha256": digest(path)}
    return records


def records_with_provenance(root: Path, source_root: Path | None = None) -> list[dict[str, Any]]:
    records = tree_records(root)
    result = []
    for relative in sorted(records):
        row = dict(records[relative])
        row["path"] = relative
        source_path = source_root / relative if source_root else None
        row["source"] = (str(source_path) if source_path and source_path.exists()
                          else "generated")
        result.append(row)
    return result


def stage1_manifest(kernel_output: Path) -> dict[str, Any]:
    directory(kernel_output, "diagnostic kernel output")
    path = kernel_output / "stage1-manifest.json"
    regular(path, "diagnostic stage1 manifest")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreparationError(f"cannot read stage1 manifest: {exc}") from exc
    require(isinstance(value, dict), "diagnostic stage1 manifest is not an object")
    require(value.get("kind") == "r8q-diagnostic-stage1-nondeployable",
            "diagnostic stage1 manifest kind is not the completed stage1 build")
    require(value.get("kernel_release") == RELEASE,
            "diagnostic stage1 manifest release is not diag1")
    require(value.get("base_efi_sha256") == ACCEPTED_EFI_SHA256,
            "diagnostic stage1 manifest EFI pin is not the accepted v2 EFI")
    require(value.get("dtb_sha256") == ACCEPTED_DTB_SHA256,
            "diagnostic stage1 manifest DTB pin is not the accepted v2 DTB")
    require(value.get("deployable") is False and value.get("stage2_required") is True,
            "diagnostic stage1 manifest has an unsafe deployment state")
    require(type(value.get("module_count")) is int and value["module_count"] > 0,
            "diagnostic stage1 manifest has no installed modules")
    image = kernel_output / "payload/BOOTAA64.EFI"
    regular(image, "diagnostic stage1 EFI payload")
    require(value.get("payload_image_sha256") == digest(image),
            "diagnostic stage1 EFI payload does not match its manifest")
    payload_dtb = kernel_output / "payload/R8Q-RTC.DTB"
    regular(payload_dtb, "diagnostic stage1 DTB payload")
    require(digest(payload_dtb) == ACCEPTED_DTB_SHA256,
            "diagnostic stage1 DTB payload is not the accepted v2 DTB")
    return value


def locate_module_root(kernel_output: Path) -> Path:
    candidates = [
        kernel_output / "modules/lib/modules" / RELEASE,
        kernel_output / "lib/modules" / RELEASE,
        kernel_output / RELEASE,
    ]
    matches = []
    for candidate in candidates:
        if candidate.is_dir() and not candidate.is_symlink():
            matches.append(candidate.resolve())
    require(len(set(matches)) == 1,
            f"expected exactly one completed diag1 module catalogue, found: {matches}")
    module_root = matches[0]
    require(any(path.is_file() and path.suffix == ".ko" for path in module_root.rglob("*")),
            f"diag1 module catalogue is empty: {module_root}")
    return module_root


def modinfo(path: Path, field: str) -> str:
    tool = shutil.which("modinfo") or "/usr/sbin/modinfo"
    require(Path(tool).is_file(), "existing modinfo tool is required")
    result = subprocess.run([tool, "-F", field, str(path)], capture_output=True,
                            text=True, check=False)
    value = result.stdout.strip()
    require(result.returncode == 0 and value,
            f"modinfo {field} failed for {path}: {result.stderr.strip()}")
    return value


def candidate_modules(module_root: Path) -> list[Path]:
    result = []
    for path in sorted(module_root.rglob("*.ko")):
        if path.is_symlink():
            raise PreparationError(f"module catalogue contains a symlink: {path}")
        if path.is_file():
            result.append(path)
    require(result, f"no regular kernel modules under {module_root}")
    return result


@lru_cache(maxsize=4)
def module_name_index(module_root: Path) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = {}
    for path in candidate_modules(module_root):
        index.setdefault(modinfo(path, "name"), []).append(path)
    return index


def resolve_module(module_root: Path, name: str, basename: str | None = None) -> Path:
    matches = [path for path in module_name_index(module_root).get(name, [])
               if basename is None or path.name == basename]
    require(len(matches) == 1,
            f"diag1 catalogue must have one {name} module; found {matches}")
    vermagic = modinfo(matches[0], "vermagic")
    require(vermagic == VERMAGIC,
            f"{name} vermagic is {vermagic!r}, expected {VERMAGIC!r}")
    return matches[0]


def module_identity(path: Path, name: str) -> dict[str, Any]:
    return {"name": name, "path": str(path), "bytes": path.stat().st_size,
            "sha256": digest(path), "vermagic": modinfo(path, "vermagic"),
            "module_name": modinfo(path, "name")}


def hardware_provenance(accepted_rootfs: Path, kernel_output: Path,
                        module_root: Path, names: list[str],
                        source_modules: dict[str, Path],
                        identity: dict[str, Any]) -> dict[str, Any]:
    bundle_manifest = accepted_rootfs.parent / "bundle-manifest.json"
    stage1_manifest_path = kernel_output / "stage1-manifest.json"
    return {
        "schema": "r8q-diagnostic-runtime-provenance/v1",
        "mode": "hardware",
        "accepted_efi_sha256": ACCEPTED_EFI_SHA256,
        "accepted_dtb_sha256": ACCEPTED_DTB_SHA256,
        "accepted_rootfs": str(accepted_rootfs),
        "accepted_bundle_manifest": str(bundle_manifest),
        "accepted_bundle_manifest_sha256": digest(bundle_manifest),
        "stage1_manifest": str(stage1_manifest_path),
        "stage1_manifest_sha256": digest(stage1_manifest_path),
        "source_module_root": str(module_root),
        "module_selection_count": len(names),
        "modules": {name: module_identity(path, name)
                    for name, path in source_modules.items()},
        "identity": identity,
    }


def read_json(path: Path, label: str) -> Any:
    regular(path, label)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreparationError(f"cannot parse {label}: {exc}") from exc


def replace_text(value: str, replacements: dict[str, str], label: str) -> str:
    result = value
    for old, new in replacements.items():
        result = result.replace(old, new)
    require(OLD_RELEASE not in result,
            f"{label} still contains accepted v2 release text")
    return result


def replace_line(text: str, key: str, value: str, label: str, quoted: bool = False) -> str:
    pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
    matches = list(pattern.finditer(text))
    require(len(matches) == 1, f"{label} must contain one {key} assignment")
    rendered = "'" + value + "'" if quoted else value
    replacement = f"{key}={rendered}"
    return text[:matches[0].start()] + replacement + text[matches[0].end():]


def initramfs_defaults(options: argparse.Namespace) -> tuple[Path, Path, Path]:
    kernel_output = absolute(options.kernel_output or DEFAULT_KERNEL, "kernel output")
    accepted = absolute(options.accepted_initramfs or OLD_INITRAMFS, "accepted initramfs")
    guard = absolute(options.guard_script or REPO / "initramfs" / GUARD_NAME,
                     "diagnostic guard script")
    directory(accepted, "accepted initramfs")
    regular(accepted / "init", "accepted initramfs init")
    regular(accepted / "etc/r8q-encryption-manifest.json", "accepted initramfs manifest")
    regular(guard, "diagnostic guard script")
    require(guard.stat().st_mode & 0o111, "diagnostic guard script is not executable")
    return kernel_output, accepted, guard


def guard_helper_defaults(options: argparse.Namespace) -> tuple[Path, dict[str, str]]:
    helper_root = absolute(options.guard_helper or DEFAULT_GUARD_HELPER, "diagnostic guard helper")
    binary = helper_root / GUARD_HELPER_BINARY
    regular(binary, "diagnostic guard helper binary")
    require(binary.stat().st_mode & 0o111, "diagnostic guard helper binary is not executable")
    links: dict[str, str] = {}
    link_root = helper_root / "applet-symlinks"
    directory(link_root, "diagnostic guard helper applets")
    for applet in GUARD_HELPER_LINKS:
        link = link_root / applet
        require(link.is_symlink(), f"diagnostic guard helper applet is not a symlink: {applet}")
        target = os.readlink(link)
        require(target == "../" + GUARD_HELPER_BINARY,
                f"diagnostic guard helper applet target differs: {applet}")
        links[applet] = f"bin/{GUARD_HELPER_BINARY}"
    return binary, links


def guard_helper_metadata(binary: Path, links: dict[str, str]) -> dict[str, Any]:
    return {"path": f"bin/{GUARD_HELPER_BINARY}", "sha256": digest(binary),
            "bytes": binary.stat().st_size, "symlinks": links}


def stage_guard_helper(output: Path, helper_binary: Path) -> list[str]:
    helper_destination = output / "bin" / GUARD_HELPER_BINARY
    require(not helper_destination.exists() and not helper_destination.is_symlink(),
            "accepted initramfs already contains the diagnostic guard helper destination")
    copy_file(helper_binary, helper_destination)
    os.chmod(helper_destination, stat.S_IMODE(helper_binary.stat().st_mode))
    helper_link_paths = []
    for applet in GUARD_HELPER_LINKS:
        destination = output / "bin" / applet
        require(not destination.exists() and not destination.is_symlink(),
                f"accepted initramfs already contains diagnostic helper applet: {applet}")
        destination.symlink_to(GUARD_HELPER_BINARY)
        helper_link_paths.append(destination.relative_to(output).as_posix())
    return helper_link_paths


def guard_hook(nonce: str, tag: str) -> str:
    return "\n".join([
        f"DIAGNOSTIC_GUARD=/{GUARD_DESTINATION}",
        f"DIAGNOSTIC_GUARD_NONCE={nonce!r}",
        f"DIAGNOSTIC_GUARD_TAG={tag!r}",
        f"DIAGNOSTIC_EXPECTED_EFI_SHA256={ACCEPTED_EFI_SHA256!r}",
        f"DIAGNOSTIC_EXPECTED_DTB_SHA256={ACCEPTED_DTB_SHA256!r}",
        "[ -x \"$DIAGNOSTIC_GUARD\" ] || fail_closed diagnostic-guard-missing",
        "\"$DIAGNOSTIC_GUARD\" --nonce \"$DIAGNOSTIC_GUARD_NONCE\" --tag \"$DIAGNOSTIC_GUARD_TAG\" --expected-efi-sha256 \"$DIAGNOSTIC_EXPECTED_EFI_SHA256\" --expected-dtb-sha256 \"$DIAGNOSTIC_EXPECTED_DTB_SHA256\" || fail_closed diagnostic-guard",
        "",
    ])


def prepare_initramfs(options: argparse.Namespace) -> Path:
    kernel_output, accepted, guard = initramfs_defaults(options)
    helper_binary, helper_links = guard_helper_defaults(options)
    helper_metadata = guard_helper_metadata(helper_binary, helper_links)
    stage1 = stage1_manifest(kernel_output)
    module_root = locate_module_root(kernel_output)
    output = safe_output(options.output or DEFAULT_GENERATED / "initramfs")
    nonce = options.guard_nonce or uuid.uuid4().hex
    tag = options.guard_tag or f"r8q-diag1-{nonce}"
    require(re.fullmatch(r"[0-9a-f]{32}", nonce), "guard nonce must be a 32-hex UUID")
    require(re.fullmatch(r"[A-Za-z0-9._-]+", tag) is not None,
            "guard tag is malformed")
    modules = {}
    for name in MODULE_NAMES:
        basename = "i2c-qcom-geni.ko" if name == "i2c_qcom_geni" else f"{name}.ko"
        modules[name] = resolve_module(module_root, name, basename)
    old_records = tree_records(accepted)
    allowed_hashes = {}
    old_module_root = accepted / "lib/modules" / OLD_RELEASE / "r8q-encryption"
    for name, source in modules.items():
        basename = "i2c-qcom-geni.ko" if name == "i2c_qcom_geni" else f"{name}.ko"
        old_path = old_module_root / basename
        regular(old_path, f"accepted {basename}")
        allowed_hashes[basename] = {"old": digest(old_path), "new": digest(source)}
    replacements = {OLD_RELEASE: RELEASE}
    replacements.update({row["old"]: row["new"] for row in allowed_hashes.values()})
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(accepted, output, symlinks=True)
        old_release_dir = output / "lib/modules" / OLD_RELEASE
        new_release_dir = output / "lib/modules" / RELEASE
        require(old_release_dir.exists(), "accepted module release directory is missing")
        require(not new_release_dir.exists(), "candidate module release directory already exists")
        os.rename(old_release_dir, new_release_dir)
        new_module_root = new_release_dir / "r8q-encryption"
        old_module_paths = []
        new_module_paths = []
        for name, source in modules.items():
            basename = "i2c-qcom-geni.ko" if name == "i2c_qcom_geni" else f"{name}.ko"
            old_path = output / "lib/modules" / RELEASE / "r8q-encryption" / basename
            new_path = new_module_root / basename
            old_mode = stat.S_IMODE(old_path.stat().st_mode)
            old_path.unlink()
            copy_file(source, new_path)
            os.chmod(new_path, old_mode)
            old_module_paths.append(f"lib/modules/{OLD_RELEASE}/r8q-encryption/{basename}")
            new_module_paths.append(new_path.relative_to(output).as_posix())
        init_path = output / "init"
        init_text = init_path.read_text(encoding="utf-8")
        mount_pattern = re.compile(r"(?m)^(mount -t tmpfs .* /run 2>/dev/null \|\| fail_closed run-mount)$")
        transformed = replace_text(init_text, replacements, "diagnostic init")
        mount_matches = list(mount_pattern.finditer(transformed))
        require(len(mount_matches) == 1, "accepted init run mount hook point is not unique")
        hook = guard_hook(nonce, tag)
        transformed = transformed[:mount_matches[0].end()] + "\n" + hook + transformed[mount_matches[0].end():]
        init_path.write_text(transformed, encoding="utf-8")
        os.chmod(init_path, stat.S_IMODE((accepted / "init").stat().st_mode))
        guard_destination = output / GUARD_DESTINATION
        require(not guard_destination.exists() and not guard_destination.is_symlink(),
                "accepted initramfs already contains the diagnostic guard destination")
        copy_file(guard, guard_destination)
        os.chmod(guard_destination, stat.S_IMODE(guard.stat().st_mode))
        helper_link_paths = stage_guard_helper(output, helper_binary)
        guard_config = output / "etc/r8q-diagnostic-fallback.conf"
        write_text(guard_config,
                   "schema=r8q-diagnostic-fallback-config/v1\n"
                   f"trial_nonce={nonce}\n"
                   f"trial_tag={tag}\n", 0o644)
        manifest_path = output / "etc/r8q-encryption-manifest.json"
        manifest = read_json(manifest_path, "accepted initramfs manifest")
        require(isinstance(manifest, dict), "accepted initramfs manifest is not an object")
        manifest = replace_json_strings(manifest, replacements)
        manifest["kind"] = "r8q-diagnostic-initramfs-candidate"
        manifest["kernel_release"] = RELEASE
        manifest["diagnostic_guard"] = {
            "path": "/" + GUARD_DESTINATION,
            "config_path": "/etc/r8q-diagnostic-fallback.conf",
            "nonce": nonce,
            "tag": tag,
            "sha256": digest(guard_destination),
            "bytes": guard_destination.stat().st_size,
            "api": "r8q-diagnostic-fallback/v1",
            "hook": "after proc/sys/dev/run mounts and before udev and PIN entry",
            "accepted_efi_sha256": ACCEPTED_EFI_SHA256,
            "accepted_dtb_sha256": ACCEPTED_DTB_SHA256,
            "helper": helper_metadata,
        }
        manifest["stage1"] = {"path": str(kernel_output / "stage1-manifest.json"),
                              "manifest_sha256": digest(kernel_output / "stage1-manifest.json"),
                              "kernel_release": stage1["kernel_release"]}
        files = {}
        for relative, row in sorted(tree_records(output).items()):
            if relative == "etc/r8q-encryption-manifest.json" or row["type"] != "file":
                continue
            files[relative] = {"source": relative, "sha256": row["sha256"],
                               "size": row["bytes"], "bytes": row["bytes"],
                               "mode": row["mode"], "kind": "runtime-file"}
        files["init"]["kind"] = "generated-diagnostic-init"
        for name, source in modules.items():
            basename = "i2c-qcom-geni.ko" if name == "i2c_qcom_geni" else f"{name}.ko"
            relative = f"lib/modules/{RELEASE}/r8q-encryption/{basename}"
            files[relative].update({"kind": "kernel-module", "module_name": name,
                                    "vermagic": VERMAGIC})
        manifest["files"] = dict(sorted(files.items()))
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(manifest_path, stat.S_IMODE((accepted / "etc/r8q-encryption-manifest.json").stat().st_mode))
        after_records = tree_records(output)
        allowed = set(old_module_paths) | set(new_module_paths) | {
            "lib/modules/" + OLD_RELEASE,
            "lib/modules/" + OLD_RELEASE + "/r8q-encryption",
            "lib/modules/" + RELEASE,
            "lib/modules/" + RELEASE + "/r8q-encryption",
            "init", GUARD_DESTINATION, "etc/r8q-diagnostic-fallback.conf",
            "bin", f"bin/{GUARD_HELPER_BINARY}", *helper_link_paths,
            "etc/r8q-encryption-manifest.json",
        }
        audit_tree(accepted, output, old_records, after_records, allowed,
                   (f"lib/modules/{OLD_RELEASE}/", f"lib/modules/{RELEASE}/"))
        identity = {
            "schema": "r8q-diagnostic-runtime-identity/v1",
            "kind": "initramfs",
            "accepted_tree": str(accepted),
            "candidate_tree": str(output),
            "unchanged_records": len([path for path in old_records if path in after_records and old_records[path] == after_records[path]]),
            "unchanged_files": len([path for path in old_records
                                    if old_records[path].get("type") == "file"
                                    and path in after_records
                                    and old_records[path] == after_records[path]]),
            "accepted_file_count": len(old_records),
            "candidate_file_count": len(after_records),
            "allowed_changes": sorted(allowed),
            "new_module_hashes": {name: digest(path) for name, path in modules.items()},
        }
        write_json(output.parent / PROVENANCE_NAME, {
            "schema": "r8q-diagnostic-runtime-provenance/v1",
            "mode": "initramfs",
            "accepted_efi_sha256": ACCEPTED_EFI_SHA256,
            "accepted_dtb_sha256": ACCEPTED_DTB_SHA256,
            "stage1_manifest": str(kernel_output / "stage1-manifest.json"),
            "stage1_manifest_sha256": digest(kernel_output / "stage1-manifest.json"),
            "guard": {"source": str(guard), "sha256": digest(guard), "nonce": nonce, "tag": tag},
            "helper": {"source": str(helper_binary), **helper_metadata},
            "modules": {name: module_identity(path, name) for name, path in modules.items()},
            "identity": identity,
        })
        write_json(output.parent / CONFIG_DELTA_NAME, {
            "schema": "r8q-diagnostic-runtime-config-delta/v1",
            "mode": "initramfs",
            "old_release": OLD_RELEASE,
            "new_release": RELEASE,
            "accepted_efi_sha256": ACCEPTED_EFI_SHA256,
            "accepted_dtb_sha256": ACCEPTED_DTB_SHA256,
            "changed_paths": sorted(allowed),
            "expected_unchanged_files": identity["unchanged_files"],
            "guard_api": "r8q-diagnostic-fallback/v1",
            "guard_helper": helper_metadata,
        })
        return output
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise


def replace_json_strings(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        result = value
        for old, new in replacements.items():
            result = result.replace(old, new)
        return result
    if isinstance(value, list):
        return [replace_json_strings(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: replace_json_strings(item, replacements) for key, item in value.items()}
    return value


def audit_tree(source_root: Path, candidate_root: Path, source: dict[str, Any],
               candidate: dict[str, Any], allowed: set[str], allowed_prefixes: tuple[str, ...] = ()) -> None:
    for relative, source_row in source.items():
        if relative in allowed or any(relative.startswith(prefix) for prefix in allowed_prefixes):
            continue
        require(relative in candidate, f"candidate removed unapproved accepted path: {relative}")
        require(candidate[relative] == source_row,
                f"candidate changed unapproved accepted path: {relative}")
    for relative in candidate:
        if relative in source:
            continue
        require(relative in allowed or any(relative.startswith(prefix) for prefix in allowed_prefixes),
                f"candidate added unapproved path: {relative}")


def hardware_defaults(options: argparse.Namespace) -> tuple[Path, Path]:
    kernel_output = absolute(options.kernel_output or DEFAULT_KERNEL, "kernel output")
    accepted_rootfs = absolute(options.accepted_hardware_rootfs or OLD_HARDWARE / "rootfs",
                               "accepted hardware rootfs")
    directory(accepted_rootfs, "accepted hardware rootfs")
    regular(accepted_rootfs / OLD_PROFILE_REL / "usr/local/sbin/r8q-kernel-profile-dispatch",
            "accepted v2 dispatcher")
    regular(accepted_rootfs / "usr/lib/modules" / OLD_RELEASE / "modules.order",
            "accepted v2 modules.order")
    return kernel_output, accepted_rootfs


def load_hardware_selection(accepted_rootfs: Path) -> tuple[list[str], list[dict[str, Any]], dict[str, Any]]:
    manifest_path = accepted_rootfs.parent / "bundle-manifest.json"
    regular(manifest_path, "accepted hardware bundle manifest")
    manifest = read_json(manifest_path, "accepted hardware bundle manifest")
    selection = manifest.get("module_selection") if isinstance(manifest, dict) else None
    require(isinstance(selection, dict), "accepted bundle lacks module selection")
    names = selection.get("selected_names")
    rows = selection.get("module_rows")
    require(isinstance(names, list) and len(names) == 78,
            "accepted module selection is not the reviewed 78-module closure")
    require(all(isinstance(name, str) for name in names) and len(set(names)) == 78,
            "accepted module selection contains duplicate or malformed names")
    require(isinstance(rows, list) and len(rows) == 42,
            "accepted module rows are not the reviewed global closure")
    return names, rows, manifest


def profile_module_files(profile: Path) -> list[Path]:
    result = []
    for path in sorted(profile.rglob("*.ko")):
        require(not path.is_symlink() and path.is_file(), f"accepted profile module is not regular: {path}")
        result.append(path)
    require(result, "accepted v2 profile has no private modules")
    return result


def profile_text_replacements(old_profile: Path, new_profile: Path,
                              module_hashes: dict[str, tuple[str, str]]) -> None:
    for current, directories, files in os.walk(old_profile, topdown=True, followlinks=False):
        current_path = Path(current)
        old_relative = current_path.relative_to(old_profile).as_posix()
        new_relative = old_relative.replace(OLD_RELEASE, RELEASE)
        target_dir = new_profile / new_relative
        target_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(target_dir, stat.S_IMODE(current_path.stat().st_mode))
        for name in sorted(files):
            source = current_path / name
            target = target_dir / name
            info = source.lstat()
            require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                    f"accepted profile contains unsupported file: {source}")
            if source.suffix == ".ko":
                continue
            if source.relative_to(old_profile).as_posix() == "usr/local/sbin/r8q-kernel-profile-dispatch":
                continue
            data = source.read_bytes()
            if b"\x00" in data:
                target.write_bytes(data)
            else:
                text = data.decode("utf-8")
                replacements = {OLD_RELEASE: RELEASE}
                replacements.update({old: new for old, new in module_hashes.values()})
                target.write_text(replace_text(text, replacements, str(source)), encoding="utf-8")
            os.chmod(target, stat.S_IMODE(info.st_mode))


def profile_dispatcher() -> str:
    prefix = "/usr/local/lib/r8q-kernel-profiles"
    v2 = f"{prefix}/{OLD_RELEASE}/rootfs/usr/local/sbin/r8q-kernel-profile-dispatch"
    diag = f"{prefix}/{RELEASE}/rootfs"
    lines = [
        "#!/bin/sh", "set -eu", "test \"$#\" -ge 1 || { echo 'r8q-kernel-profile-dispatch: missing action' >&2; exit 2; }",
        "ACTION=$1", "shift", f"V2_DISPATCH={v2}",
        f"case \"$(/usr/bin/uname -r)\" in", f"    {OLD_RELEASE}|7.1.2-r8q-rtc2) exec \"$V2_DISPATCH\" \"$ACTION\" \"$@\" ;;",
        f"    {RELEASE}) ;;", "    *) echo 'r8q-kernel-profile-dispatch: unsupported kernel release' >&2; exit 1 ;;", "esac",
        "case \"$ACTION\" in",
        f"    route) TARGET={diag}/usr/local/sbin/r8q-usb-route-up.sh ;;",
        f"    battery) TARGET={diag}/usr/local/sbin/r8q-battery-up.sh ;;",
        f"    gadget) TARGET={diag}/usr/local/sbin/r8q-usb-gadget-up.sh ;;",
        f"    audio-load) TARGET={diag}/opt/r8q-audio/{RELEASE}/load-r8q-audio.sh ;;",
        f"    audio-init) TARGET={diag}/opt/r8q-audio/{RELEASE}/init-r8q-audio.sh ;;",
        f"    wifi-standby) TARGET={diag}/usr/local/sbin/r8q-wifi-standby.py ;;",
        "    *) echo \"r8q-kernel-profile-dispatch: unknown action: $ACTION\" >&2; exit 2 ;;", "esac",
        "test -f \"$TARGET\" && test ! -L \"$TARGET\" || { echo \"r8q-kernel-profile-dispatch: target unavailable: $TARGET\" >&2; exit 1; }",
        "case \"$ACTION\" in", "    wifi-standby) exec /usr/bin/python3 \"$TARGET\" \"$@\" ;;", "    *) exec \"$TARGET\" \"$@\" ;;", "esac", "",
    ]
    return "\n".join(lines)


def dispatch_dropins() -> dict[str, str]:
    target = f"/usr/local/lib/r8q-kernel-profiles/{RELEASE}/rootfs/usr/local/sbin/r8q-kernel-profile-dispatch"
    return {
        "etc/systemd/system/r8q-hardware-prepare.service.d/95-r8q-diag1-dispatch.conf": f"[Service]\nExecStart=\nExecStart={target} route\n",
        "etc/systemd/system/r8q-battery.service.d/95-r8q-diag1-dispatch.conf": f"[Service]\nExecStart=\nExecStart={target} battery\n",
        "etc/systemd/system/r8q-usb-gadget.service.d/95-r8q-diag1-dispatch.conf": f"[Service]\nExecStart=\nExecStart={target} gadget\n",
        "etc/systemd/system/r8q-audio-start.service.d/95-r8q-diag1-dispatch.conf": f"[Service]\nExecStart=\nExecStart={target} audio-load\nExecStartPost=\nExecStartPost={target} audio-init\n",
        "etc/systemd/system/r8q-wifi-standby.service.d/95-r8q-diag1-dispatch.conf": f"[Service]\nExecStart=\nExecStart={target} wifi-standby\nExecStopPost=\nExecStopPost={target} wifi-standby --restore-off\n",
    }


def profile_assignment(text: str, key: str, label: str) -> str:
    matches = list(re.finditer(rf"(?m)^{re.escape(key)}=(.*)$", text))
    require(len(matches) == 1, f"{label} must contain one {key} assignment")
    value = matches[0].group(1).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    require(value and "\n" not in value and "\r" not in value,
            f"{label} has an empty {key} assignment")
    return value


def audit_prepared_profile(profile: Path) -> dict[str, Any]:
    directory(profile, "prepared diagnostic profile")
    dispatcher = profile / "usr/local/sbin/r8q-kernel-profile-dispatch"
    regular(dispatcher, "prepared diagnostic dispatcher")
    dispatcher_text = dispatcher.read_text(encoding="utf-8")
    target_relatives = (
        "usr/local/sbin/r8q-usb-route-up.sh",
        "usr/local/sbin/r8q-battery-up.sh",
        "usr/local/sbin/r8q-usb-gadget-up.sh",
        f"opt/r8q-audio/{RELEASE}/load-r8q-audio.sh",
        f"opt/r8q-audio/{RELEASE}/init-r8q-audio.sh",
        "usr/local/sbin/r8q-wifi-standby.py",
    )
    absolute_prefix = f"/usr/local/lib/r8q-kernel-profiles/{RELEASE}/rootfs/"
    for relative in target_relatives:
        target = profile / relative
        regular(target, f"prepared dispatcher target {relative}")
        require(not target.is_symlink(), f"prepared dispatcher target is a symlink: {relative}")
        require(absolute_prefix + relative in dispatcher_text,
                f"prepared dispatcher target is not bound: {relative}")
    route_env = profile / "etc/r8q-usb-route.env"
    regular(route_env, "prepared USB route environment")
    route_text = route_env.read_text(encoding="utf-8")
    helper = profile / "usr/local/sbin/r8q-usb-route-ensure.sh"
    protocol = profile / "usr/local/lib/r8q-usb-route/protocol-binding.env"
    regular(helper, "prepared USB route helper")
    regular(protocol, "prepared USB route protocol")
    require(profile_assignment(route_text, "EXPECTED_HELPER_SHA256", str(route_env)) == digest(helper),
            "prepared USB route helper checksum differs")
    require(profile_assignment(route_text, "EXPECTED_PROTOCOL_SHA256", str(route_env)) == digest(protocol),
            "prepared USB route protocol checksum differs")
    battery_dir = profile / f"usr/local/lib/r8q-battery/{RELEASE}"
    battery_script = profile / "usr/local/sbin/r8q-battery-up.sh"
    battery_text = battery_script.read_text(encoding="utf-8")
    battery_modules = {
        "MAX17042_SHA256": battery_dir / "max17042_battery.ko",
        "MAX77705_SHA256": battery_dir / "max77705.ko",
        "MAX77705_CHARGER_SHA256": battery_dir / "max77705_charger.ko",
    }
    for key, path in battery_modules.items():
        regular(path, f"prepared battery module {path.name}")
        require(profile_assignment(battery_text, key, str(battery_script)) == digest(path),
                f"prepared battery checksum differs: {path.name}")
    audio_dir = profile / f"opt/r8q-audio/{RELEASE}"
    audio_hashes = audio_dir / "module-hashes.sha256"
    audio_order = audio_dir / "module-load-order.tsv"
    regular(audio_hashes, "prepared audio module hashes")
    regular(audio_order, "prepared audio module order")
    hash_rows = audio_hashes.read_text(encoding="utf-8").splitlines()
    require(hash_rows, "prepared audio module hashes are empty")
    for line in hash_rows:
        fields = line.split()
        require(len(fields) == 2 and re.fullmatch(r"[0-9a-f]{64}", fields[0]) and
                Path(fields[1]).name == fields[1],
                "prepared audio module hash row is malformed")
        module_path = audio_dir / fields[1]
        regular(module_path, f"prepared audio module {fields[1]}")
        require(digest(module_path) == fields[0],
                f"prepared audio module checksum differs: {fields[1]}")
    order_rows = audio_order.read_text(encoding="utf-8").splitlines()
    require(order_rows and order_rows[0].split("\t")[:2] == ["order", "module"],
            "prepared audio module order header is malformed")
    for line in order_rows[1:]:
        if not line.strip():
            continue
        fields = line.split("\t")
        require(len(fields) >= 5 and re.fullmatch(r"[0-9a-f]{64}", fields[3]) and
                Path(fields[4]).name == fields[4],
                "prepared audio module order row is malformed")
        module_path = audio_dir / fields[4]
        regular(module_path, f"prepared ordered audio module {fields[4]}")
        require(digest(module_path) == fields[3],
                f"prepared ordered audio checksum differs: {fields[4]}")
    for script_name in ("load-r8q-audio.sh", "init-r8q-audio.sh"):
        script = audio_dir / script_name
        regular(script, f"prepared audio script {script_name}")
        script_text = script.read_text(encoding="utf-8")
        require(f"EXPECTED_RELEASE={RELEASE}" in script_text or
                f"= {RELEASE}" in script_text,
                f"prepared audio script release differs: {script_name}")
    return {
        "schema": "r8q-diagnostic-profile-reference-audit/v1",
        "dispatcher_targets": list(target_relatives),
        "route_hashes": {"helper": digest(helper), "protocol": digest(protocol)},
        "battery_hashes": {key: digest(path) for key, path in battery_modules.items()},
        "audio_hashes": {line.split()[1]: line.split()[0] for line in hash_rows},
        "audio_order_hashes": {line.split("\t")[4]: line.split("\t")[3]
                               for line in order_rows[1:] if line.strip()},
    }


def prepare_hardware(options: argparse.Namespace) -> Path:
    kernel_output, accepted_rootfs = hardware_defaults(options)
    stage1 = stage1_manifest(kernel_output)
    module_root = locate_module_root(kernel_output)
    names, rows, accepted_manifest = load_hardware_selection(accepted_rootfs)
    output = safe_output(options.output or DEFAULT_GENERATED / "runtime-preparation")
    old_records = tree_records(accepted_rootfs)
    source_modules = {name: resolve_module(module_root, name) for name in names}
    old_profile = accepted_rootfs / OLD_PROFILE_REL
    private_old = profile_module_files(old_profile)
    private_new = {}
    for old_path in private_old:
        expected_name = old_path.stem.replace("-", "_")
        old_relative = old_path.relative_to(old_profile).as_posix()
        new_relative = old_relative.replace(OLD_RELEASE, RELEASE)
        require(new_relative != old_relative,
                f"accepted private module path lacks its release namespace: {old_path}")
        private_new[new_relative] = resolve_module(module_root, expected_name, old_path.name)
    module_hashes = {}
    for relative, new_path in private_new.items():
        old_path = old_profile / relative.replace(RELEASE, OLD_RELEASE)
        module_hashes[relative] = (digest(old_path), digest(new_path))
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        rootfs = output / "rootfs"
        shutil.copytree(accepted_rootfs, rootfs, symlinks=True)
        new_profile = rootfs / NEW_PROFILE_REL
        profile_text_replacements(old_profile, new_profile, module_hashes)
        for relative, new_path in private_new.items():
            target = new_profile / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_file(new_path, target)
            old_relative = relative.replace(RELEASE, OLD_RELEASE)
            os.chmod(target, stat.S_IMODE((old_profile / old_relative).stat().st_mode))
        dispatcher = new_profile / "usr/local/sbin/r8q-kernel-profile-dispatch"
        dispatcher.write_text(profile_dispatcher(), encoding="utf-8")
        os.chmod(dispatcher, stat.S_IMODE((old_profile / "usr/local/sbin/r8q-kernel-profile-dispatch").stat().st_mode))
        module_env = new_profile / "etc/r8q-usb-route.env"
        env_text = module_env.read_text(encoding="utf-8")
        route_gpi = digest(source_modules["gpi"])
        route_geni = digest(source_modules["i2c_qcom_geni"])
        env_text = replace_line(env_text, "EXPECTED_GPI_SHA256", route_gpi, str(module_env))
        env_text = replace_line(env_text, "EXPECTED_GENI_SHA256", route_geni, str(module_env))
        helper_path = new_profile / "usr/local/sbin/r8q-usb-route-ensure.sh"
        protocol_path = new_profile / "usr/local/lib/r8q-usb-route/protocol-binding.env"
        env_text = replace_line(env_text, "EXPECTED_HELPER_SHA256", digest(helper_path), str(module_env))
        env_text = replace_line(env_text, "EXPECTED_PROTOCOL_SHA256", digest(protocol_path), str(module_env))
        module_env.write_text(env_text, encoding="utf-8")
        os.chmod(module_env, stat.S_IMODE((old_profile / "etc/r8q-usb-route.env").stat().st_mode))
        profile_audit = audit_prepared_profile(new_profile)
        module_root_output = rootfs / MODULE_ROOT_REL
        generic_rows = [row for row in rows if isinstance(row, dict) and row.get("namespace") in {"generic", "route-private"}]
        require(generic_rows, "accepted module selection contains no global module rows")
        require({"gpi", "i2c_qcom_geni"} <= set(source_modules),
                "accepted module selection lacks the reviewed route modules")
        destination_rows = []
        destination_names = []
        for row in generic_rows:
            name = row.get("name")
            destination = row.get("destination")
            require(isinstance(name, str) and isinstance(destination, str), "accepted module row is malformed")
            require(name in source_modules, f"accepted module row is outside selected names: {name}")
            destination = safe_relative(destination, "module destination")
            target = module_root_output / destination
            copy_file(source_modules[name], target)
            os.chmod(target, 0o664)
            destination_rows.append(destination)
            destination_names.append(name)
        require(len(destination_rows) == len(set(destination_rows)),
                "accepted module rows contain duplicate destinations")
        require(len(destination_names) == len(set(destination_names)),
                "accepted module rows contain duplicate module names")
        builtin_files = []
        for filename in ("modules.builtin", "modules.builtin.modinfo"):
            source = module_root / filename
            regular(source, f"diag1 catalogue {filename}")
            target = module_root_output / filename
            copy_file(source, target)
            builtin_files.append(filename)
        write_text(module_root_output / "modules.order", "\n".join(destination_rows) + "\n", 0o664)
        depmod_records = run_depmod(rootfs, module_root_output)
        direct_names = sorted({row["name"] for row in generic_rows if isinstance(row.get("name"), str)})
        modprobe_plans = audit_modprobe(rootfs, module_root_output, direct_names)
        dropins = dispatch_dropins()
        for relative, content in dropins.items():
            target = rootfs / relative
            require(not target.exists() and not target.is_symlink(), f"diag1 drop-in already exists: {target}")
            write_text(target, content, 0o644)
        after_records = tree_records(rootfs)
        allowed_prefixes = (NEW_PROFILE_REL + "/", MODULE_ROOT_REL + "/")
        allowed = set(dropins) | {
            NEW_PROFILE_RELEASE_REL,
            NEW_PROFILE_REL,
            str(Path(MODULE_ROOT_REL).parent),
            MODULE_ROOT_REL,
        }
        audit_tree(accepted_rootfs, rootfs, old_records, after_records, allowed, allowed_prefixes)
        identity = {
            "schema": "r8q-diagnostic-runtime-identity/v1",
            "kind": "hardware",
            "accepted_tree": str(accepted_rootfs),
            "candidate_tree": str(rootfs),
            "accepted_file_count": len(old_records),
            "candidate_file_count": len(after_records),
            "unchanged_records": len([path for path in old_records if path in after_records and old_records[path] == after_records[path]]),
            "unchanged_files": len([path for path in old_records
                                    if old_records[path].get("type") == "file"
                                    and path in after_records
                                    and old_records[path] == after_records[path]]),
            "new_profile": NEW_PROFILE_REL,
            "new_module_root": MODULE_ROOT_REL,
            "profile_reference_audit": profile_audit,
            "allowed_additions": sorted(allowed),
            "allowed_prefixes": list(allowed_prefixes),
            "protected_baseline_policy": "all accepted paths are byte/mode/symlink identical unless under the new diag1 namespaces",
        }
        package_files = records_with_provenance(rootfs, accepted_rootfs)
        write_json(output / MANIFEST_NAME, {
            "schema": "r8q-diagnostic-runtime-preparation/v1",
            "kind": "r8q-diagnostic-hardware-preparation",
            "kernel_release": RELEASE,
            "vermagic": VERMAGIC,
            "accepted_release": OLD_RELEASE,
            "phone_operations": False,
            "accepted_efi_sha256": ACCEPTED_EFI_SHA256,
            "accepted_dtb_sha256": ACCEPTED_DTB_SHA256,
            "stage1_manifest": {"path": str(kernel_output / "stage1-manifest.json"),
                                "sha256": digest(kernel_output / "stage1-manifest.json")},
            "module_selection": {"accepted_count": len(names), "accepted_names": names,
                                 "global_rows": generic_rows, "depmod": depmod_records,
                                 "modprobe_plans": modprobe_plans,
                                 "builtin_metadata": builtin_files},
            "private_modules": {relative: module_identity(path, path.stem.replace("-", "_"))
                                for relative, path in private_new.items()},
            "identity": identity,
            "files": package_files,
        })
        write_json(output / PROVENANCE_NAME,
                   hardware_provenance(accepted_rootfs, kernel_output, module_root,
                                       names, source_modules, identity))
        write_json(output / CONFIG_DELTA_NAME, {
            "schema": "r8q-diagnostic-runtime-config-delta/v1",
            "mode": "hardware",
            "old_release": OLD_RELEASE,
            "new_release": RELEASE,
            "new_profile": NEW_PROFILE_REL,
            "new_module_root": MODULE_ROOT_REL,
            "new_dropins": sorted(dropins),
            "old_dropins_untouched": True,
            "protected_files_untouched": True,
            "expected_unchanged_records": identity["unchanged_records"],
            "expected_unchanged_files": identity["unchanged_files"],
            "accepted_module_selection_count": len(names),
            "profile_reference_audit": profile_audit,
        })
        with (output / PACKAGE_HASHES_NAME).open("w", encoding="utf-8") as stream:
            for row in package_files:
                if row["type"] == "file":
                    stream.write(f"{row['sha256']}  rootfs/{row['path']}\n")
        return output
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise


def run_depmod(rootfs: Path, module_root: Path) -> list[dict[str, Any]]:
    tool = shutil.which("depmod") or "/usr/sbin/depmod"
    require(Path(tool).is_file(), "existing depmod tool is required")
    result = subprocess.run([tool, "-b", str(rootfs), "-m", "/usr/lib/modules", RELEASE],
                            capture_output=True, text=True, check=False)
    diagnostics = (result.stdout + result.stderr).strip()
    require(result.returncode == 0, f"depmod failed: {diagnostics or 'no diagnostics'}")
    bad = [line for line in diagnostics.splitlines() if re.search(r"error|fatal|warning|missing|not found", line, re.I)]
    require(not bad, "depmod reported a curated closure issue: " + " | ".join(bad))
    result_rows = []
    for path in sorted(module_root.iterdir()):
        if path.is_file() and path.name.startswith("modules."):
            result_rows.append({"path": path.name, "bytes": path.stat().st_size, "sha256": digest(path)})
    required = {"modules.order", "modules.dep", "modules.dep.bin", "modules.alias", "modules.alias.bin",
                "modules.builtin", "modules.builtin.modinfo", "modules.symbols", "modules.symbols.bin"}
    require(required <= {row["path"] for row in result_rows}, "depmod did not emit all required indexes")
    return result_rows


def audit_modprobe(rootfs: Path, module_root: Path, names: list[str]) -> list[dict[str, Any]]:
    tool = shutil.which("modprobe") or "/usr/sbin/modprobe"
    require(Path(tool).is_file(), "existing modprobe tool is required")
    compatibility = rootfs / "lib"
    require(not compatibility.exists() and not compatibility.is_symlink(),
            "curated rootfs unexpectedly contains /lib")
    compatibility.mkdir()
    link = compatibility / "modules"
    link.symlink_to(Path("../usr/lib/modules"))
    plans = []
    try:
        for name in names:
            result = subprocess.run([tool, "-d", str(rootfs), "-S", RELEASE, "--show-depends", name],
                                    capture_output=True, text=True, check=False)
            diagnostics = (result.stdout + result.stderr).strip()
            require(result.returncode == 0, f"modprobe plan failed for {name}: {diagnostics}")
            modules = []
            for line in result.stdout.splitlines():
                fields = line.split()
                require(len(fields) >= 2 and fields[0] == "insmod", f"unreviewed modprobe plan: {line!r}")
                candidate = Path(fields[1]).resolve()
                require(module_root.resolve() in candidate.parents, f"modprobe escaped diag1 tree for {name}: {candidate}")
                regular(candidate, f"modprobe plan {name}")
                modules.append(candidate.relative_to(rootfs.resolve()).as_posix())
            require(modules, f"modprobe plan is empty for {name}")
            plans.append({"module": name, "command": ["modprobe", "-d", "<staged-rootfs>", "-S", RELEASE, "--show-depends", name], "modules": modules})
    finally:
        link.unlink()
        compatibility.rmdir()
    return plans


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--initramfs", action="store_true")
    modes.add_argument("--hardware", action="store_true")
    parser.add_argument("--kernel-output", type=Path)
    parser.add_argument("--accepted-initramfs", type=Path)
    parser.add_argument("--accepted-hardware-rootfs", type=Path)
    parser.add_argument("--guard-script", type=Path)
    parser.add_argument("--guard-helper", type=Path)
    parser.add_argument("--guard-nonce")
    parser.add_argument("--guard-tag")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        options = parse_args(argv or sys.argv[1:])
        result = prepare_initramfs(options) if options.initramfs else prepare_hardware(options)
        print(json.dumps({"result": "PASS", "output": str(result), "release": RELEASE}, sort_keys=True))
        return 0
    except (PreparationError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"prepare-r8q-diagnostic-runtime: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
