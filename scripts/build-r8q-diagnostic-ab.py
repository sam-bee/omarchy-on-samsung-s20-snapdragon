#!/usr/bin/env python3
"""Prepare and verify a host-only pseudo-NMI A/B diagnostic candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any


REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"
CANONICAL = OUT / "diagnostic-kernel-20261020" / "kernel"
OUTPUT = OUT / "diagnostic-ab-20261020" / "kernel"
ACCEPTED_BASE = OUT / "waydroid-encrypted-20261015" / "kernel"
SOURCE = OUT / "waydroid-kernel-20261013" / "source"
RUNTIME = OUT / "diagnostic-kernel-20261020" / "initramfs"
RUNTIME_PROVENANCE = OUT / "diagnostic-kernel-20261020" / "provenance.json"
FINALIZER = REPO / "scripts" / "finalize-r8q-diagnostic-candidate.py"
RELEASE = "7.1.2-r8q-diag1"
SOURCE_SHA256 = "04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b"
EFI_SHA256 = "f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b"
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
GUARD_NONCE = "840120923183418993f4a3584c558310"
GUARD_TAG = "r8q-diag1-840120923183418993f4a3584c558310"
CMDLINE_TOKEN = "irqchip.gicv3_pseudo_nmi"
AB_CANDIDATE_KIND = "r8q-diagnostic-ab-candidate"
AB_PREPARATION_KIND = "r8q-diagnostic-ab-preparation-nondeployable"
MODULE_ROOT = "modules"
PRESERVED_RELATIVE = (
    "acceptedv2.config",
    "stage1-before-finalization.config",
    "stage1-before-finalization.json",
    "stage1-manifest.json",
    "temporary-accepted-encrypted-initramfs.cpio",
    "active-dtb.R8Q-RTC.DTB",
    "payload/R8Q-RTC.DTB",
    "usr/initramfs_data.cpio",
    "usr/initramfs_inc_data",
    "include/config/kernel.release",
)
GENERATED_RELATIVE = (
    "candidate-manifest.json",
    "embedded-initramfs-manifest.json",
    "ab-candidate-manifest.json",
    "ab-preparation-manifest.json",
    "ab-verification-manifest.json",
    "ab-make-env.json",
    "ab-config-delta.json",
)


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


def script_digest() -> str:
    return digest(Path(__file__).resolve())


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"Unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finalizer_module() -> Any:
    module = load_module(FINALIZER, "r8q_ab_finalizer")
    return module


def source_proof() -> dict[str, Any]:
    rules = load_module(REPO / "scripts" / "prepare-waydroid-kernel-source.py", "r8q_ab_source_rules")
    proof = rules.verify_complete_source_tree(SOURCE)
    require(proof.get("sha256") == SOURCE_SHA256, "Pinned complete source identity differs")
    return proof


def decode_config_string(value: str, label: str) -> str:
    require(value.startswith('"') and value.endswith('"'), f"{label} is not quoted")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label} is not valid JSON: {exc}") from exc
    require(isinstance(decoded, str), f"{label} is not a string")
    return decoded


def replace_pseudo_nmi_token(cmdline: str, enabled: bool) -> str:
    desired = f"{CMDLINE_TOKEN}={'1' if enabled else '0'}"
    opposite = f"{CMDLINE_TOKEN}={'0' if enabled else '1'}"
    tokens = cmdline.split()
    require(tokens.count(opposite) == 1, "cmdline pseudo-NMI token is not exactly one expected source token")
    require(tokens.count(desired) == 0, "cmdline pseudo-NMI token already has the requested value")
    replacement = [desired if token == opposite else token for token in tokens]
    require(replacement.count(desired) == 1, "cmdline pseudo-NMI replacement is not unique")
    return " ".join(replacement)


def config_diff(before: dict[str, str], after: dict[str, str]) -> dict[str, dict[str, str]]:
    return {
        key: {"before": before.get(key, "n"), "after": after.get(key, "n")}
        for key in sorted(before.keys() | after.keys())
        if before.get(key, "n") != after.get(key, "n")
    }


def validate_ab_config(canonical_path: Path, ab_path: Path) -> dict[str, Any]:
    canonical = config(canonical_path)
    candidate = config(ab_path)
    delta = config_diff(canonical, candidate)
    require(set(delta) == {"CONFIG_CMDLINE"}, "AB config differs in more than CONFIG_CMDLINE")
    canonical_cmdline = decode_config_string(canonical.get("CONFIG_CMDLINE", ""), "canonical CONFIG_CMDLINE")
    candidate_cmdline = decode_config_string(candidate.get("CONFIG_CMDLINE", ""), "AB CONFIG_CMDLINE")
    expected_cmdline = replace_pseudo_nmi_token(canonical_cmdline, False)
    require(candidate_cmdline == expected_cmdline, "AB CONFIG_CMDLINE is not the exact pseudo-NMI=0 replacement")
    canonical_tokens = canonical_cmdline.split()
    candidate_tokens = candidate_cmdline.split()
    require(len(canonical_tokens) == len(candidate_tokens), "AB cmdline token count differs")
    require([token for token in canonical_tokens if token != f"{CMDLINE_TOKEN}=1"] ==
            [token for token in candidate_tokens if token != f"{CMDLINE_TOKEN}=0"],
            "AB cmdline contains an unrelated token change")
    for key in ("CONFIG_LOCALVERSION", "CONFIG_INITRAMFS_SOURCE", "CONFIG_CC_VERSION_TEXT",
                "CONFIG_GCC_VERSION", "CONFIG_CLANG_VERSION", "CONFIG_LD_VERSION",
                "CONFIG_LLD_VERSION"):
        require(candidate.get(key) == canonical.get(key), f"AB config identity differs: {key}")
    return {"delta": delta, "canonical": canonical, "candidate": candidate,
            "canonical_cmdline": canonical_cmdline, "candidate_cmdline": candidate_cmdline}


def module_records(root: Path) -> dict[str, dict[str, Any]]:
    directory(root, "module tree")
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if stat.S_ISLNK(metadata.st_mode):
            records[relative] = {"type": "symlink", "mode": mode, "target": os.readlink(path)}
        elif stat.S_ISREG(metadata.st_mode):
            records[relative] = {"type": "file", "mode": mode, "bytes": metadata.st_size,
                                 "sha256": digest(path)}
        else:
            raise SystemExit(f"Unsupported module tree node: {path}")
    return records


def validate_module_inventory() -> dict[str, Any]:
    canonical_records = module_records(CANONICAL / MODULE_ROOT)
    candidate_records = module_records(OUTPUT / MODULE_ROOT)
    require(candidate_records == canonical_records, "AB complete module inventory differs")
    stage = read_json(CANONICAL / "stage1-before-finalization.json", "canonical stage1 identity")
    expected = stage.get("module_records")
    require(isinstance(expected, dict), "canonical stage1 module inventory is missing")
    require(canonical_records == expected, "canonical module tree differs from stage1 bindings")
    return {"count": len(candidate_records), "records": candidate_records,
            "sha256": hashlib.sha256(json.dumps(candidate_records, sort_keys=True).encode()).hexdigest()}


def compare_bytes(canonical_path: Path, candidate_path: Path, label: str) -> None:
    regular(canonical_path, f"canonical {label}")
    regular(candidate_path, f"AB {label}")
    require(digest(canonical_path) == digest(candidate_path) and
            canonical_path.stat().st_size == candidate_path.stat().st_size,
            f"AB {label} differs from canonical")


def validate_compiled_cmdline(canonical_data: bytes, candidate_data: bytes,
                              canonical_cmdline: str, candidate_cmdline: str) -> None:
    canonical_bytes = canonical_cmdline.encode() + b"\0"
    candidate_bytes = candidate_cmdline.encode() + b"\0"
    require(canonical_data.count(canonical_bytes) == 3,
            "canonical Image does not contain exactly three full compiled cmdlines")
    require(candidate_data.count(candidate_bytes) == 3,
            "AB Image does not contain exactly three full compiled cmdlines")
    require(candidate_data.count(canonical_bytes) == 0,
            "AB Image still contains the canonical pseudo-NMI=1 cmdline")
    require(canonical_data.count(candidate_bytes) == 0,
            "canonical Image contains the AB pseudo-NMI=0 cmdline")


def extract_build_identity(vmlinux: Path) -> dict[str, str]:
    regular(vmlinux, "vmlinux build identity")
    strings_tool = shutil.which("strings")
    require(strings_tool is not None, "Required existing tool missing: strings")
    output = subprocess.check_output([strings_tool, "-a", str(vmlinux)], text=True, errors="replace")
    pattern = re.compile(
        r"^Linux version (?P<release>[^ ]+) \((?P<user>[^@()]+)@(?P<host>[^)]+)\) "
        r"\((?P<compiler>[^,]+), (?P<linker>[^)]+)\) #(?P<version>\d+) .*?"
        r"(?P<timestamp>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) .+)$"
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            return match.groupdict()
    raise SystemExit(f"Unable to extract build identity from {vmlinux}")


def compiler_identity(config_values: dict[str, str]) -> str:
    expected = decode_config_string(config_values.get("CONFIG_CC_VERSION_TEXT", ""),
                                    "CONFIG_CC_VERSION_TEXT")
    clang = shutil.which("clang")
    require(clang is not None, "Required existing tool missing: clang")
    actual = subprocess.check_output([clang, "--version"], text=True).splitlines()[0]
    require(actual == expected, "Current clang identity differs from canonical CONFIG_CC_VERSION_TEXT")
    return actual


def validate_runtime_guard() -> dict[str, Any]:
    manifest = read_json(RUNTIME / "etc/r8q-encryption-manifest.json", "canonical runtime manifest")
    guard = manifest.get("diagnostic_guard")
    require(isinstance(guard, dict), "canonical runtime guard metadata is missing")
    require(guard.get("nonce") == GUARD_NONCE and guard.get("tag") == GUARD_TAG,
            "canonical runtime guard nonce/tag differs")
    provenance = read_json(RUNTIME_PROVENANCE, "canonical runtime provenance")
    require(provenance.get("guard", {}).get("nonce") == GUARD_NONCE and
            provenance.get("guard", {}).get("tag") == GUARD_TAG,
            "canonical provenance guard nonce/tag differs")
    return {"nonce": GUARD_NONCE, "tag": GUARD_TAG,
            "manifest_sha256": digest(RUNTIME / "etc/r8q-encryption-manifest.json"),
            "provenance_sha256": digest(RUNTIME_PROVENANCE)}


def run_canonical_finalizer_check() -> None:
    require(FINALIZER.is_file(), f"Missing canonical finalizer: {FINALIZER}")
    command = [sys.executable, str(FINALIZER), "--check-final-existing",
               "--runtime-initramfs", str(RUNTIME),
               "--runtime-provenance", str(RUNTIME_PROVENANCE)]
    subprocess.run(command, cwd=REPO, check=True)


def canonical_identity() -> dict[str, Any]:
    directory(CANONICAL, "canonical diagnostic output")
    directory(SOURCE, "pinned kernel source")
    regular(CANONICAL / "candidate-manifest.json", "canonical candidate manifest")
    candidate = read_json(CANONICAL / "candidate-manifest.json", "canonical candidate manifest")
    require(candidate.get("kind") == "r8q-diagnostic-kernel-candidate" and
            candidate.get("kernel_release") == RELEASE and
            candidate.get("deployable") is True and
            candidate.get("boot_tested") is False and
            candidate.get("installed") is False,
            "canonical candidate state is not the accepted uninstalled final candidate")
    require(candidate.get("source_complete_sha256") == SOURCE_SHA256 and
            candidate.get("base_efi_sha256") == EFI_SHA256 and
            candidate.get("dtb_sha256") == DTB_SHA256,
            "canonical candidate source or hardware pins differ")
    regular(ACCEPTED_BASE / "payload/BOOTAA64.EFI", "accepted base EFI payload")
    require(digest(ACCEPTED_BASE / "payload/BOOTAA64.EFI") == EFI_SHA256,
            "accepted base EFI bytes differ from pinned hash")
    for relative in PRESERVED_RELATIVE:
        regular(CANONICAL / relative, f"canonical {relative}")
    canonical_config = config(CANONICAL / ".config")
    canonical_cmdline = decode_config_string(canonical_config.get("CONFIG_CMDLINE", ""),
                                              "canonical CONFIG_CMDLINE")
    require(canonical_cmdline.split().count(f"{CMDLINE_TOKEN}=1") == 1,
            "canonical pseudo-NMI cmdline token is not enabled exactly once")
    require(canonical_config.get("CONFIG_LOCALVERSION") == json.dumps("-r8q-diag1"),
            "canonical release config differs")
    require(digest(CANONICAL / "payload/R8Q-RTC.DTB") == DTB_SHA256,
            "canonical DTB bytes differ")
    identity = extract_build_identity(CANONICAL / "vmlinux")
    require(identity.get("release") == RELEASE and identity.get("version") == "6",
            "canonical build identity is not release/version 6")
    proof = source_proof()
    require(proof == candidate.get("complete_source_proof"),
            "canonical complete source proof differs")
    compiler = compiler_identity(canonical_config)
    guard = validate_runtime_guard()
    module = module_records(CANONICAL / MODULE_ROOT)
    stage = read_json(CANONICAL / "stage1-before-finalization.json", "canonical stage1 identity")
    require(module == stage.get("module_records"), "canonical module bindings differ")
    return {
        "candidate": candidate,
        "config": canonical_config,
        "cmdline": canonical_cmdline,
        "source_proof": proof,
        "compiler": compiler,
        "build_identity": identity,
        "guard": guard,
        "module_records": module,
        "module_inventory_sha256": hashlib.sha256(json.dumps(module, sort_keys=True).encode()).hexdigest(),
        "files": {relative: {"bytes": (CANONICAL / relative).stat().st_size,
                               "sha256": digest(CANONICAL / relative)} for relative in PRESERVED_RELATIVE},
        "raw_cpio_sha256": digest(CANONICAL / "usr/initramfs_data.cpio"),
        "compressed_initramfs_sha256": digest(CANONICAL / "usr/initramfs_inc_data"),
    }


def prepare_configs(*, record_delta: bool) -> dict[str, Any]:
    canonical_config_path = CANONICAL / ".config"
    ab_config_path = OUTPUT / ".config"
    config_result = validate_ab_config(canonical_config_path, ab_config_path)
    finalization_path = OUTPUT / "stage2-finalization.config"
    regular(finalization_path, "AB stage2 finalization config")
    finalization_result = validate_ab_config(CANONICAL / "stage2-finalization.config", finalization_path)
    require(finalization_result["candidate_cmdline"] == config_result["candidate_cmdline"],
            "AB stage2 finalization cmdline differs from AB config")
    if record_delta:
        write_json(OUTPUT / "ab-config-delta.json", config_result["delta"])
    return config_result


def remove_new_output_generated_files() -> None:
    for relative in GENERATED_RELATIVE:
        path = OUTPUT / relative
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def make_environment(identity: dict[str, str]) -> dict[str, str]:
    return {
        "ARCH": "arm64",
        "LLVM": "1",
        "LLVM_IAS": "1",
        "CROSS_COMPILE": "aarch64-linux-gnu-",
        "KBUILD_BUILD_VERSION": identity["version"],
        "KBUILD_BUILD_USER": identity["user"],
        "KBUILD_BUILD_HOST": identity["host"],
    }


def make_command(identity: dict[str, Any]) -> list[str]:
    return ["make", "-C", str(SOURCE), "O=" + str(OUTPUT),
            "build-timestamp=" + identity["build_identity"]["timestamp"],
            "-j2", "Image"]


def preparation_manifest(identity: dict[str, Any], config_result: dict[str, Any],
                         environment: dict[str, str]) -> dict[str, Any]:
    return {
        "kind": AB_PREPARATION_KIND,
        "kernel_release": RELEASE,
        "deployable": False,
        "boot_tested": False,
        "phone_install_performed": False,
        "canonical_output": str(CANONICAL),
        "output": str(OUTPUT),
        "source": str(SOURCE),
        "source_complete_sha256": SOURCE_SHA256,
        "complete_source_proof": identity["source_proof"],
        "accepted_efi_sha256": EFI_SHA256,
        "accepted_dtb_sha256": DTB_SHA256,
        "guard": identity["guard"],
        "guard_nonce": GUARD_NONCE,
        "guard_tag": GUARD_TAG,
        "config_delta": config_result["delta"],
        "canonical_config_sha256": digest(CANONICAL / ".config"),
        "ab_config_sha256": digest(OUTPUT / ".config"),
        "module_count": len(identity["module_records"]),
        "module_inventory_sha256": identity["module_inventory_sha256"],
        "raw_cpio_sha256": identity["raw_cpio_sha256"],
        "compressed_initramfs_sha256": identity["compressed_initramfs_sha256"],
        "build_identity": identity["build_identity"],
        "compiler": identity["compiler"],
        "make_environment": environment,
        "make_command": make_command(identity),
        "payload_copy_command": ["cp", "--reflink=auto", str(OUTPUT / "arch/arm64/boot/Image"),
                                  str(OUTPUT / "payload/BOOTAA64.EFI")],
        "template_sha256": script_digest(),
    }


def prepare() -> None:
    require(not OUTPUT.exists(), f"AB output already exists; refusing overwrite: {OUTPUT}")
    run_canonical_finalizer_check()
    identity = canonical_identity()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "-a", "--reflink=auto", str(CANONICAL / "."), str(OUTPUT)], check=True)
    remove_new_output_generated_files()
    canonical_cmdline = identity["cmdline"]
    for relative in (".config", "stage2-finalization.config"):
        path = OUTPUT / relative
        current = config(path)
        current_cmdline = decode_config_string(current["CONFIG_CMDLINE"], f"{relative} CONFIG_CMDLINE")
        require(current_cmdline == canonical_cmdline, f"cloned {relative} differs before AB edit")
        updated_cmdline = replace_pseudo_nmi_token(current_cmdline, False)
        lines = path.read_text(encoding="utf-8").splitlines()
        matches = [index for index, line in enumerate(lines) if line.startswith("CONFIG_CMDLINE=")]
        require(len(matches) == 1, f"{relative} must contain one CONFIG_CMDLINE")
        lines[matches[0]] = "CONFIG_CMDLINE=" + json.dumps(updated_cmdline)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    config_result = prepare_configs(record_delta=True)
    environment = make_environment(identity["build_identity"])
    write_json(OUTPUT / "ab-make-env.json", environment)
    preparation = preparation_manifest(identity, config_result, environment)
    write_json(OUTPUT / "ab-preparation-manifest.json", preparation)
    run_canonical_finalizer_check()
    print(json.dumps({"kind": AB_PREPARATION_KIND, "deployable": False,
                      "output": str(OUTPUT), "config_delta": config_result["delta"],
                      "make_environment": environment}, indent=2, sort_keys=True))


def validate_preparation(identity: dict[str, Any]) -> dict[str, Any]:
    preparation = read_json(OUTPUT / "ab-preparation-manifest.json", "AB preparation manifest")
    require(preparation.get("kind") == AB_PREPARATION_KIND and
            preparation.get("deployable") is False and
            preparation.get("phone_install_performed") is False,
            "AB preparation state is unsafe")
    require(preparation.get("template_sha256") == script_digest(),
            "AB preparation template hash differs")
    require(preparation.get("source_complete_sha256") == SOURCE_SHA256 and
            preparation.get("accepted_efi_sha256") == EFI_SHA256 and
            preparation.get("accepted_dtb_sha256") == DTB_SHA256,
            "AB preparation pins differ")
    require(preparation.get("complete_source_proof") == identity["source_proof"],
            "AB preparation source proof differs")
    require(preparation.get("guard_nonce") == GUARD_NONCE and
            preparation.get("guard_tag") == GUARD_TAG,
            "AB preparation guard binding differs")
    require(preparation.get("guard") == identity["guard"],
            "AB preparation runtime guard identity differs")
    require(preparation.get("canonical_config_sha256") == digest(CANONICAL / ".config") and
            preparation.get("ab_config_sha256") == digest(OUTPUT / ".config"),
            "AB preparation config hashes differ")
    config_result = prepare_configs(record_delta=False)
    require(preparation.get("config_delta") == config_result["delta"],
            "AB preparation config delta differs")
    require(preparation.get("module_inventory_sha256") == identity["module_inventory_sha256"],
            "AB preparation module identity differs")
    require(preparation.get("raw_cpio_sha256") == identity["raw_cpio_sha256"] and
            preparation.get("compressed_initramfs_sha256") == identity["compressed_initramfs_sha256"],
            "AB preparation initramfs identity differs")
    require(preparation.get("make_environment") == make_environment(identity["build_identity"]),
            "AB preparation make environment differs")
    require(preparation.get("make_command") == make_command(identity),
            "AB preparation make command differs")
    return preparation


def file_rows(root: Path, relatives: list[str]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for relative in relatives:
        path = root / relative
        regular(path, f"candidate artifact {relative}")
        rows[relative] = {"bytes": path.stat().st_size, "sha256": digest(path)}
    return rows


def validate_final_image(identity: dict[str, Any]) -> dict[str, Any]:
    finalizer = finalizer_module()
    canonical_image = finalizer.inspect_image(CANONICAL)
    candidate_image = finalizer.inspect_image(OUTPUT)
    canonical_cmdline = identity["cmdline"]
    candidate_cmdline = decode_config_string(config(OUTPUT / ".config")["CONFIG_CMDLINE"],
                                              "AB CONFIG_CMDLINE")
    validate_compiled_cmdline(canonical_image["image"].read_bytes(),
                              candidate_image["image"].read_bytes(),
                              canonical_cmdline, candidate_cmdline)
    require(digest(CANONICAL / "arch/arm64/boot/Image") !=
            digest(OUTPUT / "arch/arm64/boot/Image"), "AB Image was not relinked")
    require(canonical_image["cpio"] == candidate_image["cpio"],
            "AB embedded raw cpio differs from canonical")
    require(canonical_image["records"] == candidate_image["records"],
            "AB embedded initramfs archive records differ")
    compare_bytes(CANONICAL / "usr/initramfs_data.cpio", OUTPUT / "usr/initramfs_data.cpio",
                  "raw initramfs cpio")
    compare_bytes(CANONICAL / "usr/initramfs_inc_data", OUTPUT / "usr/initramfs_inc_data",
                  "compressed embedded initramfs")
    require(hashlib.sha256(candidate_image["cpio"]).hexdigest() == identity["raw_cpio_sha256"],
            "AB embedded cpio hash differs from preparation")
    return candidate_image


def candidate_manifest(identity: dict[str, Any], config_result: dict[str, Any],
                       module: dict[str, Any], image: dict[str, Any]) -> dict[str, Any]:
    relatives = ["arch/arm64/boot/Image", "payload/BOOTAA64.EFI", "payload/R8Q-RTC.DTB",
                 ".config", "stage2-finalization.config", "usr/initramfs_data.cpio",
                 "usr/initramfs_inc_data", "include/config/kernel.release"]
    rows = file_rows(OUTPUT, relatives)
    return {
        "kind": AB_CANDIDATE_KIND,
        "kernel_release": RELEASE,
        "root_state": "encrypted",
        "deployable": True,
        "boot_tested": False,
        "accepted": False,
        "installed": False,
        "phone_install_performed": False,
        "canonical_candidate_sha256": digest(CANONICAL / "candidate-manifest.json"),
        "canonical_output": str(CANONICAL),
        "output": str(OUTPUT),
        "source": str(SOURCE),
        "source_complete_sha256": SOURCE_SHA256,
        "complete_source_proof": identity["source_proof"],
        "compiler": identity["compiler"],
        "build_identity": identity["build_identity"],
        "base_efi_sha256": EFI_SHA256,
        "dtb_sha256": DTB_SHA256,
        "guard_nonce": GUARD_NONCE,
        "guard_tag": GUARD_TAG,
        "runtime_guard_manifest_sha256": identity["guard"]["manifest_sha256"],
        "runtime_provenance_sha256": identity["guard"]["provenance_sha256"],
        "config_delta": config_result["delta"],
        "module_count": module["count"],
        "module_inventory_sha256": module["sha256"],
        "module_inventory_unchanged": True,
        "embedded_archive_entries": len(image["records"]),
        "embedded_initramfs_sha256": hashlib.sha256(image["cpio"]).hexdigest(),
        "raw_initramfs_sha256": digest(OUTPUT / "usr/initramfs_data.cpio"),
        "compressed_initramfs_sha256": digest(OUTPUT / "usr/initramfs_inc_data"),
        "files": rows,
        "template_sha256": script_digest(),
    }


def verify_final(write_manifest: bool) -> dict[str, Any]:
    run_canonical_finalizer_check()
    identity = canonical_identity()
    validate_preparation(identity)
    config_result = validate_ab_config(CANONICAL / ".config", OUTPUT / ".config")
    for relative in PRESERVED_RELATIVE:
        compare_bytes(CANONICAL / relative, OUTPUT / relative, relative)
    module = validate_module_inventory()
    require(digest(OUTPUT / "payload/R8Q-RTC.DTB") == DTB_SHA256,
            "AB payload DTB differs from accepted pin")
    require(digest(OUTPUT / "active-dtb.R8Q-RTC.DTB") == DTB_SHA256,
            "AB active DTB differs from accepted pin")
    require((OUTPUT / "include/config/kernel.release").read_text().strip() == RELEASE,
            "AB kernel release differs")
    candidate_identity = extract_build_identity(OUTPUT / "vmlinux")
    require(candidate_identity == identity["build_identity"], "AB compiler/build identity differs")
    require(compiler_identity(config_result["candidate"]) == identity["compiler"],
            "AB compiler identity differs")
    image = validate_final_image(identity)
    manifest = candidate_manifest(identity, config_result, module, image)
    existing = OUTPUT / "ab-candidate-manifest.json"
    if write_manifest:
        require(not existing.exists(), f"Refusing to overwrite AB candidate manifest: {existing}")
        write_json(existing, manifest)
        write_json(OUTPUT / "ab-embedded-initramfs-manifest.json", image["records"])
        write_json(OUTPUT / "ab-verification-manifest.json", {
            "kind": "r8q-diagnostic-ab-verification/v1",
            "deployable": True,
            "boot_tested": False,
            "phone_install_performed": False,
            "candidate_manifest_sha256": digest(existing),
            "template_sha256": script_digest(),
        })
    return manifest


def validate_existing_manifest(manifest: dict[str, Any]) -> None:
    require(manifest.get("kind") == AB_CANDIDATE_KIND and
            manifest.get("deployable") is True and
            manifest.get("boot_tested") is False and
            manifest.get("accepted") is False and
            manifest.get("phone_install_performed") is False,
            "AB candidate manifest state is unsafe")
    require(manifest.get("template_sha256") == script_digest(),
            "AB candidate template hash differs")
    require(manifest.get("guard_nonce") == GUARD_NONCE and manifest.get("guard_tag") == GUARD_TAG,
            "AB candidate guard binding differs")


def verify_mode(write_manifest: bool) -> None:
    manifest = verify_final(write_manifest)
    path = OUTPUT / "ab-candidate-manifest.json"
    if not write_manifest:
        existing = read_json(path, "AB candidate manifest")
        validate_existing_manifest(existing)
        require(existing == manifest, "existing AB candidate manifest differs from verified output")
    run_canonical_finalizer_check()
    print(json.dumps({"kind": manifest["kind"], "deployable": manifest["deployable"],
                      "boot_tested": manifest["boot_tested"],
                      "embedded_archive_entries": manifest["embedded_archive_entries"],
                      "module_count": manifest["module_count"],
                      "manifest_rewritten": write_manifest}, indent=2, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--prepare", action="store_true",
                       help="Clone canonical output and prepare the pseudo-NMI=0 config; never builds")
    modes.add_argument("--verify-final", action="store_true",
                       help="Verify an externally relinked Image and write the AB candidate manifest")
    modes.add_argument("--check-final", action="store_true",
                       help="Verify the existing AB candidate without writing manifests")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.prepare:
        prepare()
    elif args.verify_final:
        verify_mode(True)
    else:
        verify_mode(False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
