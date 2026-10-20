#!/usr/bin/env python3
"""Prepare an isolated, non-deployable R8Q diagnostic kernel candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess


REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"
BASE = OUT / "waydroid-encrypted-20261015" / "kernel"
SOURCE = OUT / "waydroid-kernel-20261013" / "source"
OUTPUT = OUT / "diagnostic-kernel-20261020" / "kernel"
FRAGMENT = REPO / "config" / "r8q_diagnostic.config"
RELEASE = "7.1.2-r8q-diag1"
SOURCE_SHA256 = "04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b"
EFI_SHA256 = "f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b"
DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"
BASE_CONFIG_SHA256 = "0375c928a377e5507a4e217d2a6da0fce4b458f1785888dd3ea2a5c6e57b2ca1"
TEMP_CPIO_SHA256 = "eaf69e92e8a30fc03f06736eb5f33169eeecae0a9cae5ce09193fffe27791abe"
BASE_MANIFEST_KIND = "r8q-encrypted-waydroid-kernel-candidate"
CMDLINE_SUFFIX = (
    "irqchip.gicv3_pseudo_nmi=1 "
    "softlockup_all_cpu_backtrace=1 "
    "hardlockup_all_cpu_backtrace=1 "
    "rcupdate.rcu_cpu_stall_cputime=1 "
    "softlockup_panic=0 hardlockup_panic=0 hung_task_panic=0 "
    "panic_on_warn=0 workqueue.panic_on_stall=0"
)
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
REMOVE_PATHS = (
    "modules",
    "payload",
    "candidate-manifest.json",
    "config-delta.json",
    "configuration-proof.json",
    "build-plan.json",
    "compiler.json",
    "module-inventory.json",
    "stage1-manifest.json",
    "embedded-initramfs-manifest.json",
    "kernel-source-after-build-inherited.jsonl",
    "kernel-source-manifest.jsonl",
    "accepted-production04.config",
    "baseline.config",
    "temporary-accepted-encrypted-initramfs.cpio",
    "active-dtb.R8Q-RTC.DTB",
    "usr/initramfs_data.cpio",
    "usr/initramfs_inc_data",
    "usr/initramfs_data.o",
    "usr/.initramfs_data.cpio.cmd",
    "usr/.initramfs_inc_data.cmd",
    "usr/.initramfs_data.o.cmd",
    "arch/arm64/boot/Image",
    "System.map",
    "vmlinux",
    "vmlinux.a",
    "vmlinux.o",
    "vmlinux.unstripped",
    "built-in.a",
    "modules-order-closure.json",
    "stage1-finalization.config",
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
    for line in path.read_text().splitlines():
        if line.startswith("CONFIG_"):
            key, value = line.split("=", 1)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-11]] = "n"
    return values


KERNEL_ENV = {
    **os.environ,
    "ARCH": "arm64",
    "LLVM": "1",
    "LLVM_IAS": "1",
    "CROSS_COMPILE": "aarch64-linux-gnu-",
}


def run(command: list[str], *, cwd: Path | None = None, kernel: bool = False) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True, env=KERNEL_ENV if kernel else None)


def require_tools(names: list[str]) -> None:
    for name in names:
        require(shutil.which(name) is not None, f"Required existing tool missing: {name}")


def source_rules():
    path = REPO / "scripts" / "prepare-waydroid-kernel-source.py"
    spec = importlib.util.spec_from_file_location("r8q_source_rules", path)
    require(spec is not None and spec.loader is not None, f"Unable to load source rules: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_inputs(*, allow_existing_output: bool = False) -> dict[str, object]:
    for path in (BASE, SOURCE, FRAGMENT):
        require(path.exists(), f"Missing input: {path}")
    require(BASE.is_dir() and SOURCE.is_dir(), "Base build or source is not a directory")
    if allow_existing_output:
        require(OUTPUT.is_dir(), f"Prepared output is missing: {OUTPUT}")
    else:
        require(not OUTPUT.exists(), f"Output already exists; refusing to overwrite: {OUTPUT}")
    require(BASE != OUTPUT and BASE not in OUTPUT.parents and OUTPUT not in BASE.parents,
            "Output overlaps the accepted base")
    require(SOURCE != OUTPUT and SOURCE not in OUTPUT.parents and OUTPUT not in SOURCE.parents,
            "Output overlaps the pinned source")
    require((BASE / ".config").is_file(), "Accepted v2 configuration is missing")
    require(digest(BASE / ".config") == BASE_CONFIG_SHA256, "Accepted v2 configuration hash differs")
    require((BASE / "candidate-manifest.json").is_file(), "Accepted v2 manifest is missing")
    manifest = json.loads((BASE / "candidate-manifest.json").read_text())
    require(manifest.get("kind") == BASE_MANIFEST_KIND, "Accepted v2 manifest kind differs")
    require(manifest.get("kernel_release") == "7.1.2-r8q-waydroid2", "Accepted v2 release differs")
    require(manifest.get("files", {}).get("payload/BOOTAA64.EFI", {}).get("sha256") == EFI_SHA256,
            "Accepted v2 EFI identity differs")
    require(manifest.get("files", {}).get("payload/R8Q-RTC.DTB", {}).get("sha256") == DTB_SHA256,
            "Accepted v2 DTB identity differs")
    accepted_efi = BASE / "payload" / "BOOTAA64.EFI"
    accepted_dtb = BASE / "payload" / "R8Q-RTC.DTB"
    require(accepted_efi.is_file() and digest(accepted_efi) == EFI_SHA256,
            "Accepted v2 EFI bytes differ")
    require(accepted_dtb.is_file() and digest(accepted_dtb) == DTB_SHA256,
            "Accepted v2 DTB bytes differ")
    temporary = BASE / "temporary-accepted-encrypted-initramfs.cpio"
    require(temporary.is_file() and digest(temporary) == TEMP_CPIO_SHA256,
            "Accepted temporary encrypted cpio identity differs")
    require((BASE / "Module.symvers").is_file(), "Accepted v2 Module.symvers is missing")
    require((SOURCE / "Makefile").is_file(), "Pinned source Makefile is missing")
    proof = source_rules().verify_complete_source_tree(SOURCE)
    require(proof["sha256"] == SOURCE_SHA256, "Pinned complete source identity differs")
    require((SOURCE / "scripts" / "config").is_file(), "Kernel scripts/config is missing")
    require((SOURCE / "scripts" / "kconfig" / "merge_config.sh").is_file(),
            "Kernel merge_config.sh is missing")
    return {
        "base_config_sha256": digest(BASE / ".config"),
        "base_efi_sha256": EFI_SHA256,
        "base_dtb_sha256": DTB_SHA256,
        "temporary_cpio_sha256": TEMP_CPIO_SHA256,
        "source": proof,
        "source_sha256": SOURCE_SHA256,
    }


def remove_output_paths() -> None:
    for relative in REMOVE_PATHS:
        path = OUTPUT / relative
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
    for path in OUTPUT.rglob("*.ko"):
        if path.is_file() and not path.is_symlink():
            path.unlink()


def copy_base_cache() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    run(["cp", "-a", "--reflink=auto", str(BASE / "."), str(OUTPUT)])
    remove_output_paths()
    run(["cp", "--reflink=auto", str(BASE / ".config"), str(OUTPUT / "acceptedv2.config")])
    run(["cp", "--reflink=auto", str(BASE / "temporary-accepted-encrypted-initramfs.cpio"),
         str(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio")])
    run(["cp", "--reflink=auto", str(BASE / "payload" / "R8Q-RTC.DTB"),
         str(OUTPUT / "active-dtb.R8Q-RTC.DTB")])


def current_cmdline(values: dict[str, str]) -> str:
    encoded = values.get("CONFIG_CMDLINE")
    require(encoded is not None, "Accepted v2 CONFIG_CMDLINE is missing")
    require(encoded.startswith('"') and encoded.endswith('"'), "Accepted v2 CONFIG_CMDLINE is not quoted")
    return json.loads(encoded)


def resolve_config(inputs: dict[str, object]) -> dict[str, object]:
    base_values = config(OUTPUT / "acceptedv2.config")
    prefix = current_cmdline(base_values)
    require(prefix and not prefix.endswith(" "), "Accepted v2 cmdline is empty or malformed")
    cmdline = prefix + " " + CMDLINE_SUFFIX
    run(["cp", "--reflink=auto", str(OUTPUT / "acceptedv2.config"), str(OUTPUT / ".config")])
    run(["bash", str(SOURCE / "scripts" / "kconfig" / "merge_config.sh"), "-m", "-O", str(OUTPUT),
         str(OUTPUT / ".config"), str(FRAGMENT)])
    run([str(SOURCE / "scripts" / "config"), "--file", str(OUTPUT / ".config"),
         "--set-str", "INITRAMFS_SOURCE", str(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"),
         "--set-str", "LOCALVERSION", "-r8q-diag1",
         "--set-str", "CMDLINE", cmdline])
    for relative in (
        "include/config/auto.conf",
        "include/config/auto.conf.cmd",
        "include/generated/autoconf.h",
        "include/generated/rustc_cfg",
        "include/generated/utsrelease.h",
    ):
        path = OUTPUT / relative
        if path.exists() or path.is_symlink():
            path.unlink()
    run(["make", "-C", str(SOURCE), "O=" + str(OUTPUT), "olddefconfig"], kernel=True)
    resolved = config(OUTPUT / ".config")
    delta = {
        key: {"before": base_values.get(key, "n"), "after": resolved.get(key, "n")}
        for key in sorted(base_values.keys() | resolved.keys())
        if base_values.get(key, "n") != resolved.get(key, "n")
    }
    require(set(delta) == DIAGNOSTIC_KEYS,
            "Resolved config delta differs: " + str(sorted(set(delta) ^ DIAGNOSTIC_KEYS)))
    expected_enabled = (
        "ARM64_PSEUDO_NMI", "SOFTLOCKUP_DETECTOR", "HARDLOCKUP_DETECTOR",
        "DETECT_HUNG_TASK", "DETECT_HUNG_TASK_BLOCKER", "WQ_WATCHDOG", "RCU_EQS_DEBUG",
    )
    for name in expected_enabled:
        require(resolved.get("CONFIG_" + name) == "y", "Diagnostic option did not resolve: " + name)
    require(resolved.get("CONFIG_HARDLOCKUP_DETECTOR_PREFER_BUDDY", "n") == "n",
            "Buddy hardlockup detector unexpectedly enabled")
    require(resolved.get("CONFIG_CMDLINE") == json.dumps(cmdline), "Diagnostic cmdline was not resolved")
    require(resolved.get("CONFIG_LOCALVERSION") == '"-r8q-diag1"', "Diagnostic release suffix differs")
    require(resolved.get("CONFIG_INITRAMFS_SOURCE") == '"' + str(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio") + '"',
            "Diagnostic initramfs source differs")
    require(resolved.get("CONFIG_PANIC_ON_OOPS", "n") == "n", "PANIC_ON_OOPS changed")
    for name in ("SOFTLOCKUP_PANIC", "HARDLOCKUP_PANIC", "DETECT_HUNG_TASK_PANIC", "PANIC_ON_WARN"):
        require(resolved.get("CONFIG_" + name, "n") in {"n", "0"}, "Panic policy changed: " + name)
    (OUTPUT / "config-delta.json").write_text(json.dumps(delta, indent=2, sort_keys=True) + "\n")
    (OUTPUT / "configuration-proof.json").write_text(json.dumps({
        "kind": "r8q-diagnostic-config-only",
        "base_config": str(BASE / ".config"),
        "base_config_sha256": digest(OUTPUT / "acceptedv2.config"),
        "resolved_config": str(OUTPUT / ".config"),
        "resolved_config_sha256": digest(OUTPUT / ".config"),
        "delta": delta,
        "cmdline_prefix": prefix,
        "cmdline_suffix": CMDLINE_SUFFIX,
        "cmdline": cmdline,
        "temporary_cpio_sha256": digest(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"),
        "active_dtb_sha256": digest(OUTPUT / "active-dtb.R8Q-RTC.DTB"),
        "source_sha256": inputs["source_sha256"],
        "kernel_release": RELEASE,
        "deployable": False,
    }, indent=2, sort_keys=True) + "\n")
    return {"base": base_values, "resolved": resolved, "delta": delta, "cmdline": cmdline}


def verify_prepared_output() -> dict[str, str]:
    accepted_path = OUTPUT / "acceptedv2.config"
    resolved_path = OUTPUT / ".config"
    temporary = OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"
    active_dtb = OUTPUT / "active-dtb.R8Q-RTC.DTB"
    for path in (accepted_path, resolved_path, temporary, active_dtb,
                 OUTPUT / "config-delta.json", OUTPUT / "configuration-proof.json",
                 OUTPUT / "diagnostic-preparation-manifest.json"):
        require(path.is_file(), f"Prepared diagnostic artifact is missing: {path}")
    require(digest(accepted_path) == BASE_CONFIG_SHA256, "Prepared acceptedv2 config hash differs")
    require(digest(temporary) == TEMP_CPIO_SHA256, "Prepared temporary cpio hash differs")
    require(digest(active_dtb) == DTB_SHA256, "Prepared DTB hash differs")
    require(not (OUTPUT / "payload").exists(), "Payload already exists; refusing to rebuild")
    require(not (OUTPUT / "stage1-manifest.json").exists(), "Stage1 manifest already exists; refusing to rebuild")
    require(not any(path.is_file() for path in OUTPUT.rglob("*.ko")),
            "A copied or previously built module remains in the preparation output")
    base_values = config(accepted_path)
    resolved = config(resolved_path)
    delta = {
        key: {"before": base_values.get(key, "n"), "after": resolved.get(key, "n")}
        for key in sorted(base_values.keys() | resolved.keys())
        if base_values.get(key, "n") != resolved.get(key, "n")
    }
    recorded_delta = json.loads((OUTPUT / "config-delta.json").read_text())
    require(recorded_delta == delta, "Recorded config delta does not match the resolved config")
    require(set(delta) == DIAGNOSTIC_KEYS,
            "Prepared resolved delta is not the exact diagnostic closure")
    require(resolved.get("CONFIG_LOCALVERSION") == '"-r8q-diag1"', "Prepared release suffix differs")
    require(resolved.get("CONFIG_INITRAMFS_SOURCE") == '"' + str(temporary) + '"',
            "Prepared initramfs source differs")
    require(resolved.get("CONFIG_DEBUG_INFO_BTF", "n") == "n" and
            resolved.get("CONFIG_DEBUG_INFO_BTF_MODULES", "n") == "n",
            "BTF unexpectedly enabled")
    require(resolved.get("CONFIG_PANIC_ON_OOPS", "n") == "n", "PANIC_ON_OOPS unexpectedly enabled")
    proof = json.loads((OUTPUT / "configuration-proof.json").read_text())
    require(proof.get("resolved_config_sha256") == digest(resolved_path),
            "Configuration proof resolved hash differs")
    require(proof.get("base_config_sha256") == digest(accepted_path),
            "Configuration proof base hash differs")
    require(proof.get("delta") == delta, "Configuration proof delta differs")
    preparation = json.loads((OUTPUT / "diagnostic-preparation-manifest.json").read_text())
    require(preparation.get("deployable") is False, "Diagnostic preparation is deployable")
    require(preparation.get("resolved_config_sha256") == digest(resolved_path),
            "Preparation resolved hash differs")
    accepted_cc = base_values.get("CONFIG_CC_VERSION_TEXT")
    require(accepted_cc is not None and accepted_cc.startswith('"') and accepted_cc.endswith('"'),
            "Accepted compiler identity is missing")
    compiler = subprocess.check_output(["clang", "--version"], text=True).splitlines()[0]
    require(json.loads(accepted_cc) == compiler, "Current clang differs from accepted CC_VERSION_TEXT")
    return {"compiler": compiler, "resolved_config_sha256": digest(resolved_path)}


def write_preparation_receipts(inputs: dict[str, object], resolved: dict[str, object]) -> None:
    tools = {
        "config_only_required": ["cp", "python3", "make", "bash"],
        "build_required": ["cp", "python3", "make", "bash", "clang", "ld.lld", "llvm-ar",
                           "llvm-nm", "aarch64-linux-gnu-gcc", "modinfo", "depmod"],
        "pahole_required": False,
        "btf_required": False,
        "detected": {name: shutil.which(name) for name in
                      ["cp", "python3", "make", "bash", "clang", "ld.lld", "llvm-ar",
                       "llvm-nm", "aarch64-linux-gnu-gcc", "modinfo", "depmod", "pahole"]},
    }
    (OUTPUT / "tools.json").write_text(json.dumps(tools, indent=2, sort_keys=True) + "\n")
    (OUTPUT / "build-plan.json").write_text(json.dumps({
        "kind": "r8q-diagnostic-kernel-preparation",
        "kernel_release": RELEASE,
        "config_only_default": True,
        "build_requires_explicit_flag": "--build",
        "deployable": False,
        "stage1_deployable": False,
        "stage2_required": True,
        "stage2_reason": "Temporary cpio intentionally retains old encrypted-root modules; regenerate matching early modules and relink Image before any boot use.",
        "base_cache": str(BASE),
        "source": str(SOURCE),
        "source_complete_sha256": inputs["source_sha256"],
        "active_dtb": str(OUTPUT / "active-dtb.R8Q-RTC.DTB"),
        "active_dtb_sha256": digest(OUTPUT / "active-dtb.R8Q-RTC.DTB"),
        "temporary_initramfs": str(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"),
        "temporary_initramfs_sha256": digest(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"),
        "preserved_base_efi_sha256": EFI_SHA256,
        "diagnostic_fragment": str(FRAGMENT),
        "jobs": 2,
        "stage1_command": ["make", "-C", str(SOURCE), "O=" + str(OUTPUT), "-j2", "Image", "modules"],
        "stage1_modules_install": ["make", "-C", str(SOURCE), "O=" + str(OUTPUT),
                                   "INSTALL_MOD_PATH=" + str(OUTPUT / "modules"), "DEPMOD=depmod", "modules_install"],
        "resolved_config_sha256": digest(OUTPUT / ".config"),
        "resolved_delta_count": len(resolved["delta"]),
    }, indent=2, sort_keys=True) + "\n")
    (OUTPUT / "diagnostic-preparation-manifest.json").write_text(json.dumps({
        "kind": "r8q-diagnostic-config-only-nondeployable",
        "kernel_release": RELEASE,
        "deployable": False,
        "stage1_allowed_only_with_explicit_build": True,
        "source_complete_sha256": inputs["source_sha256"],
        "base_efi_sha256": EFI_SHA256,
        "dtb_sha256": digest(OUTPUT / "active-dtb.R8Q-RTC.DTB"),
        "temporary_cpio_sha256": digest(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"),
        "resolved_config_sha256": digest(OUTPUT / ".config"),
        "cmdline": resolved["cmdline"],
        "old_initramfs_modules_intentionally_retained": True,
        "phone_install_performed": False,
    }, indent=2, sort_keys=True) + "\n")


def stage1_build() -> None:
    require_tools(["cp", "python3", "make", "bash", "clang", "ld.lld", "llvm-ar", "llvm-nm",
                   "aarch64-linux-gnu-gcc", "modinfo", "depmod"])
    verify_inputs(allow_existing_output=True)
    verify_prepared_output()
    run(["make", "-C", str(SOURCE), "O=" + str(OUTPUT), "-j2", "Image", "modules"], kernel=True)
    image = OUTPUT / "arch" / "arm64" / "boot" / "Image"
    require(image.is_file(), "Stage1 Image was not produced")
    (OUTPUT / "payload").mkdir()
    run(["cp", "--reflink=auto", str(image), str(OUTPUT / "payload" / "BOOTAA64.EFI")])
    run(["cp", "--reflink=auto", str(OUTPUT / "active-dtb.R8Q-RTC.DTB"),
         str(OUTPUT / "payload" / "R8Q-RTC.DTB")])
    run(["make", "-C", str(SOURCE), "O=" + str(OUTPUT),
         "INSTALL_MOD_PATH=" + str(OUTPUT / "modules"), "DEPMOD=depmod", "modules_install"], kernel=True)
    modules = sorted(str(path.relative_to(OUTPUT / "modules")) for path in
                     (OUTPUT / "modules").rglob("*.ko") if path.is_file())
    require(modules, "Stage1 did not install any modules")
    (OUTPUT / "stage1-manifest.json").write_text(json.dumps({
        "kind": "r8q-diagnostic-stage1-nondeployable",
        "kernel_release": RELEASE,
        "deployable": False,
        "stage2_required": True,
        "stage2_reason": "Temporary encrypted cpio contains old modules and must be replaced before boot.",
        "old_initramfs_modules_intentionally_retained": True,
        "source_complete_sha256": SOURCE_SHA256,
        "base_efi_sha256": EFI_SHA256,
        "dtb_sha256": digest(OUTPUT / "active-dtb.R8Q-RTC.DTB"),
        "temporary_cpio_sha256": digest(OUTPUT / "temporary-accepted-encrypted-initramfs.cpio"),
        "resolved_config_sha256": digest(OUTPUT / ".config"),
        "image_sha256": digest(image),
        "payload_image_sha256": digest(OUTPUT / "payload" / "BOOTAA64.EFI"),
        "module_count": len(modules),
        "module_paths": modules,
        "phone_install_performed": False,
    }, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"kind": "r8q-diagnostic-stage1-nondeployable", "module_count": len(modules),
                      "image_sha256": digest(image)}, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help="Explicitly build non-deployable stage1 after preparation")
    parser.add_argument("--refresh-config", action="store_true",
                        help="Regenerate configuration-only receipts in an existing prepared output")
    parser.add_argument("--jobs", type=int, default=2, help="Stage1 make parallelism; default: 2")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require(args.jobs == 2, "This bounded trial requires fixed stage1 parallelism -j2")
    require(not (args.build and args.refresh_config), "Choose either --build or --refresh-config")
    if args.build:
        stage1_build()
        return 0
    if args.refresh_config:
        require_tools(["cp", "python3", "make", "bash"])
        inputs = verify_inputs(allow_existing_output=True)
        require(not (OUTPUT / "payload").exists(), "Cannot refresh a staged output with a payload")
        require(not (OUTPUT / "stage1-manifest.json").exists(), "Cannot refresh a staged output")
        resolved = resolve_config(inputs)
        write_preparation_receipts(inputs, resolved)
        print("Configuration-only receipts refreshed; no Image, modules, payload, or phone operation performed.")
        return 0
    require_tools(["cp", "python3", "make", "bash"])
    inputs = verify_inputs()
    copy_base_cache()
    resolved = resolve_config(inputs)
    write_preparation_receipts(inputs, resolved)
    print("Configuration-only preparation complete; no Image, modules, payload, or phone operation performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
