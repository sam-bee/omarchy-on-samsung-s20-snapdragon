#!/usr/bin/env python3
"""Build the isolated five-applet diagnostic initramfs helper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


SCRIPT = Path(__file__).resolve()
REPO = SCRIPT.parents[1]
REFERENCE_SOURCE = REPO / "out/sources/busybox-1.38.0"
SOURCE_ARCHIVE = REPO / "out/downloads/busybox-1.38.0.tar.bz2"
ACCEPTED_BUSYBOX = REPO / "out/waydroid-encrypted-20261015/initramfs-preparation/initramfs/bin/busybox"
ACCEPTED_CONFIG = REPO / "out/encryption-build-20261013/busybox/.config"
DEFAULT_OUTPUT = REPO / "out/diagnostic-kernel-20261020/guard-tools"
EXPECTED_ARCHIVE_SHA256 = "34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2"
EXPECTED_ACCEPTED_BUSYBOX_SHA256 = "5390b3622a9dd6c5ef440377a62faddca7a03effec64471c16ab362e91505424"
EXPECTED_ACCEPTED_CONFIG_SHA256 = "5e096c4c05460ba8bdf098c275da9352909b754f1fd9fc076e491acb687843c7"
SOURCE_DATE_EPOCH = "1778638909"
HELPER_APPLETS = ("cp", "mv", "readlink", "sha256sum", "stat")
ENABLED_SYMBOLS = (
    "BUSYBOX",
    "STATIC",
    "STATIC_LIBGCC",
    "FEATURE_PREFER_APPLETS",
    "CP",
    "MV",
    "READLINK",
    "SHA256SUM",
    "STAT",
    "FEATURE_STAT_FORMAT",
    "FEATURE_READLINK_FOLLOW",
    "SH_IS_NONE",
)
DISABLED_SYMBOLS = ("SH_IS_ASH", "SHELL_ASH")


class BuildError(RuntimeError):
    """Raised when a pinned helper build cannot be completed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def require_file(path: Path, label: str) -> None:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or not regular: {path}")


def require_tool(name: str) -> str:
    path = shutil.which(name)
    require(path is not None, f"required existing tool is missing: {name}")
    return path


def run(command: list[str], log_path: Path, *, input_text: str | None = None,
        environment: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, input=input_text, text=True, capture_output=True,
                            check=False, env=environment)
    log_path.write_text(
        "$ " + " ".join(command) + "\n\n" + result.stdout + result.stderr,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise BuildError(f"command failed with status {result.returncode}: {' '.join(command)}")


def set_bool(config_text: str, symbol: str, enabled: bool) -> str:
    enabled_line = f"CONFIG_{symbol}=y"
    disabled_line = f"# CONFIG_{symbol} is not set"
    matches = [line for line in config_text.splitlines() if line == enabled_line or line == disabled_line]
    require(len(matches) == 1, f"BusyBox allnoconfig did not expose exactly one {symbol}")
    replacement = enabled_line if enabled else disabled_line
    return config_text.replace(matches[0], replacement, 1)


def parse_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-11]] = "n"
    return values


def helper_applets(binary: Path, qemu: str) -> list[str]:
    result = subprocess.run([qemu, "-0", "busybox", str(binary), "--list"],
                            capture_output=True, text=True, check=False)
    require(result.returncode == 0, f"cannot list helper applets: {result.stderr.strip()}")
    return sorted(line for line in result.stdout.splitlines() if line)


def extract_verified_source(archive_path: Path, temporary_root: Path) -> tuple[Path, str]:
    source_root = temporary_root / "busybox-1.38.0"
    source_root.mkdir()
    seen: set[str] = set()
    archive_records: dict[str, tuple[str, str, int, int]] = {}
    with tarfile.open(archive_path, "r:bz2") as archive:
        members = archive.getmembers()
        require(members, "BusyBox source archive is empty")
        for member in members:
            name = Path(member.name)
            require(not name.is_absolute() and ".." not in name.parts,
                    f"unsafe source archive path: {member.name}")
            require(name.parts and name.parts[0] == "busybox-1.38.0",
                    f"unexpected source archive root: {member.name}")
            relative_parts = name.parts[1:]
            if not relative_parts:
                require(member.isdir(), "BusyBox source archive root is not a directory")
                continue
            relative = Path(*relative_parts)
            relative_name = relative.as_posix()
            require(relative_name not in seen, f"duplicate source archive path: {member.name}")
            seen.add(relative_name)
            target = source_root / relative
            require(source_root in target.resolve().parents,
                    f"source archive path escapes extraction root: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(member.mode & 0o7777)
                archive_records[relative_name] = ("directory", "", 0, member.mode & 0o7777)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                require(stream is not None, f"cannot read source archive file: {member.name}")
                archive_digest = hashlib.sha256()
                archive_size = 0
                with stream, target.open("wb") as destination:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        archive_digest.update(block)
                        archive_size += len(block)
                        destination.write(block)
                target.chmod(member.mode & 0o7777)
                archive_records[relative_name] = (
                    "file",
                    archive_digest.hexdigest(),
                    archive_size,
                    member.mode & 0o7777,
                )
            elif member.issym():
                link = Path(member.linkname)
                require(not link.is_absolute() and ".." not in link.parts,
                        f"unsafe source archive symlink: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)
                archive_records[relative_name] = ("symlink", member.linkname, 0, member.mode & 0o7777)
            else:
                raise BuildError(f"unsupported source archive entry type: {member.name}")
    require((source_root / "Makefile").is_file(), "verified BusyBox source lacks Makefile")
    manifest_lines = []
    counts = {"file": 0, "directory": 0, "symlink": 0}
    extracted_records: dict[str, tuple[str, str, int, int]] = {}
    for path in sorted(source_root.rglob("*")):
        relative = path.relative_to(source_root).as_posix()
        if path.is_symlink():
            counts["symlink"] += 1
            manifest_lines.append(f"symlink {path.readlink()} {relative}")
            extracted_records[relative] = ("symlink", str(path.readlink()), 0, path.lstat().st_mode & 0o7777)
        elif path.is_dir():
            counts["directory"] += 1
            manifest_lines.append(f"directory {path.stat().st_mode & 0o7777:04o} {relative}")
            extracted_records[relative] = ("directory", "", 0, path.stat().st_mode & 0o7777)
        elif path.is_file():
            counts["file"] += 1
            manifest_lines.append(f"file {digest(path)} {path.stat().st_size} {relative}")
            extracted_records[relative] = ("file", digest(path), path.stat().st_size,
                                           path.stat().st_mode & 0o7777)
        else:
            raise BuildError(f"verified source contains unsupported path: {path}")
    require(extracted_records.keys() == archive_records.keys(),
            "extracted BusyBox source contains unknown or missing paths")
    for relative, expected in archive_records.items():
        actual = extracted_records[relative]
        require(actual[:3] == expected[:3], f"source archive content mismatch: {relative}")
    source_manifest = "\n".join(manifest_lines) + "\n"
    return source_root, source_manifest


def build(options: argparse.Namespace) -> Path:
    make = require_tool("make")
    compiler = require_tool("aarch64-linux-gnu-gcc")
    qemu = require_tool("qemu-aarch64")
    readelf = require_tool("readelf")
    file_tool = require_tool("file")
    require(REFERENCE_SOURCE.is_dir(), f"reference BusyBox source is missing: {REFERENCE_SOURCE}")
    require_file(SOURCE_ARCHIVE, "pinned BusyBox source archive")
    require_file(ACCEPTED_BUSYBOX, "accepted BusyBox")
    require_file(ACCEPTED_CONFIG, "accepted BusyBox config")
    require(digest(SOURCE_ARCHIVE) == EXPECTED_ARCHIVE_SHA256, "BusyBox source archive hash differs")
    require(digest(ACCEPTED_BUSYBOX) == EXPECTED_ACCEPTED_BUSYBOX_SHA256, "accepted BusyBox hash differs")
    require(digest(ACCEPTED_CONFIG) == EXPECTED_ACCEPTED_CONFIG_SHA256, "accepted BusyBox config hash differs")
    output = options.output.resolve()
    require(not output.exists() and not output.is_symlink(), f"refusing existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="r8q-diagnostic-guard-tools-") as temporary:
        build_environment = dict(os.environ)
        build_environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
        source_root, source_manifest = extract_verified_source(SOURCE_ARCHIVE, Path(temporary))
        build_root = Path(temporary) / "busybox-build"
        build_root.mkdir()
        allnoconfig_log = Path(temporary) / "allnoconfig.log"
        run([make, "-C", str(source_root), "O=" + str(build_root), "allnoconfig"],
            allnoconfig_log, environment=build_environment)
        baseline_config_text = (build_root / ".config").read_text(encoding="utf-8")
        config_text = baseline_config_text
        baseline_config_sha256 = digest(build_root / ".config")
        baseline_values = parse_config(build_root / ".config")
        for symbol in ENABLED_SYMBOLS:
            config_text = set_bool(config_text, symbol, True)
        for symbol in DISABLED_SYMBOLS:
            config_text = set_bool(config_text, symbol, False)
        (build_root / ".config").write_text(config_text, encoding="utf-8")
        seed_config_sha256 = digest(build_root / ".config")
        seed_values = parse_config(build_root / ".config")
        seed_changes = {
            key: {"before": baseline_values.get(key, "missing"), "after": value}
            for key, value in sorted(seed_values.items())
            if baseline_values.get(key) != value
        }
        expected_changes = {
            f"CONFIG_{symbol}": {"before": baseline_values.get(f"CONFIG_{symbol}", "missing"),
                                  "after": "y"}
            for symbol in ENABLED_SYMBOLS
        }
        expected_changes.update({
            f"CONFIG_{symbol}": {"before": baseline_values.get(f"CONFIG_{symbol}", "missing"),
                                  "after": "n"}
            for symbol in DISABLED_SYMBOLS
        })
        require(seed_changes == expected_changes, f"unexpected BusyBox seed config delta: {seed_changes}")
        config_delta = {
            "schema": "r8q-diagnostic-guard-tools-config-delta/v1",
            "base": "BusyBox 1.38.0 allnoconfig",
            "baseline_sha256": baseline_config_sha256,
            "seed_sha256": seed_config_sha256,
            "enabled": list(ENABLED_SYMBOLS),
            "disabled": list(DISABLED_SYMBOLS),
            "seed_changes": seed_changes,
            "accepted_config_sha256": EXPECTED_ACCEPTED_CONFIG_SHA256,
        }
        build_log = Path(temporary) / "build.log"
        run(
            [make, "-C", str(source_root), "O=" + str(build_root), "ARCH=arm64",
             "CROSS_COMPILE=aarch64-linux-gnu-", "busybox", f"-j{options.jobs}"],
            build_log, environment=build_environment,
        )
        resolved_values = parse_config(build_root / ".config")
        resolved_changes = {
            key: {"before": baseline_values.get(key, "missing"), "after": value}
            for key, value in sorted(resolved_values.items())
            if baseline_values.get(key) != value
        }
        require(resolved_changes == expected_changes,
                f"unexpected resolved BusyBox config delta: {resolved_changes}")
        config_delta["resolved_sha256"] = digest(build_root / ".config")
        config_delta["resolved_changes"] = resolved_changes
        binary = build_root / "busybox"
        require_file(binary, "diagnostic helper BusyBox")
        applets = helper_applets(binary, qemu)
        require(applets == list(HELPER_APPLETS), f"helper applet set differs: {applets}")
        elf_result = subprocess.run([readelf, "-l", str(binary)], capture_output=True, text=True, check=False)
        require(elf_result.returncode == 0, "readelf could not inspect helper")
        require("INTERP" not in elf_result.stdout, "helper is dynamically linked")
        file_result = subprocess.run([file_tool, str(binary)], capture_output=True, text=True, check=False)
        require(file_result.returncode == 0 and "aarch64" in file_result.stdout.lower(),
                "helper is not an AArch64 executable")
        output.mkdir()
        output_binary = output / "r8q-diagnostic-busybox"
        shutil.copy2(binary, output_binary)
        output_binary.chmod(0o755)
        (output / "source-manifest.txt").write_text(source_manifest, encoding="utf-8")
        (output / "source-proof.json").write_text(
            json.dumps({
                "schema": "r8q-diagnostic-guard-tools-source-proof/v1",
                "archive": str(SOURCE_ARCHIVE),
                "archive_sha256": EXPECTED_ARCHIVE_SHA256,
                "reference_source": str(REFERENCE_SOURCE),
                "source_root": "busybox-1.38.0",
                "manifest_sha256": hashlib.sha256(source_manifest.encode()).hexdigest(),
                "entry_count": len(source_manifest.splitlines()),
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output / "config.baseline").write_text(baseline_config_text, encoding="utf-8")
        (output / "config.seed").write_text(config_text, encoding="utf-8")
        (output / "config.resolved").write_text(
            (build_root / ".config").read_text(encoding="utf-8"), encoding="utf-8"
        )
        (output / "config-delta.json").write_text(
            json.dumps(config_delta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        shutil.copy2(allnoconfig_log, output / "allnoconfig.log")
        shutil.copy2(build_log, output / "build.log")
        (output / "ELF-VERIFICATION.txt").write_text(
            "file:\n" + file_result.stdout + "readelf-program-headers:\n" + elf_result.stdout,
            encoding="utf-8",
        )
    symlink_root = output / "applet-symlinks"
    symlink_root.mkdir()
    for applet in HELPER_APPLETS:
        (symlink_root / applet).symlink_to("../r8q-diagnostic-busybox")
    compiler_version = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=False)
    provenance = {
        "schema": "r8q-diagnostic-guard-tools-provenance/v1",
        "kind": "isolated-static-busybox-helper",
        "reference_source": str(REFERENCE_SOURCE),
        "source_archive": str(SOURCE_ARCHIVE),
        "source_archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "source_manifest_sha256": digest(output / "source-manifest.txt"),
        "source_manifest_entries": len((output / "source-manifest.txt").read_text(encoding="utf-8").splitlines()),
        "accepted_busybox": str(ACCEPTED_BUSYBOX),
        "accepted_busybox_sha256": EXPECTED_ACCEPTED_BUSYBOX_SHA256,
        "accepted_config": str(ACCEPTED_CONFIG),
        "accepted_config_sha256": EXPECTED_ACCEPTED_CONFIG_SHA256,
        "config_baseline_sha256": digest(output / "config.baseline"),
        "config_seed_sha256": digest(output / "config.seed"),
        "config_resolved_sha256": digest(output / "config.resolved"),
        "compiler": compiler_version.stdout.strip(),
        "arch": "arm64",
        "cross_compile": "aarch64-linux-gnu-",
        "helper_binary": "r8q-diagnostic-busybox",
        "helper_binary_sha256": digest(output / "r8q-diagnostic-busybox"),
        "helper_binary_bytes": (output / "r8q-diagnostic-busybox").stat().st_size,
        "applets": HELPER_APPLETS,
        "runtime_install": {
            "binary": "/bin/r8q-diagnostic-busybox",
            "symlinks": [f"/bin/{applet}" for applet in HELPER_APPLETS],
            "preserve": "/bin/busybox and all existing applet links",
        },
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and not path.is_symlink():
            checksums.append(f"{digest(path)}  {path.relative_to(output).as_posix()}")
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--jobs", type=int, default=2)
    options = parser.parse_args()
    require(options.jobs > 0, "jobs must be positive")
    try:
        output = build(options)
    except BuildError as error:
        parser.error(str(error))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
