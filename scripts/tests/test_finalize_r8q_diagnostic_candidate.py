#!/usr/bin/env python3
"""Offline fixtures for the bounded diagnostic candidate finalizer."""

from __future__ import annotations

import hashlib
import gzip
import json
import os
from pathlib import Path
import runpy
import stat
import struct
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/finalize-r8q-diagnostic-candidate.py"
MODULE = runpy.run_path(str(HELPER), run_name="r8q_finalizer_test_module")


def pad(data: bytes) -> bytes:
    return data + b"\0" * ((-len(data)) & 3)


def cpio_record(name: str, mode: int, content: bytes = b"", major: int = 0,
                minor: int = 0, uid: int = 0, gid: int = 0) -> bytes:
    name_bytes = name.encode() + b"\0"
    fields = (0, mode, uid, gid, 1, 0, len(content), 0, 0, major, minor,
              len(name_bytes), 0)
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    data = header + name_bytes
    data = pad(data)
    return pad(data + content)


def cpio_archive(records: list[bytes]) -> bytes:
    return b"".join(records) + cpio_record("TRAILER!!!", 0)


class FinalizerFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_embedded_image_fixture(self, cpio: bytes) -> Path:
        output = self.root / "kernel"
        (output / "arch/arm64/boot").mkdir(parents=True)
        (output / "payload").mkdir()
        (output / "usr").mkdir()
        compressed = gzip.compress(cpio)
        initramfs_offset = 0x200
        image_size = max(initramfs_offset + len(compressed), 0x400)
        image_data = bytearray(image_size)
        image_data[:2] = b"MZ"
        struct.pack_into("<Q", image_data, 16, image_size)
        image_data[56:60] = b"ARM\x64"
        pe_offset = 0x100
        struct.pack_into("<I", image_data, 60, pe_offset)
        image_data[pe_offset:pe_offset + 4] = b"PE\0\0"
        struct.pack_into("<H", image_data, pe_offset + 4, 0xAA64)
        struct.pack_into("<H", image_data, pe_offset + 24 + 68, 10)
        image_data[initramfs_offset:initramfs_offset + len(compressed)] = compressed
        image = output / "arch/arm64/boot/Image"
        image.write_bytes(image_data)
        (output / "payload/BOOTAA64.EFI").write_bytes(image_data)
        (output / "usr/initramfs_inc_data").write_bytes(compressed)
        (output / "vmlinux").write_bytes(b"fixture")
        return output

    def inspect_embedded_image(self, output: Path, expected_cpio: bytes | None = None) -> dict:
        with mock.patch.object(MODULE["shutil"], "which", return_value="llvm-nm"), \
                mock.patch.object(
                    MODULE["subprocess"], "check_output",
                    return_value="0000000000000000 T _text\n"
                    "0000000000000200 T __initramfs_start\n"):
            return MODULE["inspect_image"](output, expected_cpio)

    def test_accepted_early_module_layout_uses_fts5cu56a(self) -> None:
        accepted_root = ROOT / "out/waydroid-encrypted-20261015/initramfs-preparation/initramfs"
        module_root = accepted_root / "lib/modules/7.1.2-r8q-waydroid2/r8q-encryption"
        expected = {"gpi.ko", "i2c-qcom-geni.ko", "fts5cu56a.ko", "zinitix.ko"}
        self.assertEqual({path.name for path in module_root.glob("*.ko")}, expected)
        self.assertEqual(MODULE["MODULE_BASENAMES"]["fts5cu56a"], "fts5cu56a.ko")

    def test_parse_newc_accepts_regular_record(self) -> None:
        data = cpio_archive([cpio_record("etc/test", stat.S_IFREG | 0o644, b"ok")])
        records = MODULE["parse_newc"](data)
        self.assertEqual(records["etc/test"]["bytes"], 2)
        self.assertEqual(records["etc/test"]["sha256"], hashlib.sha256(b"ok").hexdigest())

    def test_parse_newc_rejects_truncated_archive(self) -> None:
        data = cpio_archive([cpio_record("etc/test", stat.S_IFREG | 0o644, b"ok")])[:-20]
        with self.assertRaises(SystemExit):
            MODULE["parse_newc"](data)

    def test_parse_newc_rejects_unsafe_path(self) -> None:
        data = cpio_archive([cpio_record("../escape", stat.S_IFREG | 0o644, b"bad")])
        with self.assertRaises(SystemExit):
            MODULE["parse_newc"](data)

    def test_parse_newc_rejects_conflicting_duplicate(self) -> None:
        data = cpio_archive([
            cpio_record("etc/test", stat.S_IFREG | 0o644, b"one"),
            cpio_record("etc/test", stat.S_IFREG | 0o644, b"two"),
        ])
        with self.assertRaises(SystemExit):
            MODULE["parse_newc"](data)

    def test_parse_newc_rejects_identical_duplicate(self) -> None:
        record = cpio_record("etc/test", stat.S_IFREG | 0o644, b"same")
        with self.assertRaises(SystemExit):
            MODULE["parse_newc"](cpio_archive([record, record]))

    def test_expected_archive_rejects_devnode_directory_overlap(self) -> None:
        runtime = self.root / "runtime"
        (runtime / "dev").mkdir(parents=True)
        with self.assertRaises(SystemExit):
            MODULE["expected_archive"](runtime)

    def test_expected_archive_records_symlink_and_file(self) -> None:
        runtime = self.root / "runtime"
        (runtime / "etc").mkdir(parents=True)
        (runtime / "etc/value").write_bytes(b"value")
        (runtime / "etc/link").symlink_to("value")
        records = MODULE["expected_archive"](runtime)
        self.assertIn("dev/console", records)
        self.assertEqual(records["etc/value"]["sha256"], hashlib.sha256(b"value").hexdigest())
        self.assertEqual(records["etc/link"]["sha256"], hashlib.sha256(b"value\0").hexdigest())
        self.assertEqual(records["etc/link"]["bytes"], 6)

    def test_expected_symlink_matches_kernel_newc_encoding(self) -> None:
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "helper").symlink_to("r8q-diagnostic-busybox")
        expected = MODULE["expected_archive"](runtime)["helper"]
        archive = cpio_archive([
            cpio_record("helper", stat.S_IFLNK | 0o777, b"r8q-diagnostic-busybox\0"),
        ])
        actual = MODULE["parse_newc"](archive)["helper"]
        self.assertEqual(actual, expected)

    def make_runtime_binding_fixture(self) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
        runtime = self.root / "runtime"
        module_root = runtime / "lib/modules" / MODULE["RELEASE"] / "r8q-encryption"
        module_root.mkdir(parents=True)
        (runtime / "etc").mkdir(parents=True)
        guard = runtime / "r8q-diagnostic-fallback.sh"
        guard.write_text("#!/bin/busybox ash\n", encoding="utf-8")
        os.chmod(guard, 0o755)
        helper = runtime / "bin/r8q-diagnostic-fallback-helper"
        helper.parent.mkdir(parents=True)
        helper_data = bytearray(64)
        helper_data[:4] = b"\x7fELF"
        helper_data[4:6] = b"\x02\x01"
        struct.pack_into("<H", helper_data, 18, 183)
        helper.write_bytes(helper_data)
        os.chmod(helper, 0o755)
        helper_links = {}
        for name in MODULE["GUARD_HELPER_LINKS"]:
            link = runtime / "bin" / name
            link.symlink_to(helper.name)
            helper_links[name] = f"bin/{helper.name}"
        helper_metadata = {
            "path": f"bin/{helper.name}",
            "sha256": MODULE["digest"](helper),
            "bytes": helper.stat().st_size,
            "symlinks": helper_links,
        }
        nonce = "0123456789abcdef0123456789abcdef"
        tag = "r8q-diag1-test"
        init = runtime / "init"
        hook = "\n".join([
            "DIAGNOSTIC_GUARD=/r8q-diagnostic-fallback.sh",
            f"DIAGNOSTIC_GUARD_NONCE={nonce!r}",
            f"DIAGNOSTIC_GUARD_TAG={tag!r}",
            f"DIAGNOSTIC_EXPECTED_EFI_SHA256={MODULE['EFI_SHA256']!r}",
            f"DIAGNOSTIC_EXPECTED_DTB_SHA256={MODULE['DTB_SHA256']!r}",
            '[ -x "$DIAGNOSTIC_GUARD" ] || fail_closed diagnostic-guard-missing',
            '"$DIAGNOSTIC_GUARD" --nonce "$DIAGNOSTIC_GUARD_NONCE" --tag "$DIAGNOSTIC_GUARD_TAG" --expected-efi-sha256 "$DIAGNOSTIC_EXPECTED_EFI_SHA256" --expected-dtb-sha256 "$DIAGNOSTIC_EXPECTED_DTB_SHA256" || fail_closed diagnostic-guard',
            "",
        ])
        init.write_text("mount -t tmpfs -o mode=0755 tmpfs /run 2>/dev/null || fail_closed run-mount\n" +
                        hook + "systemd-udevd\ncryptsetup isLuks\n", encoding="utf-8")
        os.chmod(init, 0o755)
        (runtime / "etc/r8q-diagnostic-fallback.conf").write_text(
            "schema=r8q-diagnostic-fallback-config/v1\n"
            f"trial_nonce={nonce}\ntrial_tag={tag}\n", encoding="utf-8")
        module_rows: dict[str, dict[str, str]] = {}
        stage1_dir = self.root / "kernel"
        stage_module_root = stage1_dir / "modules/lib/modules" / MODULE["RELEASE"] / "r8q-encryption"
        stage_module_root.mkdir(parents=True)
        for name, basename in MODULE["MODULE_BASENAMES"].items():
            path = module_root / basename
            path.write_bytes(name.encode())
            os.chmod(path, MODULE["ACCEPTED_EARLY_MODULE_MODE"])
            stage_path = stage_module_root / basename
            stage_path.write_bytes(path.read_bytes())
            os.chmod(stage_path, 0o664)
            module_rows[name] = {
                "path": str(stage_path),
                "sha256": MODULE["digest"](path),
                "bytes": path.stat().st_size,
                "vermagic": MODULE["VERMAGIC"],
                "module_name": name,
            }
        stage1_manifest = stage1_dir / "stage1-manifest.json"
        stage1_manifest.write_text(json.dumps({"kind": "stage1"}), encoding="utf-8")
        stage1_hash = MODULE["digest"](stage1_manifest)
        runtime_files = {}
        for relative, row in MODULE["runtime_tree_records"](runtime).items():
            if row["type"] == "file" and relative != "etc/r8q-encryption-manifest.json":
                runtime_files[relative] = {"source": relative, "sha256": row["sha256"],
                                            "size": row["bytes"], "mode": row["mode"]}
        runtime_manifest = {
            "kind": "r8q-diagnostic-initramfs-candidate",
            "kernel_release": MODULE["RELEASE"],
            "fail_closed": True,
            "diagnostic_guard": {
                "path": "/r8q-diagnostic-fallback.sh",
                "nonce": nonce,
                "tag": tag,
                "accepted_efi_sha256": MODULE["EFI_SHA256"],
                "accepted_dtb_sha256": MODULE["DTB_SHA256"],
                "sha256": MODULE["digest"](guard),
                "helper": helper_metadata,
            },
            "stage1": {"path": str(stage1_dir / "stage1-manifest.json"),
                        "manifest_sha256": stage1_hash},
            "files": runtime_files,
        }
        (runtime / "etc/r8q-encryption-manifest.json").write_text(
            json.dumps(runtime_manifest), encoding="utf-8")
        provenance = {
            "schema": "r8q-diagnostic-runtime-provenance/v1",
            "mode": "initramfs",
            "accepted_efi_sha256": MODULE["EFI_SHA256"],
            "accepted_dtb_sha256": MODULE["DTB_SHA256"],
            "stage1_manifest_sha256": stage1_hash,
            "stage1_manifest": str(stage1_dir / "stage1-manifest.json"),
            "guard": {"nonce": nonce, "tag": tag, "sha256": MODULE["digest"](guard)},
            "helper": helper_metadata,
            "modules": module_rows,
        }
        provenance_path = runtime.parent / "provenance.json"
        provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
        stage_records = {}
        for basename in MODULE["MODULE_BASENAMES"].values():
            stage_path = stage_module_root / basename
            stage_records[str(stage_path.relative_to(stage1_dir / "modules"))] = {
                "type": "file", "mode": stat.S_IMODE(stage_path.stat().st_mode),
                "bytes": stage_path.stat().st_size, "sha256": MODULE["digest"](stage_path)}
        stage = {"module_records": stage_records}
        return runtime, provenance_path, provenance, stage

    def test_validate_runtime_rejects_wrong_guard_binding(self) -> None:
        runtime, provenance_path, provenance, stage = self.make_runtime_binding_fixture()
        MODULE["validate_runtime"].__globals__["KERNEL_OUTPUT"] = self.root / "kernel"
        provenance["guard"]["tag"] = "wrong"
        provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
        with self.assertRaises(SystemExit):
            MODULE["validate_runtime"](runtime, stage, provenance_path)

    def test_validate_runtime_accepts_helper_and_module_bindings(self) -> None:
        runtime, provenance_path, _, stage = self.make_runtime_binding_fixture()
        MODULE["validate_runtime"].__globals__["KERNEL_OUTPUT"] = self.root / "kernel"
        result = MODULE["validate_runtime"](runtime, stage, provenance_path)
        self.assertEqual({row["mode"] for row in stage["module_records"].values()}, {0o664})
        self.assertEqual({row["mode"] for row in result["modules"].values()}, {0o744})
        self.assertEqual(result["helper"]["symlinks"].keys(),
                         set(MODULE["GUARD_HELPER_LINKS"]))
        self.assertEqual(set(result["modules"]), set(MODULE["MODULE_NAMES"]))

    def test_validate_runtime_rejects_runtime_module_mode_drift(self) -> None:
        runtime, provenance_path, _, stage = self.make_runtime_binding_fixture()
        MODULE["validate_runtime"].__globals__["KERNEL_OUTPUT"] = self.root / "kernel"
        module_path = (runtime / "lib/modules" / MODULE["RELEASE"] /
                       "r8q-encryption/gpi.ko")
        os.chmod(module_path, 0o664)
        manifest_path = runtime / "etc/r8q-encryption-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][f"lib/modules/{MODULE['RELEASE']}/r8q-encryption/gpi.ko"]["mode"] = 0o664
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(SystemExit):
            MODULE["validate_runtime"](runtime, stage, provenance_path)

    def test_validate_runtime_rejects_wrong_module_binding(self) -> None:
        runtime, provenance_path, provenance, stage = self.make_runtime_binding_fixture()
        MODULE["validate_runtime"].__globals__["KERNEL_OUTPUT"] = self.root / "kernel"
        provenance["modules"]["gpi"]["sha256"] = "0" * 64
        provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
        with self.assertRaises(SystemExit):
            MODULE["validate_runtime"](runtime, stage, provenance_path)

    def test_validate_runtime_rejects_runtime_file_mutation(self) -> None:
        runtime, provenance_path, _, stage = self.make_runtime_binding_fixture()
        MODULE["validate_runtime"].__globals__["KERNEL_OUTPUT"] = self.root / "kernel"
        (runtime / "init").write_text((runtime / "init").read_text() + "changed\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            MODULE["validate_runtime"](runtime, stage, provenance_path)

    def test_validate_runtime_rejects_guard_hook_after_udev(self) -> None:
        runtime, provenance_path, _, stage = self.make_runtime_binding_fixture()
        MODULE["validate_runtime"].__globals__["KERNEL_OUTPUT"] = self.root / "kernel"
        init_path = runtime / "init"
        init_text = init_path.read_text()
        mount_line, remainder = init_text.split("\n", 1)
        hook, _tail = remainder.split("systemd-udevd", 1)
        init_path.write_text(mount_line + "\nudev\n" + hook + "systemd-udevd\ncryptsetup isLuks\n",
                             encoding="utf-8")
        with self.assertRaises(SystemExit):
            MODULE["validate_runtime"](runtime, stage, provenance_path)

    def test_validate_runtime_rejects_missing_file_mode(self) -> None:
        runtime, provenance_path, _, stage = self.make_runtime_binding_fixture()
        MODULE["validate_runtime"].__globals__["KERNEL_OUTPUT"] = self.root / "kernel"
        manifest_path = runtime / "etc/r8q-encryption-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["init"].pop("mode")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(SystemExit):
            MODULE["validate_runtime"](runtime, stage, provenance_path)

    def test_inspect_image_rejects_non_arm64_payload(self) -> None:
        output = self.root / "kernel"
        (output / "arch/arm64/boot").mkdir(parents=True)
        (output / "payload").mkdir()
        (output / "arch/arm64/boot/Image").write_bytes(b"not an EFI image")
        (output / "payload/BOOTAA64.EFI").write_bytes(b"not an EFI image")
        with self.assertRaises(SystemExit):
            MODULE["inspect_image"](output)

    def test_inspect_image_stage1_expected_cpio_does_not_require_raw_file(self) -> None:
        cpio = cpio_archive([cpio_record("etc/test", stat.S_IFREG | 0o644, b"stage1")])
        output = self.make_embedded_image_fixture(cpio)
        result = self.inspect_embedded_image(output, cpio)
        self.assertEqual(result["cpio"], cpio)
        self.assertFalse((output / "usr/initramfs_data.cpio").exists())

    def test_inspect_image_stage2_requires_matching_raw_cpio(self) -> None:
        cpio = cpio_archive([cpio_record("etc/test", stat.S_IFREG | 0o644, b"stage2")])
        output = self.make_embedded_image_fixture(cpio)
        with self.assertRaises(SystemExit):
            self.inspect_embedded_image(output)
        (output / "usr/initramfs_data.cpio").write_bytes(cpio)
        result = self.inspect_embedded_image(output)
        self.assertEqual(result["cpio"], cpio)


if __name__ == "__main__":
    unittest.main(verbosity=2)
