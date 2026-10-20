import hashlib
import importlib.util
import json
from pathlib import Path
import os
import stat
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install-r8q-diagnostic-trial.py"
SPEC = importlib.util.spec_from_file_location("install_r8q_diagnostic_trial", SCRIPT)
INSTALLER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(INSTALLER)


class DiagnosticTrialFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.runtime = self.root / "runtime-preparation"
        self.target = self.root / "target"
        self.cache = self.root / "cache"
        self.baseline_path = self.root / "protected-baseline-metadata.json"
        self.output = self.root / "deployment"
        self.original_constants = {
            name: getattr(INSTALLER, name)
            for name in ("EFI_SHA256", "EFI_BYTES", "DTB_SHA256", "DTB_BYTES",
                         "PROTECTED_MANIFEST_SHA256", "MARGIN_BYTES")
        }
        accepted_efi = b"accepted-efi"
        accepted_dtb = b"accepted-dtb"
        candidate_efi = b"candidate-efi"
        INSTALLER.EFI_SHA256 = hashlib.sha256(accepted_efi).hexdigest()
        INSTALLER.EFI_BYTES = len(accepted_efi)
        INSTALLER.DTB_SHA256 = hashlib.sha256(accepted_dtb).hexdigest()
        INSTALLER.DTB_BYTES = len(accepted_dtb)
        INSTALLER.MARGIN_BYTES = 1024
        self.accepted_efi = accepted_efi
        self.accepted_dtb = accepted_dtb
        self.candidate_efi = candidate_efi
        self._make_candidate()
        self._make_runtime()
        self._make_baseline()
        self._make_target()
        self._make_cache()

    def tearDown(self):
        for name, value in self.original_constants.items():
            setattr(INSTALLER, name, value)
        self.temporary.cleanup()

    def _write(self, path, data, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _make_candidate(self):
        efi = self.candidate / "payload/BOOTAA64.EFI"
        dtb = self.candidate / "payload/R8Q-RTC.DTB"
        self._write(efi, self.candidate_efi, 0o600)
        self._write(dtb, self.accepted_dtb, 0o600)
        manifest = {
            "kind": "r8q-diagnostic-kernel-candidate",
            "kernel_release": INSTALLER.RELEASE,
            "deployable": True,
            "stage2_complete": True,
            "stage2_required": False,
            "installed": False,
            "boot_tested": False,
            "deployment_prepared": False,
            "base_efi_sha256": INSTALLER.EFI_SHA256,
            "dtb_sha256": INSTALLER.DTB_SHA256,
            "runtime_guard": {"accepted_efi_sha256": INSTALLER.EFI_SHA256,
                              "accepted_dtb_sha256": INSTALLER.DTB_SHA256,
                              "nonce": "0123456789abcdef0123456789abcdef",
                              "tag": "r8q-diag1-fixture"},
            "guard_helper": {"path": INSTALLER.GUARD_HELPER_PATH, "sha256": "0" * 64,
                              "bytes": 1,
                              "symlinks": {name: INSTALLER.GUARD_HELPER_PATH
                                           for name in INSTALLER.GUARD_HELPER_LINKS}},
            "files": {
                "payload/BOOTAA64.EFI": {"sha256": hashlib.sha256(self.candidate_efi).hexdigest(),
                                         "bytes": len(self.candidate_efi)},
                "payload/R8Q-RTC.DTB": {"sha256": INSTALLER.DTB_SHA256,
                                         "bytes": len(self.accepted_dtb)},
            },
        }
        self._write(self.candidate / "candidate-manifest.json",
                    (json.dumps(manifest, sort_keys=True) + "\n").encode())

    def _make_runtime(self):
        paths = {
            f"{INSTALLER.PROFILE_PREFIX}etc/diagnostic-profile": b"profile\n",
            f"{INSTALLER.MODULE_PREFIX}modules.dep": b"modules.dep\n",
        }
        for path in INSTALLER.DROPINS:
            paths[path] = b"[Service]\n"
        records = []
        for relative, data in sorted(paths.items()):
            destination = self.runtime / "rootfs" / relative
            self._write(destination, data, 0o644)
        accepted_rootfs = self.root / "accepted-rootfs"
        accepted_rootfs.mkdir(parents=True)
        self._write(accepted_rootfs / (
            f"usr/local/lib/r8q-kernel-profiles/{INSTALLER.CURRENT_RELEASE}/rootfs/"
            "etc/accepted-profile"), b"accepted profile\n")
        for relative, row in sorted(INSTALLER.runtime_tree_records(self.runtime / "rootfs").items()):
            record = {"path": relative, **row, "source": "generated"}
            records.append(record)
        stage_manifest = self.root / "stage1-manifest.json"
        self._write(stage_manifest, b"stage1 fixture\n")
        bundle_manifest = self.root / "bundle-manifest.json"
        self._write(bundle_manifest, b"bundle fixture\n")
        module_names = [f"module-{index:02d}" for index in range(78)]
        source_module_root = self.root / "source-modules"
        module_provenance = {}
        for name in module_names:
            source_module = source_module_root / f"{name}.ko"
            self._write(source_module, (name + "\n").encode())
            module_provenance[name] = {
                "path": str(source_module),
                "bytes": source_module.stat().st_size,
                "sha256": hashlib.sha256(source_module.read_bytes()).hexdigest(),
                "vermagic": INSTALLER.VERMAGIC,
                "module_name": name,
            }
        manifest = {"kind": "r8q-diagnostic-hardware-preparation",
                    "kernel_release": INSTALLER.RELEASE,
                    "phone_operations": False,
                    "accepted_efi_sha256": INSTALLER.EFI_SHA256,
                    "accepted_dtb_sha256": INSTALLER.DTB_SHA256,
                    "stage1_manifest": {"path": str(stage_manifest),
                                        "sha256": hashlib.sha256(stage_manifest.read_bytes()).hexdigest()},
                    "module_selection": {"accepted_count": 78,
                                          "accepted_names": module_names,
                                          "global_rows": [{"name": f"global-{index:02d}"}
                                                          for index in range(42)]},
                    "files": records}
        self._write(self.runtime / "runtime-manifest.json",
                    (json.dumps(manifest, sort_keys=True) + "\n").encode())
        provenance = {
            "schema": "r8q-diagnostic-runtime-provenance/v1",
            "mode": "hardware",
            "accepted_efi_sha256": INSTALLER.EFI_SHA256,
            "accepted_dtb_sha256": INSTALLER.DTB_SHA256,
            "accepted_rootfs": str(accepted_rootfs),
            "accepted_bundle_manifest": str(bundle_manifest),
            "accepted_bundle_manifest_sha256": hashlib.sha256(bundle_manifest.read_bytes()).hexdigest(),
            "stage1_manifest": str(stage_manifest),
            "stage1_manifest_sha256": hashlib.sha256(stage_manifest.read_bytes()).hexdigest(),
            "source_module_root": str(source_module_root),
            "module_selection_count": 78,
            "modules": module_provenance,
        }
        self._write(self.runtime / "provenance.json",
                    (json.dumps(provenance, sort_keys=True) + "\n").encode())

    def _make_baseline(self):
        rows = {}
        manifest_rows = []
        for index in range(410):
            relative = f"baseline/file-{index:03d}"
            data = f"baseline-{index:03d}\n".encode()
            self._write(self.target / relative, data)
            rows["/" + relative] = {"kind": "file", "bytes": len(data),
                                    "mode": 0o644,
                                    "uid": os.getuid(), "gid": os.getgid(),
                                    "sha256": hashlib.sha256(data).hexdigest()}
            manifest_rows.append(f"{hashlib.sha256(data).hexdigest()}  /{relative}\n")
        manifest = "".join(manifest_rows).encode()
        self._write(self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/"), manifest)
        INSTALLER.PROTECTED_MANIFEST_SHA256 = hashlib.sha256(manifest).hexdigest()
        baseline = {"schema": INSTALLER.PROTECTED_SCHEMA,
                    "manifest_sha256": INSTALLER.PROTECTED_MANIFEST_SHA256,
                    "files": rows}
        self._write(self.baseline_path,
                    (json.dumps(baseline, sort_keys=True) + "\n").encode())

    def _make_target(self):
        self.target.mkdir(parents=True, exist_ok=True)

    def _make_cache(self):
        self._write(self.cache / "EFI/BOOT/BOOTAA64.EFI", self.accepted_efi, 0o600)
        self._write(self.cache / "EFI/BOOT/R8Q-RTC.DTB", self.accepted_dtb, 0o600)

    def _archive(self):
        result = INSTALLER.build_archive(self.candidate, self.runtime, self.baseline_path,
                                         self.output / INSTALLER.ARCHIVE_NAME,
                                         expected_manifest_sha256=INSTALLER.PROTECTED_MANIFEST_SHA256,
                                         finalizer_check=False)
        return Path(result["archive"]["path"])

    def test_package_and_fixture_install_preserves_baseline(self):
        archive = self._archive()
        before = (self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")).read_bytes()
        result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["nonce"], "0123456789abcdef0123456789abcdef")
        self.assertEqual(result["tag"], "r8q-diag1-fixture")
        self.assertEqual((self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")).read_bytes()[:len(before)], before)
        for path in (self.runtime / "rootfs").rglob("*"):
            if path.is_file():
                relative = path.relative_to(self.runtime / "rootfs").as_posix()
                self.assertEqual((self.target / relative).read_bytes(), path.read_bytes())
        self.assertEqual((self.cache / "EFI/BOOT/BOOTAA64.EFI").read_bytes(), self.candidate_efi)
        marker = next(self.cache.glob("EFI/BOOT/R8Q-DIAG1-GUARD-*.marker"))
        marker_fields = dict(line.split("=", 1) for line in marker.read_text().splitlines())
        self.assertEqual(set(marker_fields), {
            "schema", "state", "nonce", "tag", "candidate_sha256", "candidate_bytes",
            "accepted_sha256", "accepted_bytes", "cache_partuuid", "cache_partname",
            "cache_bytes", "cache_logical_block_size", "cache_fstype", "efi_rel", "dtb_rel",
            "backup_rel", "temp_rel", "candidate_copy_rel", "marker_rel",
        })
        self.assertEqual(marker_fields["nonce"], result["nonce"])
        self.assertEqual(marker_fields["temp_rel"],
                         f"EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-RECOVERY-{result['nonce']}")
        saved = self.cache / f"EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-SAVED-{result['nonce']}"
        self.assertEqual(saved.read_bytes(),
                         self.accepted_efi)
        journal = self.target / f"root/r8q-diagnostic-transaction-0123456789abcdef0123456789abcdef.json"
        plan = self.target / f"root/r8q-diagnostic-transaction-0123456789abcdef0123456789abcdef.plan.json"
        journal_value = json.loads(journal.read_text())
        self.assertEqual(journal_value["state"], "committed")
        manifest_info = (self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")).stat()
        self.assertEqual(journal_value["protected_manifest_mode"], stat.S_IMODE(manifest_info.st_mode))
        self.assertEqual(journal_value["protected_manifest_uid"], manifest_info.st_uid)
        self.assertEqual(journal_value["protected_manifest_gid"], manifest_info.st_gid)
        self.assertEqual(json.loads(plan.read_text())["schema"],
                         "r8q-diagnostic-root-transaction-plan/v1")

    def test_package_runs_finalizer_for_canonical_candidate(self):
        output = self.root / "finalizer-package"
        initramfs = self.root / "initramfs"
        with mock.patch.object(INSTALLER, "DEFAULT_CANDIDATE", self.candidate), \
                mock.patch.object(INSTALLER, "run_finalizer_check") as finalizer:
            result = INSTALLER.build_archive(
                self.candidate, self.runtime, self.baseline_path,
                output / INSTALLER.ARCHIVE_NAME,
                expected_manifest_sha256=INSTALLER.PROTECTED_MANIFEST_SHA256,
                finalizer_check=True, initramfs=initramfs)
        finalizer.assert_called_once_with(initramfs.resolve())
        self.assertEqual(result["archive"]["path"], str(output / INSTALLER.ARCHIVE_NAME))

    def test_finalizer_command_receives_canonical_initramfs_path(self):
        initramfs = self.root / "initramfs"
        initramfs.mkdir()
        completed = subprocess.CompletedProcess([], 0, "{}", "")
        with mock.patch.object(INSTALLER.subprocess, "run", return_value=completed) as runner:
            INSTALLER.run_finalizer_check(initramfs)
        command = runner.call_args.args[0]
        self.assertEqual(command[command.index("--runtime-initramfs") + 1], str(initramfs.resolve()))

    def test_phone_preflight_is_read_only(self):
        archive = self._archive()
        manifest = self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")
        before_manifest = manifest.read_bytes()
        before_efi = (self.cache / "EFI/BOOT/BOOTAA64.EFI").read_bytes()
        before_dtb = (self.cache / "EFI/BOOT/R8Q-RTC.DTB").read_bytes()
        result = INSTALLER.phone_preflight(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["mode"], "phone-preflight")
        self.assertEqual(result["baseline_entries"], 410)
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual((self.cache / "EFI/BOOT/BOOTAA64.EFI").read_bytes(), before_efi)
        self.assertEqual((self.cache / "EFI/BOOT/R8Q-RTC.DTB").read_bytes(), before_dtb)
        self.assertFalse((self.target / INSTALLER.PROFILE_PREFIX).exists())
        self.assertFalse(any(self.cache.glob("EFI/BOOT/R8Q-DIAG1-*")))

    def test_phone_preflight_keeps_identity_before_mount_disappears(self):
        archive = self._archive()

        def disappear_on_unmount(cache_mount, mounted, fixture):
            for path in sorted(cache_mount.rglob("*"), key=lambda value: len(value.parts),
                                reverse=True):
                if path.is_file() or path.is_symlink():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            cache_mount.rmdir()

        with mock.patch.object(INSTALLER, "mount_cache", return_value=True), \
                mock.patch.object(INSTALLER, "unmount_cache", side_effect=disappear_on_unmount):
            result = INSTALLER.phone_preflight(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["current_efi_sha256"], INSTALLER.EFI_SHA256)
        self.assertEqual(result["current_dtb_sha256"], INSTALLER.DTB_SHA256)
        self.assertFalse(self.cache.exists())

    def test_unmount_postcheck_reports_already_unmounted(self):
        mountpoint = self.root / "mountpoint"
        mountpoint.mkdir()
        (mountpoint / "leftover").write_bytes(b"leftover")
        with mock.patch.object(INSTALLER, "run_command", return_value=""), \
                mock.patch.object(INSTALLER, "mountinfo_rows", return_value=[]):
            with self.assertRaises(INSTALLER.CacheUnmountError) as raised:
                INSTALLER.unmount_cache(mountpoint, True, fixture=False)
        self.assertTrue(raised.exception.unmounted)
        self.assertTrue(mountpoint.exists())

    def test_post_unmount_failure_does_not_retry_umount_during_rollback(self):
        archive = self._archive()
        calls = []

        def fail_after_umount(cache_mount, mounted, fixture):
            calls.append((cache_mount, mounted, fixture))
            raise INSTALLER.CacheUnmountError("mountpoint cleanup failed", True)

        with mock.patch.object(INSTALLER, "mount_cache", return_value=True), \
                mock.patch.object(INSTALLER, "unmount_cache", side_effect=fail_after_umount):
            result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(len(calls), 1)
        self.assertEqual((self.cache / "EFI/BOOT/BOOTAA64.EFI").read_bytes(), self.accepted_efi)
        self.assertFalse((self.target / f"{INSTALLER.PROFILE_PREFIX}etc/diagnostic-profile").exists())

    def test_vfat_mount_options_preserve_marker_mode(self):
        cache_device = self.root / "dev/cache"
        cache_mount = self.root / "cache-mount"
        commands = []

        def capture(command, _label):
            commands.append(command)
            return ""

        with mock.patch.object(INSTALLER, "device_major_minor", return_value="259:16"), \
                mock.patch.object(INSTALLER, "mountinfo_rows", return_value=[]), \
                mock.patch.object(INSTALLER, "verify_cache_mount"):
            with mock.patch.object(INSTALLER, "run_command", side_effect=capture):
                self.assertTrue(INSTALLER.mount_cache(cache_device, cache_mount, fixture=False))
                INSTALLER.remount_cache(cache_device, cache_mount, fixture=False)
                self.assertTrue(INSTALLER.remount_cache_for_rollback(
                    cache_device, cache_mount, fixture=False))

        mount_options = [command[command.index("-o") + 1] for command in commands
                         if "/usr/bin/mount" in command]
        self.assertEqual(len(mount_options), 4)
        for options in mount_options:
            self.assertIn("fmask=0177", options)
            self.assertIn("dmask=0077", options)
            self.assertNotIn("umask=0077", options)

    def test_fixture_mode_rejects_live_root_before_archive_or_mutation(self):
        archive = self._archive()
        with mock.patch("sys.stderr"):
            self.assertEqual(INSTALLER.main(["--phone-preflight", "--fixture",
                                             "--archive", str(archive),
                                             "--cache-mount", str(self.cache)]), 2)
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.phone_preflight(archive, Path("/"), self.cache, fixture=True)
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.phone_install(archive, Path("/"), self.cache, fixture=True)

    def test_package_fixture_cannot_bypass_finalizer(self):
        output = self.root / "package-fixture"
        with mock.patch("sys.stderr"):
            result = INSTALLER.main([
                "--package", "--fixture", "--candidate", str(self.candidate),
                "--runtime", str(self.runtime), "--protected-baseline", str(self.baseline_path),
                "--output", str(output)])
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())

    def test_fixture_mode_rejects_actual_cache_mountpoint(self):
        archive = self._archive()
        mountpoint = self.root / "cache-mount"
        mountpoint.mkdir()
        rows = [{"mountpoint": str(mountpoint.resolve())}]
        with mock.patch.object(INSTALLER, "mountinfo_rows", return_value=rows):
            with self.assertRaises(INSTALLER.InstallError):
                INSTALLER.phone_preflight(archive, self.target, mountpoint, fixture=True)

    def test_wrong_current_efi_fails_without_mutation(self):
        archive = self._archive()
        manifest = self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")
        before_manifest = manifest.read_bytes()
        efi = self.cache / "EFI/BOOT/BOOTAA64.EFI"
        efi.write_bytes(b"wrong")
        result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(efi.read_bytes(), b"wrong")
        self.assertFalse(any(self.cache.glob("EFI/BOOT/R8Q-DIAG1-*.marker")))

    def test_existing_target_rolls_back_earlier_new_file(self):
        archive = self._archive()
        existing = self.target / f"{INSTALLER.MODULE_PREFIX}modules.dep"
        self._write(existing, b"preexisting\n")
        result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        profile = self.target / f"{INSTALLER.PROFILE_PREFIX}etc/diagnostic-profile"
        self.assertFalse(profile.exists())
        self.assertEqual(existing.read_bytes(), b"preexisting\n")
        self.assertEqual((self.cache / "EFI/BOOT/BOOTAA64.EFI").read_bytes(), self.accepted_efi)

    def test_runtime_symlink_is_rejected(self):
        link = self.runtime / "rootfs" / f"{INSTALLER.PROFILE_PREFIX}etc/symlink"
        link.symlink_to("diagnostic-profile")
        manifest_path = self.runtime / "runtime-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        relative = link.relative_to(self.runtime / "rootfs").as_posix()
        row = INSTALLER.runtime_tree_records(self.runtime / "rootfs")[relative]
        manifest["files"].append({"path": relative, **row, "source": "generated"})
        self._write(manifest_path, (json.dumps(manifest, sort_keys=True) + "\n").encode())
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.validate_runtime(self.runtime)

    def test_runtime_validation_accepts_preparation_dir_and_rootfs(self):
        preparation_rows, preparation_manifest = INSTALLER.validate_runtime(self.runtime)
        rootfs_rows, rootfs_manifest = INSTALLER.validate_runtime(self.runtime / "rootfs")
        self.assertEqual(preparation_rows, rootfs_rows)
        self.assertEqual(preparation_manifest, rootfs_manifest)

    def _make_sysfs_cache_fixture(self):
        sysfs = self.root / "sys/class/block"
        device_root = self.root / "devices/mmcblk0"
        partition = device_root / "mmcblk0p1"
        (partition / "holders").mkdir(parents=True)
        (device_root / "queue").mkdir(parents=True)
        (partition / "size").write_text(str(INSTALLER.CACHE_SECTORS))
        (partition / "queue").mkdir()
        (device_root / "queue/logical_block_size").write_text(str(INSTALLER.CACHE_BLOCK_SIZE))
        (partition / "uevent").write_text(
            f"MAJOR=259\nMINOR=16\nDEVNAME=mmcblk0p1\nPARTUUID={INSTALLER.CACHE_PARTUUID}\n"
            f"PARTNAME={INSTALLER.CACHE_PARTNAME}\n")
        (device_root / "uevent").write_text("DEVNAME=mmcblk0\nDEVTYPE=disk\n")
        sysfs.mkdir(parents=True)
        (sysfs / "mmcblk0p1").symlink_to(partition)
        return sysfs

    def test_cache_sysfs_parent_queue_and_major_minor_are_pinned(self):
        sysfs = self._make_sysfs_cache_fixture()

        def fake_command(command, label):
            if "PTUUID" in command:
                return INSTALLER.DISK_GUID
            if "TYPE" in command:
                return INSTALLER.CACHE_FSTYPE
            raise AssertionError(command)

        with mock.patch.object(INSTALLER, "device_major_minor", return_value="259:16"), \
                mock.patch.object(INSTALLER, "run_command", side_effect=fake_command), \
                mock.patch.object(INSTALLER, "mountinfo_rows", return_value=[]):
            self.assertEqual(INSTALLER.locate_cache_device(sysfs), Path("/dev/mmcblk0p1"))

    def test_cache_sysfs_wrong_major_minor_fails_closed(self):
        sysfs = self._make_sysfs_cache_fixture()
        with mock.patch.object(INSTALLER, "device_major_minor", return_value="8:1"):
            with self.assertRaises(INSTALLER.InstallError):
                INSTALLER.locate_cache_device(sysfs)

    def test_final_unmount_failure_rolls_back_transaction(self):
        archive = self._archive()
        manifest = self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")
        before_manifest = manifest.read_bytes()
        original_unmount = INSTALLER.unmount_cache
        calls = []

        def fail_once(cache_mount, mounted, fixture):
            calls.append(1)
            if len(calls) == 1:
                raise INSTALLER.InstallError("injected unmount failure")
            return original_unmount(cache_mount, mounted, fixture)

        with mock.patch.object(INSTALLER, "unmount_cache", side_effect=fail_once):
            result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual((self.cache / "EFI/BOOT/BOOTAA64.EFI").read_bytes(), self.accepted_efi)
        self.assertEqual(len(calls), 1)

    def test_manifest_fsync_failure_rolls_back_append(self):
        archive = self._archive()
        manifest = self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")
        before_manifest = manifest.read_bytes()
        original_fsync = INSTALLER.fsync_path
        calls = []

        def fail_once(path):
            calls.append(path)
            if len(calls) == 1:
                raise INSTALLER.InstallError("injected manifest fsync failure")
            return original_fsync(path)

        with mock.patch.object(INSTALLER, "fsync_path", side_effect=fail_once):
            result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertFalse(any(self.cache.glob("EFI/BOOT/R8Q-DIAG1-GUARD-*.marker")))

    def test_recovery_efi_temporary_is_verified_before_replace(self):
        archive = self._archive()
        original_copy = INSTALLER.copy_exclusive

        def corrupt_recovery(source, destination, mode, owned):
            original_copy(source, destination, mode, owned)
            if "RECOVERY-" in destination.name:
                destination.write_bytes(b"corrupted recovery EFI")

        with mock.patch.object(INSTALLER, "copy_exclusive", side_effect=corrupt_recovery):
            result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual((self.cache / "EFI/BOOT/BOOTAA64.EFI").read_bytes(), self.accepted_efi)
        self.assertFalse((self.target / f"{INSTALLER.PROFILE_PREFIX}etc/diagnostic-profile").exists())

    def test_corrupt_manifest_restore_is_rejected_before_replace(self):
        archive = self._archive()
        manifest = self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")
        before_manifest = manifest.read_bytes()
        original_update = INSTALLER.update_transaction_json

        def corrupt_backup(path, value):
            original_update(path, value)
            if value.get("state") == "manifest-appended":
                backup = manifest.with_name(
                    manifest.name + ".R8Q-DIAG1-SAVED-0123456789abcdef0123456789abcdef")
                backup.write_bytes(b"corrupted protected manifest backup")
                raise INSTALLER.InstallError("injected post-manifest failure")

        with mock.patch.object(INSTALLER, "update_transaction_json", side_effect=corrupt_backup):
            result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertNotEqual(manifest.read_bytes(), before_manifest)
        self.assertTrue(any(self.target.glob(
            "root/r8q-screen-lock-20261013.sha256.R8Q-DIAG1-SAVED-*")))

    def test_rootfs_files_stage_atomically_and_dropins_are_last(self):
        archive = self._archive()
        original_write = INSTALLER.write_atomic_new
        paths = []

        def capture_write(destination, data, mode, owned, nonce):
            paths.append(destination.relative_to(self.target).as_posix())
            return original_write(destination, data, mode, owned, nonce)

        with mock.patch.object(INSTALLER, "write_atomic_new", side_effect=capture_write):
            result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "PASS")
        dropin_indexes = [index for index, path in enumerate(paths) if path in INSTALLER.DROPINS]
        profile_indexes = [index for index, path in enumerate(paths) if path.startswith(INSTALLER.PROFILE_PREFIX)]
        module_indexes = [index for index, path in enumerate(paths) if path.startswith(INSTALLER.MODULE_PREFIX)]
        self.assertTrue(dropin_indexes and profile_indexes and module_indexes)
        self.assertGreater(min(dropin_indexes), max(profile_indexes + module_indexes))
        self.assertFalse(any(".R8Q-DIAG1-STAGE-" in path for path in paths))

    def test_efi_rollback_failure_preserves_recovery_state(self):
        archive = self._archive()
        manifest = self.target / INSTALLER.PROTECTED_MANIFEST.lstrip("/")
        original_copy = INSTALLER.copy_exclusive

        def fail_restore(source, destination, mode, owned):
            if "RESTORE" in destination.name:
                raise INSTALLER.InstallError("injected EFI rollback copy failure")
            return original_copy(source, destination, mode, owned)

        with mock.patch.object(INSTALLER.os, "sync", side_effect=INSTALLER.InstallError("injected sync failure")), \
                mock.patch.object(INSTALLER, "copy_exclusive", side_effect=fail_restore):
            result = INSTALLER.phone_install(archive, self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertTrue((self.target / f"{INSTALLER.PROFILE_PREFIX}etc/diagnostic-profile").exists())
        self.assertEqual(len(INSTALLER.parse_manifest_lines(manifest.read_bytes())), 417)
        self.assertTrue(any(self.cache.glob("EFI/BOOT/R8Q-DIAG1-GUARD-*.marker")))


if __name__ == "__main__":
    unittest.main()
