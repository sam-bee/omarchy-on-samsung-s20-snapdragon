import hashlib
import importlib.util
import json
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install-r8q-diagnostic-ab.py"
SPEC = importlib.util.spec_from_file_location("install_r8q_diagnostic_ab", SCRIPT)
AB = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AB)


class DiagnosticABFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.cache = self.root / "cache"
        self.candidate = self.root / "candidate"
        self.baseline = self.root / "protected-baseline-523.json"
        self.packet = self.root / "ab-arm-packet.json"
        self.output = self.root / "deployment"
        self.original = {
            name: getattr(AB, name)
            for name in ("EFI_SHA256", "EFI_BYTES", "DTB_SHA256", "DTB_BYTES",
                         "ORIGINAL_CANDIDATE_SHA256", "ORIGINAL_CANDIDATE_BYTES",
                         "ORIGINAL_CANDIDATE_MANIFEST_SHA256", "CACHE_BASELINE_SHA256")
        }
        self.accepted = b"accepted-efi"
        self.dtb = b"accepted-dtb"
        self.old_candidate = b"old-candidate"
        self.new_candidate = b"new-candidate"
        AB.EFI_SHA256 = hashlib.sha256(self.accepted).hexdigest()
        AB.EFI_BYTES = len(self.accepted)
        AB.DTB_SHA256 = hashlib.sha256(self.dtb).hexdigest()
        AB.DTB_BYTES = len(self.dtb)
        AB.ORIGINAL_CANDIDATE_SHA256 = hashlib.sha256(self.old_candidate).hexdigest()
        AB.ORIGINAL_CANDIDATE_BYTES = len(self.old_candidate)
        AB.ORIGINAL_CANDIDATE_MANIFEST_SHA256 = "a" * 64
        AB.SUPPORT_MODULE.PROTECTED_MANIFEST_SHA256 = hashlib.sha256(b"old-410-manifest\n").hexdigest()
        self.nonce = "0123456789abcdef0123456789abcdef"
        self.tag = "r8q-diag1-fixture"
        self.revision = "ab01"
        self._make_target_and_baseline()
        self._make_candidate()
        self._make_cache()
        self._make_packet()

    def tearDown(self):
        for name, value in self.original.items():
            setattr(AB, name, value)
        AB.SUPPORT_MODULE.PROTECTED_MANIFEST_SHA256 = (
            "1b63409d3e1cb9662d8f97bdbe59b53d06b967979967d18218ddd7280251922b")
        self.temporary.cleanup()

    def _write(self, path, data, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _make_target_and_baseline(self):
        self.target.mkdir()
        rows = {}
        lines = []
        for index in range(523):
            relative = f"baseline/file-{index:03d}"
            data = f"baseline-{index:03d}\n".encode()
            path = self.target / relative
            self._write(path, data)
            digest = hashlib.sha256(data).hexdigest()
            rows["/" + relative] = {
                "kind": "file", "bytes": len(data), "mode": 0o644,
                "uid": path.stat().st_uid, "gid": path.stat().st_gid, "sha256": digest,
            }
            lines.append(f"{digest}  /{relative}\n")
        manifest_text = "".join(lines)
        manifest_path = self.target / AB.PROTECTED_MANIFEST.lstrip("/")
        self._write(manifest_path, manifest_text.encode(), 0o600)
        old_backup = self.target / "root/old-manifest-backup"
        self._write(old_backup, b"old-410-manifest\n", 0o600)
        journal_path = self.target / "root/original-journal.json"
        plan_path = self.target / "root/original-plan.json"
        journal = {
            "schema": "r8q-diagnostic-root-transaction/v1", "state": "committed",
            "release": AB.RELEASE, "current_release": AB.ORIGINAL_RELEASE,
            "nonce": self.nonce, "tag": self.tag,
            "journal_path": "/root/original-journal.json", "plan_path": "/root/original-plan.json",
        }
        plan = {
            "schema": "r8q-diagnostic-root-transaction-plan/v1", "state": "prepared",
            "release": AB.RELEASE, "current_release": AB.ORIGINAL_RELEASE,
            "nonce": self.nonce, "tag": self.tag,
            "journal_path": "/root/original-journal.json", "plan_path": "/root/original-plan.json",
        }
        self._write(journal_path, (json.dumps(journal, sort_keys=True) + "\n").encode(), 0o600)
        self._write(plan_path, (json.dumps(plan, sort_keys=True) + "\n").encode(), 0o600)
        metadata = {
            "schema": AB.BASELINE_SCHEMA, "current_release": AB.RELEASE,
            "manifest_path": AB.PROTECTED_MANIFEST,
            "manifest_sha256": hashlib.sha256(manifest_text.encode()).hexdigest(),
            "manifest_text": manifest_text, "files": rows,
            "manifest_mode": 0o600, "manifest_uid": manifest_path.stat().st_uid,
            "manifest_gid": manifest_path.stat().st_gid,
            "boot_id": "fixture-boot-id",
            "guard_receipt_sha256": "0" * 64,
            "old_manifest_backup_path": "/root/old-manifest-backup",
            "old_manifest_sha256": AB.SUPPORT_MODULE.PROTECTED_MANIFEST_SHA256,
            "source_journal_path": "/root/original-journal.json",
            "source_journal_sha256": hashlib.sha256(journal_path.read_bytes()).hexdigest(),
            "source_plan_path": "/root/original-plan.json",
            "source_plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        }
        self._write(self.baseline, (json.dumps(metadata, sort_keys=True) + "\n").encode())

    def _make_candidate(self):
        self._write(self.candidate / "payload/BOOTAA64.EFI", self.new_candidate, 0o600)
        self._write(self.candidate / "payload/R8Q-RTC.DTB", self.dtb, 0o600)
        manifest = {
            "kind": "r8q-diagnostic-ab-candidate", "kernel_release": AB.RELEASE,
            "deployable": True, "boot_tested": False, "accepted": False,
            "installed": False, "phone_install_performed": False,
            "guard_nonce": self.nonce, "guard_tag": self.tag,
            "base_efi_sha256": AB.EFI_SHA256, "dtb_sha256": AB.DTB_SHA256,
            "canonical_candidate_sha256": "a" * 64,
            "runtime_guard_manifest_sha256": "b" * 64,
            "runtime_provenance_sha256": "c" * 64,
            "embedded_initramfs_sha256": "d" * 64,
            "raw_initramfs_sha256": "e" * 64,
            "compressed_initramfs_sha256": "f" * 64,
            "config_delta": {"CONFIG_CMDLINE": {
                "before": "foo irqchip.gicv3_pseudo_nmi=1 bar",
                "after": "foo irqchip.gicv3_pseudo_nmi=0 bar",
            }},
            "files": {
                "payload/BOOTAA64.EFI": {"bytes": len(self.new_candidate),
                                          "sha256": hashlib.sha256(self.new_candidate).hexdigest()},
                "payload/R8Q-RTC.DTB": {"bytes": len(self.dtb),
                                         "sha256": AB.DTB_SHA256},
            },
        }
        self._write(self.candidate / "ab-candidate-manifest.json",
                    (json.dumps(manifest, sort_keys=True) + "\n").encode())

    def _marker(self, state, candidate_hash, candidate_bytes):
        paths = AB.marker_paths(self.cache, self.nonce)
        fields = {
            "schema": AB.MARKER_SCHEMA, "state": state, "nonce": self.nonce, "tag": self.tag,
            "candidate_sha256": candidate_hash, "candidate_bytes": str(candidate_bytes),
            "accepted_sha256": AB.EFI_SHA256, "accepted_bytes": str(AB.EFI_BYTES),
            "cache_partuuid": AB.CACHE_PARTUUID, "cache_partname": AB.CACHE_PARTNAME,
            "cache_bytes": str(AB.CACHE_BYTES), "cache_logical_block_size": str(AB.CACHE_BLOCK_SIZE),
            "cache_fstype": AB.CACHE_FSTYPE, "efi_rel": "EFI/BOOT/BOOTAA64.EFI",
            "dtb_rel": "EFI/BOOT/R8Q-RTC.DTB",
            "backup_rel": paths["backup"].relative_to(self.cache).as_posix(),
            "temp_rel": paths["temp"].relative_to(self.cache).as_posix(),
            "candidate_copy_rel": paths["candidate"].relative_to(self.cache).as_posix(),
            "marker_rel": paths["marker"].relative_to(self.cache).as_posix(),
        }
        self._write(paths["marker"], AB.marker_text(fields).encode(), 0o600)

    def _make_cache(self):
        self._write(self.cache / "EFI/BOOT/BOOTAA64.EFI", self.accepted, 0o600)
        self._write(self.cache / "EFI/BOOT/R8Q-RTC.DTB", self.dtb, 0o600)
        paths = AB.marker_paths(self.cache, self.nonce)
        self._write(paths["backup"], self.accepted, 0o600)
        self._write(paths["candidate"], self.old_candidate, 0o600)
        self._marker("consumed", hashlib.sha256(self.old_candidate).hexdigest(), len(self.old_candidate))
        for index in range(13):
            self._write(self.cache / f"logs/fixture-{index:02d}", f"fixture-{index:02d}\n".encode(), 0o600)
        self.cache_capture = {
            "schema": "r8q-diagnostic-ab-cache-baseline/v1",
            "files": {
                path.relative_to(self.cache).as_posix(): {
                    "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in self.cache.rglob("*") if path.is_file()
            },
            "free_bytes": 123456789,
            "marker_text": AB.marker_paths(self.cache, self.nonce)["marker"].read_text(),
            "resolved_device": "fixture-cache",
        }
        AB.CACHE_BASELINE_SHA256 = hashlib.sha256(
            (json.dumps(self.cache_capture, indent=2, sort_keys=True) + "\n").encode()).hexdigest()

    def _make_packet(self):
        packet = {
            "schema": "r8q-diagnostic-ab-arm-packet/v1", "release": AB.RELEASE,
            "current_release": AB.RELEASE, "nonce": self.nonce, "tag": self.tag,
            "rearm_revision": self.revision, "support_sha256": AB.SUPPORT_SHA256,
            "baseline_sha256": hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
            "cache_baseline": {"sha256": AB.CACHE_BASELINE_SHA256, "capture": self.cache_capture},
            "original_candidate": {
                "nonce": self.nonce, "tag": self.tag,
                "candidate_sha256": AB.ORIGINAL_CANDIDATE_SHA256,
                "candidate_bytes": AB.ORIGINAL_CANDIDATE_BYTES,
                "dependency_sha256": "a" * 64,
            },
            "runtime": {"manifest_sha256": "b" * 64, "provenance_sha256": "c" * 64,
                         "embedded_initramfs_sha256": "d" * 64,
                         "raw_initramfs_sha256": "e" * 64,
                         "compressed_initramfs_sha256": "f" * 64},
            "cache": {"partuuid": AB.CACHE_PARTUUID, "partname": AB.CACHE_PARTNAME,
                      "bytes": AB.CACHE_BYTES, "logical_block_size": AB.CACHE_BLOCK_SIZE,
                      "fstype": AB.CACHE_FSTYPE},
            "manifest_path": AB.PROTECTED_MANIFEST,
            "source_journal_path": "/root/original-journal.json",
            "source_journal_sha256": hashlib.sha256(
                (self.target / "root/original-journal.json").read_bytes()).hexdigest(),
            "source_plan_path": "/root/original-plan.json",
            "source_plan_sha256": hashlib.sha256(
                (self.target / "root/original-plan.json").read_bytes()).hexdigest(),
            "old_manifest_backup_path": "/root/old-manifest-backup",
            "old_manifest_sha256": AB.SUPPORT_MODULE.PROTECTED_MANIFEST_SHA256,
        }
        self._write(self.packet, (json.dumps(packet, sort_keys=True) + "\n").encode())

    def _archive(self):
        return AB.build_archive(self.candidate, self.baseline, self.packet,
                                self.output)

    def test_package_and_check(self):
        package = self._archive()
        transaction, efi = AB.validate_archive(Path(package["archive"]["path"]), self.baseline, self.packet)
        self.assertEqual(transaction["rearm_revision"], self.revision)
        self.assertEqual(efi, self.new_candidate)

    def test_cli_package_runs_builder_check_before_archive(self):
        with mock.patch.object(AB, "run_builder_check") as builder_check, \
                mock.patch.object(AB, "build_archive", return_value={"archive": {}}) as build_archive:
            result = AB.main(["--package", "--baseline", str(self.baseline),
                              "--packet", str(self.packet),
                              "--output", str(self.output)])
        self.assertEqual(result, 0)
        builder_check.assert_called_once_with()
        build_archive.assert_called_once()

    def test_cli_package_rejects_noncanonical_candidate(self):
        with mock.patch.object(AB, "run_builder_check") as builder_check, \
                mock.patch.object(AB, "build_archive") as build_archive:
            result = AB.main(["--package", "--candidate", str(self.candidate),
                              "--baseline", str(self.baseline), "--packet", str(self.packet),
                              "--output", str(self.output)])
        self.assertEqual(result, 2)
        builder_check.assert_not_called()
        build_archive.assert_not_called()

    def test_preflight_is_read_only(self):
        package = self._archive()
        before = sorted(path.relative_to(self.cache).as_posix() for path in self.cache.rglob("*"))
        result = AB.phone_preflight(Path(package["archive"]["path"]), self.baseline, self.packet,
                                    self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(before, sorted(path.relative_to(self.cache).as_posix() for path in self.cache.rglob("*")))

    def test_arm_archives_old_state_and_arms_new_candidate(self):
        package = self._archive()
        result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                              self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "PASS")
        paths = AB.marker_paths(self.cache, self.nonce)
        archives = AB.archived_paths(self.cache, self.nonce, self.revision)
        self.assertEqual(paths["efi"].read_bytes(), self.new_candidate)
        self.assertEqual(paths["candidate"].read_bytes(), self.new_candidate)
        self.assertEqual(paths["backup"].read_bytes(), self.accepted)
        self.assertEqual(archives["candidate"].read_bytes(), self.old_candidate)
        self.assertIn("state=armed", paths["marker"].read_text())
        self.assertTrue(archives["marker"].is_file())
        journal = self.target / f"root/r8q-diagnostic-ab-transaction-{self.revision}-{self.nonce}.json"
        self.assertEqual(json.loads(journal.read_text())["state"], "committed")

    def test_already_armed_state_fails_closed_without_mutation(self):
        package = self._archive()
        first = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                             self.target, self.cache, fixture=True)
        self.assertEqual(first["result"], "PASS")
        before = (AB.marker_paths(self.cache, self.nonce)["efi"].read_bytes(),
                  AB.marker_paths(self.cache, self.nonce)["marker"].read_bytes())
        second = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                              self.target, self.cache, fixture=True)
        self.assertEqual(second["result"], "FAIL")
        self.assertEqual(before[0], AB.marker_paths(self.cache, self.nonce)["efi"].read_bytes())
        self.assertEqual(before[1], AB.marker_paths(self.cache, self.nonce)["marker"].read_bytes())

    def test_marker_write_failure_restores_old_state(self):
        package = self._archive()
        original_write = AB.write_bytes_exclusive

        def fail_marker(path, data, mode, support):
            if path.name.endswith(".marker.tmp"):
                raise AB.InstallError("injected marker write failure")
            return original_write(path, data, mode, support)

        with mock.patch.object(AB, "write_bytes_exclusive", side_effect=fail_marker):
            result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                                  self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        paths = AB.marker_paths(self.cache, self.nonce)
        self.assertEqual(paths["efi"].read_bytes(), self.accepted)
        self.assertEqual(paths["candidate"].read_bytes(), self.old_candidate)
        self.assertIn("state=consumed", paths["marker"].read_text())

    def test_archive_collision_does_not_delete_original_state(self):
        package = self._archive()
        archive_path = AB.archived_paths(self.cache, self.nonce, self.revision)["candidate"]
        self._write(archive_path, b"preexisting collision", 0o600)
        result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                              self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        paths = AB.marker_paths(self.cache, self.nonce)
        self.assertEqual(paths["efi"].read_bytes(), self.accepted)
        self.assertEqual(paths["candidate"].read_bytes(), self.old_candidate)
        self.assertIn("state=consumed", paths["marker"].read_text())
        self.assertEqual(archive_path.read_bytes(), b"preexisting collision")

    def test_baseline_manifest_set_mismatch_fails_closed(self):
        original = self.baseline.read_bytes()
        metadata = json.loads(original)
        first = metadata["manifest_text"].splitlines(keepends=True)
        first[0] = "0" * 64 + first[0][64:]
        metadata["manifest_text"] = "".join(first)
        metadata["manifest_sha256"] = hashlib.sha256(
            metadata["manifest_text"].encode()).hexdigest()
        self.baseline.write_text(json.dumps(metadata, sort_keys=True) + "\n")
        with self.assertRaises(AB.InstallError):
            AB.validate_baseline(self.baseline)
        self.baseline.write_bytes(original)

    def test_packet_host_baseline_path_fails_closed(self):
        metadata = json.loads(self.packet.read_text())
        metadata["baseline_path"] = str(self.baseline)
        self.packet.write_text(json.dumps(metadata, sort_keys=True) + "\n")
        with self.assertRaises(AB.InstallError):
            AB.validate_packet(self.packet, self.baseline)

    def test_cache_baseline_hash_or_inventory_mismatch_fails_closed(self):
        metadata = json.loads(self.packet.read_text())
        metadata["cache_baseline"]["sha256"] = "c" * 64
        self.packet.write_text(json.dumps(metadata, sort_keys=True) + "\n")
        with self.assertRaises(AB.InstallError):
            AB.validate_packet(self.packet, self.baseline)
        metadata["cache_baseline"]["sha256"] = AB.CACHE_BASELINE_SHA256
        del metadata["cache_baseline"]["capture"]["files"]["logs/fixture-00"]
        self.packet.write_text(json.dumps(metadata, sort_keys=True) + "\n")
        with self.assertRaises(AB.InstallError):
            AB.validate_packet(self.packet, self.baseline)

    def test_stale_stage_and_restore_artifacts_fail_closed(self):
        package = self._archive()
        for name in ("BOOTAA64.EFI.R8Q-DIAG1-AB-STAGE-ab01",
                     "BOOTAA64.EFI.R8Q-DIAG1-AB-RESTORE-ab01"):
            self._write(self.cache / "EFI/BOOT" / name, b"stale", 0o600)
            result = AB.phone_preflight(Path(package["archive"]["path"]), self.baseline, self.packet,
                                        self.target, self.cache, fixture=True)
            self.assertEqual(result["result"], "FAIL")
            (self.cache / "EFI/BOOT" / name).unlink()

    def test_archive_rename_post_replace_failure_reconciles_identity(self):
        for stage in ("candidate", "marker"):
            with self.subTest(stage=stage):
                self.output = self.root / f"deployment-{stage}"
                package = self._archive()
                original_rename = AB.rename_owned

                def fail_after_replace(source, destination, support):
                    if ((stage == "candidate" and "CANDIDATE" in source.name and
                         "AB-ARCHIVE" in destination.name) or
                            (stage == "marker" and source.name.endswith(".marker") and
                             "AB-ARCHIVE" in destination.name)):
                        os.replace(source, destination)
                        raise OSError("injected post-replace archive failure")
                    return original_rename(source, destination, support)

                with mock.patch.object(AB, "rename_owned", side_effect=fail_after_replace):
                    result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                                          self.target, self.cache, fixture=True)
                self.assertEqual(result["result"], "FAIL")
                self.assertFalse(result["recovery_required"])
                paths = AB.marker_paths(self.cache, self.nonce)
                self.assertEqual(paths["efi"].read_bytes(), self.accepted)
                self.assertEqual(paths["candidate"].read_bytes(), self.old_candidate)
                self.assertIn("state=consumed", paths["marker"].read_text())

    def test_efi_publish_failure_rolls_back_old_state(self):
        package = self._archive()
        original_replace = os.replace

        def fail_efi(source, destination):
            if Path(source).name.endswith("RECOVERY-" + self.nonce) and Path(destination).name == "BOOTAA64.EFI":
                raise OSError("injected EFI publish failure")
            return original_replace(source, destination)

        with mock.patch.object(AB.os, "replace", side_effect=fail_efi):
            result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                                  self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        paths = AB.marker_paths(self.cache, self.nonce)
        self.assertEqual(paths["efi"].read_bytes(), self.accepted)
        self.assertEqual(paths["backup"].read_bytes(), self.accepted)
        self.assertEqual(paths["candidate"].read_bytes(), self.old_candidate)
        self.assertIn("state=consumed", paths["marker"].read_text())

    def test_efi_restore_failure_preserves_armed_state_and_recovery_artifacts(self):
        package = self._archive()
        original_copy = AB.SUPPORT_MODULE.copy_exclusive
        original_write = AB.SUPPORT_MODULE.write_transaction_json

        def fail_restore(source, destination, mode, owned):
            if Path(destination).name.startswith("BOOTAA64.EFI.R8Q-DIAG1-AB-RESTORE-"):
                raise AB.InstallError("injected accepted EFI restore failure")
            return original_copy(source, destination, mode, owned)

        def fail_receipt(path, value, owned):
            if path.name.startswith("r8q-diagnostic-ab-receipt-"):
                raise AB.InstallError("injected receipt failure")
            return original_write(path, value, owned)

        with mock.patch.object(AB.SUPPORT_MODULE, "write_transaction_json", side_effect=fail_receipt), \
                mock.patch.object(AB.SUPPORT_MODULE, "copy_exclusive", side_effect=fail_restore):
            result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                                  self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertTrue(result["recovery_required"])
        paths = AB.marker_paths(self.cache, self.nonce)
        archives = AB.archived_paths(self.cache, self.nonce, self.revision)
        self.assertEqual(paths["efi"].read_bytes(), self.new_candidate)
        self.assertEqual(paths["candidate"].read_bytes(), self.new_candidate)
        self.assertIn("state=armed", paths["marker"].read_text())
        self.assertTrue(archives["candidate"].is_file())
        self.assertTrue(archives["marker"].is_file())
        journal = self.target / f"root/r8q-diagnostic-ab-transaction-{self.revision}-{self.nonce}.json"
        self.assertEqual(json.loads(journal.read_text())["state"], "recovery-required")

    def test_post_unmount_receipt_failure_remounts_and_rolls_back(self):
        package = self._archive()
        original_write = AB.SUPPORT_MODULE.write_transaction_json

        def fail_receipt(path, value, owned):
            if path.name.startswith("r8q-diagnostic-ab-receipt-"):
                raise AB.InstallError("injected receipt failure")
            return original_write(path, value, owned)

        with mock.patch.object(AB.SUPPORT_MODULE, "write_transaction_json", side_effect=fail_receipt):
            result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                                  self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertFalse(result["recovery_required"])
        paths = AB.marker_paths(self.cache, self.nonce)
        archives = AB.archived_paths(self.cache, self.nonce, self.revision)
        self.assertEqual(paths["efi"].read_bytes(), self.accepted)
        self.assertEqual(paths["candidate"].read_bytes(), self.old_candidate)
        self.assertIn("state=consumed", paths["marker"].read_text())
        self.assertFalse(archives["candidate"].exists())
        self.assertFalse(archives["marker"].exists())
        journal = self.target / f"root/r8q-diagnostic-ab-transaction-{self.revision}-{self.nonce}.json"
        self.assertEqual(json.loads(journal.read_text())["state"], "rolled-back")

    def test_unmount_failure_rolls_back_and_preserves_journal(self):
        package = self._archive()
        original_unmount = AB.unmount_cache_for_mode
        calls = []

        def fail_once(cache_mount, mounted, fixture):
            calls.append(1)
            if len(calls) == 1:
                raise AB.InstallError("injected unmount failure")
            return original_unmount(cache_mount, mounted, fixture)

        with mock.patch.object(AB, "unmount_cache_for_mode", side_effect=fail_once):
            result = AB.phone_arm(Path(package["archive"]["path"]), self.baseline, self.packet,
                                  self.target, self.cache, fixture=True)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(AB.marker_paths(self.cache, self.nonce)["efi"].read_bytes(), self.accepted)
        self.assertTrue((self.target / f"root/r8q-diagnostic-ab-transaction-{self.revision}-{self.nonce}.json").exists())


if __name__ == "__main__":
    unittest.main()
