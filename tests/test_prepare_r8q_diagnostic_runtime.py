import importlib.util
import json
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare-r8q-diagnostic-runtime.py"
SPEC = importlib.util.spec_from_file_location("prepare_r8q_diagnostic_runtime", SCRIPT)
PREPARER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PREPARER)
FINALIZER_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/finalize-r8q-diagnostic-candidate.py"
FINALIZER_SPEC = importlib.util.spec_from_file_location("finalize_r8q_diagnostic_candidate", FINALIZER_SCRIPT)
FINALIZER = importlib.util.module_from_spec(FINALIZER_SPEC)
assert FINALIZER_SPEC.loader is not None
FINALIZER_SPEC.loader.exec_module(FINALIZER)


class DiagnosticRuntimeFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, path, data, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, mode)

    def test_staged_helper_applets_resolve_inside_bin(self):
        helper = self.root / "source" / PREPARER.GUARD_HELPER_BINARY
        self._write(helper, b"diagnostic helper\n", 0o755)
        output = self.root / "initramfs"
        output.mkdir()
        paths = PREPARER.stage_guard_helper(output, helper)
        binary = output / "bin" / PREPARER.GUARD_HELPER_BINARY
        self.assertEqual(set(paths), {f"bin/{name}" for name in PREPARER.GUARD_HELPER_LINKS})
        self.assertEqual(binary.read_bytes(), helper.read_bytes())
        for applet in PREPARER.GUARD_HELPER_LINKS:
            link = output / "bin" / applet
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(strict=True), binary.resolve(strict=True))
            self.assertEqual(os.readlink(link), PREPARER.GUARD_HELPER_BINARY)

    def test_profile_path_and_audio_release_are_rewritten(self):
        old_profile = self.root / "old-profile"
        new_profile = self.root / "new-profile"
        old_hash = "old-private-module-hash"
        new_hash = "new-private-module-hash"
        audio = old_profile / "opt/r8q-audio" / PREPARER.OLD_RELEASE / "load-r8q-audio.sh"
        config = old_profile / "etc/r8q-audio.env"
        self._write(audio, f"release={PREPARER.OLD_RELEASE}\nhash={old_hash}\n".encode(), 0o755)
        self._write(config, f"audio={PREPARER.OLD_RELEASE}\nhash={old_hash}\n".encode())
        PREPARER.profile_text_replacements(old_profile, new_profile,
                                            {"private": (old_hash, new_hash)})
        rewritten_audio = new_profile / "opt/r8q-audio" / PREPARER.RELEASE / "load-r8q-audio.sh"
        rewritten_config = new_profile / "etc/r8q-audio.env"
        self.assertTrue(rewritten_audio.is_file())
        self.assertFalse((new_profile / "opt/r8q-audio" / PREPARER.OLD_RELEASE).exists())
        self.assertIn(PREPARER.RELEASE, rewritten_audio.read_text())
        self.assertIn(new_hash, rewritten_audio.read_text())
        self.assertIn(PREPARER.RELEASE, rewritten_config.read_text())
        self.assertIn(new_hash, rewritten_config.read_text())

    def test_dispatcher_delegates_v2_and_targets_diag1_audio(self):
        dispatcher = PREPARER.profile_dispatcher()
        delegation = (f"    {PREPARER.OLD_RELEASE}|7.1.2-r8q-rtc2) exec \"$V2_DISPATCH\" "
                      "\"$ACTION\" \"$@\" ;;")
        self.assertIn(delegation, dispatcher)
        self.assertIn(f"/opt/r8q-audio/{PREPARER.RELEASE}/load-r8q-audio.sh", dispatcher)
        self.assertIn(f"/opt/r8q-audio/{PREPARER.RELEASE}/init-r8q-audio.sh", dispatcher)
        self.assertIn(f"{PREPARER.OLD_RELEASE}/rootfs/usr/local/sbin/r8q-kernel-profile-dispatch",
                      dispatcher)
        dispatcher_path = self.root / "r8q-kernel-profile-dispatch"
        self._write(dispatcher_path, dispatcher.encode(), 0o755)
        result = subprocess.run(["/bin/sh", "-n", str(dispatcher_path)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        dropins = PREPARER.dispatch_dropins()
        self.assertEqual(len(dropins), 5)
        for content in dropins.values():
            self.assertIn(f"/usr/local/lib/r8q-kernel-profiles/{PREPARER.RELEASE}/rootfs/",
                          content)

    def test_prepared_profile_references_and_checksums_are_audited(self):
        profile = self.root / "profile"
        dispatcher = profile / "usr/local/sbin/r8q-kernel-profile-dispatch"
        self._write(dispatcher, PREPARER.profile_dispatcher().encode(), 0o755)
        target_relatives = (
            "usr/local/sbin/r8q-usb-route-up.sh",
            "usr/local/sbin/r8q-battery-up.sh",
            "usr/local/sbin/r8q-usb-gadget-up.sh",
            f"opt/r8q-audio/{PREPARER.RELEASE}/load-r8q-audio.sh",
            f"opt/r8q-audio/{PREPARER.RELEASE}/init-r8q-audio.sh",
            "usr/local/sbin/r8q-wifi-standby.py",
        )
        for relative in target_relatives:
            self._write(profile / relative,
                        f"EXPECTED_RELEASE={PREPARER.RELEASE}\n".encode(), 0o755)
        helper = profile / "usr/local/sbin/r8q-usb-route-ensure.sh"
        protocol = profile / "usr/local/lib/r8q-usb-route/protocol-binding.env"
        self._write(helper, b"helper\n", 0o755)
        self._write(protocol, b"protocol\n")
        self._write(profile / "etc/r8q-usb-route.env", (
            f"EXPECTED_HELPER_SHA256={PREPARER.digest(helper)}\n"
            f"EXPECTED_PROTOCOL_SHA256={PREPARER.digest(protocol)}\n").encode())
        battery_dir = profile / f"usr/local/lib/r8q-battery/{PREPARER.RELEASE}"
        battery_modules = {
            "MAX17042_SHA256": battery_dir / "max17042_battery.ko",
            "MAX77705_SHA256": battery_dir / "max77705.ko",
            "MAX77705_CHARGER_SHA256": battery_dir / "max77705_charger.ko",
        }
        for path in battery_modules.values():
            self._write(path, path.name.encode())
        battery_script = profile / "usr/local/sbin/r8q-battery-up.sh"
        battery_text = "\n".join(f"{key}={PREPARER.digest(path)}"
                                  for key, path in battery_modules.items()) + "\n"
        self._write(battery_script, battery_text.encode(), 0o755)
        audio_dir = profile / f"opt/r8q-audio/{PREPARER.RELEASE}"
        audio_module = audio_dir / "fixture-audio.ko"
        self._write(audio_module, b"audio module\n")
        audio_hash = PREPARER.digest(audio_module)
        self._write(audio_dir / "module-hashes.sha256",
                    f"{audio_hash}  {audio_module.name}\n".encode())
        self._write(audio_dir / "module-load-order.tsv",
                    f"order\tmodule\tsource_artifact\tsha256\tprivate_artifact\twhy\n"
                    f"1\tfixture_audio\tfixture\t{audio_hash}\t{audio_module.name}\tfixture\n".encode())
        PREPARER.audit_prepared_profile(profile)
        helper.write_bytes(b"changed\n")
        with self.assertRaises(PREPARER.PreparationError):
            PREPARER.audit_prepared_profile(profile)

    def test_generated_initramfs_manifest_matches_finalizer_inventory(self):
        accepted = self.root / "accepted-initramfs"
        old_module_root = accepted / "lib/modules" / PREPARER.OLD_RELEASE / "r8q-encryption"
        source_module_root = self.root / "diag1-modules"
        modules = {}
        for name in PREPARER.MODULE_NAMES:
            basename = "i2c-qcom-geni.ko" if name == "i2c_qcom_geni" else f"{name}.ko"
            old_module = old_module_root / basename
            new_module = source_module_root / basename
            self._write(old_module, f"old-{name}\n".encode(), 0o744)
            self._write(new_module, f"new-{name}\n".encode(), 0o664)
            modules[name] = new_module
        init_text = ("mount -t tmpfs none /run 2>/dev/null || fail_closed run-mount\n"
                     "systemd-udevd\ncryptsetup isLuks\n")
        self._write(accepted / "init", init_text.encode(), 0o755)
        self._write(accepted / "etc/r8q-encryption-manifest.json",
                    json.dumps({"fail_closed": True}).encode())
        guard = self.root / "guard.sh"
        self._write(guard, b"#!/bin/sh\nexit 0\n", 0o755)
        helper_root = self.root / "guard-tools"
        helper = helper_root / PREPARER.GUARD_HELPER_BINARY
        self._write(helper, b"helper\n", 0o755)
        for applet in PREPARER.GUARD_HELPER_LINKS:
            link = helper_root / "applet-symlinks" / applet
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to("../" + PREPARER.GUARD_HELPER_BINARY)
        kernel_output = self.root / "kernel"
        stage_manifest = kernel_output / "stage1-manifest.json"
        self._write(stage_manifest, b"stage1\n")
        options = type("Options", (), {
            "kernel_output": kernel_output,
            "accepted_initramfs": accepted,
            "guard_script": guard,
            "guard_helper": helper_root,
            "guard_nonce": "0123456789abcdef0123456789abcdef",
            "guard_tag": "r8q-diag1-fixture",
            "output": self.root / "generated" / "initramfs",
        })()
        stage = {"kernel_release": PREPARER.RELEASE}

        def resolve_module(_root, name, _basename):
            return modules[name]

        def module_identity(path, name):
            return {"name": name, "path": str(path), "bytes": path.stat().st_size,
                    "sha256": PREPARER.digest(path), "vermagic": PREPARER.VERMAGIC,
                    "module_name": name}

        with mock.patch.object(PREPARER, "stage1_manifest", return_value=stage), \
                mock.patch.object(PREPARER, "locate_module_root", return_value=source_module_root), \
                mock.patch.object(PREPARER, "resolve_module", side_effect=resolve_module), \
                mock.patch.object(PREPARER, "module_identity", side_effect=module_identity):
            output = PREPARER.prepare_initramfs(options)
        manifest = json.loads((output / "etc/r8q-encryption-manifest.json").read_text())
        self.assertEqual(manifest["stage1"]["path"], str(stage_manifest))
        self.assertEqual(manifest["stage1"]["manifest_sha256"], PREPARER.digest(stage_manifest))
        for relative, row in manifest["files"].items():
            self.assertEqual(row["source"], relative)
            self.assertIn("mode", row)
            self.assertEqual(row["bytes"], row["size"])
        FINALIZER.runtime_manifest_file_inventory(output, manifest)

    def test_hardware_provenance_declares_accepted_boot_pins(self):
        accepted_rootfs = self.root / "accepted-rootfs"
        bundle_manifest = accepted_rootfs.parent / "bundle-manifest.json"
        kernel_output = self.root / "kernel"
        stage1_manifest = kernel_output / "stage1-manifest.json"
        self._write(bundle_manifest, b"bundle\n")
        self._write(stage1_manifest, b"stage1\n")
        provenance = PREPARER.hardware_provenance(
            accepted_rootfs, kernel_output, self.root / "modules", [], {}, {})
        self.assertEqual(provenance["accepted_efi_sha256"], PREPARER.ACCEPTED_EFI_SHA256)
        self.assertEqual(provenance["accepted_dtb_sha256"], PREPARER.ACCEPTED_DTB_SHA256)


if __name__ == "__main__":
    unittest.main()
