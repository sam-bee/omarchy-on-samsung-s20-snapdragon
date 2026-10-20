#!/usr/bin/env python3
"""Mock-only protocol tests for the diagnostic initramfs fallback guard."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "initramfs/r8q-diagnostic-fallback.sh"
NONCE = "0123456789abcdef0123456789abcdef"
TAG = "diag1-rcu-20261020"
PARTUUID = "5594c694-c871-4b5f-90b1-690a6f68e0f7"
EFI_REL = "EFI/BOOT/BOOTAA64.EFI"
DTB_REL = "EFI/BOOT/R8Q-RTC.DTB"
ACCEPTED = b"accepted-efi-fixture"
DTB = b"dtb-fixture"
CANDIDATE = b"candidate-efi-fixture"
ACCEPTED_SHA256 = hashlib.sha256(ACCEPTED).hexdigest()
DTB_SHA256 = hashlib.sha256(DTB).hexdigest()
CANDIDATE_SHA256 = hashlib.sha256(CANDIDATE).hexdigest()


class GuardFixture:
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="r8q-diagnostic-fallback-")
        self.root = Path(self.tempdir.name)
        self.cache = self.root / "cache"
        self.cache_boot = self.cache / "EFI/BOOT"
        self.cache_boot.mkdir(parents=True)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.mount = self.cache
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.mounts = self.proc / "mounts"
        self.mounts.write_text("", encoding="utf-8")
        self.mountinfo = self.proc / "self-mountinfo"
        self.mountinfo.write_text("", encoding="utf-8")
        self.dev = self.root / "dev"
        self.dev.mkdir()
        self.device = self.dev / "cachedev"
        self.device.write_bytes(b"node")
        self.sysfs_root = self.root / "sys/class/block"
        self.sysfs_root.mkdir(parents=True)
        self.sysfs_parent = self.root / "sys/devices/platform/fake/block/sda"
        self.sysfs_target = self.sysfs_parent / "cachedev"
        (self.sysfs_parent / "queue").mkdir(parents=True)
        self.sysfs_target.mkdir()
        (self.sysfs_target / "holders").mkdir()
        self.sysfs = self.sysfs_root / "cachedev"
        self.sysfs.symlink_to("../../devices/platform/fake/block/sda/cachedev")
        (self.sysfs / "uevent").write_text(
            "MAJOR=8\nMINOR=32\nDEVNAME=cachedev\nPARTNAME=cache\n"
            f"PARTUUID={PARTUUID}\n",
            encoding="utf-8",
        )
        (self.sysfs / "size").write_text("1228800\n", encoding="utf-8")
        (self.sysfs_parent / "queue/logical_block_size").write_text("4096\n", encoding="utf-8")
        self.config = self.root / "etc/r8q-diagnostic-fallback.conf"
        self.config.parent.mkdir(parents=True)
        self.config.write_text(
            "schema=r8q-diagnostic-fallback-config/v1\n"
            f"trial_nonce={NONCE}\n"
            f"trial_tag={TAG}\n",
            encoding="utf-8",
        )
        self.efi = self.cache / EFI_REL
        self.dtb = self.cache / DTB_REL
        self.backup = self.cache / f"EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-SAVED-{NONCE}"
        self.temp = self.cache / f"EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-RECOVERY-{NONCE}"
        self.candidate_copy = self.cache / f"EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-CANDIDATE-{NONCE}"
        self.marker = self.cache / f"EFI/BOOT/R8Q-DIAG1-GUARD-{NONCE}.marker"
        self.marker_temp = self.cache / f"EFI/BOOT/R8Q-DIAG1-GUARD-{NONCE}.marker.tmp"
        self.dtb.write_bytes(DTB)
        self.backup.write_bytes(ACCEPTED)
        self.efi.write_bytes(CANDIDATE)
        self.write_marker("armed")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.write_mocks()

    def close(self) -> None:
        self.tempdir.cleanup()

    def write_marker(self, state: str) -> None:
        lines = [
            "schema=r8q-diagnostic-fallback-marker/v1",
            f"state={state}",
            f"nonce={NONCE}",
            f"tag={TAG}",
            f"candidate_sha256={CANDIDATE_SHA256}",
            f"candidate_bytes={len(CANDIDATE)}",
            f"accepted_sha256={ACCEPTED_SHA256}",
            f"accepted_bytes={len(ACCEPTED)}",
            f"cache_partuuid={PARTUUID}",
            "cache_partname=cache",
            "cache_bytes=629145600",
            "cache_logical_block_size=4096",
            "cache_fstype=vfat",
            f"efi_rel={EFI_REL}",
            f"dtb_rel={DTB_REL}",
            f"backup_rel={self.backup.relative_to(self.cache).as_posix()}",
            f"temp_rel={self.temp.relative_to(self.cache).as_posix()}",
            f"candidate_copy_rel={self.candidate_copy.relative_to(self.cache).as_posix()}",
            f"marker_rel={self.marker.relative_to(self.cache).as_posix()}",
        ]
        self.marker.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_mocks(self) -> None:
        self.write_executable(
            self.bin / "mount",
            """
            last=
            for argument in "$@"; do last=$argument; done
            case "$*" in *remount*) options=rw,nosuid,nodev,noexec ;; *) options=ro,nosuid,nodev,noexec ;; esac
            [ "${MOCK_MOUNT_FAIL:-0}" = 1 ] && exit 1
            if [ "${MOCK_MOUNT_IGNORE_TERM:-0}" = 1 ]; then
                trap ':' TERM
                while :; do :; done
            fi
            case "$*" in *remount*) [ "${MOCK_REMOUNT_FAIL:-0}" = 1 ] && exit 1 ;; esac
            mkdir -p "$last"
            printf '%s %s vfat %s 0 0\n' "$MOCK_DEVICE" "$last" "$options" > "$MOCK_MOUNTS"
            exit 0
            """,
        )
        self.write_executable(
            self.bin / "umount",
            """
            if [ "${MOCK_UMOUNT_IGNORE_TERM:-0}" = 1 ]; then
                trap ':' TERM
                while :; do :; done
            fi
            [ "${MOCK_UMOUNT_FAIL:-0}" = 1 ] && exit 1
            : > "$MOCK_MOUNTS"
            exit 0
            """,
        )
        self.write_executable(
            self.bin / "stat",
            """
            if [ "$1" = -c ] && [ "$2" = '%t:%T' ] && [ "$3" = "$MOCK_DEVICE" ]; then
                printf '8:20\n'
                exit 0
            fi
            exec /usr/bin/stat "$@"
            """,
        )
        self.write_executable(
            self.bin / "cp",
            """
            [ "${MOCK_CP_FAIL:-0}" = 1 ] && exit 1
            /bin/cp "$@" || exit $?
            if [ "${MOCK_CP_CORRUPT:-0}" = 1 ]; then
                destination=
                for argument in "$@"; do destination=$argument; done
                printf 'corrupt\n' > "$destination"
            fi
            exit 0
            """,
        )
        self.write_executable(
            self.bin / "mv",
            """
            [ "${MOCK_MV_FAIL:-0}" = 1 ] && exit 1
            /bin/mv "$@" || exit $?
            destination=
            for argument in "$@"; do destination=$argument; done
            case "$destination" in
                *marker) [ "${MOCK_MV_CORRUPT_MARKER:-0}" = 1 ] && printf 'corrupt\\n' > "$destination" ;;
                *r8q-diagnostic-fallback) [ "${MOCK_MV_CORRUPT_RECEIPT:-0}" = 1 ] && printf 'corrupt\\n' > "$destination" ;;
            esac
            exit 0
            """,
        )
        self.write_executable(self.bin / "sync", "exit 0\n")

    def write_executable(self, path: Path, body: str) -> None:
        path.write_text("#!/bin/sh\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "R8Q_GUARD_CONFIG": str(self.config),
                "R8Q_GUARD_SYSFS_ROOT": str(self.root / "sys/class/block"),
                "R8Q_GUARD_DEV_ROOT": str(self.dev),
                "R8Q_GUARD_PROC_MOUNTS": str(self.mounts),
                "R8Q_GUARD_PROC_MOUNTINFO": str(self.mountinfo),
                "R8Q_GUARD_CACHE_MOUNT": str(self.mount),
                "R8Q_GUARD_RECEIPT": str(self.run_dir / "r8q-diagnostic-fallback"),
                "R8Q_GUARD_TEST_MODE": "1",
                "R8Q_GUARD_TEST_ACCEPTED_EFI_SHA256": ACCEPTED_SHA256,
                "R8Q_GUARD_TEST_ACCEPTED_EFI_BYTES": str(len(ACCEPTED)),
                "R8Q_GUARD_TEST_DTB_SHA256": DTB_SHA256,
                "R8Q_GUARD_TEST_DTB_BYTES": str(len(DTB)),
                "MOCK_DEVICE": str(self.device),
                "MOCK_MOUNTS": str(self.mounts),
            }
        )
        environment.update(overrides)
        return environment

    def run(self, *arguments: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", str(SCRIPT), *arguments],
            env=self.environment(**overrides),
            text=True,
            capture_output=True,
            timeout=10,
        )


class ArmGuardFixture(GuardFixture):
    BASE_APPLETS = ("cat", "dirname", "grep", "mkdir", "mknod", "rm", "sleep")
    HELPER_APPLETS = ("cp", "mv", "readlink", "sha256sum", "stat")

    def __init__(self, qemu: str, accepted: Path, helper: Path) -> None:
        super().__init__()
        self.qemu = qemu
        self.accepted = accepted
        self.helper = helper
        self.device.unlink()
        self.device.symlink_to("/dev/null")
        uevent = self.sysfs / "uevent"
        uevent.write_text(
            uevent.read_text(encoding="utf-8").replace("MAJOR=8", "MAJOR=1").replace("MINOR=32", "MINOR=3"),
            encoding="utf-8",
        )
        self.arm_bin = self.root / "arm-bin"
        self.arm_bin.mkdir()
        for command in ("mount", "umount", "sync"):
            source = self.bin / command
            target = self.arm_bin / command
            target.write_text(
                source.read_text(encoding="utf-8").replace(
                    "#!/bin/sh\n", "#!/bin/sh\nPATH=/usr/bin:/bin\nexport PATH\n", 1
                ),
                encoding="utf-8",
            )
            target.chmod(0o755)
        for applet in self.BASE_APPLETS:
            self.write_qemu_launcher(applet, self.accepted)
        for applet in self.HELPER_APPLETS:
            helper_link = self.helper.parent / "applet-symlinks" / applet
            self.assert_helper_link(helper_link)
            if applet == "stat":
                self.write_qemu_stat_launcher(helper_link)
            else:
                self.write_qemu_launcher(applet, helper_link)

    def assert_helper_link(self, path: Path) -> None:
        if not path.is_symlink():
            raise RuntimeError(f"diagnostic helper applet link is missing: {path}")

    def write_qemu_launcher(self, applet: str, binary: Path) -> None:
        launcher = self.arm_bin / applet
        launcher.write_text(
            "#!/bin/sh\n"
            f"exec {shlex.quote(self.qemu)} -0 {shlex.quote(applet)} {shlex.quote(str(binary))} \"$@\"\n",
            encoding="utf-8",
        )
        launcher.chmod(0o755)

    def write_qemu_stat_launcher(self, binary: Path) -> None:
        launcher = self.arm_bin / "stat"
        launcher.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = -c ] && [ \"$2\" = '%t:%T' ] && [ \"$3\" = \"$MOCK_DEVICE\" ]; then\n"
            "    printf '1:3\\n'\n"
            "    exit 0\n"
            "fi\n"
            f"exec {shlex.quote(self.qemu)} -0 stat {shlex.quote(str(binary))} \"$@\"\n",
            encoding="utf-8",
        )
        launcher.chmod(0o755)

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = super().environment(**overrides)
        environment["PATH"] = f"{self.arm_bin}:/usr/bin:/bin"
        return environment

    def run_arm(self, *arguments: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.qemu, "-0", "busybox", str(self.accepted), "ash", str(SCRIPT), *arguments],
            env=self.environment(**overrides),
            text=True,
            capture_output=True,
            timeout=20,
        )


class DiagnosticFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = GuardFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_static_guard_has_independent_production_pins_and_no_source_or_eval(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b", source)
        self.assertIn("67631616", source)
        self.assertIn("d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca", source)
        self.assertIn("124302", source)
        self.assertNotRegex(source, r"(?m)^\s*(eval|source)(?:\s|$)")

    def test_explicit_hook_arguments_match_initramfs_config(self) -> None:
        result = self.fixture.run(
            *[
                "--nonce",
                NONCE,
                "--tag",
                TAG,
                "--expected-efi-sha256",
                ACCEPTED_SHA256,
                "--expected-dtb-sha256",
                DTB_SHA256,
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mismatched_hook_argument_is_fail_closed(self) -> None:
        result = self.fixture.run(
            "--nonce",
            NONCE,
            "--tag",
            TAG,
            "--expected-efi-sha256",
            "0" * 64,
            "--expected-dtb-sha256",
            DTB_SHA256,
        )
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_accepted_busybox_requires_explicit_helper_capabilities(self) -> None:
        qemu = shutil.which("qemu-aarch64")
        busybox = ROOT / "out/waydroid-encrypted-20261015/initramfs-preparation/initramfs/bin/busybox"
        if qemu is None or not busybox.is_file():
            self.skipTest("accepted ARM BusyBox or qemu-aarch64 is unavailable")
        result = subprocess.run([qemu, str(busybox), "--list"], text=True, capture_output=True, check=True)
        applets = set(result.stdout.splitlines())
        self.assertEqual({"cp", "mv", "readlink", "sha256sum", "stat"} - applets, {"cp", "mv", "readlink", "sha256sum", "stat"})

    def test_armed_candidate_restores_accepted_and_preserves_copies(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fixture.efi.read_bytes(), ACCEPTED)
        self.assertEqual(self.fixture.backup.read_bytes(), ACCEPTED)
        self.assertEqual(self.fixture.candidate_copy.read_bytes(), CANDIDATE)
        self.assertFalse(self.fixture.temp.exists())
        self.assertIn("state=consumed\n", self.fixture.marker.read_text(encoding="utf-8"))
        self.assertIn("cache_mount=unmounted\n", (self.fixture.run_dir / "r8q-diagnostic-fallback").read_text(encoding="utf-8"))
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

        repeated = self.fixture.run()
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(self.fixture.efi.read_bytes(), ACCEPTED)
        self.assertIn("action=idempotent\n", (self.fixture.run_dir / "r8q-diagnostic-fallback").read_text(encoding="utf-8"))
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_consumed_accepted_is_idempotent_read_only(self) -> None:
        self.fixture.efi.write_bytes(ACCEPTED)
        self.fixture.candidate_copy.write_bytes(CANDIDATE)
        self.fixture.write_marker("consumed")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fixture.efi.read_bytes(), ACCEPTED)
        self.assertEqual(self.fixture.marker.read_text(encoding="utf-8").splitlines()[1], "state=consumed")
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_armed_accepted_finishes_consumed_after_interrupted_restore(self) -> None:
        self.fixture.efi.write_bytes(ACCEPTED)
        self.fixture.candidate_copy.write_bytes(CANDIDATE)
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("state=consumed\n", self.fixture.marker.read_text(encoding="utf-8"))

    def test_unknown_marker_is_fail_closed(self) -> None:
        self.fixture.marker.write_text(self.fixture.marker.read_text(encoding="utf-8") + "unknown=value\n", encoding="utf-8")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertIn("FAIL CLOSED", result.stderr)
        self.assertEqual(self.fixture.efi.read_bytes(), CANDIDATE)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_missing_marker_is_fail_closed(self) -> None:
        self.fixture.marker.unlink()
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertIn("FAIL CLOSED", result.stderr)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_unknown_active_hash_is_fail_closed(self) -> None:
        self.fixture.efi.write_bytes(b"unexpected")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_backup_identity_is_fail_closed(self) -> None:
        self.fixture.backup.write_bytes(b"wrong-backup")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.efi.read_bytes(), CANDIDATE)

    def test_partition_identity_is_fail_closed(self) -> None:
        uevent = self.fixture.sysfs / "uevent"
        uevent.write_text(uevent.read_text(encoding="utf-8").replace(PARTUUID, "00000000-0000-0000-0000-000000000000"), encoding="utf-8")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_existing_mount_alias_is_fail_closed(self) -> None:
        self.fixture.mountinfo.write_text(
            "36 29 8:32 / /other rw,relatime - vfat /dev/cachedev rw,relatime\n",
            encoding="utf-8",
        )
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertIn("cache-mount-alias", result.stderr)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_existing_block_holder_is_fail_closed(self) -> None:
        (self.fixture.sysfs_target / "holders/dm-0").write_text("", encoding="utf-8")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertIn("cache-holders", result.stderr)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_dtb_identity_is_fail_closed(self) -> None:
        self.fixture.dtb.write_bytes(b"wrong-dtb")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.efi.read_bytes(), CANDIDATE)

    def test_copy_failure_preserves_candidate_and_unmounts(self) -> None:
        result = self.fixture.run(MOCK_CP_FAIL="1")
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.efi.read_bytes(), CANDIDATE)
        self.assertFalse(self.fixture.candidate_copy.exists())
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_copy_readback_failure_is_fail_closed(self) -> None:
        result = self.fixture.run(MOCK_CP_CORRUPT="1")
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.efi.read_bytes(), CANDIDATE)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_marker_rename_failure_is_fail_closed(self) -> None:
        self.fixture.efi.write_bytes(ACCEPTED)
        self.fixture.candidate_copy.write_bytes(CANDIDATE)
        self.fixture.write_marker("armed")
        result = self.fixture.run(MOCK_MV_FAIL="1")
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.efi.read_bytes(), ACCEPTED)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_marker_readback_failure_is_fail_closed(self) -> None:
        result = self.fixture.run(MOCK_MV_CORRUPT_MARKER="1")
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.efi.read_bytes(), ACCEPTED)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_receipt_readback_failure_is_fail_closed(self) -> None:
        result = self.fixture.run(MOCK_MV_CORRUPT_RECEIPT="1")
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_unmount_failure_is_reported_and_does_not_claim_success(self) -> None:
        result = self.fixture.run(MOCK_UMOUNT_FAIL="1")
        self.assertEqual(result.returncode, 111)
        self.assertIn("FAIL CLOSED", result.stderr)

    def test_mount_timeout_and_mount_failure_are_bounded_failures(self) -> None:
        result = self.fixture.run(MOCK_MOUNT_FAIL="1")
        self.assertEqual(result.returncode, 111)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_ignored_term_mount_is_killed_without_unbounded_wait(self) -> None:
        started = time.monotonic()
        result = self.fixture.run(
            MOCK_MOUNT_IGNORE_TERM="1",
            R8Q_GUARD_TEST_ASYNC_MOUNT="1",
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 111)
        self.assertLess(elapsed, 8)
        self.assertIn("exceeded bounded deadline", result.stderr)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")

    def test_ignored_term_unmount_is_killed_without_retry_loop(self) -> None:
        started = time.monotonic()
        result = self.fixture.run(
            MOCK_UMOUNT_IGNORE_TERM="1",
            R8Q_GUARD_TEST_ASYNC_MOUNT="1",
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 111)
        self.assertLess(elapsed, 12)
        self.assertIn("exceeded bounded deadline", result.stderr)


class DiagnosticFallbackArmTests(unittest.TestCase):
    def setUp(self) -> None:
        qemu = shutil.which("qemu-aarch64")
        accepted = ROOT / "out/waydroid-encrypted-20261015/initramfs-preparation/initramfs/bin/busybox"
        helper = ROOT / "out/diagnostic-kernel-20261020/guard-tools/r8q-diagnostic-busybox"
        if qemu is None or not accepted.is_file() or not helper.is_file():
            self.skipTest("qemu-aarch64, accepted BusyBox, or diagnostic helper is unavailable")
        self.fixture = ArmGuardFixture(qemu, accepted, helper)

    def tearDown(self) -> None:
        if hasattr(self, "fixture"):
            self.fixture.close()

    def test_actual_arm_busybox_and_helper_restore_and_repeat(self) -> None:
        result = self.fixture.run_arm()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fixture.efi.read_bytes(), ACCEPTED)
        self.assertEqual(self.fixture.candidate_copy.read_bytes(), CANDIDATE)
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")
        self.assertIn("state=consumed\n", self.fixture.marker.read_text(encoding="utf-8"))

        repeated = self.fixture.run_arm()
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(self.fixture.efi.read_bytes(), ACCEPTED)
        self.assertIn("action=idempotent\n", (self.fixture.run_dir / "r8q-diagnostic-fallback").read_text(encoding="utf-8"))
        self.assertEqual(self.fixture.mounts.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
