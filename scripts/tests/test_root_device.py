#!/usr/bin/env python3
"""Offline identity fixtures for the r8q root-device resolver."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "rootfs/usr/local/sbin/r8q-root-device"
ROOT_UUID = "217b9308-40c7-4eb0-90a9-09ed4e233173"
USERDATA_PARTUUID = "1b81e7e6-f50d-419b-a739-2aeef8da3335"
LUKS_UUID = "11111111-2222-3333-4444-555555555555"


class RootDeviceFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="r8q-root-device-")
        self.root = Path(self.temp.name)
        self.etc = self.root / "etc"
        self.fake_bin = self.root / "bin"
        self.etc.mkdir()
        self.fake_bin.mkdir()
        self.write_fake_tools()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_fake_tools(self) -> None:
        (self.fake_bin / "findmnt").write_text(
            "#!/bin/sh\n"
            "case \" $* \" in\n"
            "  *' -o SOURCE '*) printf '%s\\n' \"$R8Q_TEST_SOURCE\" ;;\n"
            "  *' -o FSTYPE '*) printf '%s\\n' \"$R8Q_TEST_FSTYPE\" ;;\n"
            "  *' -o UUID '*) printf '%s\\n' \"$R8Q_TEST_ROOT_UUID\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        (self.fake_bin / "blkid").write_text(
            "#!/bin/sh\n"
            "case \"$2\" in\n"
            "  TYPE) printf '%s\\n' \"$R8Q_TEST_RAW_TYPE\" ;;\n"
            "  PARTUUID) printf '%s\\n' \"$R8Q_TEST_PARTUUID\" ;;\n"
            "  UUID) printf '%s\\n' \"$R8Q_TEST_LUKS_UUID\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        (self.fake_bin / "stat").write_text(
            "#!/bin/sh\n"
            "test \"$1\" = -c && test \"$2\" = '%u:%g:%a' || exit 1\n"
            "printf '%s\\n' \"$R8Q_TEST_PROFILE_META\"\n",
            encoding="utf-8",
        )
        (self.fake_bin / "cryptsetup").write_text(
            "#!/bin/sh\n"
            "test \"$1\" = status && test \"$2\" = cryptroot || exit 1\n"
            "printf '%s\\n' \"$R8Q_TEST_CRYPT_STATUS\"\n",
            encoding="utf-8",
        )
        for path in self.fake_bin.iterdir():
            path.chmod(0o755)

    def run_case(
        self,
        *,
        source: str,
        profile: str | None = None,
        profile_meta: str = "0:0:600",
        fstype: str = "ext4",
        root_uuid: str = ROOT_UUID,
        raw_type: str = "crypto_LUKS",
        partuuid: str = USERDATA_PARTUUID,
        luks_uuid: str = LUKS_UUID,
        crypt_status: str = "  type: LUKS2\n  device: /dev/sda36",
    ) -> subprocess.CompletedProcess[str]:
        profile_path = self.etc / "r8q-encrypted-root.env"
        if profile is None:
            profile_path.unlink(missing_ok=True)
        else:
            profile_path.write_text(profile, encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "PATH": str(self.fake_bin) + os.pathsep + env["PATH"],
                "R8Q_ROOT_DEVICE_OFFLINE": "1",
                "R8Q_ROOT_DEVICE_ETC_ROOT": str(self.etc),
                "R8Q_ROOT_DEVICE_PROFILE": str(profile_path),
                "R8Q_ROOT_DEVICE_FINDMNT": str(self.fake_bin / "findmnt"),
                "R8Q_ROOT_DEVICE_BLKID": str(self.fake_bin / "blkid"),
                "R8Q_ROOT_DEVICE_STAT": str(self.fake_bin / "stat"),
                "R8Q_ROOT_DEVICE_CRYPTSETUP": str(self.fake_bin / "cryptsetup"),
                "R8Q_TEST_SOURCE": source,
                "R8Q_TEST_FSTYPE": fstype,
                "R8Q_TEST_ROOT_UUID": root_uuid,
                "R8Q_TEST_PROFILE_META": profile_meta,
                "R8Q_TEST_RAW_TYPE": raw_type,
                "R8Q_TEST_PARTUUID": partuuid,
                "R8Q_TEST_LUKS_UUID": luks_uuid,
                "R8Q_TEST_CRYPT_STATUS": crypt_status,
            }
        )
        return subprocess.run(
            [str(HELPER)], env=env, text=True, capture_output=True, check=False
        )

    def test_plaintext_known_root_is_accepted(self) -> None:
        result = self.run_case(source="/dev/sda36", raw_type="ext4")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "/dev/sda36\n")

    def test_plaintext_arbitrary_mapper_is_rejected(self) -> None:
        result = self.run_case(source="/dev/mapper/other", raw_type="ext4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("known USERDATA device", result.stderr)

    def test_plaintext_wrong_filesystem_uuid_is_rejected(self) -> None:
        result = self.run_case(source="/dev/sda36", root_uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", raw_type="ext4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("filesystem UUID", result.stderr)

    def test_encrypted_mapper_and_backing_are_accepted(self) -> None:
        result = self.run_case(
            source="/dev/mapper/cryptroot",
            profile=f"# image-owned profile\nLUKS_UUID={LUKS_UUID}\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "/dev/mapper/cryptroot\n")

    def test_profile_must_be_root_owned_and_not_group_writable(self) -> None:
        for metadata in ("1000:1000:600", "0:0:662"):
            with self.subTest(metadata=metadata):
                result = self.run_case(
                    source="/dev/mapper/cryptroot",
                    profile=f"LUKS_UUID={LUKS_UUID}\n",
                    profile_meta=metadata,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_encrypted_profile_mismatches_fail_closed(self) -> None:
        cases = (
            {"luks_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
            {"partuuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
            {"raw_type": "ext4"},
            {"source": "/dev/mapper/other"},
            {"source": "/dev/dm-0"},
            {"crypt_status": "  type: LUKS2\n  device: /dev/sda36\n  device: /dev/sdb36"},
            {"crypt_status": "  type: PLAIN\n  device: /dev/sda36"},
            {"crypt_status": "  type: LUKS2\n  type: LUKS2\n  device: /dev/sda36"},
            {"crypt_status": "  device: /dev/sda36"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                result = self.run_case(
                    source=overrides.pop("source", "/dev/mapper/cryptroot"),
                    profile=f"LUKS_UUID={LUKS_UUID}\n",
                    **overrides,
                )
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
