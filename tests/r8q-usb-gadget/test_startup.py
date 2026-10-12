#!/usr/bin/env python3
"""Startup fixtures for the r8q gadget power descriptor."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
WRAPPER = HERE.parents[1] / "rootfs/usr/local/sbin/r8q-usb-gadget-up.sh"
HELPER = HERE.parents[1] / "rootfs/usr/local/libexec/r8q-gadget-maxpower.py"


class Fixture:
    def __init__(self, bound: str = "", max_power: str = "2", product: str = "r8q-mainline"):
        self.tmp = tempfile.TemporaryDirectory(prefix="r8q-gadget-up-fixture-")
        root = Path(self.tmp.name)
        self.configfs = root / "config"
        self.udc = root / "udc"
        (self.configfs / "usb_gadget").mkdir(parents=True)
        target = root / "sys/devices/platform/soc@0/a6f8800.usb/a600000.usb/udc/a600000.usb"
        target.mkdir(parents=True)
        self.udc.mkdir()
        (self.udc / "a600000.usb").symlink_to(target, target_is_directory=True)
        g = self.configfs / "usb_gadget/g1"
        (g / "strings/0x409").mkdir(parents=True)
        (g / "configs/c.1/strings/0x409").mkdir(parents=True)
        (g / "functions/ncm.usb0").mkdir(parents=True)
        values = {
            "idVendor": "0x1d6b",
            "idProduct": "0x0104",
            "bcdUSB": "0x0201",
            "strings/0x409/product": product,
            "strings/0x409/manufacturer": "Samsung",
            "strings/0x409/serialnumber": "r8q0001",
            "configs/c.1/strings/0x409/configuration": "ncm",
            "configs/c.1/bmAttributes": "0x80",
            "functions/ncm.usb0/dev_addr": "4e:e0:a2:98:8c:90",
            "functions/ncm.usb0/host_addr": "aa:dd:21:b3:df:6a",
            "configs/c.1/MaxPower": max_power,
            "UDC": bound,
        }
        for relative, value in values.items():
            path = g / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value + "\n")
        if bound:
            (g / "configs/c.1/ncm.usb0").symlink_to(g / "functions/ncm.usb0")
        self.gadget = g

    def run(self, helper: Path = HELPER, extra: dict[str, str] | None = None):
        env = os.environ.copy()
        env.update({
            "R8Q_GADGET_TEST_MODE": "1",
            "R8Q_CONFIGFS_ROOT": str(self.configfs),
            "R8Q_UDC_ROOT": str(self.udc),
            "R8Q_GADGET_MAXPOWER_HELPER": str(helper),
            "R8Q_PYTHON3": sys.executable,
        })
        if extra:
            env.update(extra)
        return subprocess.run([str(WRAPPER)], env=env, text=True,
                              capture_output=True, timeout=5)

    def close(self):
        self.tmp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def read(self, relative: str) -> str:
        return (self.gadget / relative).read_text().strip()


class GadgetWrapperTests(unittest.TestCase):
    def test_bound_500_redirected_udc_fails_untouched(self):
        with Fixture(bound="a600000.usb", max_power="500") as f:
            link = f.udc / "a600000.usb"
            link.unlink()
            target = Path(f.tmp.name) / "unexpected-controller"
            target.mkdir()
            link.symlink_to(target)
            result = f.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(f.read("UDC"), "a600000.usb")
            self.assertEqual(f.read("configs/c.1/MaxPower"), "500")

    def test_bound_legacy_two_without_python_is_deferred_untouched(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            missing = Path(f.tmp.name) / "python3-missing"
            missing_helper = Path(f.tmp.name) / "maxpower-helper-missing"
            result = f.run(extra={"R8Q_PYTHON3": str(missing),
                                  "R8Q_GADGET_MAXPOWER_HELPER": str(missing_helper)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("descriptor correction deferred until phone Python 3 is installed", result.stderr)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "2")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_bound_500_without_python_is_noop(self):
        with Fixture(bound="a600000.usb", max_power="500") as f:
            missing = Path(f.tmp.name) / "python3-missing"
            missing_helper = Path(f.tmp.name) / "maxpower-helper-missing"
            result = f.run(extra={"R8Q_PYTHON3": str(missing),
                                  "R8Q_GADGET_MAXPOWER_HELPER": str(missing_helper)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "500")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_unbound_without_python_writes_500_before_bind(self):
        with Fixture(bound="", max_power="2") as f:
            missing = Path(f.tmp.name) / "python3-missing"
            missing_helper = Path(f.tmp.name) / "maxpower-helper-missing"
            result = f.run(extra={"R8Q_PYTHON3": str(missing),
                                  "R8Q_GADGET_MAXPOWER_HELPER": str(missing_helper)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "500")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_unsupported_bound_power_without_python_fails_untouched(self):
        with Fixture(bound="a600000.usb", max_power="100") as f:
            missing = Path(f.tmp.name) / "python3-missing"
            missing_helper = Path(f.tmp.name) / "maxpower-helper-missing"
            result = f.run(extra={"R8Q_PYTHON3": str(missing),
                                  "R8Q_GADGET_MAXPOWER_HELPER": str(missing_helper)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsupported bound MaxPower", result.stderr)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "100")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_bound_missing_link_fails_untouched(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            link = f.gadget / "configs/c.1/ncm.usb0"
            link.unlink()
            result = f.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(link.exists())
            self.assertEqual(f.read("UDC"), "a600000.usb")
            self.assertEqual(f.read("configs/c.1/MaxPower"), "2")

    def test_unbound_maxpower_is_persistent_before_final_bind(self):
        with Fixture(bound="", max_power="2") as f:
            result = f.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "500")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_initramfs_bound_two_is_rebound_at_500(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            result = f.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "500")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_bound_500_is_noop(self):
        with Fixture(bound="a600000.usb", max_power="500") as f:
            result = f.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "500")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_helper_failure_does_not_final_bind_unbound_gadget(self):
        with Fixture(bound="", max_power="2") as f:
            fake = Path(f.tmp.name) / "failing-helper"
            fake.write_text("#!/bin/sh\necho injected-helper-failure >&2\nexit 1\n")
            fake.chmod(0o755)
            result = f.run(helper=fake)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "2")
            self.assertEqual(f.read("UDC"), "")

    def test_bound_identity_mismatch_is_untouched(self):
        with Fixture(bound="a600000.usb", max_power="2", product="unexpected") as f:
            result = f.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(f.read("configs/c.1/MaxPower"), "2")
            self.assertEqual(f.read("UDC"), "a600000.usb")

    def test_unknown_udc_name_fails_before_layout_writes(self):
        with Fixture(bound="", max_power="2") as f:
            (f.udc / "unexpected.usb").mkdir()
            result = f.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(f.read("UDC"), "")
            self.assertFalse((f.gadget / "configs/c.1/ncm.usb0").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
