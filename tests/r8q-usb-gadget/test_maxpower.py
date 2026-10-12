#!/usr/bin/env python3
"""Temporary ConfigFS fixtures for r8q-gadget-maxpower.py."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("gadget", HERE.parents[1] / "rootfs/usr/local/libexec/r8q-gadget-maxpower.py")
assert SPEC and SPEC.loader
GADGET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GADGET)


class Fixture:
    def __init__(self, bound: str = "", max_power: str = "2", product: str | None = None):
        self.tmp = tempfile.TemporaryDirectory(prefix="r8q-gadget-fixture-")
        root = Path(self.tmp.name)
        self.configfs = root / "config"
        self.udc = root / "udc"
        # /sys/class/udc exposes a class symlink, not a plain directory.
        udc_target = root / "sys/devices/platform/soc@0/a6f8800.usb/a600000.usb/udc/a600000.usb"
        udc_target.mkdir(parents=True)
        self.udc.mkdir(parents=True)
        (self.udc / "a600000.usb").symlink_to(udc_target, target_is_directory=True)
        g = self.configfs / "usb_gadget/g1"
        (g / "strings/0x409").mkdir(parents=True)
        (g / "configs/c.1/strings/0x409").mkdir(parents=True)
        (g / "functions/ncm.usb0").mkdir(parents=True)
        values = {
            "idVendor": GADGET.EXPECTED_UDC_VENDOR,
            "idProduct": GADGET.EXPECTED_UDC_PRODUCT,
            "bcdUSB": GADGET.EXPECTED_BCD_USB,
            "strings/0x409/product": product if product is not None else GADGET.EXPECTED_PRODUCT,
            "strings/0x409/manufacturer": GADGET.EXPECTED_MANUFACTURER,
            "strings/0x409/serialnumber": GADGET.EXPECTED_SERIAL,
            "configs/c.1/strings/0x409/configuration": GADGET.EXPECTED_CONFIGURATION,
            "configs/c.1/bmAttributes": GADGET.EXPECTED_BM_ATTRIBUTES,
            "functions/ncm.usb0/dev_addr": GADGET.EXPECTED_DEVICE_MAC,
            "functions/ncm.usb0/host_addr": GADGET.EXPECTED_HOST_MAC,
            "configs/c.1/MaxPower": max_power,
            "UDC": bound,
        }
        for relative, value in values.items():
            path = g / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value + "\n")
        self.link = g / "configs/c.1/ncm.usb0"
        if bound:
            self.link.symlink_to(g / "functions/ncm.usb0")
        self.gadget = g
        self.writes: list[tuple[str, str]] = []
        self.original_write = GADGET.write_attr
        def record(path: Path, value: str) -> None:
            self.writes.append((str(path.relative_to(g)), value))
            self.original_write(path, value)
        GADGET.write_attr = record

    def close(self):
        GADGET.write_attr = self.original_write
        self.tmp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class GadgetMaxPowerTests(unittest.TestCase):
    def run_apply(self, fixture: Fixture):
        return GADGET.apply(fixture.configfs, fixture.udc)

    def test_unbound_setup_sets_500_before_bind(self):
        with Fixture(bound="", max_power="2") as f:
            result = self.run_apply(f)
            self.assertIn("created and bound", result)
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "500")
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "a600000.usb")
            self.assertIn(("configs/c.1/MaxPower", "500"), f.writes)
            self.assertEqual(f.writes[-1], ("UDC", "a600000.usb"))

    def test_prepare_before_bind_leaves_udc_empty(self):
        with Fixture(bound="", max_power="2") as f:
            self.assertIn("prepared unbound", GADGET.prepare_unbound(f.configfs, f.udc))
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "500")
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "")

    def test_bound_exact_500_is_read_only(self):
        with Fixture(bound="a600000.usb", max_power="500") as f:
            self.assertIn("already normalized", self.run_apply(f))
            self.assertEqual(f.writes, [])

    def test_bound_2_narrow_transition_rebinds_same_udc(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            self.assertIn("normalized bound", self.run_apply(f))
            self.assertEqual(f.writes, [
                ("UDC", ""),
                ("configs/c.1/MaxPower", "500"),
                ("UDC", "a600000.usb"),
            ])
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "a600000.usb")
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "500")

    def test_unknown_udc_is_untouched(self):
        with Fixture(bound="other-udc", max_power="2") as f:
            with self.assertRaises(GADGET.GadgetError):
                self.run_apply(f)
            self.assertEqual(f.writes, [])
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "other-udc")
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "2")

    def test_unknown_udc_name_is_untouched(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            (f.udc / "unexpected.usb").mkdir()
            with self.assertRaises(GADGET.GadgetError):
                self.run_apply(f)
            self.assertEqual(f.writes, [])
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "a600000.usb")
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "2")

    def test_unknown_udc_redirect_is_untouched(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            link = f.udc / "a600000.usb"
            link.unlink()
            wrong = Path(f.tmp.name) / "wrong-target"
            wrong.mkdir()
            link.symlink_to(wrong, target_is_directory=True)
            with self.assertRaises(GADGET.GadgetError):
                self.run_apply(f)
            self.assertEqual(f.writes, [])
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "a600000.usb")
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "2")

    def test_unknown_bound_identity_is_untouched(self):
        with Fixture(bound="a600000.usb", max_power="2", product="unexpected") as f:
            with self.assertRaises(GADGET.GadgetError):
                self.run_apply(f)
            self.assertEqual(f.writes, [])
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "a600000.usb")
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "2")

    def test_unsupported_bound_power_is_untouched(self):
        with Fixture(bound="a600000.usb", max_power="1000") as f:
            with self.assertRaises(GADGET.GadgetError):
                self.run_apply(f)
            self.assertEqual(f.writes, [])

    def test_injected_maxpower_failure_restores_power_and_binding(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            original = f.original_write
            def fail_new_power(path: Path, value: str) -> None:
                if path.name == "MaxPower" and value == "500":
                    raise GADGET.GadgetError("injected MaxPower write failure")
                original(path, value)
            GADGET.write_attr = fail_new_power
            with self.assertRaises(GADGET.GadgetError):
                self.run_apply(f)
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "2")
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "a600000.usb")

    def test_cleanup_failure_is_reported_explicitly(self):
        with Fixture(bound="a600000.usb", max_power="2") as f:
            original = f.original_write
            failed_once = {"new": False}
            def fail_restore_bind(path: Path, value: str) -> None:
                if path.name == "MaxPower" and value == "500":
                    failed_once["new"] = True
                    raise GADGET.GadgetError("injected MaxPower failure")
                if failed_once["new"] and path.name == "UDC" and value == "a600000.usb":
                    raise GADGET.GadgetError("injected rollback bind failure")
                original(path, value)
            GADGET.write_attr = fail_restore_bind
            with self.assertRaisesRegex(GADGET.GadgetError, "rollback failed"):
                self.run_apply(f)
            self.assertEqual(GADGET.read_attr(f.gadget / "configs/c.1/MaxPower"), "2")
            self.assertEqual(GADGET.read_attr(f.gadget / "UDC"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
