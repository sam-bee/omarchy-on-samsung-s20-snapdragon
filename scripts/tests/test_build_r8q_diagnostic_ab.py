#!/usr/bin/env python3
"""Offline fixtures for the bounded pseudo-NMI A/B preparation verifier."""

from __future__ import annotations

import json
from pathlib import Path
import runpy
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/build-r8q-diagnostic-ab.py"
MODULE = runpy.run_path(str(HELPER), run_name="r8q_ab_test_module")


class DiagnosticAbFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_cmdline_replaces_only_pseudo_nmi_token(self) -> None:
        source = "console=tty0 irqchip.gicv3_pseudo_nmi=1 panic=30"
        expected = "console=tty0 irqchip.gicv3_pseudo_nmi=0 panic=30"
        self.assertEqual(MODULE["replace_pseudo_nmi_token"](source, False), expected)

    def test_cmdline_rejects_missing_or_duplicate_token(self) -> None:
        with self.assertRaises(SystemExit):
            MODULE["replace_pseudo_nmi_token"]("console=tty0", False)
        with self.assertRaises(SystemExit):
            MODULE["replace_pseudo_nmi_token"](
                "irqchip.gicv3_pseudo_nmi=1 irqchip.gicv3_pseudo_nmi=1", False)

    def test_config_delta_rejects_unrelated_change(self) -> None:
        before = {"CONFIG_CMDLINE": '"a irqchip.gicv3_pseudo_nmi=1"', "CONFIG_LOCALVERSION": '"-r8q-diag1"'}
        after = {"CONFIG_CMDLINE": '"a irqchip.gicv3_pseudo_nmi=0"', "CONFIG_LOCALVERSION": '"-changed"'}
        delta = MODULE["config_diff"](before, after)
        self.assertNotEqual(set(delta), {"CONFIG_CMDLINE"})

    def test_config_validation_rejects_template_token_drift(self) -> None:
        canonical = self.root / "canonical.config"
        candidate = self.root / "candidate.config"
        canonical.write_text(
            'CONFIG_CMDLINE="console=tty0 irqchip.gicv3_pseudo_nmi=1 panic=30"\n'
            'CONFIG_LOCALVERSION="-r8q-diag1"\n', encoding="utf-8")
        candidate.write_text(
            'CONFIG_CMDLINE="console=tty0 irqchip.gicv3_pseudo_nmi=0 panic=31"\n'
            'CONFIG_LOCALVERSION="-r8q-diag1"\n', encoding="utf-8")
        with self.assertRaises(SystemExit):
            MODULE["validate_ab_config"](canonical, candidate)

    def test_module_inventory_detects_module_drift(self) -> None:
        canonical = self.root / "canonical-modules"
        candidate = self.root / "candidate-modules"
        canonical.mkdir()
        candidate.mkdir()
        (canonical / "touch.ko").write_bytes(b"module")
        (candidate / "touch.ko").write_bytes(b"module")
        self.assertEqual(MODULE["module_records"](canonical), MODULE["module_records"](candidate))
        (candidate / "touch.ko").write_bytes(b"drift")
        self.assertNotEqual(MODULE["module_records"](canonical), MODULE["module_records"](candidate))

    def test_archive_identity_detects_drift(self) -> None:
        canonical = self.root / "canonical.cpio"
        candidate = self.root / "candidate.cpio"
        canonical.write_bytes(b"newc archive")
        candidate.write_bytes(b"newc archive")
        MODULE["compare_bytes"](canonical, candidate, "raw cpio")
        candidate.write_bytes(b"changed archive")
        with self.assertRaises(SystemExit):
            MODULE["compare_bytes"](canonical, candidate, "raw cpio")

    def test_stale_compiled_cmdline_is_rejected(self) -> None:
        canonical_cmdline = "console=tty0 irqchip.gicv3_pseudo_nmi=1"
        candidate_cmdline = "console=tty0 irqchip.gicv3_pseudo_nmi=0"
        canonical_bytes = (canonical_cmdline + "\0").encode()
        candidate_bytes = (candidate_cmdline + "\0").encode()
        canonical_image = b"prefix" + canonical_bytes * 3
        candidate_image = b"prefix" + candidate_bytes * 3
        MODULE["validate_compiled_cmdline"](canonical_image, candidate_image,
                                             canonical_cmdline, candidate_cmdline)
        with self.assertRaises(SystemExit):
            MODULE["validate_compiled_cmdline"](canonical_image, canonical_image,
                                                 canonical_cmdline, candidate_cmdline)

    def test_template_hash_change_rejected(self) -> None:
        manifest = {"template_sha256": "0" * 64}
        with self.assertRaises(SystemExit):
            MODULE["require"](manifest["template_sha256"] == MODULE["script_digest"](),
                               "AB preparation template hash differs")

    def test_build_environment_freezes_version_and_identity(self) -> None:
        identity = {"version": "6", "user": "sierra", "host": "a14",
                    "timestamp": "Tue Oct 20 14:59:07 BST 2026"}
        environment = MODULE["make_environment"](identity)
        self.assertEqual(environment["KBUILD_BUILD_VERSION"], "6")
        self.assertEqual(environment["KBUILD_BUILD_USER"], "sierra")
        self.assertEqual(environment["KBUILD_BUILD_HOST"], "a14")
        self.assertNotIn("KBUILD_BUILD_TIMESTAMP", environment)
        self.assertEqual(
            "build-timestamp=" + identity["timestamp"],
            MODULE["make_command"]({"build_identity": identity})[4])

    def test_preparation_manifest_is_distinct_and_nondeployable(self) -> None:
        function_globals = MODULE["preparation_manifest"].__globals__
        canonical_output = function_globals["CANONICAL"]
        ab_output = function_globals["OUTPUT"]
        function_globals["CANONICAL"] = self.root / "canonical"
        function_globals["OUTPUT"] = self.root / "ab"
        function_globals["CANONICAL"].mkdir()
        function_globals["OUTPUT"].mkdir()
        (function_globals["CANONICAL"] / ".config").write_text("canonical\n", encoding="utf-8")
        (function_globals["OUTPUT"] / ".config").write_text("ab\n", encoding="utf-8")
        identity = {
            "source_proof": {"sha256": MODULE["SOURCE_SHA256"]},
            "guard": {"manifest_sha256": "a", "provenance_sha256": "b"},
            "build_identity": {"version": "6", "user": "sierra", "host": "a14",
                                "timestamp": "Tue Oct 20 14:59:07 BST 2026"},
            "compiler": "clang",
            "module_records": {"touch.ko": {"type": "file"}},
            "module_inventory_sha256": "m",
            "raw_cpio_sha256": "r",
            "compressed_initramfs_sha256": "g",
            "cmdline": "x",
        }
        config_result = {"delta": {"CONFIG_CMDLINE": {"before": "1", "after": "0"}}}
        result = MODULE["preparation_manifest"](identity, config_result,
                                                   MODULE["make_environment"](identity["build_identity"]))
        self.assertEqual(result["kind"], MODULE["AB_PREPARATION_KIND"])
        self.assertFalse(result["deployable"])
        self.assertEqual(result["guard_nonce"], MODULE["GUARD_NONCE"])
        json.dumps(result)
        function_globals["CANONICAL"] = canonical_output
        function_globals["OUTPUT"] = ab_output


if __name__ == "__main__":
    unittest.main()
