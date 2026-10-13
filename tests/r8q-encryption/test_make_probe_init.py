#!/usr/bin/env python3
"""Offline protocol checks for the disposable encryption probe generator."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/prepare-encryption-probe.py"
PARTUUID = "5594c694-c871-4b5f-90b1-690a6f68e0f7"


def load_module():
    spec = importlib.util.spec_from_file_location("make_probe_init", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROBE = load_module()


class ProbeInitTests(unittest.TestCase):
    def test_generated_find_cache_requires_exact_identity_and_size(self):
        with tempfile.TemporaryDirectory(prefix="r8q-probe-find-cache-") as temporary:
            root = Path(temporary)
            sysfs = root / "sys"
            for node, partname, partuuid, sectors in (
                ("sda30", "cache-extra", PARTUUID, "1228800"),
                ("sda31", "cache", PARTUUID + "-suffix", "1228800"),
                ("sda32", "cache", PARTUUID, "1228800"),
                ("sda33", "cache", PARTUUID, "1228799"),
            ):
                block = sysfs / "class/block" / node
                block.mkdir(parents=True)
                (block / "uevent").write_text(
                    f"PARTNAME={partname}\nPARTUUID={partuuid}\n", encoding="ascii"
                )
                (block / "size").write_text(sectors + "\n", encoding="ascii")

            bb = root / "busybox"
            bb.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  grep|basename|dirname|cat) command=$1; shift; exec \"$command\" \"$@\" ;;\n"
                "  *) echo \"unexpected applet: $1\" >&2; exit 125 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            bb.chmod(0o755)

            generated = PROBE.init_source("a" * 64, "b" * 64, "test-release")
            self.assertIn('grep -q "^R8Q-PROBE-RESULT $result$"', generated)
            start = generated.index("find_cache() {")
            end = generated.index("wait_for_cache() {")
            script = root / "find-cache-test.sh"
            script.write_text(
                "#!/bin/sh\nset -eu\n"
                f"BB={shlex.quote(str(bb))}\n"
                f"CACHE_PARTUUID={shlex.quote(PARTUUID)}\n"
                "CACHE_SECTORS=1228800\n"
                f"SYSFS_ROOT={shlex.quote(str(sysfs))}\n"
                + generated[start:end]
                + "find_cache\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            result = subprocess.run(
                ["/bin/sh", str(script)], text=True, capture_output=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "sda32")


if __name__ == "__main__":
    unittest.main()
