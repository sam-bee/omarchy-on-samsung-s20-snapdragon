#!/usr/bin/env python3
"""Prepare and attest a private Waydroid kernel source tree.

This helper only copies and audits source files.  It never writes the source
input or an accepted build output, never builds a kernel, and never performs
phone operations.  The private tree is intentionally separate from the
shared RTC2 source because the Waydroid config and audio patches change the
kernel/module ABI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Iterable


REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"

KERNEL_VERSION = "7.1.2"
MAKEFILE_SHA256 = "9e74f1c62c24972fc6b4e56e6761a28e3f497984978131d24119a0aaabba8a8c"
ARCHIVE_SHA256 = "37198c93727be247c9fb5309bb86cd5e496c61e5322cd8c4eca9476bb0b5883f"
# Derived from the complete pinned-archive reconstruction with patches 0001
# through 0012, the FTS driver, and the audited RTC board/common DTS files.
# Relative link targets are normalized so equivalent ./ spellings agree.
COMPLETE_SOURCE_SHA256 = "04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b"

RTC_DRIVER = Path("drivers/rtc/rtc-pm8xxx.c")
RTC_DRIVER_BEFORE = "a7364852aae55844e117d7799bd1be339775ae576af6d131269da6d5500826d6"
RTC_DRIVER_AFTER = "e5eb2dc990ee79ee8bcdbc0710b96f08fe881253276700d054181b8050f5c516"

BOARD_DTS = Path("arch/arm64/boot/dts/qcom/sm8250-samsung-r8q.dts")
BOARD_DTS_BEFORE = "2f8f58cb5cd97b366815a300d0f12520eeddb1a61ac5b2bd806b7422c5012947"
BOARD_DTS_AFTER = "e47ba24f4e0663a5b6c66ccfa47468eaf6e98a4bda226c7428dfa59f717caafd"

ACTIVE_DTB = OUT / "encryption-build-20261013" / "backup" / "R8Q-RTC.DTB"
ACTIVE_DTB_SHA256 = "d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca"

PATCHES = (
    (
        "0009-r8q-rtc-flush-offset-on-unbind.patch",
        Path("patches/0009-r8q-rtc-flush-offset-on-unbind.patch"),
        "4a8dd0836d876b57d1ffb71d13511c1fed197afc12ffcd78afc6ca156108a522",
    ),
    (
        "0010-r8q-cs35l41-card.patch",
        Path("patches/0010-r8q-cs35l41-card.patch"),
        "93ba185d1cd3abf7219897be57fb148c8b590f1bcc752211d28568d169cf0a86",
    ),
    (
        "0011-r8q-cs35l41-protected-speakers.patch",
        Path("patches/0011-r8q-cs35l41-protected-speakers.patch"),
        "f85e21118439150ccfbb5a82cb99936d1065c29d76daa99b1602baeccbf5cbf4",
    ),
    (
        "0012-r8q-q6afe-tdm-fields.patch",
        Path("patches/0012-r8q-q6afe-tdm-fields.patch"),
        "9a75343ceab4bc1675363f123d02f065050fb95826eb04f43991d5a8f3d6ef5c",
    ),
)

# These are the audited source bytes, rather than hashes discovered by
# looking at whichever source happens to be present at runtime.
PRESERVED_AUDIO_SOURCES = {
    "drivers/firmware/cirrus/cs_dsp.c": "3817c3ba64b901abc669e082fa3ad3bc488cffec2e816ae47edf467212419aef",
    "drivers/firmware/cirrus/cs_dsp.h": "db28629a54be4bd60c386b496061a9106c04d1d28abd6c2982868d01c357fdbd",
    "include/linux/firmware/cirrus/cs_dsp.h": "9cac263776f0ae2f02487dd7ebf9072ccb18a5e5853ec1aadd587c01a4fae264",
    "include/linux/firmware/cirrus/wmfw.h": "2950007f3a3b76e8999a2511d1161af0ee15b7addfc4037820c4512a1549bfe2",
    "sound/soc/codecs/wm_adsp.c": "ee052ebcc6a0a5c0250efe06e64510ced1f021865f50ebaf13470c7ed15e24b0",
    "sound/soc/codecs/wm_adsp.h": "71050cae977ac594abfcbf8f7394c603c84a25976cb183a011c8dd3cb7fff297",
    "sound/soc/codecs/cs35l41-lib.c": "16c4df663df7db60a50c365a32cdebc7b24ec1fa5b0a04f39394e2cc7f23528c",
    "sound/soc/codecs/cs35l41-i2c.c": "4e53ec4b34132c936565180bd86964c5f110c2558a5575657d0fdde938053c26",
    "include/sound/cs35l41.h": "2f4c7eb3807238a2060427a18a202c4190d7f7ea8dab478ba6a86292e775c7d6",
    "sound/soc/qcom/r8q-cs35l41-card.c": "6898a00c3cc3eae3e77f91fddaf5a30a4d2128ce91aec374d54b35b16d0949cd",
    "sound/soc/codecs/cs35l41.c": "c1fd55b9595414d329785e65a4a452aca90a72a5c31f13dde3ef6ccf1b6b04f4",
    "sound/soc/codecs/cs35l41.h": "0a847131fd3e4fac5a09b9f920711be46661582d7fe7923e178c54c1ffdab9fd",
    "sound/soc/qcom/qdsp6/q6afe.c": "e89af61872f6caa50874b74ed52cdbfe57dd139566fe057e19170f8846e77fd8",
    "sound/soc/qcom/qdsp6/q6afe-dai.c": "bfa4a57408b05059bdea3cf889613442d7501bcc3ccce8e9635c8170b70beab8",
    "sound/soc/qcom/qdsp6/q6afe.h": "67d3cebe5fb92647b851bf10cbe027aad6a84e03bca1f51c92eff9402ab9654e",
}

SOURCE_CHANGED_PATHS = [
    str(RTC_DRIVER),
    str(BOARD_DTS),
    "sound/soc/qcom/Kconfig",
    "sound/soc/qcom/Makefile",
    "sound/soc/qcom/r8q-cs35l41-card.c",
    "sound/soc/codecs/cs35l41.c",
    "sound/soc/codecs/cs35l41.h",
    "sound/soc/qcom/qdsp6/q6afe.c",
    "sound/soc/qcom/qdsp6/q6afe-dai.c",
    "sound/soc/qcom/qdsp6/q6afe.h",
]


class PreparationError(RuntimeError):
    """A fail-closed source preparation check failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PreparationError(f"{label} is unavailable: {path}: {exc}") from exc
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a regular non-symlink file: {path}")


def directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PreparationError(f"{label} is unavailable: {path}: {exc}") from exc
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            f"{label} is not a regular non-symlink directory: {path}")


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def paths_do_not_overlap(named_paths: Iterable[tuple[str, Path]]) -> None:
    items = list(named_paths)
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1:]:
            require(not inside(left, right) and not inside(right, left),
                    f"{left_name} and {right_name} overlap: {left} / {right}")


def parse_kernel_version(makefile: Path) -> str:
    values: dict[str, str] = {}
    for raw in makefile.read_text(encoding="utf-8").splitlines():
        if "=" not in raw or raw.lstrip().startswith("#"):
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        if key in {"VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION"}:
            values[key] = value.strip()
    require(values.get("VERSION") == "7", "kernel Makefile VERSION is not 7")
    require(values.get("PATCHLEVEL") == "1", "kernel Makefile PATCHLEVEL is not 1")
    require(values.get("SUBLEVEL") == "2", "kernel Makefile SUBLEVEL is not 2")
    require(values.get("EXTRAVERSION", "") == "", "kernel EXTRAVERSION is not empty")
    return ".".join(values[key] for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"))


def run_patch_check(source: Path, patch_file: Path, reverse: bool) -> subprocess.CompletedProcess[bytes]:
    direction = "--reverse" if reverse else "--forward"
    return subprocess.run(
        ["patch", "--batch", "--fuzz=0", "--dry-run", direction, "-p1"],
        cwd=source,
        input=patch_file.read_bytes(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def apply_one_patch(source: Path, name: str, patch_file: Path) -> str:
    forward = run_patch_check(source, patch_file, reverse=False)
    if forward.returncode == 0:
        result = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "--forward", "-p1"],
            cwd=source,
            input=patch_file.read_bytes(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        require(result.returncode == 0,
                f"applying {name} failed:\n{result.stdout.decode(errors='replace')}")
        return "applied"

    reverse = run_patch_check(source, patch_file, reverse=True)
    require(reverse.returncode == 0,
            f"{name} is neither cleanly applicable nor exactly already applied:\n"
            f"forward:\n{forward.stdout.decode(errors='replace')}"
            f"reverse:\n{reverse.stdout.decode(errors='replace')}")
    return "already_applied"


def verify_hashes(source: Path, expected: dict[str, str], label: str) -> None:
    for relative, expected_hash in expected.items():
        path = source / relative
        regular_file(path, f"{label} source file {relative}")
        actual = sha256_file(path)
        require(actual == expected_hash,
                f"{label} hash mismatch for {relative}: {actual} != {expected_hash}")


def complete_source_identity(source: Path) -> dict[str, object]:
    """Hash every source entry and reject references outside the private tree."""
    source = source.resolve()
    for name in ('.git', 'out', 'r8q-arch'):
        require(not (source / name).exists() and not (source / name).is_symlink(),
                f"generated or shared source entry is forbidden: {name}")
    aggregate = hashlib.sha256()
    count = 0
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(source).as_posix()
        if relative == 'r8q-waydroid-source.json':
            regular_file(path, 'source preparation receipt')
            continue
        info = path.lstat()
        row: dict[str, object] = {'path': relative}
        if stat.S_ISLNK(info.st_mode):
            try:
                target = path.resolve(strict=True)
            except OSError as exc:
                raise PreparationError(f"broken source symlink: {relative}") from exc
            require(inside(target, source), f"source symlink leaves the private tree: {relative}")
            row.update(type='symlink', target=posixpath.normpath(str(path.readlink())))
        elif stat.S_ISREG(info.st_mode):
            row.update(type='file', sha256=sha256_file(path))
        elif stat.S_ISDIR(info.st_mode):
            row['type'] = 'dir'
        else:
            raise PreparationError(f"unsupported source entry: {relative}")
        aggregate.update((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode())
        count += 1
    return {'entries': count, 'sha256': aggregate.hexdigest(), 'archive_sha256': ARCHIVE_SHA256,
            'serialization': 'sorted JSONL path/type/content digest or normalized relative link; compact sorted keys'}


def verify_complete_source_tree(source: Path) -> dict[str, object]:
    proof = complete_source_identity(source)
    require(proof['sha256'] == COMPLETE_SOURCE_SHA256,
            f"complete source differs from the pinned archive and patch reconstruction: {proof['sha256']}")
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_source", type=Path)
    parser.add_argument("accepted_build", type=Path)
    parser.add_argument("private_dest", type=Path)
    parser.add_argument(
        "--use-existing-copy",
        action="store_true",
        help="audit the existing private destination instead of copying the source",
    )
    args = parser.parse_args()

    input_source = args.input_source.expanduser().resolve()
    accepted_build = args.accepted_build.expanduser().resolve()
    private_dest = args.private_dest.expanduser().resolve()
    directory(input_source, "INPUT_SOURCE")
    directory(accepted_build, "ACCEPTED_BUILD")

    require(inside(accepted_build, OUT.resolve()),
            f"ACCEPTED_BUILD must be under {OUT}: {accepted_build}")
    require(private_dest.name == "source" and private_dest.parent.name.startswith("waydroid-"),
            "PRIVATE_DEST must end in out/waydroid-*/source")
    require(private_dest.parent.parent == OUT.resolve(),
            f"PRIVATE_DEST must be directly under {OUT}/waydroid-*")
    paths_do_not_overlap((
        ("INPUT_SOURCE", input_source),
        ("ACCEPTED_BUILD", accepted_build),
        ("PRIVATE_DEST", private_dest),
    ))

    makefile = input_source / "Makefile"
    regular_file(makefile, "INPUT_SOURCE Makefile")
    require(sha256_file(makefile) == MAKEFILE_SHA256,
            "INPUT_SOURCE Makefile is not the audited Linux 7.1.2 source")
    require(parse_kernel_version(makefile) == KERNEL_VERSION,
            f"INPUT_SOURCE is not Linux {KERNEL_VERSION}")

    source_key_paths = (makefile, input_source / RTC_DRIVER, input_source / BOARD_DTS)
    for path in source_key_paths[1:]:
        regular_file(path, f"INPUT_SOURCE source file {path.relative_to(input_source)}")
    input_snapshot = {str(path.relative_to(input_source)): sha256_file(path)
                      for path in source_key_paths}
    require(input_snapshot[str(RTC_DRIVER)] in {RTC_DRIVER_BEFORE, RTC_DRIVER_AFTER},
            "INPUT_SOURCE RTC driver is neither the audited pre-patch nor post-patch file")
    require(input_snapshot[str(BOARD_DTS)] in {BOARD_DTS_BEFORE, BOARD_DTS_AFTER},
            "INPUT_SOURCE board DTS is neither the audited pre-candidate nor candidate file")

    build_receipt = accepted_build / "candidate-build.json"
    audit_dts = accepted_build / "audit" / "source-r8q-after.dts"
    regular_file(build_receipt, "ACCEPTED_BUILD candidate receipt")
    regular_file(audit_dts, "ACCEPTED_BUILD audited candidate DTS")
    require(sha256_file(audit_dts) == BOARD_DTS_AFTER,
            "accepted candidate DTS does not match the audited RTC2 candidate")
    try:
        receipt = json.loads(build_receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PreparationError(f"cannot read accepted candidate receipt: {exc}") from exc
    require(receipt.get("config", {}).get("kernel_release") == "7.1.2-r8q-rtc2",
            "accepted receipt is not the audited RTC2 build")
    require(receipt.get("source", {}).get("kernel_source_makefile", {}).get("sha256") == MAKEFILE_SHA256,
            "accepted receipt Makefile identity does not match the audited source")
    require(receipt.get("source", {}).get("driver_after_patch", {}).get("sha256") == RTC_DRIVER_AFTER,
            "accepted receipt RTC driver identity does not match the audit")

    regular_file(ACTIVE_DTB, "captured active DTB")
    active_dtb_hash = sha256_file(ACTIVE_DTB)
    require(active_dtb_hash == ACTIVE_DTB_SHA256,
            f"captured active DTB hash mismatch: {active_dtb_hash} != {ACTIVE_DTB_SHA256}")

    if args.use_existing_copy:
        directory(private_dest, "PRIVATE_DEST")
    else:
        require(not private_dest.exists(),
                f"PRIVATE_DEST already exists; use --use-existing-copy to audit it: {private_dest}")
        if private_dest.parent.exists():
            directory(private_dest.parent, "PRIVATE_DEST parent")
        else:
            private_dest.parent.mkdir(parents=False)
        def ignore_generated(directory_name, names):
            if Path(directory_name) == input_source:
                return set(names) & {'.git', 'out', 'r8q-arch'}
            return set()
        shutil.copytree(input_source, private_dest, symlinks=True, ignore=ignore_generated)

    private_makefile = private_dest / "Makefile"
    regular_file(private_makefile, "PRIVATE_DEST Makefile")
    require(sha256_file(private_makefile) == MAKEFILE_SHA256,
            "PRIVATE_DEST Makefile changed during copy or is not the audited source")
    require(parse_kernel_version(private_makefile) == KERNEL_VERSION,
            f"PRIVATE_DEST is not Linux {KERNEL_VERSION}")

    for relative in SOURCE_CHANGED_PATHS:
        path = private_dest / relative
        require(inside(path.parent.resolve(), private_dest),
                f"patch destination leaves private tree: {relative}")
        require(not path.is_symlink(), f"patch destination is a symlink: {relative}")

    patch_records: list[dict[str, str]] = []
    for name, relative_patch, expected_hash in PATCHES:
        patch_file = REPO / relative_patch
        regular_file(patch_file, f"patch {name}")
        actual_patch_hash = sha256_file(patch_file)
        require(actual_patch_hash == expected_hash,
                f"patch hash mismatch for {name}: {actual_patch_hash} != {expected_hash}")
        status = apply_one_patch(private_dest, name, patch_file)
        patch_records.append({
            "name": name,
            "path": str(relative_patch),
            "sha256": actual_patch_hash,
            "status": status,
            "strip": "1",
            "fuzz": "0",
        })

    private_driver = private_dest / RTC_DRIVER
    regular_file(private_driver, "PRIVATE_DEST RTC driver")
    require(sha256_file(private_driver) == RTC_DRIVER_AFTER,
            "PRIVATE_DEST RTC driver is not the audited post-0009 source")

    private_dts = private_dest / BOARD_DTS
    regular_file(private_dts, "PRIVATE_DEST board DTS")
    shutil.copy2(audit_dts, private_dts)
    require(sha256_file(private_dts) == BOARD_DTS_AFTER,
            "PRIVATE_DEST board DTS copy does not match the audited candidate")

    verify_hashes(private_dest, PRESERVED_AUDIO_SOURCES, "preserved audio")
    complete_proof = verify_complete_source_tree(private_dest)
    for relative in SOURCE_CHANGED_PATHS:
        regular_file(private_dest / relative, f"changed source path {relative}")

    # The input tree is an immutable source of provenance.  Recheck the key
    # files after all destination operations to detect an accidental alias.
    for relative, before_hash in input_snapshot.items():
        actual = sha256_file(input_source / relative)
        require(actual == before_hash,
                f"INPUT_SOURCE changed during preparation: {relative}")

    manifest = {
        "schema": 1,
        "candidate": "r8q-waydroid1",
        "kernel_source_version": KERNEL_VERSION,
        "rtc_patch_preserved": True,
        "phone_operations": False,
        "origin": {
            "input_source": str(input_source),
            "accepted_build": str(accepted_build),
            "private_destination": str(private_dest),
            "mode": "use-existing-copy" if args.use_existing_copy else "copytree",
        },
        "input_identities": {
            "kernel_makefile": {
                "path": str(makefile),
                "sha256": input_snapshot["Makefile"],
            },
            "kernel_source_version": KERNEL_VERSION,
            "rtc_driver_before_expected": RTC_DRIVER_BEFORE,
            "rtc_driver_after_expected": RTC_DRIVER_AFTER,
            "input_key_hashes_before": input_snapshot,
            "accepted_candidate_receipt": {
                "path": str(build_receipt),
                "sha256": sha256_file(build_receipt),
            },
            "accepted_candidate_dts": {
                "path": str(audit_dts),
                "sha256": BOARD_DTS_AFTER,
            },
        },
        "external_active_dtb": {
            "path": str(ACTIVE_DTB),
            "sha256": active_dtb_hash,
            "bytes": ACTIVE_DTB.stat().st_size,
            "used_as_source_dtb": False,
            "intended_separate_payload_staging": True,
        },
        "applied_patches": patch_records,
        "complete_source_proof": complete_proof,
        "preserved_audio_sources": PRESERVED_AUDIO_SOURCES,
        "source_changed_paths": SOURCE_CHANGED_PATHS,
        "final_source_identities": {
            "makefile": sha256_file(private_makefile),
            "rtc_driver": sha256_file(private_driver),
            "board_dts": sha256_file(private_dts),
            "preserved_audio_sources": {
                relative: sha256_file(private_dest / relative)
                for relative in PRESERVED_AUDIO_SOURCES
            },
        },
    }
    manifest_path = private_dest / "r8q-waydroid-source.json"
    with manifest_path.open("w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.chmod(manifest_path, 0o644)

    print(json.dumps({
        "private_destination": str(private_dest),
        "manifest": str(manifest_path),
        "patch_status": {record["name"]: record["status"] for record in patch_records},
        "rtc_driver": RTC_DRIVER_AFTER,
        "board_dts": BOARD_DTS_AFTER,
        "active_dtb": active_dtb_hash,
        "phone_operations": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreparationError as exc:
        print(f"prepare-waydroid-kernel-source: {exc}", file=sys.stderr)
        raise SystemExit(2)
