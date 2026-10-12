#!/usr/bin/env python3
"""Safely normalize the r8q ConfigFS gadget MaxPower to 500 mA.

This helper owns only ConfigFS gadget g1.  It does not touch the charger,
USB route, UDC driver, network, or systemd.  A bound gadget is changed only
when its complete known identity/layout has been read back and MaxPower is
exactly the observed legacy value ``2``.  Every other bound value or mismatch
fails before any write.

The production caller must provide the project's root/machine/kernel guards.
Those checks are deliberately outside this review helper so its fixture tests
can use temporary directories.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import signal
import sys
from typing import Iterable

EXPECTED_UDC_VENDOR = "0x1d6b"
EXPECTED_UDC_PRODUCT = "0x0104"
EXPECTED_UDC = "a600000.usb"
EXPECTED_BCD_USB = "0x0201"
EXPECTED_BM_ATTRIBUTES = "0x80"
EXPECTED_PRODUCT = "r8q-mainline"
EXPECTED_MANUFACTURER = "Samsung"
EXPECTED_SERIAL = "r8q0001"
EXPECTED_CONFIGURATION = "ncm"
EXPECTED_DEVICE_MAC = "4e:e0:a2:98:8c:90"
EXPECTED_HOST_MAC = "aa:dd:21:b3:df:6a"
TARGET_MAX_POWER = "500"
LEGACY_MAX_POWER = "2"


class GadgetError(RuntimeError):
    pass


class Interrupted(GadgetError):
    pass


def _clean(value: str) -> str:
    return value.replace("\x00", "").strip()


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise GadgetError(f"symlink is not allowed: {path}")


def _require_file(path: Path) -> None:
    _reject_symlink(path)
    if not path.is_file():
        raise GadgetError(f"missing ConfigFS attribute: {path}")


def read_attr(path: Path) -> str:
    _require_file(path)
    try:
        return _clean(path.read_text())
    except OSError as exc:
        raise GadgetError(f"cannot read ConfigFS attribute: {path}: {exc}") from exc


def write_attr(path: Path, value: str) -> None:
    """Write one ConfigFS value and close it; ConfigFS fsync is not required."""
    _require_file(path)
    try:
        with path.open("w") as stream:
            stream.write(value + "\n")
    except OSError as exc:
        raise GadgetError(f"cannot write ConfigFS attribute: {path}: {exc}") from exc


def require_dir(path: Path) -> None:
    _reject_symlink(path)
    if not path.is_dir():
        raise GadgetError(f"missing ConfigFS directory: {path}")


def ensure_dir(path: Path) -> None:
    _reject_symlink(path)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise GadgetError(f"cannot create ConfigFS directory: {path}: {exc}") from exc
    require_dir(path)


def check_link(path: Path, target: Path) -> None:
    _reject_symlink(path) if path.exists() and not path.is_symlink() else None
    if not path.is_symlink():
        raise GadgetError(f"missing configuration symlink: {path}")
    try:
        if path.resolve(strict=True) != target.resolve(strict=True):
            raise GadgetError(f"unexpected configuration symlink: {path}")
    except OSError as exc:
        raise GadgetError(f"cannot resolve configuration symlink: {path}: {exc}") from exc


def discover_udc(udc_root: Path) -> str:
    require_dir(udc_root)
    names = []
    try:
        entries = list(udc_root.iterdir())
    except OSError as exc:
        raise GadgetError(f"cannot enumerate UDCs: {exc}") from exc
    for entry in entries:
        # /sys/class/udc is a class directory: the expected entry is normally
        # a symlink into the platform device tree.  Accept it only when the
        # name and resolved directory are the known r8q controller; unknown
        # names or redirects must fail before any gadget write.
        if entry.name != EXPECTED_UDC:
            raise GadgetError(f"unexpected UDC entry: {entry}")
        try:
            resolved = entry.resolve(strict=True)
        except OSError as exc:
            raise GadgetError(f"cannot resolve UDC entry: {entry}: {exc}") from exc
        if not resolved.is_dir() or resolved.name != EXPECTED_UDC:
            raise GadgetError(f"unexpected UDC target: {entry} -> {resolved}")
        names.append(entry.name)
    if len(names) != 1:
        raise GadgetError(f"expected exactly one UDC, found {len(names)}")
    return names[0]


def _expected_attributes(gadget: Path) -> dict[Path, str]:
    return {
        gadget / "idVendor": EXPECTED_UDC_VENDOR,
        gadget / "idProduct": EXPECTED_UDC_PRODUCT,
        gadget / "bcdUSB": EXPECTED_BCD_USB,
        gadget / "strings/0x409/product": EXPECTED_PRODUCT,
        gadget / "strings/0x409/manufacturer": EXPECTED_MANUFACTURER,
        gadget / "strings/0x409/serialnumber": EXPECTED_SERIAL,
        gadget / "configs/c.1/strings/0x409/configuration": EXPECTED_CONFIGURATION,
        gadget / "configs/c.1/bmAttributes": EXPECTED_BM_ATTRIBUTES,
        gadget / "functions/ncm.usb0/dev_addr": EXPECTED_DEVICE_MAC,
        gadget / "functions/ncm.usb0/host_addr": EXPECTED_HOST_MAC,
    }


def validate_identity(gadget: Path) -> None:
    """Read every immutable identity/string/MAC attribute before any unbind."""
    for path, expected in _expected_attributes(gadget).items():
        if read_attr(path) != expected:
            raise GadgetError(f"unexpected bound attribute: {path}")
    function = gadget / "functions/ncm.usb0"
    link = gadget / "configs/c.1/ncm.usb0"
    require_dir(function)
    check_link(link, function)


def setup_unbound_layout(gadget: Path) -> None:
    # Only called when UDC is empty.  It mirrors the existing NCM layout and
    # leaves MaxPower unbound until every identity attribute is ready.
    for relative in (
        "strings/0x409",
        "configs/c.1/strings/0x409",
        "functions/ncm.usb0",
    ):
        ensure_dir(gadget / relative)
    for path, expected in _expected_attributes(gadget).items():
        current = read_attr(path)
        if current != expected:
            write_attr(path, expected)
            if read_attr(path) != expected:
                raise GadgetError(f"ConfigFS write did not stick: {path}")
    link = gadget / "configs/c.1/ncm.usb0"
    function = gadget / "functions/ncm.usb0"
    if link.exists() or link.is_symlink():
        check_link(link, function)
    else:
        try:
            link.symlink_to(function)
        except OSError as exc:
            raise GadgetError(f"cannot create configuration symlink: {link}: {exc}") from exc
        check_link(link, function)


def _read_bound(gadget: Path) -> str:
    return read_attr(gadget / "UDC")


def _verify_bound(gadget: Path, udc: str) -> None:
    if _read_bound(gadget) != udc:
        raise GadgetError(f"gadget binding did not stick: expected {udc}")


def _write_and_verify(gadget: Path, relative: str, value: str) -> None:
    path = gadget / relative
    write_attr(path, value)
    if read_attr(path) != value:
        raise GadgetError(f"ConfigFS write did not stick: {path}")


def _safe_restore(gadget: Path, old_udc: str, old_power: str) -> None:
    """Restore only the previously known UDC and MaxPower state."""
    current = _read_bound(gadget)
    if current not in ("", old_udc):
        raise GadgetError(f"cannot restore unknown UDC binding: {current}")
    if current == old_udc:
        _write_and_verify(gadget, "UDC", "")
    if read_attr(gadget / "configs/c.1/MaxPower") != old_power:
        _write_and_verify(gadget, "configs/c.1/MaxPower", old_power)
    if _read_bound(gadget) != old_udc:
        _write_and_verify(gadget, "UDC", old_udc)
    _verify_bound(gadget, old_udc)


def transition_bound(gadget: Path, udc: str, old_power: str) -> None:
    if old_power == TARGET_MAX_POWER:
        return
    if old_power != LEGACY_MAX_POWER:
        raise GadgetError(f"unsupported bound MaxPower: {old_power!r}")

    previous_handlers = {}
    interrupted = False

    def stop(signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
        raise Interrupted(f"signal {signum} during MaxPower transition")

    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[sig] = signal.getsignal(sig)
        signal.signal(sig, stop)

    mutated = False
    try:
        if interrupted:
            raise Interrupted("interrupted before transition")
        _write_and_verify(gadget, "UDC", "")
        mutated = True
        if interrupted:
            raise Interrupted("interrupted after UDC unbind")
        _write_and_verify(gadget, "configs/c.1/MaxPower", TARGET_MAX_POWER)
        if interrupted:
            raise Interrupted("interrupted after MaxPower write")
        _write_and_verify(gadget, "UDC", udc)
        _verify_bound(gadget, udc)
        mutated = False
    except BaseException as primary:
        if not mutated:
            # A failed write may have partially changed a ConfigFS value, so
            # always verify/restore after the transition began.
            pass
        try:
            for sig in previous_handlers:
                signal.signal(sig, signal.SIG_IGN)
            _safe_restore(gadget, udc, old_power)
        except BaseException as cleanup:
            raise GadgetError(f"transition failed ({primary}); rollback failed ({cleanup})") from cleanup
        raise
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


def apply(configfs_root: Path, udc_root: Path) -> str:
    # Mount/identity checks belong to the privileged runtime wrapper, but
    # reject redirected roots here as well so a mistaken invocation cannot
    # silently operate through a symlinked ConfigFS tree.
    require_dir(configfs_root)
    require_dir(configfs_root / "usb_gadget")
    udc = discover_udc(udc_root)
    gadget = configfs_root / "usb_gadget/g1"
    _reject_symlink(gadget)
    if not gadget.exists():
        ensure_dir(gadget)
        # ConfigFS creates these files. A missing fixture attribute is still a
        # hard error; this helper never fabricates kernel attributes.
    require_dir(gadget)
    bound = _read_bound(gadget)

    if bound:
        # This is deliberately before the MaxPower write or UDC unbind.
        if bound != udc:
            raise GadgetError(f"gadget is already bound to a different UDC: {bound}")
        validate_identity(gadget)
        max_power = read_attr(gadget / "configs/c.1/MaxPower")
        transition_bound(gadget, udc, max_power)
        return f"already normalized: {udc}" if max_power == TARGET_MAX_POWER else f"normalized bound gadget: {udc}"

    setup_unbound_layout(gadget)
    max_path = gadget / "configs/c.1/MaxPower"
    max_power = read_attr(max_path)
    if max_power != TARGET_MAX_POWER:
        write_attr(max_path, TARGET_MAX_POWER)
        if read_attr(max_path) != TARGET_MAX_POWER:
            raise GadgetError("MaxPower write did not stick")
    _write_and_verify(gadget, "UDC", udc)
    _verify_bound(gadget, udc)
    return f"created and bound gadget: {udc}"


def prepare_unbound(configfs_root: Path, udc_root: Path) -> str:
    """Normalize an unbound gadget, leaving its final UDC bind to the caller."""
    discover_udc(udc_root)
    require_dir(configfs_root)
    require_dir(configfs_root / "usb_gadget")
    gadget = configfs_root / "usb_gadget/g1"
    _reject_symlink(gadget)
    if not gadget.exists():
        ensure_dir(gadget)
    require_dir(gadget)
    if _read_bound(gadget):
        raise GadgetError("--prepare-before-bind requires an unbound gadget")
    setup_unbound_layout(gadget)
    max_path = gadget / "configs/c.1/MaxPower"
    if read_attr(max_path) != TARGET_MAX_POWER:
        write_attr(max_path, TARGET_MAX_POWER)
        if read_attr(max_path) != TARGET_MAX_POWER:
            raise GadgetError("MaxPower write did not stick")
    return "prepared unbound gadget: MaxPower=500"


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configfs-root", default="/sys/kernel/config", type=Path)
    parser.add_argument("--udc-root", default="/sys/class/udc", type=Path)
    parser.add_argument("--prepare-before-bind", action="store_true",
                        help="normalize an unbound gadget without writing UDC")
    args = parser.parse_args(argv)
    try:
        action = prepare_unbound if args.prepare_before_bind else apply
        print(action(args.configfs_root, args.udc_root))
        return 0
    except (GadgetError, OSError, Interrupted) as exc:
        print(f"r8q-gadget-maxpower: ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
