#!/usr/bin/env python3
"""Prepare a minimal Arch rootfs in a fresh, local one-shot directory.

This helper deliberately has no phone, block-device, mount, loop, chroot, or
firmware operations.  It verifies a caller-supplied archive before extracting
it with the host's ``bsdtar``, then writes only the first-boot rootfs files
under ``out/arch-preparation-20261009/rootdir``.
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
import tarfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PREPARATION = REPO / 'out' / 'arch-preparation-20261009'
ROOTDIR = PREPARATION / 'rootdir'

NCM_SERVICE = REPO / 'rootfs/etc/systemd/system/r8q-usb-gadget.service'
NCM_SCRIPT = REPO / 'rootfs/usr/local/sbin/r8q-usb-gadget-up.sh'
NCM_MAXPOWER = REPO / 'rootfs/usr/local/libexec/r8q-gadget-maxpower.py'
GETTY_OVERLAY = REPO / 'rootfs/etc/systemd/system/getty@tty1.service.d/autologin.conf'
USB_ROUTE_SERVICE = REPO / 'rootfs/etc/systemd/system/r8q-usb-route.service'
USB_ROUTE_WITNESS = REPO / 'rootfs/usr/local/sbin/r8q-usb-route-witness.sh'
HARDWARE_PREPARE_SERVICE = REPO / 'rootfs/etc/systemd/system/r8q-hardware-prepare.service'
USB_ROUTE_WRAPPER = REPO / 'rootfs/usr/local/sbin/r8q-usb-route-up.sh'
USB_ROUTE_HELPER = REPO / 'rootfs/usr/local/sbin/r8q-usb-route-ensure.sh'
USB_ROUTE_PROTOCOL = REPO / 'rootfs/usr/local/lib/r8q-usb-route/protocol-binding.env'
USB_ROUTE_MODPROBE = REPO / 'rootfs/etc/modprobe.d/r8q-usb-route.conf'
USB_ROUTE_ENV_EXAMPLE = REPO / 'rootfs/etc/r8q-usb-route.env.example'
USB_ROUTE_PACKAGES = REPO / 'rootfs/usr/share/r8q/r8q-usb-route.packages'

MODULES_REL = 'usr/lib/modules'
DISABLED_MODULES_REL = 'usr/lib/r8q-disabled-modules'


class PreparationError(RuntimeError):
    """A fail-closed preparation guard failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise PreparationError(f'{label} is unavailable: {path}: {exc}') from exc


def is_symlink(path: Path) -> bool:
    try:
        return stat.S_ISLNK(path.lstat().st_mode)
    except FileNotFoundError:
        return False


def ensure_regular_source(path: Path, label: str) -> Path:
    st = lstat(path, label)
    require(stat.S_ISREG(st.st_mode), f'{label} is not a regular file: {path}')
    require(not stat.S_ISLNK(st.st_mode), f'{label} is a symlink: {path}')
    return path


def ensure_directory(path: Path, label: str) -> None:
    st = lstat(path, label)
    require(stat.S_ISDIR(st.st_mode), f'{label} is not a directory: {path}')
    require(not stat.S_ISLNK(st.st_mode), f'{label} is a symlink: {path}')


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def archive_relative(raw_name: str, label: str) -> str:
    require(isinstance(raw_name, str), f'{label} has a non-text name')
    require('\x00' not in raw_name, f'{label} contains NUL')
    require(not raw_name.startswith('/'), f'{label} is absolute: {raw_name!r}')
    # On Linux a backslash is a literal filename character, including in
    # systemd's escaped unit names; only '/' separates path components.
    parts = raw_name.split('/')
    require('..' not in parts, f'{label} traverses parent directories: {raw_name!r}')
    cleaned = [part for part in parts if part not in ('', '.')]
    return '/'.join(cleaned) or '.'


def archive_link_target(member_name: str, link_name: str, label: str) -> str:
    require(isinstance(link_name, str), f'{label} has a non-text link target')
    require('\x00' not in link_name, f'{label} link target contains NUL')
    if link_name.startswith('/'):
        candidate = link_name[1:]
    else:
        candidate = posixpath.join(posixpath.dirname(member_name), link_name)
    normalized = posixpath.normpath(candidate)
    require(normalized not in ('..',) and not normalized.startswith('../'),
            f'{label} link target escapes the root: {link_name!r}')
    return normalized or '.'


def inspect_archive(archive: Path) -> tuple[int, list[str]]:
    """Validate names and links without extracting or executing anything."""
    try:
        with tarfile.open(archive, mode='r:*') as stream:
            members = stream.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise PreparationError(f'cannot inspect archive: {exc}') from exc

    names: set[str] = set()
    symlinks: set[str] = set()
    hardlinks: list[tuple[str, str]] = []
    for member in members:
        name = archive_relative(member.name, 'archive member')
        require(name not in names, f'duplicate archive member after normalization: {name}')
        names.add(name)
        require(member.isdir() or member.isfile() or member.issym() or member.islnk(),
                f'archive contains an unsupported special member: {name}')
        if member.issym():
            archive_link_target(name, member.linkname, f'archive symlink {name}')
            symlinks.add(name)
        elif member.islnk():
            target = archive_relative(member.linkname, f'archive hardlink {name}')
            hardlinks.append((name, target))

    for name in sorted(names):
        if name == '.':
            continue
        components = name.split('/')
        for index in range(1, len(components)):
            parent = '/'.join(components[:index])
            require(parent not in symlinks,
                    f'archive member traverses an archive symlink: {name}')

    for name, target in hardlinks:
        require(target in names and target not in symlinks,
                f'hardlink target is absent or a symlink: {name} -> {target}')
    return len(members), sorted(names)


def relative_path(value: str, label: str) -> tuple[str, ...]:
    require(value and not value.startswith('/'), f'{label} must be relative')
    require('\x00' not in value and '\\' not in value,
            f'{label} contains an unsafe character')
    parts = tuple(part for part in value.split('/') if part not in ('', '.'))
    require('..' not in parts, f'{label} traverses parent directories')
    return parts


def root_path(relative: str, label: str) -> Path:
    parts = relative_path(relative, label)
    path = ROOTDIR.joinpath(*parts)
    current = ROOTDIR
    for part in parts[:-1]:
        current = current / part
        if current.exists() or is_symlink(current):
            ensure_directory(current, f'{label} parent')
    return path


def ensure_target_parent(relative: str) -> Path:
    parts = relative_path(relative, 'target path')
    require(parts, 'target path cannot be the root directory')
    current = ROOTDIR
    for part in parts[:-1]:
        current = current / part
        if current.exists() or is_symlink(current):
            ensure_directory(current, 'target parent')
        else:
            current.mkdir(mode=0o755)
            os.chown(current, 0, 0)
            os.chmod(current, 0o755)
    return ROOTDIR.joinpath(*parts)


def safe_read(relative: str, label: str) -> str:
    path = root_path(relative, label)
    st = lstat(path, label)
    require(stat.S_ISREG(st.st_mode), f'{label} is not a regular file: {path}')
    return path.read_text(encoding='utf-8')


def safe_write(relative: str, data: str, mode: int = 0o644) -> None:
    path = ensure_target_parent(relative)
    if path.exists() or is_symlink(path):
        st = lstat(path, f'target {relative}')
        require(stat.S_ISREG(st.st_mode), f'target is not a regular file: {path}')
        require(not stat.S_ISLNK(st.st_mode), f'target is a symlink: {path}')
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, mode)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        payload = data.encode('utf-8')
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            require(written > 0, f'zero-length write for {path}')
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def safe_copy(source: Path, relative: str, mode: int) -> None:
    ensure_regular_source(source, f'overlay source {source}')
    safe_write(relative, source.read_text(encoding='utf-8'), mode)


def safe_symlink(relative: str, target: str) -> None:
    path = ensure_target_parent(relative)
    if path.exists() or is_symlink(path):
        st = lstat(path, f'symlink target {relative}')
        require(stat.S_ISLNK(st.st_mode), f'cannot replace non-symlink: {path}')
        require(os.readlink(path) == target,
                f'existing symlink points elsewhere: {path}')
        return
    os.symlink(target, path)
    os.lchown(path, 0, 0)


def remove_managed_symlink(relative: str, target: str) -> None:
    """Remove an old profile link only when it is the expected unit link."""
    path = root_path(relative, f'legacy unit link {relative}')
    if not path.exists() and not is_symlink(path):
        return
    st = lstat(path, f'legacy unit link {relative}')
    require(stat.S_ISLNK(st.st_mode), f'legacy unit link is not a symlink: {path}')
    require(os.readlink(path) == target,
            f'legacy unit link points elsewhere: {path}')
    path.unlink()


def normalize_top_directory(path: Path, label: str) -> None:
    ensure_directory(path, label)
    os.lchown(path, 0, 0)
    os.chmod(path, 0o755)


def run_host_openssl() -> str:
    openssl = shutil.which('openssl')
    require(openssl is not None, 'host openssl is required to set the root bring-up password')
    result = subprocess.run(
        [openssl, 'passwd', '-6', '-salt', 'r8qroot', '-stdin'],
        input='root\n', check=False, capture_output=True, text=True, timeout=10,
    )
    require(result.returncode == 0, f'openssl passwd failed: {result.stderr.strip()}')
    hashed = result.stdout.strip()
    require(hashed.startswith('$6$') and '\n' not in hashed and '\x00' not in hashed,
            'openssl did not return a SHA-512 crypt hash')
    return hashed


def configure_shadow() -> str:
    shadow = safe_read('etc/shadow', 'root shadow file')
    hashed = run_host_openssl()
    lines = shadow.splitlines()
    replaced = False
    output: list[str] = []
    for line in lines:
        if line.startswith('root:'):
            fields = line.split(':')
            require(len(fields) >= 2, 'root shadow entry is malformed')
            fields[1] = hashed
            line = ':'.join(fields)
            replaced = True
        output.append(line)
    require(replaced, 'root shadow entry is absent')
    safe_write('etc/shadow', '\n'.join(output) + '\n', 0o600)
    return 'set-to-root-with-fixed-salt'


def configure_sshd() -> None:
    config = safe_read('etc/ssh/sshd_config', 'sshd configuration')
    kept: list[str] = []
    managed = {'permitrootlogin', 'passwordauthentication', 'kbdinteractiveauthentication'}
    for line in config.splitlines():
        stripped = line.lstrip()
        if stripped and not stripped.startswith('#'):
            key = stripped.split(None, 1)[0].casefold()
            if key in managed:
                continue
        kept.append(line)
    if kept and kept[-1] != '':
        kept.append('')
    kept.extend([
        '# r8q temporary bring-up access',
        'PermitRootLogin yes',
        'PasswordAuthentication yes',
        'KbdInteractiveAuthentication no',
    ])
    safe_write('etc/ssh/sshd_config', '\n'.join(kept) + '\n', 0o644)


def check_runtime_files() -> dict[str, str]:
    candidates = ('usr/sbin/sshd', 'usr/bin/sshd')
    sshd = None
    for candidate in candidates:
        path = ROOTDIR / candidate
        if path.exists() and not is_symlink(path):
            st = lstat(path, f'sshd binary {candidate}')
            if stat.S_ISREG(st.st_mode):
                sshd = candidate
                break
    require(sshd is not None, 'Arch rootfs does not contain an sshd binary')
    required = {
        'systemd': 'usr/lib/systemd/systemd',
        'networkd': 'usr/lib/systemd/systemd-networkd',
        'sshd_unit': 'usr/lib/systemd/system/sshd.service',
        'networkd_unit': 'usr/lib/systemd/system/systemd-networkd.service',
        'networkd_socket': 'usr/lib/systemd/system/systemd-networkd.socket',
    }
    for label, relative in required.items():
        path = root_path(relative, label)
        st = lstat(path, label)
        require(stat.S_ISREG(st.st_mode), f'{label} is not a regular file: {path}')
    # Python is intentionally optional at bootstrap.  The startup wrapper
    # performs a shell-only MaxPower write for an unbound gadget and defers a
    # bound legacy descriptor when Python is absent; the helper is still copied
    # into the image for later transactional normalization.
    return {'sshd': sshd, **required}


def move_stock_modules() -> list[str]:
    modules = root_path(MODULES_REL, 'stock module directory')
    disabled = root_path(DISABLED_MODULES_REL, 'disabled module directory')
    if modules.exists() or is_symlink(modules):
        ensure_directory(modules, 'stock module directory')
    else:
        ensure_target_parent(DISABLED_MODULES_REL)
        if disabled.exists() or is_symlink(disabled):
            ensure_directory(disabled, 'disabled module directory')
            require(not any(disabled.iterdir()), 'disabled module directory is not empty')
        else:
            disabled.mkdir(mode=0o755)
            os.chown(disabled, 0, 0)
            os.chmod(disabled, 0o755)
        return []
    if disabled.exists() or is_symlink(disabled):
        ensure_directory(disabled, 'disabled module directory')
        require(not any(disabled.iterdir()), 'disabled module directory is not empty')
    else:
        ensure_target_parent(DISABLED_MODULES_REL)
        disabled.mkdir(mode=0o755)
        os.chown(disabled, 0, 0)
        os.chmod(disabled, 0o755)
    moved: list[str] = []
    for entry in sorted(modules.iterdir(), key=lambda value: value.name):
        destination = disabled / entry.name
        require(not destination.exists() and not is_symlink(destination),
                f'module destination already exists: {destination}')
        os.rename(entry, destination)
        moved.append(entry.name)
    return moved


def enable_units() -> list[str]:
    remove_managed_symlink(
        'etc/systemd/system/multi-user.target.wants/r8q-usb-route.service',
        '/etc/systemd/system/r8q-usb-route.service',
    )
    links = {
        'etc/systemd/system/multi-user.target.wants/r8q-usb-gadget.service':
            '/etc/systemd/system/r8q-usb-gadget.service',
        # The hardware preparation unit is the sole early GPI/GENI owner. The
        # legacy route unit remains installed as a read-only current-boot receipt
        # witness, but is intentionally not enabled in this profile.
        'etc/systemd/system/network-pre.target.wants/r8q-hardware-prepare.service':
            '/etc/systemd/system/r8q-hardware-prepare.service',
        'etc/systemd/system/multi-user.target.wants/systemd-networkd.service':
            '/usr/lib/systemd/system/systemd-networkd.service',
        'etc/systemd/system/sockets.target.wants/systemd-networkd.socket':
            '/usr/lib/systemd/system/systemd-networkd.socket',
        'etc/systemd/system/multi-user.target.wants/sshd.service':
            '/usr/lib/systemd/system/sshd.service',
    }
    for relative, target in links.items():
        safe_symlink(relative, target)
    return sorted(links)


def configure_rootfs(archive_sha256: str, archive_members: int) -> dict[str, object]:
    normalize_top_directory(ROOTDIR, 'rootfs root')
    usr = root_path('usr', 'rootfs /usr')
    etc = root_path('etc', 'rootfs /etc')
    ensure_directory(usr, 'rootfs /usr')
    ensure_directory(etc, 'rootfs /etc')
    normalize_top_directory(usr, 'rootfs /usr')
    normalize_top_directory(etc, 'rootfs /etc')

    runtime = check_runtime_files()
    moved_modules = move_stock_modules()

    safe_write('etc/fstab', 'LABEL=archroot  /  ext4  rw,relatime  0 1\n', 0o644)
    safe_write('etc/hostname', 'r8q\n', 0o644)
    safe_write(
        'etc/systemd/network/20-usb0.network',
        '[Match]\n'
        'Name=usb0\n\n'
        '[Network]\n'
        'Address=172.16.42.1/24\n'
        'ConfigureWithoutCarrier=yes\n',
        0o644,
    )
    safe_copy(NCM_SERVICE, 'etc/systemd/system/r8q-usb-gadget.service', 0o644)
    safe_copy(NCM_SCRIPT, 'usr/local/sbin/r8q-usb-gadget-up.sh', 0o755)
    safe_copy(NCM_MAXPOWER, 'usr/local/libexec/r8q-gadget-maxpower.py', 0o755)
    safe_copy(USB_ROUTE_SERVICE, 'etc/systemd/system/r8q-usb-route.service', 0o644)
    safe_copy(USB_ROUTE_WITNESS, 'usr/local/sbin/r8q-usb-route-witness.sh', 0o755)
    safe_copy(HARDWARE_PREPARE_SERVICE,
              'etc/systemd/system/r8q-hardware-prepare.service', 0o644)
    safe_copy(USB_ROUTE_WRAPPER, 'usr/local/sbin/r8q-usb-route-up.sh', 0o755)
    safe_copy(USB_ROUTE_HELPER, 'usr/local/sbin/r8q-usb-route-ensure.sh', 0o755)
    safe_copy(USB_ROUTE_PROTOCOL,
              'usr/local/lib/r8q-usb-route/protocol-binding.env', 0o644)
    safe_copy(USB_ROUTE_MODPROBE, 'etc/modprobe.d/r8q-usb-route.conf', 0o644)
    safe_copy(USB_ROUTE_ENV_EXAMPLE, 'etc/r8q-usb-route.env.example', 0o644)
    safe_copy(USB_ROUTE_PACKAGES, 'usr/share/r8q/r8q-usb-route.packages', 0o644)
    safe_copy(GETTY_OVERLAY,
              'etc/systemd/system/getty@tty1.service.d/autologin.conf', 0o644)

    configure_sshd()
    password_action = configure_shadow()

    masks = [
        'sleep.target',
        'suspend.target',
        'hibernate.target',
        'hybrid-sleep.target',
        'suspend-then-hibernate.target',
    ]
    for unit in masks:
        safe_symlink(f'etc/systemd/system/{unit}', '/dev/null')
    enabled = enable_units()

    # Reassert ownership/modes on every prepared file. Only the repository
    # overlay files listed above are included; /home/alarm and the rest of
    # the extracted tree remain as provided by the trusted archive.
    for relative, mode in (
        ('etc/fstab', 0o644),
        ('etc/hostname', 0o644),
        ('etc/systemd/network/20-usb0.network', 0o644),
        ('etc/systemd/system/r8q-usb-gadget.service', 0o644),
        ('usr/local/sbin/r8q-usb-gadget-up.sh', 0o755),
        ('usr/local/libexec/r8q-gadget-maxpower.py', 0o755),
        ('etc/systemd/system/r8q-usb-route.service', 0o644),
        ('usr/local/sbin/r8q-usb-route-witness.sh', 0o755),
        ('etc/systemd/system/r8q-hardware-prepare.service', 0o644),
        ('usr/local/sbin/r8q-usb-route-up.sh', 0o755),
        ('usr/local/sbin/r8q-usb-route-ensure.sh', 0o755),
        ('usr/local/lib/r8q-usb-route/protocol-binding.env', 0o644),
        ('etc/modprobe.d/r8q-usb-route.conf', 0o644),
        ('etc/r8q-usb-route.env.example', 0o644),
        ('usr/share/r8q/r8q-usb-route.packages', 0o644),
        ('etc/systemd/system/getty@tty1.service.d/autologin.conf', 0o644),
        ('etc/ssh/sshd_config', 0o644),
        ('etc/shadow', 0o600),
    ):
        path = root_path(relative, f'prepared file {relative}')
        st = lstat(path, f'prepared file {relative}')
        require(stat.S_ISREG(st.st_mode), f'prepared file is not regular: {path}')
        os.chown(path, 0, 0)
        os.chmod(path, mode)

    return {
        'schema': 'r8q-arch-rootfs-preparation/v1',
        'archive_sha256': archive_sha256,
        'archive_members': archive_members,
        'rootdir': str(ROOTDIR),
        'runtime_files': runtime,
        'moved_stock_module_releases': moved_modules,
        'disabled_module_directory': str(ROOTDIR / DISABLED_MODULES_REL),
        'configured_files': [
            'etc/fstab',
            'etc/hostname',
            'etc/systemd/network/20-usb0.network',
            'etc/systemd/system/r8q-usb-gadget.service',
            'usr/local/sbin/r8q-usb-gadget-up.sh',
            'usr/local/libexec/r8q-gadget-maxpower.py',
            'etc/systemd/system/r8q-usb-route.service',
            'usr/local/sbin/r8q-usb-route-witness.sh',
            'etc/systemd/system/r8q-hardware-prepare.service',
            'usr/local/sbin/r8q-usb-route-up.sh',
            'usr/local/sbin/r8q-usb-route-ensure.sh',
            'usr/local/lib/r8q-usb-route/protocol-binding.env',
            'etc/modprobe.d/r8q-usb-route.conf',
            'etc/r8q-usb-route.env.example',
            'usr/share/r8q/r8q-usb-route.packages',
            'etc/systemd/system/getty@tty1.service.d/autologin.conf',
            'etc/ssh/sshd_config',
            'etc/shadow',
        ],
        'enabled_units': enabled,
        'required_phone_packages': ['i2c-tools'],
        'masked_sleep_units': masks,
        'root_password': password_action,
        'phone_access': False,
        'block_device_access': False,
        'mount_or_loop_access': False,
        'chroot_or_rootfs_binary_execution': False,
    }


def prepare(archive_arg: str, expected_arg: str) -> dict[str, object]:
    require(os.geteuid() == 0, 'run this helper as root')
    archive = Path(archive_arg)
    require(archive.is_absolute(), 'archive path must be absolute')
    ensure_regular_source(archive, 'archive')
    archive = archive.resolve(strict=True)
    expected = expected_arg.casefold()
    require(len(expected) == 64 and all(char in '0123456789abcdef' for char in expected),
            'expected SHA256 must be exactly 64 hexadecimal characters')
    actual = sha256_file(archive)
    require(actual == expected, f'archive SHA256 mismatch: expected {expected}, got {actual}')
    member_count, _ = inspect_archive(archive)

    if PREPARATION.exists() or is_symlink(PREPARATION):
        ensure_directory(PREPARATION, 'preparation directory')
    else:
        require(PREPARATION.parent.is_dir() and not is_symlink(PREPARATION.parent),
                f'output parent is unavailable: {PREPARATION.parent}')
        PREPARATION.mkdir(mode=0o755)
        os.chown(PREPARATION, 0, 0)
        os.chmod(PREPARATION, 0o755)
    require(not ROOTDIR.exists() and not is_symlink(ROOTDIR),
            f'one-shot rootdir already exists: {ROOTDIR}')
    ROOTDIR.mkdir(mode=0o755)
    os.chown(ROOTDIR, 0, 0)
    os.chmod(ROOTDIR, 0o755)

    bsdtar = shutil.which('bsdtar')
    require(bsdtar is not None, 'host bsdtar is required')
    command = [
        bsdtar, '-xpf', str(archive), '-C', str(ROOTDIR),
        '--numeric-owner', '--xattrs', '--acls',
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    require(result.returncode == 0,
            f'bsdtar extraction failed: {result.stderr.strip() or result.stdout.strip()}')
    return configure_rootfs(actual, member_count)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', help='absolute path to a trusted Arch rootfs archive')
    parser.add_argument('sha256', help='expected SHA256 of the archive')
    args = parser.parse_args()
    try:
        receipt = prepare(args.archive, args.sha256)
    except (PreparationError, OSError, subprocess.SubprocessError) as exc:
        print(f'prepare-arch-rootfs: ERROR: {exc}', file=sys.stderr, flush=True)
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
