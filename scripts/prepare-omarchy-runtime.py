#!/usr/bin/env python3
"""Prepare the reviewed, selective Omarchy Quattro runtime for the R8Q.

This is an offline file preparer.  It accepts a caller-provided Omarchy source
archive, verifies the pinned v4.0.4 SHA-256, copies only the shell/runtime files
needed by the phone overlay plus the pinned Tokyo Night wallpaper inputs, and
emits a hashed manifest.  It never downloads, executes archive content, invokes
a package manager, touches a live root, or changes the existing rootfs
preparation flow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tarfile
from pathlib import Path
from typing import Iterable


REPO = Path(__file__).resolve().parents[1]
PHONE_OVERLAY = REPO / 'rootfs' / 'usr' / 'share' / 'r8q' / 'omarchy'
PINNED_SHA256 = '8cc6b1d9d903c606600395e3b3d80ad9f15bd3ab78f0f19b0f49041b1df82013'
PINNED_COMMIT = 'c668141e9c42b13c80c9ca4ea108e11708c5e8a5'
PINNED_VERSION = '4.0.4'

SOURCE_PREFIXES = ('shell', 'default/omarchy')
SOURCE_FILES = (
    # The upstream default is retained as provenance under
    # config/omarchy/upstream-shell.json.  The reviewed phone shell replaces
    # the live default at config/omarchy/shell.json below.
    'config/omarchy/shell.json',
    'bin/omarchy-launch-shell',
    'bin/omarchy-shell',
    # The audio panel invokes these helpers through Quickshell Process and
    # execDetached.  Its sink-availability probe calls audio-tuning only to
    # detect an existing tuning; no tuning payload or service is staged.
    'bin/omarchy-audio-output-sink',
    'bin/omarchy-audio-sink-availability',
    'bin/omarchy-audio-output-set-default',
    'bin/omarchy-audio-input-set-default',
    'bin/omarchy-audio-tuning',
    # The pinned Tokyo Night selection is deliberately limited to the color
    # data, two authentic wallpaper choices, and the templates/helpers needed
    # to apply them. Other themes, app templates and picker helpers stay out;
    # the bundled image-picker code remains disabled in the phone config.
    'themes/tokyo-night/colors.toml',
    'themes/tokyo-night/backgrounds/0-winding-road.jpg',
    'themes/tokyo-night/backgrounds/1-quattro.jpg',
    'default/themed/foot.ini.tpl',
    'default/themed/hyprland.lua.tpl',
    'bin/omarchy-theme-bg-set',
    'version',
    'LICENSE',
)
# These are deliberately explicit transformations of the tracked phone
# overlay.  Keeping the source config and the phone replacement in separate
# manifest entries makes the only changed upstream path auditable.
RUNTIME_OVERLAY_FILES = {
    'phone-hyprland.lua': 'phone-hyprland.lua',
    'phone-hypridle.conf': 'phone-hypridle.conf',
    'phone-session.env': 'phone-session.env',
    'phone-shell.json': 'config/omarchy/shell.json',
    'omarchy-runtime.packages': 'config/omarchy/omarchy-runtime.packages',
}
RUNTIME_OVERLAY_PREFIXES = {
    'plugin/r8q.launcher': 'phone-plugin/r8q.launcher',
    'plugin/r8q.battery': 'phone-plugin/r8q.battery',
}
EXTRA_ROOTFS_FILES = ('usr/local/bin/r8q-lock-preview',)
ABSOLUTE_SYMLINKS = {
    'usr/bin/omarchy-launch-shell': '/usr/share/omarchy/bin/omarchy-launch-shell',
    'usr/bin/omarchy-shell': '/usr/share/omarchy/bin/omarchy-shell',
    'usr/bin/omarchy-audio-output-sink': '/usr/share/omarchy/bin/omarchy-audio-output-sink',
    'usr/bin/omarchy-audio-sink-availability': '/usr/share/omarchy/bin/omarchy-audio-sink-availability',
    'usr/bin/omarchy-audio-output-set-default': '/usr/share/omarchy/bin/omarchy-audio-output-set-default',
    'usr/bin/omarchy-audio-input-set-default': '/usr/share/omarchy/bin/omarchy-audio-input-set-default',
    'usr/bin/omarchy-audio-tuning': '/usr/share/omarchy/bin/omarchy-audio-tuning',
}


class PreparationError(RuntimeError):
    """A fail-closed preparation guard failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_archive_name(raw_name: str, label: str) -> str:
    require(isinstance(raw_name, str), f'{label} has a non-text name')
    require('\x00' not in raw_name, f'{label} contains NUL')
    require(not raw_name.startswith('/'), f'{label} is absolute: {raw_name!r}')
    parts = raw_name.split('/')
    require('..' not in parts, f'{label} traverses a parent: {raw_name!r}')
    cleaned = [part for part in parts if part not in ('', '.')]
    require(cleaned, f'{label} is empty')
    return '/'.join(cleaned)


def relative_archive_member(name: str, top: str) -> str | None:
    if name == top:
        return ''
    prefix = top + '/'
    if name.startswith(prefix):
        return name[len(prefix):]
    return None


def is_selected(relative: str) -> bool:
    if relative in SOURCE_FILES:
        return True
    return any(relative == prefix or relative.startswith(prefix + '/')
               for prefix in SOURCE_PREFIXES)


def selected_parent_names(relative: str) -> Iterable[str]:
    parts = relative.split('/')
    for index in range(1, len(parts)):
        yield '/'.join(parts[:index])


def inspect_archive(archive: Path) -> tuple[str, dict[str, tarfile.TarInfo], int]:
    """Index the archive and reject traversal/special selected members."""
    try:
        stream = tarfile.open(archive, mode='r:*')
    except (OSError, tarfile.TarError) as exc:
        raise PreparationError(f'cannot open source archive: {exc}') from exc

    members: dict[str, tarfile.TarInfo] = {}
    try:
        raw_members = stream.getmembers()
    except (OSError, tarfile.TarError) as exc:
        stream.close()
        raise PreparationError(f'cannot inspect source archive: {exc}') from exc
    finally:
        stream.close()

    top_names: set[str] = set()
    for index, member in enumerate(raw_members):
        name = normalized_archive_name(member.name, f'archive member {index}')
        top_names.add(name.split('/', 1)[0])
        require(name not in members, f'duplicate archive member: {name}')
        members[name] = member
        # The source archive is trusted by hash, but never extract an archive
        # link. Selected trees must be made entirely from regular files/dirs.
        if is_selected(name) or any(name.startswith(prefix + '/') for prefix in SOURCE_PREFIXES):
            require(member.isdir() or member.isfile(),
                    f'selected source member is not a regular file/directory: {name}')

    require(len(top_names) == 1, f'archive must have one top directory: {sorted(top_names)}')
    top = next(iter(top_names))
    require(top not in ('.', '..'), f'invalid archive top directory: {top}')

    selected: dict[str, tarfile.TarInfo] = {}
    for name, member in members.items():
        relative = relative_archive_member(name, top)
        if relative is None or not relative or not is_selected(relative):
            continue
        if member.isdir():
            continue
        selected[relative] = member

    for relative, member in selected.items():
        require(member.isfile(), f'selected file is not regular: {relative}')
        for parent in selected_parent_names(relative):
            parent_member = members.get(top + '/' + parent)
            require(parent_member is None or parent_member.isdir(),
                    f'selected path traverses non-directory: {relative}')

    required = set(SOURCE_FILES)
    missing = sorted(required - selected.keys())
    require(not missing, f'source archive is missing required files: {missing}')
    require(any(name == 'shell/shell.qml' for name in selected),
            'source archive is missing shell/shell.qml')
    return top, selected, len(raw_members)


def ensure_output_path(output: Path) -> Path:
    output = output.expanduser()
    require(output.is_absolute(), 'output must be an absolute path')
    output = output.resolve(strict=False)
    out_root = (REPO / 'out').resolve(strict=True)
    require(output != out_root and out_root in output.parents,
            f'output must be a new child of {out_root}: {output}')
    live_roots = tuple(Path(path) for path in (
        '/usr', '/etc', '/boot', '/var', '/bin', '/sbin',
        '/lib', '/lib64', '/run', '/sys', '/proc', '/dev', '/opt',
    ))
    require(all(output != root and root not in output.parents for root in live_roots),
            f'refusing live/system output path: {output}')
    require(not output.exists() and not output.is_symlink(),
            f'output already exists; choose a fresh destination: {output}')
    parent = output.parent
    require(parent.exists() and parent.is_dir() and not parent.is_symlink(),
            f'output parent must be an existing non-symlink directory: {parent}')
    return output


def ensure_regular_overlay(path: Path, relative: str) -> None:
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode), f'phone overlay is not regular: {relative}')
    require(not stat.S_ISLNK(st.st_mode), f'phone overlay is a symlink: {relative}')


def write_regular(source: bytes, target: Path, mode: int) -> dict[str, object]:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    require(not target.exists() and not target.is_symlink(),
            f'refusing to replace staged path: {target}')
    target.write_bytes(source)
    os.chmod(target, mode & 0o777)
    return {
        'path': '/' + target.relative_to(CURRENT_OUTPUT).as_posix(),
        'bytes': len(source),
        'mode': format(mode & 0o777, '04o'),
        'sha256': hashlib.sha256(source).hexdigest(),
    }


CURRENT_OUTPUT = Path('/')


def copy_source_files(archive: Path, top: str, selected: dict[str, tarfile.TarInfo],
                      output: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    with tarfile.open(archive, mode='r:*') as stream:
        for relative in sorted(selected):
            member = selected[relative]
            extracted = stream.extractfile(member)
            require(extracted is not None, f'cannot read selected archive file: {relative}')
            data = extracted.read()
            # Preserve the stock config before placing the reviewed phone
            # config at the canonical default path.  This is the only source
            # file whose staged target is intentionally renamed.
            target_relative = (
                'config/omarchy/upstream-shell.json'
                if relative == 'config/omarchy/shell.json' else relative
            )
            target = output / 'rootfs' / 'usr' / 'share' / 'omarchy' / target_relative
            # All explicitly selected bin helpers are executable, regardless
            # of the mode recorded in the source archive.  Non-bin inputs are
            # staged as data files.
            mode = 0o755 if relative.startswith('bin/') else 0o644
            files.append(write_regular(data, target, mode))
    return files


def copy_runtime_overlay(output: Path) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    """Stage the reviewed phone overlay at the frozen runtime locations."""
    files: list[dict[str, object]] = []
    transformations: list[dict[str, str]] = []

    for source_relative, target_relative in sorted(RUNTIME_OVERLAY_FILES.items()):
        source = PHONE_OVERLAY / source_relative
        ensure_regular_overlay(source, source_relative)
        target = output / 'rootfs' / 'usr' / 'share' / 'omarchy' / target_relative
        data = source.read_bytes()
        files.append(write_regular(data, target, source.stat().st_mode))
        transformations.append({
            'source': '/usr/share/r8q/omarchy/' + source_relative,
            'target': '/usr/share/omarchy/' + target_relative,
            'action': 'phone-overlay-copy',
        })

    for source_prefix, target_prefix in sorted(RUNTIME_OVERLAY_PREFIXES.items()):
        source_root = PHONE_OVERLAY / source_prefix
        require(source_root.is_dir() and not source_root.is_symlink(),
                f'phone overlay directory is unavailable: {source_prefix}')
        for source in sorted(source_root.rglob('*')):
            relative = source.relative_to(PHONE_OVERLAY).as_posix()
            if source.is_dir():
                require(not source.is_symlink(), f'phone overlay directory is a symlink: {relative}')
                continue
            ensure_regular_overlay(source, relative)
            suffix = source.relative_to(source_root).as_posix()
            target_relative = target_prefix + '/' + suffix
            target = output / 'rootfs' / 'usr' / 'share' / 'omarchy' / target_relative
            files.append(write_regular(source.read_bytes(), target, source.stat().st_mode))
            transformations.append({
                'source': '/usr/share/r8q/omarchy/' + relative,
                'target': '/usr/share/omarchy/' + target_relative,
                'action': 'phone-overlay-copy',
            })

    return files, transformations


def copy_overlay(output: Path) -> list[dict[str, object]]:
    require(PHONE_OVERLAY.is_dir() and not PHONE_OVERLAY.is_symlink(),
            f'tracked phone overlay is unavailable: {PHONE_OVERLAY}')
    files: list[dict[str, object]] = []
    for source in sorted(PHONE_OVERLAY.rglob('*')):
        relative = source.relative_to(PHONE_OVERLAY).as_posix()
        if source.is_dir():
            require(not source.is_symlink(), f'phone overlay directory is a symlink: {relative}')
            continue
        ensure_regular_overlay(source, relative)
        target = output / 'rootfs' / 'usr' / 'share' / 'r8q' / 'omarchy' / relative
        data = source.read_bytes()
        files.append(write_regular(data, target, source.stat().st_mode))
    require(files, 'tracked phone overlay is empty')
    # The standalone timed preview is additive and does not enable a lock.
    for relative in EXTRA_ROOTFS_FILES:
        source = REPO / 'rootfs' / relative
        ensure_regular_overlay(source, relative)
        files.append(write_regular(source.read_bytes(), output / 'rootfs' / relative,
                                   source.stat().st_mode))
    return files


def add_absolute_symlinks(output: Path) -> list[dict[str, str]]:
    symlinks: list[dict[str, str]] = []
    for relative, target in sorted(ABSOLUTE_SYMLINKS.items()):
        path = output / 'rootfs' / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        require(not path.exists() and not path.is_symlink(),
                f'refusing to replace staged path: {path}')
        os.symlink(target, path)
        symlinks.append({'path': '/' + relative, 'target': target})
    return symlinks


def prepare(archive_arg: str, expected_sha256: str, output_arg: str) -> dict[str, object]:
    global CURRENT_OUTPUT
    archive = Path(archive_arg).expanduser()
    require(archive.is_absolute(), 'source archive must be an absolute path')
    require(archive.is_file() and not archive.is_symlink(),
            f'source archive is not a regular file: {archive}')
    archive = archive.resolve(strict=True)
    expected = expected_sha256.casefold()
    require(expected == PINNED_SHA256,
            f'expected SHA256 must be the pinned c668... archive hash: {PINNED_SHA256}')
    actual = sha256_file(archive)
    require(actual == expected,
            f'source archive SHA256 mismatch: expected {expected}, got {actual}')
    top, selected, member_count = inspect_archive(archive)
    output = ensure_output_path(Path(output_arg))
    CURRENT_OUTPUT = output
    output.mkdir(mode=0o755)

    source_files = copy_source_files(archive, top, selected, output)
    runtime_overlay_files, runtime_transformations = copy_runtime_overlay(output)
    overlay_files = copy_overlay(output)
    symlinks = add_absolute_symlinks(output)

    manifest: dict[str, object] = {
        'schema': 'r8q-omarchy-runtime-preparer/v1',
        'source_archive': str(archive),
        'source_sha256': actual,
        'source_commit': PINNED_COMMIT,
        'source_version': PINNED_VERSION,
        'archive_top_directory': top,
        'archive_member_count': member_count,
        'source_selected': [*SOURCE_PREFIXES, *SOURCE_FILES],
        'runtime_target': '/usr/share/omarchy',
        'phone_overlay_target': '/usr/share/r8q/omarchy',
        'regular_files': sorted(source_files + runtime_overlay_files + overlay_files,
                                 key=lambda item: str(item['path'])),
        'source_target_rewrites': [{
            'source': '/usr/share/omarchy/config/omarchy/shell.json',
            'target': '/usr/share/omarchy/config/omarchy/upstream-shell.json',
            'reason': 'retain upstream default beside the reviewed phone default',
        }],
        'phone_runtime_transformations': runtime_transformations,
        'absolute_usr_bin_symlinks': symlinks,
        'archive_content_executed': False,
        'network_access': False,
        'package_manager_invoked': False,
        'system_configuration_changed': False,
        'phone_execution': False,
        'manifest_excludes_itself': True,
    }
    manifest_path = output / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.chmod(manifest_path, 0o644)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', help='absolute path to the trusted Omarchy c668... tar.gz')
    parser.add_argument('--output', required=True,
                        help='new child directory below r8q-arch/out/')
    parser.add_argument('--expected-sha256', default=PINNED_SHA256,
                        help='expected archive SHA256 (must equal the pinned manifest hash)')
    args = parser.parse_args()
    try:
        manifest = prepare(args.archive, args.expected_sha256, args.output)
    except (PreparationError, OSError, tarfile.TarError) as exc:
        print(f'prepare-omarchy-runtime: ERROR: {exc}', file=sys.stderr, flush=True)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
