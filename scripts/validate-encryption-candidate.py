#!/usr/bin/env python3
"""Audit the produced EFI Image and its embedded cpio without executing them."""
import gzip
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def capture_source(source, destination):
    aggregate = hashlib.sha256()
    count = 0
    with destination.open('w') as receipt:
        for path in sorted(source.rglob('*')):
            if (path.is_file() or path.is_symlink()) and '.git' not in path.relative_to(source).parts:
                record = dict(path=path.relative_to(source).as_posix())
                if path.is_symlink():
                    record['symlink'] = str(path.readlink())
                else:
                    record['sha256'] = sha(path.read_bytes())
                line = json.dumps(record, sort_keys=True) + '\n'
                receipt.write(line)
                aggregate.update(line.encode())
                count += 1
    return count, aggregate.hexdigest()


def parse_cpio(data):
    records = {}
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        require(header[:6] == b'070701', 'Invalid newc header')
        fields = [int(header[n:n + 8], 16) for n in range(6, 110, 8)]
        _, mode, uid, gid, _, _, size, _, _, rmajor, rminor, namesize, _ = fields
        offset += 110
        raw_name = data[offset:offset + namesize]
        require(len(raw_name) == namesize and raw_name.endswith(b'\0'), 'Invalid cpio name')
        name = raw_name[:-1].decode()
        offset = (offset + namesize + 3) & ~3
        content = data[offset:offset + size]
        require(len(content) == size, 'Truncated cpio payload')
        offset = (offset + size + 3) & ~3
        if name == 'TRAILER!!!':
            require(not any(data[offset:]), 'Unexpected data after cpio trailer')
            return records
        require(not name.startswith('/') and '..' not in name.split('/'), 'Unsafe cpio path')
        require(uid == 0 and gid == 0, 'Non-root archive ownership: ' + name)
        record = dict(mode=mode, uid=uid, gid=gid, bytes=size, sha256=sha(content), rdev_major=rmajor, rdev_minor=rminor)
        if name in records:
            require(records[name] == record, 'Conflicting duplicate cpio path: ' + name)
        records[name] = record
    raise SystemExit('Missing cpio trailer')


def main():
    output, source, initroot = map(Path, sys.argv[1:])
    image = output / 'payload/BOOTAA64.EFI'
    data = image.read_bytes()
    require(data[:2] == b'MZ' and data[56:60] == b'ARM\x64', 'Invalid ARM64 EFI header')
    pe = struct.unpack_from('<I', data, 60)[0]
    require(data[pe:pe + 4] == b'PE\0\0', 'Missing PE signature')
    require(struct.unpack_from('<H', data, pe + 4)[0] == 0xaa64, 'Wrong PE architecture')
    require(struct.unpack_from('<H', data, pe + 24 + 68)[0] == 10, 'Not an EFI application')
    # ARM64 image_size includes the zero-filled BSS; Image omits those bytes.
    runtime_size = struct.unpack_from('<Q', data, 16)[0]
    require(len(data) <= runtime_size < len(data) + 64 * 1024 * 1024, 'Invalid ARM64 runtime size')
    symbols = {}
    for line in subprocess.check_output(['llvm-nm', str(output / 'vmlinux')], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in ('_text', '__initramfs_start'):
            symbols[fields[2]] = int(fields[0], 16)
    require(len(symbols) == 2, 'Missing embedded initramfs symbols')
    compressed = (output / 'usr/initramfs_inc_data').read_bytes()
    offset = symbols['__initramfs_start'] - symbols['_text']
    require(data[offset:offset + len(compressed)] == compressed, 'Image does not contain generated initramfs')
    cpio = gzip.decompress(compressed)
    require(cpio == (output / 'usr/initramfs_data.cpio').read_bytes(), 'Compressed initramfs differs from cpio')
    records = parse_cpio(cpio)
    require('init.normal' not in records, 'Plaintext fallback embedded')
    expected = {path.relative_to(initroot).as_posix() for path in initroot.rglob('*')}
    node_list = Path(__file__).resolve().parents[1] / 'initramfs/irfs.devnodes'
    for line in node_list.read_text().splitlines():
        fields = line.split()
        if not fields or fields[0].startswith('#'):
            continue
        kind, absolute, mode, uid, gid = fields[:5]
        name = absolute.lstrip('/')
        expected.add(name)
        require(name in records, 'Missing explicit device/directory: ' + name)
        record = records[name]
        require(stat.S_IMODE(record['mode']) == int(mode, 8), 'Incorrect node mode: ' + name)
        if kind == 'nod':
            require(fields[5] == 'c' and stat.S_ISCHR(record['mode']), 'Incorrect device type: ' + name)
            require((record['rdev_major'], record['rdev_minor']) == tuple(map(int, fields[6:8])), 'Incorrect device number: ' + name)
        else:
            require(kind == 'dir' and stat.S_ISDIR(record['mode']), 'Incorrect directory type: ' + name)
    require(set(records) == expected, 'Unexpected embedded paths: ' + str(set(records) ^ expected))
    checked = 0
    for path in sorted(initroot.rglob('*')):
        name = path.relative_to(initroot).as_posix()
        require(stat.S_IMODE(records[name]['mode']) == stat.S_IMODE(path.lstat().st_mode), 'Embedded mode differs: ' + name)
        require(stat.S_IFMT(records[name]['mode']) == stat.S_IFMT(path.lstat().st_mode), 'Embedded type differs: ' + name)
        if path.is_file() and not path.is_symlink():
            name = path.relative_to(initroot).as_posix()
            require(name in records, 'Staged file absent from image: ' + name)
            require(stat.S_ISREG(records[name]['mode']), 'Wrong embedded file type: ' + name)
            require(records[name]['sha256'] == sha(path.read_bytes()), 'Embedded file differs: ' + name)
            checked += 1
        elif path.is_symlink():
            name = path.relative_to(initroot).as_posix()
            require(name in records and stat.S_ISLNK(records[name]['mode']), 'Embedded symlink absent: ' + name)
            require(records[name]['sha256'] == sha(str(path.readlink()).encode()), 'Embedded symlink differs: ' + name)
    metadata = json.loads((initroot / 'etc/r8q-encryption-manifest.json').read_text())
    for name, info in metadata['files'].items():
        require(name in records and records[name]['sha256'] == info['sha256'], 'Manifest mismatch: ' + name)
    (output / 'embedded-initramfs-manifest.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')
    # The patched source snapshot has no standalone Git checkout. Record each
    # source file hash so extra local board/RTC changes remain reproducible.
    count, source_hash = capture_source(source, output / 'kernel-source-manifest.jsonl')
    before = output / 'kernel-source-before.jsonl'
    require(before.read_bytes() == (output / 'kernel-source-manifest.jsonl').read_bytes(), 'Kernel source changed during build')
    files = {}
    for path in (image, output / 'payload/R8Q-RTC.DTB', output / '.config', output / 'baseline.config',
                 initroot / 'etc/r8q-encryption-manifest.json', output / 'embedded-initramfs-manifest.json',
                 output / 'kernel-source-manifest.jsonl'):
        files[str(path)] = dict(bytes=path.stat().st_size, sha256=sha(path.read_bytes()))
    probe = metadata.get('userdata_targeted') is False and metadata.get('root_handoff') is False
    candidate_kind = ('r8q-test-only-volatile-encryption-boot-probe' if probe
                      else 'r8q-isolated-encrypted-root-boot-candidate')
    record = dict(kind=candidate_kind, kernel_release='7.1.2-r8q-rtc2',
                  source=str(source), source_files=count, source_sha256=source_hash,
                  compiler=subprocess.check_output(['clang', '--version'], text=True).splitlines()[0],
                  embedded_files_checked=checked, archive_owners='all UID/GID 0', files=files,
                  installed=False, boot_tested=False, encrypted_io_tested=False,
                  root_handoff=not probe)
    (output / 'candidate-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--source-receipt':
        print(capture_source(Path(sys.argv[2]), Path(sys.argv[3])))
    else:
        main()
