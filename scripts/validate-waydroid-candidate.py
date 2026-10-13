#!/usr/bin/env python3
"""Audit an offline Waydroid kernel and its matching modules without loading it."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
RELEASE = '7.1.2-r8q-waydroid1'
VERMAGIC = RELEASE + ' SMP preempt mod_unload aarch64'
DTB_SHA256 = 'd3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca'
BASELINE_CONFIG_SHA256 = '25879d3bf45fa6bc77a7146fcd4fb854e11fbf5f4f14c908eb86020817cbf5dc'
BASELINE_IMAGE_SHA256 = '50631087ad9b22b8f009b98e9279c1c65d27e4f26c456fe6ce10f29854aaa2bf'
ACCEPTED_CPIO_SHA256 = '0a6b828b9376a5b6db3152c14187036bc47f88cc0f99da0f7a7a74fc8887f317'


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generic = helper('r8q_archive_audit', REPO / 'scripts/validate-encryption-candidate.py')
rules = helper('r8q_source_rules', REPO / 'scripts/prepare-waydroid-kernel-source.py')


def config(path):
    result = {}
    for line in path.read_text().splitlines():
        if line.startswith('CONFIG_'):
            key, value = line.split('=', 1)
            result[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            result[line[2:-11]] = 'n'
    return result


def audit_modules(output):
    entries = []
    for item in (output / 'modules.order').read_text().splitlines():
        path = Path(item)
        require(path.suffix in {'.o', '.ko'}, 'Unexpected modules.order entry')
        entries.append(path.with_suffix('.ko').as_posix())
    built = {path.relative_to(output).as_posix() for path in output.rglob('*.ko')
             if path.relative_to(output).parts[0] != 'modules'}
    require(built == set(entries), 'Built modules differ from modules.order')
    exports = {line.split()[1] for line in (output / 'Module.symvers').read_text().splitlines() if line.strip()}
    inventory = []
    names = set()
    for relative in entries:
        relative_path = Path(relative)
        require(not relative_path.is_absolute() and '..' not in relative_path.parts, 'Unsafe module path')
        path = output / relative_path
        require(path.is_file() and not path.is_symlink(), 'Missing built module: ' + relative)
        with path.open('rb') as stream:
            header = stream.read(64)
        require(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 18)[0] == 183,
                'Not an ARM64 ELF module: ' + relative)
        info = {}
        for line in subprocess.check_output(['modinfo', str(path)], text=True).splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                if key in ('name', 'vermagic', 'depends'):
                    info[key] = value.strip()
        name = info.get('name')
        require(name and name not in names, 'Duplicate or missing module name: ' + relative)
        names.add(name)
        require(info.get('vermagic') == VERMAGIC, 'Wrong module identity: ' + relative)
        missing = []
        for line in subprocess.check_output(['llvm-nm', '--undefined-only', str(path)], text=True).splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == 'U' and fields[1] not in exports:
                missing.append(fields[1])
        require(not missing, 'Unexported strong module imports in ' + relative + ': ' + ', '.join(missing))
        inventory.append(dict(path=relative, name=name, bytes=path.stat().st_size,
                              sha256=digest(path), vermagic=info['vermagic'],
                              depends=[item.replace('-', '_') for item in info.get('depends', '').split(',') if item]))
    require(inventory, 'No matching modules built')
    for row in inventory:
        require(set(row['depends']) <= names, 'Module dependency outside candidate: ' + row['name'])
    essential = {'msm', 'fts5cu56a', 'gpi', 'i2c_qcom_geni', 'max77705', 'max77705_charger',
                 'max17042_battery', 'ath11k', 'ath11k_pci', 'cfg80211', 'mac80211',
                 'r8q_cs35l41_card', 'snd_soc_cs35l41', 'snd_soc_cs35l41_i2c', 'q6afe', 'q6afe_dai',
                 'qcom_pd_mapper', 'qrtr_smd', 'bridge', 'veth', 'overlay', 'nf_tables', 'nf_nat',
                 'nft_chain_nat', 'nft_masq'}
    require(essential <= names, 'Required hardware/runtime modules missing: ' + str(sorted(essential - names)))
    (output / 'module-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    staged = output / 'modules/lib/modules' / RELEASE
    require(staged.is_dir(), 'Matching staged module tree missing')
    require((staged / 'modules.dep').is_file(), 'Staged dependency metadata missing')
    for row in inventory:
        path = staged / 'kernel' / row['path']
        require(path.is_file() and digest(path) == row['sha256'], 'Staged module differs: ' + row['path'])
    depmod = subprocess.run(['depmod', '-n', '-e', '-F', str(output / 'System.map'),
                             '-b', str(output / 'modules'), RELEASE], capture_output=True, text=True)
    require(depmod.returncode == 0 and 'unknown symbol' not in depmod.stderr.lower()
            and 'ERROR:' not in depmod.stderr, 'Staged depmod audit failed: ' + depmod.stderr.strip())
    def dependencies(text):
        return {line.split(':', 1)[0]: set(line.split(':', 1)[1].split())
                for line in text.splitlines() if line.startswith('kernel/') and ':' in line}
    actual_deps = dependencies((staged / 'modules.dep').read_text())
    require(actual_deps == dependencies(depmod.stdout), 'Staged dependency metadata differs from depmod')
    require(set(actual_deps) == {'kernel/' + row['path'] for row in inventory}, 'Staged dependency inventory differs')
    return len(inventory)


def audit_source(output, source):
    before = output / 'kernel-source-before.jsonl'
    after = output / 'kernel-source-manifest.jsonl'
    count, aggregate = generic.capture_source(source, after)
    if before.read_bytes() != after.read_bytes():
        cleanup = json.loads((output.parent / 'source-cleanup.json').read_text())
        require(cleanup['paths_quarantined'] == ['out', 'r8q-arch'], 'Unexpected source cleanup')
        require(cleanup['before_source_manifest_sha256'] == digest(before), 'Initial source receipt differs')
        require(not (source / 'out').exists() and not (source / 'r8q-arch').exists(), 'Unused source trees remain')
        original = [json.loads(line) for line in before.read_text().splitlines()]
        projected = [row for row in original if Path(row['path']).parts[0] not in {'out', 'r8q-arch'}]
        current = [json.loads(line) for line in after.read_text().splitlines()]
        require(projected == current, 'Compiled source changed during build or cleanup')
    # The whole-tree policy is derived from the pinned Linux archive and the
    # reviewed patch/asset reconstruction, rather than a mutable receipt.
    proof = rules.verify_complete_source_tree(source)
    origin = json.loads((source / 'r8q-waydroid-source.json').read_text())['origin']['input_source']
    command_files = list(output.rglob('*.cmd'))
    for path in command_files:
        require(origin not in path.read_text(errors='replace'), 'Build referenced shared source: ' + str(path))
    return count, aggregate, proof, len(command_files)


def main():
    require(len(sys.argv) == 5, 'Usage: validate-waydroid-candidate.py OUTPUT SOURCE ACCEPTED_BUILD ACCEPTED_CPIO')
    output, source, baseline, accepted_cpio = (Path(item).resolve() for item in sys.argv[1:])
    require(digest(baseline / '.config') == BASELINE_CONFIG_SHA256, 'Accepted baseline config differs')
    require(digest(baseline / 'arch/arm64/boot/Image') == BASELINE_IMAGE_SHA256, 'Accepted baseline Image differs')
    require(digest(accepted_cpio) == ACCEPTED_CPIO_SHA256, 'Accepted boot archive differs')
    cfg = config(output / '.config')
    required_y = ('ANDROID_BINDER_IPC', 'ANDROID_BINDERFS', 'MEMFD_CREATE', 'PSI', 'NAMESPACES',
                  'CGROUPS', 'SECCOMP', 'SECCOMP_FILTER', 'BLK_DEV_LOOP', 'EXT4_FS', 'DRM_SIMPLEDRM',
                  'EFI', 'CMDLINE_FORCE', 'NF_TABLES_INET', 'NF_TABLES_IPV4', 'NF_TABLES_IPV6', 'NF_NAT_MASQUERADE')
    required_m = ('BRIDGE', 'VETH', 'OVERLAY_FS', 'NF_CONNTRACK', 'NF_NAT', 'NF_TABLES',
                  'NETFILTER_NETLINK', 'NFT_NAT', 'NFT_MASQ', 'SND_SOC_R8Q_CS35L41')
    require(all(cfg.get('CONFIG_' + key) == 'y' for key in required_y), 'Missing built-in prerequisite')
    require(all(cfg.get('CONFIG_' + key) == 'm' for key in required_m), 'Missing module prerequisite')
    require(cfg.get('CONFIG_PSI_DEFAULT_DISABLED', 'n') == 'n', 'PSI disabled by default')
    require(cfg.get('CONFIG_ANDROID_BINDER_DEVICES') == '""', 'Wrong default Binder devices')
    require(cfg.get('CONFIG_LOCALVERSION') == '"-r8q-waydroid1"', 'Wrong kernel release')
    require(cfg.get('CONFIG_INITRAMFS_SOURCE') == '"' + str(accepted_cpio) + '"', 'Initramfs input binding differs')
    require((output / 'include/config/kernel.release').read_text().strip() == RELEASE, 'Generated release differs')
    require(cfg.get('CONFIG_CMDLINE') == config(baseline / '.config').get('CONFIG_CMDLINE'), 'Boot command line differs')
    image = output / 'payload/BOOTAA64.EFI'
    data = image.read_bytes()
    require(data == (output / 'arch/arm64/boot/Image').read_bytes(), 'Payload differs from built Image')
    require(data[:2] == b'MZ' and data[56:60] == b'ARM\x64', 'Invalid ARM64 EFI header')
    pe = struct.unpack_from('<I', data, 60)[0]
    require(data[pe:pe + 4] == b'PE\0\0', 'Missing PE signature')
    require(struct.unpack_from('<H', data, pe + 4)[0] == 0xaa64, 'Wrong EFI architecture')
    require(struct.unpack_from('<H', data, pe + 24 + 68)[0] == 10, 'Not an EFI application')
    runtime_size = struct.unpack_from('<Q', data, 16)[0]
    require(len(data) <= runtime_size < len(data) + 64 * 1024 * 1024, 'Invalid runtime size')
    symbols = {}
    feature_symbols = {}
    required_features = {'binder_init', 'init_binderfs', 'psi_init'}
    for line in subprocess.check_output(['llvm-nm', str(output / 'vmlinux')], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in ('_text', '__initramfs_start'):
            symbols[fields[2]] = int(fields[0], 16)
        if len(fields) == 3 and fields[2] in required_features:
            feature_symbols[fields[2]] = fields[1]
    require(len(symbols) == 2, 'Missing embedded initramfs symbols')
    require(set(feature_symbols) == required_features
            and all(kind in {'T', 't'} for kind in feature_symbols.values()), 'Built-in Android/PSI code missing')
    compressed = (output / 'usr/initramfs_inc_data').read_bytes()
    offset = symbols['__initramfs_start'] - symbols['_text']
    require(data[offset:offset + len(compressed)] == compressed, 'Generated archive is not embedded in Image')
    cpio = gzip.decompress(compressed)
    require(cpio == accepted_cpio.read_bytes() == (baseline / 'usr/initramfs_data.cpio').read_bytes(), 'Accepted archive bytes differ')
    # With a single .cpio input, usr/Makefile compresses that file directly
    # and does not create usr/initramfs_data.cpio. Audit a raw intermediate
    # only when it exists; the embedded bytes must always equal the fixed input.
    raw_archive = output / 'usr/initramfs_data.cpio'
    if raw_archive.exists():
        require(cpio == raw_archive.read_bytes(), 'Generated cpio differs')
    records = generic.parse_cpio(cpio)
    require('init' in records and stat.S_ISREG(records['init']['mode']), 'Boot init missing')
    require(not any('.ko' in name for name in records), 'Accepted archive contains old modules')
    dtb = output / 'payload/R8Q-RTC.DTB'
    require(digest(dtb) == DTB_SHA256, 'Captured active DTB differs')
    module_count = audit_modules(output)
    source_count, source_hash, proof, command_count = audit_source(output, source)
    artifacts = [image, dtb, output / '.config', output / 'Module.symvers', output / 'module-inventory.json',
              output / 'kernel-source-manifest.jsonl', output / 'kernel-source-before.jsonl', output / 'vmlinux',
              output / 'arch/arm64/boot/Image', output / 'usr/initramfs_inc_data',
              output / 'accepted-initramfs.cpio', output / 'include/config/kernel.release',
              output / 'modules/lib/modules' / RELEASE / 'modules.dep']
    if raw_archive.exists():
        artifacts.append(raw_archive)
    files = {str(path.relative_to(output)): dict(bytes=path.stat().st_size, sha256=digest(path)) for path in artifacts}
    result = dict(kind='r8q-offline-waydroid-kernel-candidate', kernel_release=RELEASE, root_state='plaintext',
                  installed=False, boot_tested=False, deployment_prepared=False, source=str(source),
                  source_files=source_count, source_sha256=source_hash, complete_source_proof=proof,
                  compile_command_files_checked=command_count, shared_source_references=0,
                  built_in_feature_symbols=feature_symbols,
                  module_count=module_count, embedded_archive_entries=len(records),
                  accepted_cpio_sha256=hashlib.sha256(cpio).hexdigest(), files=files)
    (output / 'candidate-manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('kind', 'kernel_release', 'module_count', 'source_files',
                                                 'root_state', 'installed', 'boot_tested', 'deployment_prepared')}, indent=2))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--source-receipt':
        print(generic.capture_source(Path(sys.argv[2]), Path(sys.argv[3])))
    else:
        main()
