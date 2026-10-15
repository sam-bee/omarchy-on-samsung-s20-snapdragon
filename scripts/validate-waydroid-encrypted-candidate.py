#!/usr/bin/env python3
"""Validate the combined encrypted Waydroid boot payload without installing it."""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import json
import stat
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
RELEASE = '7.1.2-r8q-waydroid2'
DTB_SHA = 'd3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca'
ENCRYPTED_CONFIG_SHA = 'c5ad00ab5781b5ca1602effd684c06fe5fdd759fa286ad800491a940ce3f598a'
CACHE_CONFIG_SHA = 'a12add1213809486195c84a9c94f20371254491ff613b442fdeba68886df0925'


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def helper(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = helper('waydroid_module_audit', 'validate-waydroid-candidate.py')
archive = helper('encrypted_archive_audit', 'validate-encryption-candidate.py')
rules = helper('waydroid_source_rules', 'prepare-waydroid-kernel-source.py')
init_rules = helper('waydroid_encrypted_init_rules', 'prepare-waydroid-encrypted-initramfs.py')


def main():
    require(len(sys.argv) == 4, 'Usage: validate-waydroid-encrypted-candidate.py OUTPUT SOURCE INITRAMFS')
    output, source, initroot = map(lambda value: Path(value).resolve(), sys.argv[1:])
    require(output == REPO / 'out/waydroid-encrypted-20261015/kernel', 'Unexpected output identity')
    require(initroot == REPO / 'out/waydroid-encrypted-20261015/initramfs-preparation/initramfs', 'Unexpected initramfs identity')
    require(source == REPO / 'out/waydroid-kernel-20261013/source', 'Unexpected source identity')
    accepted = REPO / 'out/encryption-implementation-20261013/production-kernel04'
    accepted_audit = init_rules.inspect_old_artifacts(
        init_rules.DEFAULT_ACCEPTED_INIT, init_rules.DEFAULT_PRODUCTION_MANIFEST,
        init_rules.DEFAULT_RUNTIME_AUDIT, init_rules.DEFAULT_ROOT_ACCEPTANCE,
        source, init_rules.DEFAULT_SOURCE_MANIFEST)
    require(digest(accepted / '.config') == ENCRYPTED_CONFIG_SHA, 'Accepted encrypted configuration differs')
    require(digest(output / 'baseline.config') == CACHE_CONFIG_SHA, 'Incremental baseline differs')
    cfg = common.config(output / '.config')
    base = common.config(output / 'baseline.config')
    accepted_cfg = common.config(accepted / '.config')
    required_y = ('ANDROID_BINDER_IPC', 'ANDROID_BINDERFS', 'MEMFD_CREATE', 'PSI', 'NAMESPACES',
                  'CGROUPS', 'SECCOMP', 'SECCOMP_FILTER', 'BLK_DEV_LOOP', 'EXT4_FS', 'DRM_SIMPLEDRM',
                  'EFI', 'CMDLINE_FORCE', 'NF_TABLES_INET', 'NF_TABLES_IPV4', 'NF_TABLES_IPV6',
                  'NF_NAT_MASQUERADE', 'BLK_DEV_DM', 'DM_CRYPT', 'CRYPTO_AES', 'CRYPTO_XTS',
                  'CRYPTO_AES_ARM64_CE_BLK', 'CRYPTO_CBC', 'CRYPTO_AUTHENC', 'CRYPTO_ESSIV',
                  'CRYPTO_LIB_AES', 'CRYPTO_LIB_MD5', 'CRYPTO_LIB_SHA256', 'SCSI_UFSHCD', 'SCSI_UFS_QCOM')
    required_m = ('BRIDGE', 'VETH', 'OVERLAY_FS', 'NF_CONNTRACK', 'NF_NAT', 'NF_TABLES',
                  'NETFILTER_NETLINK', 'NFT_NAT', 'NFT_MASQ', 'FW_CS_DSP', 'SND_SOC_WM_ADSP',
                  'SND_SOC_CS35L41_LIB', 'SND_SOC_CS35L41', 'SND_SOC_CS35L41_I2C', 'SND_SOC_R8Q_CS35L41')
    require(all(cfg.get('CONFIG_' + name) == 'y' for name in required_y), 'Missing built-in encryption/Waydroid prerequisite')
    require(all(cfg.get('CONFIG_' + name) == 'm' for name in required_m), 'Missing hardware/network module prerequisite')
    require(cfg.get('CONFIG_PSI_DEFAULT_DISABLED', 'n') == 'n', 'PSI disabled')
    require(cfg.get('CONFIG_ANDROID_BINDER_DEVICES') == '""', 'Binder policy differs')
    require(cfg.get('CONFIG_MODVERSIONS') == 'n', 'Module version policy differs')
    require(cfg.get('CONFIG_LOCALVERSION') == '"-r8q-waydroid2"', 'Wrong local release')
    require(cfg.get('CONFIG_INITRAMFS_SOURCE') == '"' + str(initroot) + ' ' + str(REPO / 'initramfs/irfs.devnodes') + '"', 'Wrong encrypted archive input')
    require(cfg.get('CONFIG_INITRAMFS_ROOT_UID') == accepted_cfg.get('CONFIG_INITRAMFS_ROOT_UID')
            and cfg.get('CONFIG_INITRAMFS_ROOT_GID') == accepted_cfg.get('CONFIG_INITRAMFS_ROOT_GID'), 'Wrong archive owner mapping')
    generated_cfg = common.config(output / 'include/config/auto.conf')
    expected_generated_cfg = {key: json.loads(value) if value.startswith('"') else value
                              for key, value in cfg.items() if value != 'n'}
    require(generated_cfg == expected_generated_cfg, 'Generated build configuration differs')
    require(cfg.get('CONFIG_CMDLINE') == base.get('CONFIG_CMDLINE') == accepted_cfg.get('CONFIG_CMDLINE'), 'Boot command line changed')
    require(cfg.get('CONFIG_CC_VERSION_TEXT') == accepted_cfg.get('CONFIG_CC_VERSION_TEXT'), 'Compiler differs')
    require((output / 'include/config/kernel.release').read_text().strip() == RELEASE, 'Generated release differs')
    delta = {key: {'before': base.get(key, 'n'), 'after': cfg.get(key, 'n')}
             for key in sorted(base.keys() | cfg.keys()) if base.get(key, 'n') != cfg.get(key, 'n')}
    allowed = {'CONFIG_BLK_DEV_DM', 'CONFIG_DM_CRYPT', 'CONFIG_CRYPTO_AES', 'CONFIG_CRYPTO_AUTHENC',
               'CONFIG_CRYPTO_CBC', 'CONFIG_CRYPTO_ESSIV', 'CONFIG_CRYPTO_LIB_MD5', 'CONFIG_CRYPTO_XTS',
               'CONFIG_PNFS_BLOCK', 'CONFIG_INITRAMFS_SOURCE', 'CONFIG_LOCALVERSION'}
    require(set(delta) == allowed, 'Unexpected final configuration changes: ' + str(sorted(set(delta) ^ allowed)))

    image = output / 'payload/BOOTAA64.EFI'
    data = image.read_bytes()
    require(data == (output / 'arch/arm64/boot/Image').read_bytes(), 'Payload differs from Image')
    require(data[:2] == b'MZ' and data[56:60] == b'ARM\x64', 'Invalid ARM64 EFI Image')
    pe = struct.unpack_from('<I', data, 60)[0]
    require(data[pe:pe + 4] == b'PE\0\0' and struct.unpack_from('<H', data, pe + 4)[0] == 0xaa64, 'Invalid EFI architecture')
    require(struct.unpack_from('<H', data, pe + 24 + 68)[0] == 10, 'EFI subsystem differs')
    require(len(data) <= struct.unpack_from('<Q', data, 16)[0] < len(data) + 64 * 1024 * 1024, 'Invalid Image runtime size')
    wanted = {'_text', '__initramfs_start', 'binder_init', 'init_binderfs', 'psi_init', 'dm_init', 'dm_crypt_init'}
    symbols = {}
    for line in subprocess.check_output(['llvm-nm', str(output / 'vmlinux')], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in wanted:
            symbols[fields[2]] = int(fields[0], 16)
    require(set(symbols) == wanted, 'Built-in Binder/PSI/initramfs symbols missing')
    compressed = (output / 'usr/initramfs_inc_data').read_bytes()
    offset = symbols['__initramfs_start'] - symbols['_text']
    require(data[offset:offset + len(compressed)] == compressed, 'Archive not embedded in Image')
    cpio = gzip.decompress(compressed)
    require(cpio == (output / 'usr/initramfs_data.cpio').read_bytes(), 'Generated encrypted archive differs')
    records = archive.parse_cpio(cpio)
    require('init.normal' not in records, 'Plaintext fallback present')
    expected = {p.relative_to(initroot).as_posix() for p in initroot.rglob('*')}
    for line in (REPO / 'initramfs/irfs.devnodes').read_text().splitlines():
        fields = line.split()
        if not fields or fields[0].startswith('#'):
            continue
        kind, name, mode, uid, gid = fields[:5]
        name = name.lstrip('/')
        expected.add(name)
        require(name in records and stat.S_IMODE(records[name]['mode']) == int(mode, 8), 'Device node mode differs: ' + name)
        if kind == 'nod':
            require(fields[5] == 'c' and stat.S_ISCHR(records[name]['mode']), 'Device node type differs')
            require((records[name]['rdev_major'], records[name]['rdev_minor']) == tuple(map(int, fields[6:8])), 'Device node identity differs')
        else:
            require(kind == 'dir' and stat.S_ISDIR(records[name]['mode']), 'Explicit directory differs')
    require(set(records) == expected, 'Embedded path inventory differs')
    for path in sorted(initroot.rglob('*')):
        name = path.relative_to(initroot).as_posix()
        record = records[name]
        require(record['mode'] == path.lstat().st_mode, 'Embedded file type/mode differs: ' + name)
        if path.is_symlink():
            require(record['sha256'] == hashlib.sha256(str(path.readlink()).encode()).hexdigest(), 'Embedded link differs: ' + name)
        elif path.is_file():
            require(record['sha256'] == digest(path), 'Embedded content differs: ' + name)
    metadata = json.loads((initroot / 'etc/r8q-encryption-manifest.json').read_text())
    require(metadata.get('kernel_release') == RELEASE and metadata.get('fail_closed') is True, 'Wrong encrypted manifest identity')
    init_rules.reject_sensitive_tree(initroot, 'encrypted candidate')
    for name, info in metadata['files'].items():
        require(name in records and records[name]['sha256'] == info['sha256'], 'Runtime manifest differs: ' + name)
    module_paths, early_modules = init_rules.module_inputs(output)
    for name in init_rules.MODULES:
        path = initroot / f'lib/modules/{RELEASE}/r8q-encryption/{name}'
        require(digest(path) == early_modules['modules'][name]['sha256'], 'Early module differs from compiled candidate: ' + name)
    old_init = init_rules.DEFAULT_ACCEPTED_INIT
    init_rules.assert_hash(old_init / 'init', init_rules.OLD_INIT_SHA256, 'accepted init')
    init_rules.assert_hash(old_init / 'etc/r8q-encryption-manifest.json', init_rules.OLD_INIT_MANIFEST_SHA256, 'accepted manifest')
    init_rules.assert_hash(init_rules.DEFAULT_ROOT_ACCEPTANCE, init_rules.OLD_ROOT_ACCEPTANCE_SHA256, 'accepted root profile')
    profile = accepted_audit['root_profile']
    old_metadata = json.loads((old_init / 'etc/r8q-encryption-manifest.json').read_text())
    expected_metadata = init_rules.rewrite_manifest(old_metadata, early_modules['modules'], profile)
    expected_metadata['files']['init'] = {'kind': 'generated-encrypted-init', 'sha256': digest(initroot / 'init'),
                                          'size': (initroot / 'init').stat().st_size, 'source': 'generated'}
    require(metadata == expected_metadata, 'Accepted encrypted runtime/root contracts changed')
    removed = {f'lib/modules/{init_rules.OLD_RELEASE}/r8q-encryption/{name}' for name in init_rules.MODULES}
    added = {f'lib/modules/{RELEASE}/r8q-encryption/{name}' for name in init_rules.MODULES}
    old_paths = {p.relative_to(old_init).as_posix() for p in old_init.rglob('*')}
    old_version_dirs = {f'lib/modules/{init_rules.OLD_RELEASE}', f'lib/modules/{init_rules.OLD_RELEASE}/r8q-encryption'}
    new_version_dirs = {f'lib/modules/{RELEASE}', f'lib/modules/{RELEASE}/r8q-encryption'}
    new_paths = {p.relative_to(initroot).as_posix() for p in initroot.rglob('*')}
    expected_paths = (old_paths - removed - old_version_dirs) | added | new_version_dirs
    require(new_paths == expected_paths, 'Unexpected candidate paths')
    for name in old_paths - removed - old_version_dirs:
        require((old_init / name).lstat().st_mode == (initroot / name).lstat().st_mode, 'Inherited mode/type changed: ' + name)
    for name in added:
        require(stat.S_IMODE((initroot / name).stat().st_mode) == 0o744, 'New early module mode differs')
    old_text = (old_init / 'init').read_text()
    new_text = (initroot / 'init').read_text()
    reversed_text = new_text.replace(RELEASE, init_rules.OLD_RELEASE)
    for name in init_rules.MODULES:
        reversed_text = reversed_text.replace(early_modules['modules'][name]['sha256'], init_rules.MODULE_OLD_HASHES[name])
    require(reversed_text == old_text, 'Early-unlock logic differs from accepted production04')
    old_files = {p.relative_to(old_init).as_posix(): p for p in old_init.rglob('*') if p.is_file()}
    runtime_checked = 0
    for name, path in old_files.items():
        if name in {'init', 'etc/r8q-encryption-manifest.json'} or name.startswith('lib/modules/'):
            continue
        require(digest(path) == digest(initroot / name), 'Accepted runtime changed: ' + name)
        runtime_checked += 1
    require(digest(output / 'payload/R8Q-RTC.DTB') == DTB_SHA, 'Active DTB differs')
    common.RELEASE = RELEASE
    common.VERMAGIC = RELEASE + ' SMP preempt mod_unload aarch64'
    count = common.audit_modules(output)
    staged_metadata = []
    for name in ('modules.builtin', 'modules.builtin.modinfo', 'modules.builtin.ranges'):
        built_metadata = output / name
        staged_file = output / 'modules/lib/modules' / RELEASE / name
        if name == 'modules.builtin.ranges' and not built_metadata.exists():
            require(not staged_file.exists(), 'Unexpected staged built-in ranges')
            continue
        require(digest(built_metadata) == digest(staged_file), 'Staged built-in metadata differs: ' + name)
        staged_metadata.append(staged_file)
    source_count, source_sha = archive.capture_source(source, output / 'kernel-source-manifest.jsonl')
    require((output / 'kernel-source-before.jsonl').read_bytes() == (output / 'kernel-source-manifest.jsonl').read_bytes(), 'Source changed during build')
    proof = rules.verify_complete_source_tree(source)
    origin = json.loads((source / 'r8q-waydroid-source.json').read_text())['origin']['input_source']
    commands = list(output.rglob('*.cmd'))
    for path in commands:
        require(origin not in path.read_text(errors='replace'), 'Shared source used by compiler: ' + str(path))
    (output / 'embedded-initramfs-manifest.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')
    (output / 'config-delta.json').write_text(json.dumps(delta, indent=2, sort_keys=True) + '\n')
    artifacts = [image, output / 'payload/R8Q-RTC.DTB', output / '.config', output / 'Module.symvers',
                 output / 'config-delta.json',
                 output / 'module-inventory.json', output / 'kernel-source-before.jsonl', output / 'kernel-source-manifest.jsonl',
                 output / 'embedded-initramfs-manifest.json', output / 'usr/initramfs_data.cpio', output / 'usr/initramfs_inc_data',
                 output / 'include/config/kernel.release', output / 'modules/lib/modules' / RELEASE / 'modules.dep']
    artifacts.extend(staged_metadata)
    result = dict(kind='r8q-encrypted-waydroid-kernel-candidate', kernel_release=RELEASE, root_state='encrypted',
                  source=str(source), complete_source_proof=proof, source_files=source_count, source_sha256=source_sha,
                  compile_command_files_checked=len(commands), shared_source_references=0, module_count=count,
                  accepted_runtime_files_unchanged=runtime_checked, embedded_archive_entries=len(records),
                  accepted_input_pins=accepted_audit['old_artifact_pins'],
                  stage2_complete=True,
                  early_modules=early_modules, config_delta=delta,
                  files={str(path.relative_to(output)): {'bytes': path.stat().st_size, 'sha256': digest(path)} for path in artifacts},
                  installed=False, boot_tested=False, deployment_prepared=False)
    (output / 'candidate-manifest.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('kind', 'kernel_release', 'root_state', 'module_count', 'accepted_runtime_files_unchanged')}, indent=2))


if __name__ == '__main__':
    main()
