#!/usr/bin/env bash
# Prepare an incremental encrypted-root Waydroid kernel build.
#
# This wrapper never changes its source, cache, or accepted encrypted build
# inputs.  It copies only generated kbuild state into a new output, resolves
# the reviewed configuration, and (unless config-only is requested) builds
# Image plus every module against a temporary copy of the accepted encrypted
# cpio.  The temporary cpio intentionally contains production04's rtc2
# modules; the primary build step must replace those early modules and relink
# Image before any boot use.
set -euo pipefail

if [[ $# != 5 ]]; then
    echo "Usage: $0 PRIVATE_WAYDROID_SOURCE WAYDROID_CACHE ACCEPTED_ENCRYPTED_BUILD ACTIVE_DTB NEW_OUTPUT" >&2
    exit 2
fi

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE=$(realpath "$1")
CACHE=$(realpath "$2")
ENCRYPTED=$(realpath "$3")
DTB=$(realpath "$4")
OUTPUT=$(realpath -m "$5")
JOBS=${R8Q_WAYDROID_ENCRYPTED_JOBS:-2}
CONFIG_ONLY=${R8Q_WAYDROID_ENCRYPTED_CONFIG_ONLY:-0}

[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid R8Q_WAYDROID_ENCRYPTED_JOBS' >&2; exit 2; }
[[ $CONFIG_ONLY == 0 || $CONFIG_ONLY == 1 ]] || { echo 'Invalid config-only switch' >&2; exit 2; }
[[ $OUTPUT == "$REPO/out/"* && ! -e $OUTPUT && ! -L $OUTPUT ]] || {
    echo "NEW_OUTPUT must be a new path under $REPO/out: $OUTPUT" >&2
    exit 2
}
[[ $SOURCE == "$REPO/out/"* && $SOURCE == */source ]] || exit 2
[[ $CACHE == "$REPO/out/"* && $CACHE != "$OUTPUT" ]] || exit 2
[[ $ENCRYPTED == "$REPO/out/"* && $ENCRYPTED != "$OUTPUT" ]] || exit 2
[[ $DTB == "$REPO/out/"* && $DTB != "$OUTPUT" ]] || exit 2
for input_root in "$SOURCE" "$CACHE" "$ENCRYPTED" "$DTB"; do
    [[ $OUTPUT != "$input_root" && $OUTPUT != "$input_root/"* ]] || {
        echo "NEW_OUTPUT overlaps an input: $OUTPUT / $input_root" >&2
        exit 2
    }
done
STALE_ROOT="$REPO/out/waydroid-encrypted-20261015/kernel-preparation/stale-modules-$(basename "$OUTPUT")"
[[ $STALE_ROOT != "$OUTPUT" && $STALE_ROOT != "$OUTPUT/"* && ! -e $STALE_ROOT && ! -L $STALE_ROOT ]] || {
    echo "STALE_ROOT must be a new path outside NEW_OUTPUT: $STALE_ROOT" >&2
    exit 2
}

for tool in cp make clang ld.lld llvm-ar llvm-nm python3 aarch64-linux-gnu-gcc modinfo depmod; do
    command -v "$tool" >/dev/null || { echo "Required existing tool missing: $tool" >&2; exit 2; }
done
[[ -f "$SOURCE/Makefile" && -f "$SOURCE/r8q-waydroid-source.json" ]] || exit 2
[[ -f "$CACHE/.config" && -f "$CACHE/Module.symvers" && -f "$CACHE/kernel-source-before.jsonl" ]] || {
    echo 'Waydroid cache is incomplete' >&2
    exit 2
}
[[ -f "$ENCRYPTED/.config" && -f "$ENCRYPTED/baseline.config" && -f "$ENCRYPTED/candidate-manifest.json" ]] || {
    echo 'Accepted encrypted build is incomplete' >&2
    exit 2
}
[[ -f "$ENCRYPTED/usr/initramfs_data.cpio" && -f "$ENCRYPTED/payload/R8Q-RTC.DTB" ]] || {
    echo 'Accepted encrypted cpio or DTB is missing' >&2
    exit 2
}
[[ -f "$DTB" ]] || exit 2
[[ -x "$SOURCE/scripts/config" && -f "$SOURCE/scripts/kconfig/merge_config.sh" ]] || exit 2

# Validate immutable identities before making the new output.  In particular,
# do not trust a cache merely because its directory name looks right: command
# files can otherwise silently point at a different compiler or source tree.
python3 -I - "$REPO" "$SOURCE" "$CACHE" "$ENCRYPTED" "$DTB" "$OUTPUT" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys

repo, source, cache, encrypted, dtb, output = map(pathlib.Path, sys.argv[1:])

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def read_config(path):
    values = {}
    for line in path.read_text().splitlines():
        if line.startswith('CONFIG_'):
            key, value = line.split('=', 1)
            values[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[2:-11]] = 'n'
    return values

def inside(path, parent):
    return path == parent or parent in path.parents

for name, path in (('SOURCE', source), ('CACHE', cache), ('ENCRYPTED', encrypted), ('DTB', dtb)):
    require(path.exists(), f'{name} is missing: {path}')
for name, path in (('SOURCE', source), ('CACHE', cache), ('ENCRYPTED', encrypted), ('DTB', dtb)):
    require(not inside(output, path) and not inside(path, output),
            f'OUTPUT overlaps {name}: {output} / {path}')
require(not inside(cache, source) and not inside(source, cache), 'SOURCE and CACHE overlap')
require(not inside(encrypted, source) and not inside(source, encrypted), 'SOURCE and ENCRYPTED overlap')

source_rules_path = repo / 'scripts/prepare-waydroid-kernel-source.py'
spec = importlib.util.spec_from_file_location('waydroid_source_rules', source_rules_path)
rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules)
proof = rules.verify_complete_source_tree(source)
require(proof['sha256'] == rules.COMPLETE_SOURCE_SHA256, 'Private Waydroid source differs from pinned complete source')
receipt = json.loads((source / 'r8q-waydroid-source.json').read_text())
require(receipt.get('schema') == 1, 'Unexpected private source receipt schema')
require(receipt.get('candidate') == 'r8q-waydroid1', 'Private source was not prepared for the audited Waydroid tree')
require(receipt.get('kernel_source_version') == '7.1.2', 'Private source kernel version differs')
require(receipt.get('preserved_audio_sources') == rules.PRESERVED_AUDIO_SOURCES,
        'Private source audio identities differ')
require([(p['name'], p['sha256']) for p in receipt.get('applied_patches', [])] ==
        [(p[0], p[2]) for p in rules.PATCHES], 'Private source patch identities differ')
require(sha(source / 'Makefile') == rules.MAKEFILE_SHA256, 'Private source Makefile differs')
require(sha(source / rules.RTC_DRIVER) == rules.RTC_DRIVER_AFTER, 'Private source RTC patch differs')
require(sha(source / rules.BOARD_DTS) == rules.BOARD_DTS_AFTER, 'Private source board DTS differs')

compiler = subprocess.check_output(['clang', '--version'], text=True).splitlines()[0]
cache_config = read_config(cache / '.config')
encrypted_config = read_config(encrypted / '.config')
require(sha(cache / '.config') == 'a12add1213809486195c84a9c94f20371254491ff613b442fdeba68886df0925',
        'Waydroid cache config differs from the accepted Waydroid1 candidate')
require(sha(encrypted / '.config') == 'c5ad00ab5781b5ca1602effd684c06fe5fdd759fa286ad800491a940ce3f598a',
        'Accepted encrypted production04 config differs')
require(sha(encrypted / 'baseline.config') == '25879d3bf45fa6bc77a7146fcd4fb854e11fbf5f4f14c908eb86020817cbf5dc',
        'Accepted encrypted production04 baseline differs')
require(cache_config.get('CONFIG_CC_VERSION_TEXT') == '"' + compiler + '"',
        'Compiler differs from the Waydroid cache config')
require(encrypted_config.get('CONFIG_CC_VERSION_TEXT') == '"' + compiler + '"',
        'Compiler differs from the accepted encrypted config')
require(cache_config.get('CONFIG_CMDLINE') == encrypted_config.get('CONFIG_CMDLINE'),
        'Accepted external-DTB command line differs')
require(cache_config.get('CONFIG_MODVERSIONS') == 'n' and encrypted_config.get('CONFIG_MODVERSIONS') == 'n',
        'Module version policy is not the accepted no-modversions policy')

for key in ('BLK_DEV_DM', 'DM_CRYPT', 'CRYPTO_AES', 'CRYPTO_XTS',
            'CRYPTO_AES_ARM64_CE_BLK', 'CRYPTO_CBC', 'CRYPTO_AUTHENC',
            'CRYPTO_ESSIV', 'CRYPTO_LIB_AES', 'CRYPTO_LIB_MD5',
            'CRYPTO_LIB_SHA256', 'PNFS_BLOCK'):
    require(encrypted_config.get('CONFIG_' + key) == 'y',
            f'Accepted production04 encryption gate is not built in: {key}')

manifest = json.loads((encrypted / 'candidate-manifest.json').read_text())
require(manifest.get('kind') == 'r8q-isolated-encrypted-root-boot-candidate',
        'Accepted encrypted build is not the production encrypted-root candidate')
require(manifest.get('kernel_release') == '7.1.2-r8q-rtc2', 'Accepted encrypted release differs')
require(manifest.get('root_handoff') is True, 'Accepted encrypted build is not a root-handoff candidate')
require(manifest.get('files', {}).get(str(encrypted / 'payload/BOOTAA64.EFI'), {}).get('sha256') ==
        '730627f49b8d41b9bdc6ef7931fe94911636003c61596c84d769d532ad27c49b',
        'Accepted production04 EFI identity differs')
require(sha(encrypted / 'usr/initramfs_data.cpio') ==
        'eaf69e92e8a30fc03f06736eb5f33169eeecae0a9cae5ce09193fffe27791abe',
        'Accepted production04 encrypted cpio differs')
require(sha(encrypted / 'usr/initramfs_inc_data') ==
        '3dd56f3b4bf86f10b3ce3c40e5c49c3c79bab269c130f4f6ba0ea94a210a3d83',
        'Accepted production04 compressed cpio differs')
require(sha(encrypted / 'payload/R8Q-RTC.DTB') ==
        'd3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca',
        'Accepted production04 DTB differs')
require(sha(dtb) == 'd3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca',
        'Requested active DTB differs from the captured phone DTB')
dtb_data = dtb.read_bytes()
require(len(dtb_data) >= 8 and struct.unpack_from('>II', dtb_data) == (0xd00dfeed, len(dtb_data)),
        'Active DTB is not a complete FDT')

require(sha(cache / 'Module.symvers') ==
        '7a9ba3287daadaf44713acde6910c48bc6907fa2e83731e66f357d916220677f',
        'Waydroid cache Module.symvers differs')
require(sha(cache / 'kernel-source-before.jsonl') ==
        '2bf3db9dac7bee359d8ca9b2d91f68b9d1b12ea7a3826c5d4bf81f14f6734160',
        'Waydroid cache source receipt differs')
require(sha(cache / 'kernel-source-manifest.jsonl') ==
        'aca2ca580368e8529967e7f5a88c632580aee569aec565a795bab3def3767e29',
        'Waydroid cache source manifest differs')

print(json.dumps({
    'compiler': compiler,
    'complete_source': proof,
    'cache_config_sha256': sha(cache / '.config'),
    'cache_module_symvers_sha256': sha(cache / 'Module.symvers'),
    'accepted_encrypted_config_sha256': sha(encrypted / '.config'),
    'accepted_encrypted_cpio_sha256': sha(encrypted / 'usr/initramfs_data.cpio'),
    'active_dtb_sha256': sha(dtb),
}, sort_keys=True))
PY

mkdir -p "$OUTPUT"
# A reflink copy keeps this operation local and cheap where the filesystem
# supports it.  The destination is new and the exclusions below are all
# generated entries belonging only to that destination; no input is removed.
cp -a --reflink=auto "$CACHE/." "$OUTPUT/"
for path in \
    modules payload candidate-manifest.json config-delta.json module-inventory.json \
    kernel-source-after-build-inherited.jsonl kernel-source-before.jsonl \
    kernel-source-manifest.jsonl build.log staging.log validation.log \
    accepted-initramfs.cpio \
    usr/initramfs_data.cpio usr/initramfs_inc_data usr/initramfs_data.o \
    usr/.initramfs_data.cpio.cmd usr/.initramfs_inc_data.cmd usr/.initramfs_data.o.cmd; do
    rm -rf -- "$OUTPUT/$path"
done

cp --reflink=auto "$CACHE/.config" "$OUTPUT/baseline.config"
cp --reflink=auto "$ENCRYPTED/.config" "$OUTPUT/accepted-production04.config"
cp --reflink=auto "$ENCRYPTED/usr/initramfs_data.cpio" "$OUTPUT/temporary-accepted-encrypted-initramfs.cpio"
cp --reflink=auto "$DTB" "$OUTPUT/active-dtb.R8Q-RTC.DTB"

# A copied .ko is a final product, not a reusable object.  Remove it from the
# build tree before kbuild sees the new config; retain it in a sibling
# quarantine for audit instead of allowing an object that just became built-in
# to survive into the new module bundle.
python3 -I - "$OUTPUT" "$STALE_ROOT" <<'PY'
import json
import pathlib
import shutil
import sys

output, stale_root = map(pathlib.Path, sys.argv[1:])
paths = sorted(path for path in output.rglob('*.ko') if path.is_file())
if paths:
    destination = stale_root / 'before-build'
    for path in paths:
        relative = path.relative_to(output)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(target))
    destination.mkdir(parents=True, exist_ok=True)
    (stale_root / 'before-build.json').write_text(json.dumps({
        'count': len(paths),
        'paths': [str(path.relative_to(output)) for path in paths],
        'reason': 'Copied Waydroid1 final modules are not reusable products; kbuild must relink modules under waydroid2.',
    }, indent=2, sort_keys=True) + '\n')
PY

# Keep an independent source receipt in the new output and compare it with the
# cleaned source manifest captured after the accepted Waydroid1 build.  The
# cache's historical *before* receipt includes the quarantined inherited `out`
# subtree; the current private source deliberately omits that generated tree.
# Comparing with the cache's post-cleanup manifest detects source drift without
# reintroducing the historical generated files.
python3 -I "$REPO/scripts/validate-encryption-candidate.py" --source-receipt \
    "$SOURCE" "$OUTPUT/kernel-source-before.jsonl"
cmp -s "$OUTPUT/kernel-source-before.jsonl" "$CACHE/kernel-source-manifest.jsonl" || {
    echo 'Private source differs from the Waydroid cache source receipt' >&2
    exit 1
}

export ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-
bash "$SOURCE/scripts/kconfig/merge_config.sh" -m -O "$OUTPUT" \
    "$OUTPUT/.config" "$REPO/config/r8q_audio_integration.config" \
    "$REPO/config/r8q_waydroid.config" "$REPO/config/r8q_encryption.config"
"$SOURCE/scripts/config" --file "$OUTPUT/.config" \
    --set-str INITRAMFS_SOURCE "$OUTPUT/temporary-accepted-encrypted-initramfs.cpio" \
    --set-str LOCALVERSION '-r8q-waydroid2'
# The copied cache contains generated config state whose timestamps are older
# than the copied objects but may still satisfy make's dependency check.  Drop
# only Kconfig's generated summary files so olddefconfig must regenerate them;
# per-object command files remain available for incremental reuse.
rm -f -- "$OUTPUT/include/config/auto.conf" "$OUTPUT/include/config/auto.conf.cmd" \
    "$OUTPUT/include/config/kernel.release" "$OUTPUT/include/generated/autoconf.h" \
    "$OUTPUT/include/generated/rustc_cfg" "$OUTPUT/include/generated/utsrelease.h"
make -C "$SOURCE" O="$OUTPUT" olddefconfig

python3 -I - "$OUTPUT" "$ENCRYPTED" "$CACHE" <<'PY'
import json
import pathlib
import sys

output, encrypted, cache = map(pathlib.Path, sys.argv[1:])

def config(path):
    values = {}
    for line in path.read_text().splitlines():
        if line.startswith('CONFIG_'):
            key, value = line.split('=', 1)
            values[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[2:-11]] = 'n'
    return values

def require(condition, message):
    if not condition:
        raise SystemExit(message)

before = config(output / 'baseline.config')
after = config(output / '.config')
accepted = config(encrypted / '.config')
delta = {key: {'before': before.get(key, 'n'), 'after': after.get(key, 'n')}
         for key in sorted(before.keys() | after.keys())
         if before.get(key, 'n') != after.get(key, 'n')}
expected_delta = {
    'CONFIG_BLK_DEV_DM', 'CONFIG_DM_CRYPT', 'CONFIG_CRYPTO_AES',
    'CONFIG_CRYPTO_AUTHENC', 'CONFIG_CRYPTO_CBC', 'CONFIG_CRYPTO_ESSIV',
    'CONFIG_CRYPTO_LIB_MD5', 'CONFIG_CRYPTO_XTS', 'CONFIG_PNFS_BLOCK',
    'CONFIG_INITRAMFS_SOURCE', 'CONFIG_LOCALVERSION',
}
require(set(delta) == expected_delta,
        'Unexpected resolved config delta: ' + str(sorted(set(delta) ^ expected_delta)))
for key in ('BLK_DEV_DM', 'DM_CRYPT', 'CRYPTO_AES', 'CRYPTO_XTS',
            'CRYPTO_AES_ARM64_CE_BLK', 'CRYPTO_CBC', 'CRYPTO_AUTHENC',
            'CRYPTO_ESSIV', 'CRYPTO_LIB_AES', 'CRYPTO_LIB_MD5',
            'CRYPTO_LIB_SHA256', 'PNFS_BLOCK'):
    name = 'CONFIG_' + key
    require(after.get(name) == accepted.get(name) == 'y',
            f'Encryption gate differs from accepted production04: {name}')
for key in ('ANDROID_BINDER_IPC', 'ANDROID_BINDERFS', 'MEMFD_CREATE', 'PSI',
            'NAMESPACES', 'CGROUPS', 'SECCOMP', 'SECCOMP_FILTER', 'BLK_DEV_INITRD',
            'MODULES', 'EFI', 'CMDLINE_FORCE', 'NF_TABLES_INET', 'NF_TABLES_IPV4',
            'NF_TABLES_IPV6', 'NF_NAT_MASQUERADE'):
    require(after.get('CONFIG_' + key) == 'y', 'Missing built-in Waydroid gate: ' + key)
for key in ('BRIDGE', 'VETH', 'OVERLAY_FS', 'NF_CONNTRACK', 'NF_NAT', 'NF_TABLES',
            'NFT_NAT', 'NFT_MASQ', 'NETFILTER_NETLINK', 'FW_CS_DSP',
            'SND_SOC_WM_ADSP', 'SND_SOC_CS35L41_LIB', 'SND_SOC_CS35L41',
            'SND_SOC_CS35L41_I2C', 'SND_SOC_R8Q_CS35L41'):
    require(after.get('CONFIG_' + key) == 'm', 'Missing Waydroid/audio module gate: ' + key)
require(after.get('CONFIG_ANDROID_BINDER_DEVICES') == '""', 'Binder device policy differs')
require(after.get('CONFIG_PSI_DEFAULT_DISABLED', 'n') == 'n', 'PSI must be active at boot')
require(after.get('CONFIG_MODVERSIONS') == 'n', 'Module version policy changed')
require(after.get('CONFIG_CC_VERSION_TEXT') == before.get('CONFIG_CC_VERSION_TEXT'), 'Compiler config changed')
require(after.get('CONFIG_CC_VERSION_TEXT') == accepted.get('CONFIG_CC_VERSION_TEXT'), 'Accepted compiler differs')
require(after.get('CONFIG_CMDLINE') == before.get('CONFIG_CMDLINE') == accepted.get('CONFIG_CMDLINE'),
        'External-DTB command line changed')
require(after.get('CONFIG_LOCALVERSION') == '"-r8q-waydroid2"', 'Wrong target local version')
require(after.get('CONFIG_INITRAMFS_SOURCE') == '"' + str(output / 'temporary-accepted-encrypted-initramfs.cpio') + '"',
        'Wrong temporary encrypted initramfs input')

(output / 'config-delta.json').write_text(json.dumps(delta, indent=2, sort_keys=True) + '\n')
(output / 'configuration-proof.json').write_text(json.dumps({
    'baseline': str(output / 'baseline.config'),
    'baseline_sha256': __import__('hashlib').sha256((output / 'baseline.config').read_bytes()).hexdigest(),
    'accepted_production04': str(encrypted / '.config'),
    'accepted_production04_sha256': __import__('hashlib').sha256((encrypted / '.config').read_bytes()).hexdigest(),
    'resolved': str(output / '.config'),
    'resolved_sha256': __import__('hashlib').sha256((output / '.config').read_bytes()).hexdigest(),
    'delta': delta,
    'compiler_config': after.get('CONFIG_CC_VERSION_TEXT'),
    'kernel_release': '7.1.2-r8q-waydroid2',
}, indent=2, sort_keys=True) + '\n')
print('Configuration gates passed: ' + str(len(delta)) + ' intended changes')
PY

RELEASE=$(make -s -C "$SOURCE" O="$OUTPUT" kernelrelease)
[[ $RELEASE == '7.1.2-r8q-waydroid2' ]] || { echo "Unexpected kernel release: $RELEASE" >&2; exit 1; }

python3 -I - "$OUTPUT" "$SOURCE" "$ENCRYPTED" "$DTB" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

output, source, encrypted, dtb = map(pathlib.Path, sys.argv[1:])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
(output / 'compiler.json').write_text(json.dumps({
    'clang': subprocess.check_output(['clang', '--version'], text=True).splitlines()[0],
    'ld_lld': subprocess.check_output(['ld.lld', '--version'], text=True).splitlines()[0],
    'llvm_ar': subprocess.check_output(['llvm-ar', '--version'], text=True).splitlines()[0],
    'cross_compiler': subprocess.check_output(['aarch64-linux-gnu-gcc', '--version'], text=True).splitlines()[0],
}, indent=2, sort_keys=True) + '\n')
(output / 'build-plan.json').write_text(json.dumps({
    'kind': 'r8q-waydroid-encrypted-incremental-preparation',
    'kernel_release': '7.1.2-r8q-waydroid2',
    'source': str(source),
    'source_complete_identity': '04902856706e864b6f9bb3e00ff96cc8b7e5129134d055b1e01a02a07378846b',
    'accepted_encrypted_build': str(encrypted),
    'temporary_initramfs': str(output / 'temporary-accepted-encrypted-initramfs.cpio'),
    'temporary_initramfs_sha256': sha(output / 'temporary-accepted-encrypted-initramfs.cpio'),
    'active_dtb': str(dtb),
    'active_dtb_sha256': sha(dtb),
    'cache_copy': 'cp -a --reflink=auto with staged modules, payload, receipts, and initramfs outputs excluded',
    'build_targets': ['Image', 'modules'],
    'jobs': int(__import__('os').environ.get('R8Q_WAYDROID_ENCRYPTED_JOBS', '2')),
    'stage2_required': True,
    'stage2': 'Primary must repackage matching 7.1.2-r8q-waydroid2 early modules into a new encrypted cpio, set INITRAMFS_SOURCE to that cpio, and relink Image before payload validation or boot.',
}, indent=2, sort_keys=True) + '\n')
PY

if [[ $CONFIG_ONLY == 1 ]]; then
    echo 'Configuration-only inspection complete; no Image or modules built.'
    exit 0
fi

# Stage 1: kbuild decides which copied objects are still valid from the
# source/config/compiler command identities.  No make clean or blanket -B is
# used, so dependency changes are rebuilt by kbuild while unaffected objects
# remain reusable.
make -C "$SOURCE" O="$OUTPUT" -j"$JOBS" Image modules

# modules.order is the kbuild authority for the current resolved config.  Any
# final .ko outside that closure is stale (for example a module that became
# built-in through the encryption gates), so quarantine it before modules_install
# can copy it into the staged bundle.  Also fail if kbuild promised a module but
# did not produce its final link product.
python3 -I - "$OUTPUT" "$STALE_ROOT" <<'PY'
import json
import pathlib
import shutil
import sys

output, stale_root = map(pathlib.Path, sys.argv[1:])
order = {
    line.strip()[:-2] + '.ko'
    for line in (output / 'modules.order').read_text().splitlines()
    if line.strip().endswith('.o')
}
actual = {
    str(path.relative_to(output))
    for path in output.rglob('*.ko')
    if path.is_file()
}
missing = sorted(order - actual)
stale = sorted(actual - order)
if missing:
    raise SystemExit('modules.order products missing after Image/modules: ' + str(missing[:12]))
if stale:
    destination = stale_root / 'after-build'
    for name in stale:
        path = output / name
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(target))
    (stale_root / 'after-build.json').write_text(json.dumps({
        'count': len(stale),
        'paths': stale,
        'reason': 'Final .ko was outside the current modules.order closure and was excluded before modules_install.',
    }, indent=2, sort_keys=True) + '\n')
(output / 'modules-order-closure.json').write_text(json.dumps({
    'modules_order_count': len(order),
    'final_module_count': len(actual - set(stale)),
    'stale_quarantined_count': len(stale),
}, indent=2, sort_keys=True) + '\n')
PY
mkdir "$OUTPUT/payload"
cp --reflink=auto "$OUTPUT/arch/arm64/boot/Image" "$OUTPUT/payload/BOOTAA64.EFI"
cp --reflink=auto "$DTB" "$OUTPUT/payload/R8Q-RTC.DTB"
make -C "$SOURCE" O="$OUTPUT" INSTALL_MOD_PATH="$OUTPUT/modules" DEPMOD=depmod modules_install

python3 -I - "$OUTPUT" "$SOURCE" "$DTB" <<'PY'
import hashlib
import json
import pathlib
import sys

output, source, dtb = map(pathlib.Path, sys.argv[1:])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
release = (output / 'include/config/kernel.release').read_text().strip()
if release != '7.1.2-r8q-waydroid2':
    raise SystemExit('Staged modules have the wrong kernel release: ' + release)
modules = sorted(str(p.relative_to(output / 'modules')) for p in (output / 'modules').rglob('*.ko'))
if not modules:
    raise SystemExit('No modules were staged')
(output / 'stage1-manifest.json').write_text(json.dumps({
    'kind': 'r8q-waydroid-encrypted-stage1',
    'kernel_release': release,
    'temporary_initramfs_sha256': sha(output / 'temporary-accepted-encrypted-initramfs.cpio'),
    'image_sha256': sha(output / 'arch/arm64/boot/Image'),
    'payload_image_sha256': sha(output / 'payload/BOOTAA64.EFI'),
    'dtb_sha256': sha(dtb),
    'module_count': len(modules),
    'module_paths': modules,
    'source': str(source),
    'stage2_required': True,
    'stage2': 'Replace temporary encrypted initramfs module paths with matching staged early modules, regenerate cpio, set INITRAMFS_SOURCE to the new cpio, then make Image before final embedded audit.',
}, indent=2, sort_keys=True) + '\n')
print(json.dumps({'kernel_release': release, 'module_count': len(modules),
                  'image_sha256': sha(output / 'arch/arm64/boot/Image')}, sort_keys=True))
PY
