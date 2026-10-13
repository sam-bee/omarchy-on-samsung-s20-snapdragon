#!/usr/bin/env bash
# Offline build only. No device, boot-filesystem or host installation actions.
set -euo pipefail
if [[ $# != 4 ]]; then
    echo "Usage: $0 PRIVATE_PATCHED_SOURCE ACCEPTED_BUILD ACTIVE_DTB NEW_OUTPUT" >&2
    exit 2
fi
R8Q_WAYDROID_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
R8Q_WAYDROID_SOURCE=$(realpath "$1")
R8Q_WAYDROID_BASELINE=$(realpath "$2")
R8Q_WAYDROID_DTB=$(realpath "$3")
R8Q_WAYDROID_OUTPUT=$(realpath -m "$4")
R8Q_WAYDROID_JOBS=${R8Q_WAYDROID_JOBS:-2}
[[ "$R8Q_WAYDROID_JOBS" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ ! -e "$R8Q_WAYDROID_OUTPUT" && "$R8Q_WAYDROID_OUTPUT" == "$R8Q_WAYDROID_REPO/out/"* ]]
[[ "$R8Q_WAYDROID_SOURCE" == "$R8Q_WAYDROID_REPO/out/waydroid-"*/source ]]
[[ -f "$R8Q_WAYDROID_SOURCE/Makefile" && -f "$R8Q_WAYDROID_SOURCE/r8q-waydroid-source.json" ]]
for tool in make clang ld.lld llvm-ar llvm-nm python3 aarch64-linux-gnu-gcc modinfo depmod; do
    command -v "$tool" >/dev/null || { echo "Required existing tool missing: $tool" >&2; exit 2; }
done
python3 -I - "$R8Q_WAYDROID_SOURCE" "$R8Q_WAYDROID_BASELINE" "$R8Q_WAYDROID_DTB" "$R8Q_WAYDROID_OUTPUT" "$R8Q_WAYDROID_REPO" <<'PY'
import gzip,hashlib,importlib.util,json,pathlib,struct,subprocess,sys
def require(condition,message):
    if not condition: raise SystemExit(message)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
source,baseline,dtb,output,repo=map(pathlib.Path,sys.argv[1:])
for root in (source,baseline):
    require(not output.is_relative_to(root) and not root.is_relative_to(output),'Output overlaps input')
config=(baseline/'.config').read_text()
require(sha(baseline/'.config')=='25879d3bf45fa6bc77a7146fcd4fb854e11fbf5f4f14c908eb86020817cbf5dc','Accepted config differs')
require(sha(baseline/'arch/arm64/boot/Image')=='50631087ad9b22b8f009b98e9279c1c65d27e4f26c456fe6ce10f29854aaa2bf','Accepted Image differs')
require(sha(source/'Makefile')=='9e74f1c62c24972fc6b4e56e6761a28e3f497984978131d24119a0aaabba8a8c','Kernel version source differs')
require(sha(source/'drivers/rtc/rtc-pm8xxx.c')=='e5eb2dc990ee79ee8bcdbc0710b96f08fe881253276700d054181b8050f5c516','Accepted RTC patch is missing')
receipt=json.loads((source/'r8q-waydroid-source.json').read_text())
spec=importlib.util.spec_from_file_location('waydroid_source_rules',repo/'scripts/prepare-waydroid-kernel-source.py')
rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)
require(receipt.get('schema')==1 and receipt.get('candidate')=='r8q-waydroid1' and receipt.get('kernel_source_version')=='7.1.2','Wrong source preparation identity')
require(receipt.get('preserved_audio_sources')==rules.PRESERVED_AUDIO_SOURCES,'Audio expectations differ from repository policy')
require([(p['name'],p['sha256']) for p in receipt['applied_patches']]==[(p[0],p[2]) for p in rules.PATCHES],'Source patch identities differ')
require(sha(source/rules.BOARD_DTS)==rules.BOARD_DTS_AFTER,'Accepted RTC board source differs')
for name,expected in rules.PRESERVED_AUDIO_SOURCES.items():
    require(sha(source/name)==expected,'Audio source differs: '+name)
require(receipt['rtc_patch_preserved'] is True and receipt['phone_operations'] is False,'Invalid source preparation receipt')
compiler=subprocess.check_output(['clang','--version'],text=True).splitlines()[0]
require('CONFIG_CC_VERSION_TEXT="'+compiler+'"' in config,'Compiler differs from accepted baseline')
require(sha(dtb)=='d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca','DTB differs from captured active payload')
data=dtb.read_bytes()
require(struct.unpack_from('>II',data)==(0xd00dfeed,len(data)),'Invalid FDT size')
cpio=(baseline/'usr/initramfs_data.cpio').read_bytes()
require(hashlib.sha256(cpio).hexdigest()=='0a6b828b9376a5b6db3152c14187036bc47f88cc0f99da0f7a7a74fc8887f317','Accepted cpio differs')
compressed=(baseline/'usr/initramfs_inc_data').read_bytes()
require(gzip.decompress(compressed)==cpio,'Accepted initramfs compression differs')
symbols={}
for line in subprocess.check_output(['llvm-nm',str(baseline/'vmlinux')],text=True).splitlines():
    fields=line.split()
    if len(fields)==3 and fields[2] in ('_text','__initramfs_start'): symbols[fields[2]]=int(fields[0],16)
require(len(symbols)==2,'Accepted initramfs symbols missing')
offset=symbols['__initramfs_start']-symbols['_text']
image=(baseline/'arch/arm64/boot/Image').read_bytes()
require(image[offset:offset+len(compressed)]==compressed,'Accepted cpio is not embedded in accepted Image')
rules.verify_complete_source_tree(source)
PY
mkdir -p "$R8Q_WAYDROID_OUTPUT"
cp "$R8Q_WAYDROID_BASELINE/.config" "$R8Q_WAYDROID_OUTPUT/baseline.config"
cp "$R8Q_WAYDROID_BASELINE/.config" "$R8Q_WAYDROID_OUTPUT/.config"
cp "$R8Q_WAYDROID_BASELINE/usr/initramfs_data.cpio" "$R8Q_WAYDROID_OUTPUT/accepted-initramfs.cpio"
# Reuse only the generic source-receipt action, not encryption build policy.
python3 -I "$R8Q_WAYDROID_REPO/scripts/validate-encryption-candidate.py" --source-receipt \
    "$R8Q_WAYDROID_SOURCE" "$R8Q_WAYDROID_OUTPUT/kernel-source-before.jsonl"
export ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-
bash "$R8Q_WAYDROID_SOURCE/scripts/kconfig/merge_config.sh" -m -O "$R8Q_WAYDROID_OUTPUT" \
    "$R8Q_WAYDROID_OUTPUT/.config" "$R8Q_WAYDROID_REPO/config/r8q_audio_integration.config" \
    "$R8Q_WAYDROID_REPO/config/r8q_waydroid.config"
"$R8Q_WAYDROID_SOURCE/scripts/config" --file "$R8Q_WAYDROID_OUTPUT/.config" \
    --set-str INITRAMFS_SOURCE "$R8Q_WAYDROID_OUTPUT/accepted-initramfs.cpio" \
    --set-str LOCALVERSION '-r8q-waydroid1'
make -C "$R8Q_WAYDROID_SOURCE" O="$R8Q_WAYDROID_OUTPUT" olddefconfig
python3 -I - "$R8Q_WAYDROID_OUTPUT" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
def config(path):
    values={}
    for line in path.read_text().splitlines():
        if line.startswith('CONFIG_'):k,v=line.split('=',1);values[k]=v
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):values[line[2:-11]]='n'
    return values
a=config(p/'baseline.config');b=config(p/'.config')
delta={k:{'before':a.get(k,'n'),'after':b.get(k,'n')} for k in sorted(a.keys()|b.keys()) if a.get(k,'n')!=b.get(k,'n')}
allowed={'CONFIG_ANDROID_BINDER_IPC','CONFIG_ANDROID_BINDERFS','CONFIG_ANDROID_BINDER_DEVICES',
         'CONFIG_PSI','CONFIG_NF_TABLES','CONFIG_NF_TABLES_INET',
         'CONFIG_NF_TABLES_IPV4','CONFIG_NF_TABLES_IPV6','CONFIG_NF_NAT','CONFIG_NF_NAT_MASQUERADE',
         'CONFIG_NFT_NAT','CONFIG_NFT_MASQ',
         'CONFIG_NETFILTER_NETLINK','CONFIG_LOCALVERSION','CONFIG_INITRAMFS_SOURCE',
         'CONFIG_CC_CAN_LINK','CONFIG_FW_CS_DSP','CONFIG_SND_SOC_WM_ADSP','CONFIG_SND_SOC_CS35L41',
         'CONFIG_SND_SOC_CS35L41_LIB','CONFIG_SND_SOC_CS35L41_I2C','CONFIG_SND_SOC_R8Q_CS35L41'}
(p/'config-delta.json').write_text(json.dumps(delta,indent=2)+'\n')
unexpected=set(delta)-allowed
if unexpected: raise SystemExit('Unexpected config changes: '+str(sorted(unexpected)))
required_y=('ANDROID_BINDER_IPC','ANDROID_BINDERFS','MEMFD_CREATE','PSI','NAMESPACES',
            'CGROUPS','SECCOMP','SECCOMP_FILTER','BLK_DEV_LOOP','EXT4_FS','DRM_SIMPLEDRM',
            'EFI','CMDLINE_FORCE','NF_TABLES_INET','NF_TABLES_IPV4','NF_TABLES_IPV6','NF_NAT_MASQUERADE')
required_m=('BRIDGE','VETH','OVERLAY_FS','NF_CONNTRACK','NF_NAT','NF_TABLES','NFT_NAT','NFT_MASQ','NETFILTER_NETLINK',
            'FW_CS_DSP','SND_SOC_WM_ADSP','SND_SOC_CS35L41_LIB','SND_SOC_CS35L41',
            'SND_SOC_CS35L41_I2C','SND_SOC_R8Q_CS35L41')
if any(b.get('CONFIG_'+k)!='y' for k in required_y) or any(b.get('CONFIG_'+k)!='m' for k in required_m):
    raise SystemExit('Missing resolved Waydroid/hardware prerequisite')
if b.get('CONFIG_ANDROID_BINDER_DEVICES')!='""' or b.get('CONFIG_PSI_DEFAULT_DISABLED','n')!='n':
    raise SystemExit('Binder device or PSI policy differs')
if b.get('CONFIG_CMDLINE')!=a.get('CONFIG_CMDLINE'):
    raise SystemExit('Accepted external-DTB command line changed')
if b.get('CONFIG_MODVERSIONS')!='n' or b.get('CONFIG_LOCALVERSION')!='"-r8q-waydroid1"':
    raise SystemExit('Module version policy differs')
print('Configuration gates passed: '+str(len(delta))+' intended changes')
PY
R8Q_WAYDROID_RELEASE=$(make -s -C "$R8Q_WAYDROID_SOURCE" O="$R8Q_WAYDROID_OUTPUT" kernelrelease)
[[ "$R8Q_WAYDROID_RELEASE" == 7.1.2-r8q-waydroid1 ]]
if [[ ${R8Q_WAYDROID_CONFIG_ONLY:-0} == 1 ]]; then
    echo 'Configuration-only inspection complete; no Image or modules built.'
    exit 0
fi
make -C "$R8Q_WAYDROID_SOURCE" O="$R8Q_WAYDROID_OUTPUT" -j"$R8Q_WAYDROID_JOBS" Image modules
mkdir "$R8Q_WAYDROID_OUTPUT/payload"
cp "$R8Q_WAYDROID_OUTPUT/arch/arm64/boot/Image" "$R8Q_WAYDROID_OUTPUT/payload/BOOTAA64.EFI"
cp "$R8Q_WAYDROID_DTB" "$R8Q_WAYDROID_OUTPUT/payload/R8Q-RTC.DTB"
make -C "$R8Q_WAYDROID_SOURCE" O="$R8Q_WAYDROID_OUTPUT" \
    INSTALL_MOD_PATH="$R8Q_WAYDROID_OUTPUT/modules" DEPMOD=depmod modules_install
python3 -I "$R8Q_WAYDROID_REPO/scripts/validate-waydroid-candidate.py" \
    "$R8Q_WAYDROID_OUTPUT" "$R8Q_WAYDROID_SOURCE" "$R8Q_WAYDROID_BASELINE" \
    "$R8Q_WAYDROID_OUTPUT/accepted-initramfs.cpio"
